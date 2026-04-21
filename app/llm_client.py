import asyncio
import json
import logging
import time

import httpx

from app.circuit_breaker import CircuitBreaker
from app.config import settings
from app.metrics import (
    ollama_request_duration_seconds,
    ollama_requests_total,
    triage_fallback_total,
    triage_llm_token_count,
)
from app.models import Decision, GatheredContext, GrafanaAlert, LLMDecision

logger = logging.getLogger(__name__)

# Transient HTTP status codes that warrant a retry
_RETRIABLE_STATUS_CODES = set(range(500, 600))

SYSTEM_PROMPT = """You are an expert SRE assistant analyzing infrastructure alerts for the CIRES Technologies observability platform.

Your job:
1. Analyze the alert and the pre-gathered context (metrics, logs, traces) provided below.
2. Use the MCP tools available to gather additional data if needed.
3. Always check all three pillars (metrics, logs, traces) within the alert time window before reaching a verdict.
4. Determine if the alert represents a real issue (ESCALATE), noise (DISMISS), or if you cannot determine with confidence (INCONCLUSIVE).
5. If ESCALATE: provide a root cause analysis, supporting evidence, and suggested remediation.
6. If DISMISS: explain why this is not actionable.
7. If INCONCLUSIVE: explain what additional information would be needed.

You MUST respond with ONLY valid JSON matching this exact schema:
{
  "decision": "ESCALATE" | "DISMISS" | "INCONCLUSIVE",
  "severity": "critical" | "warning" | "info",
  "confidence": <float between 0.0 and 1.0>,
  "reason": "<one-line summary of why this decision was made>",
  "rca": "<detailed root cause analysis (2-5 sentences)>",
  "anomaly_summary": "<summary of Drain3 anomaly findings>",
  "suggested_actions": ["<action 1>", "<action 2>"],
  "evidence": ["<metric/log/trace evidence used>"]
}

Field descriptions:
- decision: ESCALATE (real issue requiring human attention), DISMISS (noise/not actionable), or INCONCLUSIVE (cannot determine)
- severity: the assessed severity level
- confidence: your confidence in the decision from 0.0 (no confidence) to 1.0 (certain)
- reason: brief one-line explanation
- rca: root cause analysis in 2-5 sentences; if DISMISS, explain why it's noise
- anomaly_summary: summary of any log anomalies detected by Drain3
- suggested_actions: list of recommended remediation steps
- evidence: list of specific metrics, log lines, or trace data supporting the decision"""


def _build_fallback_decision() -> LLMDecision:
    """Return a safe NEEDS_HUMAN_REVIEW fallback when the LLM is unavailable."""
    return LLMDecision(
        decision=Decision.ESCALATE,
        severity="warning",
        confidence=0.0,
        reason="LLM unavailable \u2014 automatic escalation for human review",
        rca="AI triage could not complete analysis. Raw alert forwarded for manual review.",
        suggested_actions=["Review the raw alert manually", "Check Ollama service health"],
        evidence=[],
    )


class LLMClient:
    """Ollama-backed LLM client with retry, circuit breaker, and schema enforcement."""

    # Retry configuration
    MAX_RETRIES = 2
    BACKOFF_BASE = 1  # seconds; delays will be 1s, 2s

    def __init__(self):
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.ollama_request_timeout, connect=10)
        )
        self._circuit = CircuitBreaker()

    async def close(self):
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def investigate(
        self,
        alert: GrafanaAlert,
        context: GatheredContext,
        drain_summary: str,
        history_context: str = "",
    ) -> tuple[LLMDecision, int]:
        """Run LLM investigation. Returns (decision, duration_ms)."""
        messages = self._build_prompt(alert, context, drain_summary, history_context)

        start = time.monotonic()
        raw_response = await self._call_ollama_with_resilience(messages)
        duration_ms = int((time.monotonic() - start) * 1000)

        if raw_response is None:
            # Circuit open or retries exhausted -- fallback already counted
            return _build_fallback_decision(), duration_ms

        logger.info("LLM response received in %dms", duration_ms)
        logger.debug("Raw LLM response: %s", raw_response)

        # --- AI-02: Schema enforcement with retry ---
        decision, parse_error = self._parse_response(raw_response)

        if decision is None:
            # Retry once with the Pydantic validation error appended
            logger.warning("LLM JSON parse failed, retrying with error feedback")
            messages.append({"role": "assistant", "content": raw_response})
            messages.append({
                "role": "user",
                "content": (
                    "Your response was not valid JSON or did not match the required schema. "
                    f"Validation error: {parse_error}\n\n"
                    "Respond ONLY with valid JSON matching the exact schema specified in the system prompt."
                ),
            })
            retry_response = await self._call_ollama_with_resilience(messages)
            if retry_response is not None:
                logger.debug("Raw LLM retry response: %s", retry_response)
                decision, _ = self._parse_response(retry_response)

        if decision is None:
            # Second parse failure -> fallback
            logger.error("LLM JSON parse failed after retry -- falling back to NEEDS_HUMAN_REVIEW")
            triage_fallback_total.labels(reason="parse_failure").inc()
            return _build_fallback_decision(), duration_ms

        # --- AI-02: INCONCLUSIVE handling ---
        if decision.decision == Decision.INCONCLUSIVE:
            logger.warning(
                "LLM returned INCONCLUSIVE (confidence=%.2f) for alert -- treating as ESCALATE",
                decision.confidence,
            )
            decision.decision = Decision.ESCALATE

        return decision, duration_ms

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_prompt(
        self,
        alert: GrafanaAlert,
        context: GatheredContext,
        drain_summary: str,
        history_context: str,
    ) -> list[dict]:
        user_content = f"""## Alert Details
- **Name:** {alert.alertname}
- **Severity:** {alert.severity}
- **Service:** {alert.service}
- **Instance:** {alert.instance}
- **Status:** {alert.status}
- **Started:** {alert.startsAt}
- **Summary:** {alert.annotations.get("summary", "N/A")}
- **Description:** {alert.annotations.get("description", "N/A")}

## Pre-Gathered Context

### Metrics (Prometheus, last {settings.prometheus_range_minutes}min)
{json.dumps(context.metrics, indent=2) if context.metrics else "[Prometheus] unavailable"}

### Logs (Loki, last {settings.loki_log_limit} lines, Drain3-annotated)
{chr(10).join(context.annotated_logs) if context.annotated_logs else "[Loki] unavailable"}

### {drain_summary}

### Traces (Jaeger, last {settings.jaeger_trace_limit} traces)
{json.dumps(context.traces, indent=2, default=str) if context.traces else "[Jaeger] unavailable"}

### Context Gathering Stats
- Sources available: {context.sources_available}/3
- Prometheus: {context.prometheus_ms}ms, Loki: {context.loki_ms}ms, Jaeger: {context.jaeger_ms}ms
{chr(10).join(context.errors) if context.errors else ""}

## RCA History
{history_context if history_context else "No prior RCA records for this alert."}

Analyze this alert using the context above. Respond with ONLY valid JSON."""

        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]

    # ------------------------------------------------------------------
    # Ollama call with circuit breaker + exponential backoff retry
    # ------------------------------------------------------------------

    async def _call_ollama_with_resilience(self, messages: list[dict]) -> str | None:
        """Call Ollama with circuit breaker check and retries.

        Returns the raw response string, or None if the circuit is open
        or all retries are exhausted.
        """
        # Circuit breaker gate
        if self._circuit.is_open:
            logger.warning("Circuit breaker OPEN -- returning fallback immediately")
            ollama_requests_total.labels(status="circuit_open").inc()
            triage_fallback_total.labels(reason="circuit_open").inc()
            return None

        last_exception: Exception | None = None
        for attempt in range(self.MAX_RETRIES + 1):  # 0, 1, 2 = initial + 2 retries
            if attempt > 0:
                # Check circuit again before retry (may have tripped open)
                if self._circuit.is_open:
                    logger.warning("Circuit breaker OPEN during retry -- aborting")
                    ollama_requests_total.labels(status="circuit_open").inc()
                    triage_fallback_total.labels(reason="circuit_open").inc()
                    return None

                delay = self.BACKOFF_BASE * (2 ** (attempt - 1))  # 1s, 2s
                logger.info("Retrying Ollama call (attempt %d/%d) after %.1fs backoff",
                            attempt + 1, self.MAX_RETRIES + 1, delay)
                await asyncio.sleep(delay)

            try:
                result = await self._call_ollama(messages)
                self._circuit.record_success()
                ollama_requests_total.labels(status="success").inc()
                return result

            except httpx.TimeoutException as exc:
                last_exception = exc
                self._circuit.record_failure()
                ollama_requests_total.labels(status="timeout").inc()
                logger.warning("Ollama request timeout (attempt %d/%d): %s",
                               attempt + 1, self.MAX_RETRIES + 1, exc)

            except httpx.ConnectError as exc:
                last_exception = exc
                self._circuit.record_failure()
                ollama_requests_total.labels(status="error").inc()
                logger.warning("Ollama connect error (attempt %d/%d): %s",
                               attempt + 1, self.MAX_RETRIES + 1, exc)

            except httpx.HTTPStatusError as exc:
                last_exception = exc
                if exc.response.status_code in _RETRIABLE_STATUS_CODES:
                    self._circuit.record_failure()
                    ollama_requests_total.labels(status="error").inc()
                    logger.warning("Ollama 5xx error (attempt %d/%d): %s",
                                   attempt + 1, self.MAX_RETRIES + 1, exc)
                else:
                    # Non-retriable HTTP error (4xx) -- client-side issue, not server
                    # Do NOT count toward circuit breaker (Ollama is healthy)
                    ollama_requests_total.labels(status="error").inc()
                    logger.error("Ollama non-retriable HTTP error: %s", exc)
                    break

        # All retries exhausted
        logger.error("Ollama retries exhausted after %d attempts: %s",
                      self.MAX_RETRIES + 1, last_exception)
        triage_fallback_total.labels(reason="retries_exhausted").inc()
        return None

    async def _call_ollama(self, messages: list[dict]) -> str:
        """Make a single HTTP request to the Ollama chat API."""
        start = time.monotonic()
        try:
            resp = await self._client.post(
                f"{settings.ollama_url}/api/chat",
                json={
                    "model": settings.ollama_model,
                    "messages": messages,
                    "stream": False,
                    "format": "json",
                },
            )
            resp.raise_for_status()
            data = resp.json()
            # Ollama reports token counts on the chat response; record for self-observability (AI-03)
            prompt_tokens = data.get("prompt_eval_count")
            completion_tokens = data.get("eval_count")
            if isinstance(prompt_tokens, int) and prompt_tokens >= 0:
                triage_llm_token_count.labels(type="prompt").observe(prompt_tokens)
            if isinstance(completion_tokens, int) and completion_tokens >= 0:
                triage_llm_token_count.labels(type="completion").observe(completion_tokens)
            return data.get("message", {}).get("content", "")
        finally:
            elapsed = time.monotonic() - start
            ollama_request_duration_seconds.observe(elapsed)

    # ------------------------------------------------------------------
    # Response parsing with Pydantic validation
    # ------------------------------------------------------------------

    def _parse_response(self, raw: str) -> tuple[LLMDecision | None, str]:
        """Parse the LLM response into an LLMDecision.

        Returns (decision, error_message). On success error_message is empty.
        """
        try:
            text = raw.strip()
            # Handle case where LLM wraps JSON in markdown code block
            if text.startswith("```"):
                lines = text.split("\n")
                text = "\n".join(
                    lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
                )

            data = json.loads(text)

            # Map alternative field names the LLM might produce
            if "root_cause" in data and "rca" not in data:
                data["rca"] = data.pop("root_cause")
            if "recommended_actions" in data and "suggested_actions" not in data:
                data["suggested_actions"] = data.pop("recommended_actions")
            # Accept "verdict" as alias for "decision"
            if "verdict" in data and "decision" not in data:
                data["decision"] = data.pop("verdict")

            decision = LLMDecision(**data)
            return decision, ""
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            error_msg = str(e)
            logger.warning("Failed to parse LLM response: %s", error_msg)
            return None, error_msg
        except Exception as e:
            error_msg = str(e)
            logger.warning("Unexpected error parsing LLM response: %s", error_msg)
            return None, error_msg
