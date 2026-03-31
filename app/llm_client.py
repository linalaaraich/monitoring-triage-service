import json
import logging
import time

import httpx

from app.config import settings
from app.models import Decision, GatheredContext, GrafanaAlert, LLMDecision

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert SRE assistant analyzing infrastructure alerts for the CIRES Technologies observability platform.

Your job:
1. Analyze the alert and the pre-gathered context (metrics, logs, traces) provided below.
2. Use the MCP tools available to gather additional data if needed.
3. Always check all three pillars (metrics, logs, traces) within the alert time window before reaching a verdict.
4. Determine if the alert represents a real issue (ESCALATE) or noise (DISMISS).
5. If ESCALATE: provide a root cause analysis, supporting evidence, and suggested remediation.
6. If DISMISS: explain why this is not actionable.

You MUST respond with ONLY valid JSON in this exact format (no other text):
{
  "decision": "ESCALATE" or "DISMISS",
  "severity": "critical" or "warning" or "info",
  "reason": "one-line summary of why this decision was made",
  "rca": "detailed root cause analysis (2-5 sentences)",
  "anomaly_summary": "summary of Drain3 anomaly findings",
  "suggested_actions": ["action 1", "action 2"],
  "evidence": ["metric/log/trace evidence used"]
}"""


class LLMClient:
    def __init__(self):
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.ollama_timeout, connect=10)
        )

    async def close(self):
        await self._client.aclose()

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
        raw_response = await self._call_ollama(messages)
        duration_ms = int((time.monotonic() - start) * 1000)

        logger.info("LLM response received in %dms", duration_ms)
        logger.debug("Raw LLM response: %s", raw_response)

        decision = self._parse_response(raw_response)
        if decision is None:
            # Retry once with stricter instruction
            logger.warning("LLM JSON parse failed, retrying with strict instruction")
            messages.append({"role": "assistant", "content": raw_response})
            messages.append({
                "role": "user",
                "content": "Your response was not valid JSON. Respond ONLY with valid JSON matching the exact format specified. No other text.",
            })
            raw_response = await self._call_ollama(messages)
            logger.debug("Raw LLM retry response: %s", raw_response)
            decision = self._parse_response(raw_response)

        if decision is None:
            # Safe fallback: ESCALATE
            logger.error("LLM JSON parse failed after retry — defaulting to ESCALATE")
            decision = LLMDecision(
                decision=Decision.ESCALATE,
                severity=alert.severity,
                reason="LLM response could not be parsed — escalating as safety fallback",
                rca="Automated fallback: the AI triage system could not produce a structured analysis. The raw alert has been escalated for manual review.",
                suggested_actions=["Review the alert manually", "Check LLM logs for debugging"],
                evidence=["LLM parse failure"],
            )

        return decision, duration_ms

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

    async def _call_ollama(self, messages: list[dict]) -> str:
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
        return data.get("message", {}).get("content", "")

    def _parse_response(self, raw: str) -> LLMDecision | None:
        try:
            # Try to extract JSON from the response
            text = raw.strip()
            # Handle case where LLM wraps JSON in markdown code block
            if text.startswith("```"):
                lines = text.split("\n")
                text = "\n".join(
                    lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
                )

            data = json.loads(text)
            return LLMDecision(**data)
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            logger.warning("Failed to parse LLM response: %s", e)
            return None
