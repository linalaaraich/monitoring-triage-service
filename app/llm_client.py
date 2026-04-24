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
2. Always check all three pillars (metrics, logs, traces) within the alert time window before reaching a verdict.
3. Determine if the alert represents a real issue (ESCALATE), noise (DISMISS), or if you cannot determine with confidence (INCONCLUSIVE).
4. If ESCALATE: provide a root cause analysis, supporting evidence, and suggested remediation.
5. If DISMISS: explain why this is not actionable.
6. If INCONCLUSIVE: explain what additional information would be needed.

CRITICAL output quality rules (must follow):
A. The alert itself ALWAYS carries useful signal: a PromQL expression, a current observed value, and a time window. Always start your RCA by restating the rule's PromQL, the observed value, and whether the value is materially above or below the threshold. This is data — treat it as such.
B. If any pre-gathered pillar (metrics/logs/traces) is empty, name WHICH pillar returned nothing and WHY that might be (e.g. "Loki returned 0 lines for service=X — possible causes: service not emitting logs, wrong label, shipper down"). Never write the phrase "insufficient data" as a standalone conclusion — always pair it with a named missing source and a concrete hypothesis to test next.
C. If the "Prior decisions for this alert" section below shows past decisions that hedged (tagged data_starved), DO NOT repeat the same hedge. Use the available signal — even if thin — to propose a specific hypothesis, and suggest concrete remediation the human can check.
D. Prefer ESCALATE over INCONCLUSIVE when you can at least name a probable cause. INCONCLUSIVE should be rare and always accompanied by a specific remediation: what query to run, what label to add, which shipper to restart.

E. suggested_actions MUST be concrete, not advice. Each entry must be ONE of:
   - an exact shell command (with args filled in based on the alert labels), OR
   - a specific PromQL/LogQL query the operator can paste into Grafana, OR
   - a specific URL to open (Grafana panel, Jaeger trace, runbook).
   BAD (reject these — too vague, don't emit): "Check logs for errors", "Monitor the situation",
        "Investigate further", "Review CPU usage", "Look into it".
   GOOD (emit these): "Run `kubectl top nodes` — the instance 10.0.1.194:9100 is likely CPU-bound",
        "Query Loki: `{service_name=\"spring-boot\"} |~ \"(?i)error|exception\" | count_over_time[5m]`",
        "Open http://grafana/d/spring-boot and check the request-rate panel at 22:36 UTC",
        "ssh deploy@observability-rca-k3s and run `top -b -n 1 | head -20` to see the hottest process".
   If you cannot produce a concrete action, emit fewer actions — an empty list is better than vague advice.
F. evidence items must cite a SPECIFIC metric value, log line, or trace ID — not a general category.
   BAD: "Prometheus metrics", "Log patterns"
   GOOD: "node_cpu_seconds_total{instance=\"10.0.1.194:9100\",mode=\"idle\"} = 5.6%",
         "Loki line `[ANOMALY] java.lang.OutOfMemoryError: Java heap space` appeared 4x in last 60s",
         "Jaeger trace 7f3a2c1d9b4e: GET /api/employee took 2347ms, span waits on MySQL connection pool"

G. Match the suggested_actions to the service's actual deployment type. The alert labels include a `deployment_type` field (one of: k8s, docker-vm, systemd, external). If deployment_type=docker-vm do NOT emit kubectl commands — use `ssh deploy@<host> docker ps` / `docker logs <container>` / `systemctl status <unit>`. If deployment_type=k8s use kubectl. If deployment_type=systemd use systemctl on the host directly. Mixing deployment types in suggested_actions is a rejectable error.

H. If the alert has correlated neighbors (see "Neighboring alerts" section), your RCA MUST explicitly explain the relationship: either (a) "X caused Y because ...", (b) "X and Y share common cause Z", or (c) "X and Y are unrelated, coincident timing." Don't silently ignore correlations — they are a signal the operator is already looking at.

## Response schema (enforced at decode time)

You MUST return JSON matching the schema below. The Ollama runtime validates at decode — invalid JSON is IMPOSSIBLE, but semantic quality is still on you.

{
  "decision": "ESCALATE" | "DISMISS" | "INCONCLUSIVE",
  "severity": "critical" | "warning" | "info",
  "confidence": <float 0.0-1.0>,
  "reason": "<one-line summary>",
  "rca": "<2-5 sentences; start by restating observed value + PromQL>",
  "anomaly_summary": "<Drain3 findings or '' if none>",
  "suggested_actions": [<2-4 concrete commands/queries/URLs — see rule E>],
  "evidence": [<specific metric values / log lines / trace IDs — see rule F>]
}

## Few-shot examples

The three examples below show expected quality. Match this shape, not just the schema.

### Example 1 — ESCALATE with clear metric signal

INPUT:
  alertname=HighCpuUsage, service=k3s-node, deployment_type=systemd
  observed_value=94.4 (refId=B) [A=94.4, C=1], threshold=85, unit=percent
  metric interpretation: CPU busy = 94.4% (idle = 5.6%), 9.4 percentage points above 80% threshold, sustained for 1 min
  loki: 0 lines (expected for node-level alert)
  jaeger: 0 traces (expected for infrastructure metric)
  correlated: HighMemoryUsage same host within ±5 min

EXPECTED OUTPUT:
{
  "decision": "ESCALATE",
  "severity": "warning",
  "confidence": 0.85,
  "reason": "CPU busy 94.4% sustained on 10.0.1.194 — 9.4pp over threshold; coincident memory pressure points to load spike or runaway process.",
  "rca": "PromQL `100 - (avg by(instance) (rate(node_cpu_seconds_total{mode=\\"idle\\"}[1m])) * 100)` returned 94.4% on instance 10.0.1.194:9100, placing the host well above the 85% threshold. Correlated HighMemoryUsage on the same host within 5 minutes suggests either a workload-level spike (pod burst) or a runaway process consuming both CPU and RAM. Node-level logs aren't in Loki for this service (expected — no app pipeline), so host-level introspection is needed.",
  "anomaly_summary": "",
  "suggested_actions": [
    "ssh deploy@observability-rca-k3s 'top -b -n 1 | head -20' — identify the hottest process",
    "kubectl top pods -A --sort-by=cpu | head -10 — see which workload is consuming CPU",
    "Query Grafana: rate(node_cpu_seconds_total{instance=\\"10.0.1.194:9100\\"}[5m]) by (mode) — confirm mode (user vs system vs iowait)"
  ],
  "evidence": [
    "node_cpu_seconds_total{instance=\\"10.0.1.194:9100\\",mode=\\"idle\\"} rate = 5.6% (observed value 94.4% busy)",
    "Correlated HighMemoryUsage alert on same instance fired 2 minutes prior"
  ]
}

### Example 2 — DISMISS noise / self-resolving

INPUT:
  alertname=HighP95Latency, service=spring-boot, deployment_type=k8s
  observed_value=1020 (refId=B), threshold=1000, unit=milliseconds
  metric interpretation: p95 = 1020 ms, 20 ms above 1000 ms threshold (2% over), spike duration 1 sample (10s)
  prometheus: p95 dropped back to 340 ms within next scrape interval
  loki: 50 lines all INFO, no errors
  jaeger: 12 traces, slowest 340 ms — all under threshold
  prior decisions: this rule has fired 14 times in last 24h, all DISMISS

EXPECTED OUTPUT:
{
  "decision": "DISMISS",
  "severity": "info",
  "confidence": 0.75,
  "reason": "Single-sample spike 20ms over threshold; next scrape p95 back to 340ms; no supporting log/trace anomalies.",
  "rca": "PromQL `histogram_quantile(0.95, ...)` reported 1020 ms at fire time, briefly crossing the 1000 ms threshold by 2%. The next scrape interval dropped p95 back to 340 ms, and the slowest Jaeger trace in window was 340 ms — no individual request exceeded the threshold. 50 Loki lines show no errors or exceptions. This matches the pattern seen 14 times in the last 24h on this rule, all of which have been dismissed.",
  "anomaly_summary": "0 of 50 lines anomalous",
  "suggested_actions": [
    "Consider raising the HighP95Latency threshold from 1000ms to 1200ms — current firing rate is mostly noise",
    "Query Grafana: histogram_quantile(0.99, ...) to see if p99 captures real spikes while p95 stays quiet"
  ],
  "evidence": [
    "Prometheus histogram_quantile(0.95) = 1020 ms at fire, 340 ms at next scrape (+10s)",
    "Jaeger slowest trace in window: 340 ms GET /api/employee — below threshold",
    "14 prior DISMISS decisions for this rule in last 24h (signal: threshold too tight)"
  ]
}

### Example 3 — data-thin but still actionable (replaces old INCONCLUSIVE behavior)

INPUT:
  alertname=TargetDown, service=monitoring, deployment_type=docker-vm
  observed_value=0 (refId=B) [A=0, C=1], threshold=1, unit=boolean
  metric interpretation: up = 0 on instance 10.0.1.68:9100 — scrape target unreachable for 2+ min
  prometheus: empty (target itself is what's down — can't query it directly)
  loki: 0 lines for service=monitoring — this is Grafana on docker-vm, not k8s, so no app-pipeline logs here
  jaeger: 0 traces (not a traced service)
  prior decisions: none for this specific instance

EXPECTED OUTPUT:
{
  "decision": "ESCALATE",
  "severity": "critical",
  "confidence": 0.70,
  "reason": "Scrape target 10.0.1.68:9100 (node-exporter on monitoring-vm) unreachable 2+ min; metric/log/trace pillars expected-empty because we can't probe the down target or its logs.",
  "rca": "PromQL `up == 0` returned 0 for instance 10.0.1.68:9100 — the node-exporter on the monitoring VM. Metrics from this target are unavailable by definition (that's what's being alerted), and Loki has no service=monitoring logs because Grafana/node-exporter on the monitoring VM are deployed via docker-compose, not k8s, and ship logs directly via docker rather than through the app log pipeline. The most likely causes, in order, are: (1) node-exporter container stopped or crashed on monitoring-vm, (2) network path between Prometheus and monitoring-vm is broken, (3) Prometheus scrape config drift.",
  "anomaly_summary": "",
  "suggested_actions": [
    "ssh deploy@observability-rca-monitoring 'docker ps --filter name=node-exporter' — verify the container is running",
    "ssh deploy@observability-rca-monitoring 'curl -sf http://localhost:9100/metrics | head -5' — verify the scrape endpoint is alive",
    "Query Grafana: up{instance=\\"10.0.1.68:9100\\"}[30m] — see when the target went down"
  ],
  "evidence": [
    "up{instance=\\"10.0.1.68:9100\\"} = 0 (target unreachable for 2+ min)",
    "Loki empty: expected for service=monitoring (deployment_type=docker-vm, no app log pipeline)"
  ]
}

---

Respond with valid JSON only. Start your RCA by restating the observed value and PromQL."""


def pick_primary_value(values: dict) -> tuple[str | None, float | None]:
    """Pick the most informative (refId, value) pair from a Grafana alert values dict.

    Grafana's standard alert rule is a 3-step pipeline: A=query -> B=reduce
    -> C=threshold. The threshold step emits a boolean (0 or 1) indicating
    whether the condition matched — it is NOT the metric value. Naively
    taking the alphabetically-last refId picks C, feeds "1" to the LLM,
    and the LLM then writes RCAs like "observed value is 1, target is UP"
    for a TargetDown alert. The actual metric value lives in the reduce
    step (B).

    Rule: if the highest-refId entry is exactly 0 or 1 AND there are other
    entries, treat it as the threshold step and prefer the one just below
    it. Otherwise the last entry IS the value (single-step rules exist).
    """
    if not values:
        return None, None
    items = sorted(values.items())
    # Single entry — that IS the observed value
    if len(items) == 1:
        return items[0][0], items[0][1]
    last_ref, last_val = items[-1]
    try:
        is_boolean_threshold = float(last_val) in (0.0, 1.0)
    except (TypeError, ValueError):
        is_boolean_threshold = False
    if is_boolean_threshold:
        # Skip the threshold step; the reduce step is the one below
        return items[-2]
    return last_ref, last_val


def _format_observed_value(values: dict) -> str:
    """Render the Grafana webhook's `values` dict for inclusion in the LLM prompt.

    Shows the primary metric value prominently and lists other refIds for
    context. See pick_primary_value() for why we avoid the threshold step.
    """
    if not values:
        return ""
    primary_ref, primary_val = pick_primary_value(values)
    out = [f"{primary_val} (refId={primary_ref})"]
    # Show the rest for transparency (including the boolean threshold)
    rest_items = [(k, v) for k, v in sorted(values.items()) if k != primary_ref]
    if rest_items:
        rest = ", ".join(f"{k}={v}" for k, v in rest_items)
        out.append(f"[other refIds: {rest}]")
    return " ".join(out)


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
        correlated: list[dict] | None = None,
        metric_facts=None,  # app.metric_interpreter.MetricFacts, but avoid import cycle
        tool_result_block: str | None = None,
    ) -> tuple[LLMDecision, int]:
        """Run LLM investigation. Returns (decision, duration_ms).

        If tool_result_block is given, it's appended to the user_content as
        additional evidence from a bounded-agency retry (see app.bounded_agency).
        """
        messages = self._build_prompt(alert, context, drain_summary, history_context, correlated, metric_facts)
        if tool_result_block:
            # Append to the final user message so the tool result is read
            # together with the original evidence.
            messages[-1]["content"] += "\n\n" + tool_result_block

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
                    "STRICT: valid JSON only, no markdown fences, no prose, no extra keys. "
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

    async def request_tool_or_decide(
        self,
        alert: GrafanaAlert,
        context: GatheredContext,
        drain_summary: str,
        history_context: str,
        correlated: list[dict] | None,
        metric_facts,
    ) -> tuple[dict | None, int]:
        """Bounded-agency first half: ask the LLM to either request ONE
        tool call from the whitelist OR emit a final decision.

        Returns (parsed_response_dict, duration_ms). The caller introspects
        the dict: if it has `tool_request`, execute + re-prompt via
        investigate(). Otherwise treat as a completed decision (try to
        parse into LLMDecision).

        Doesn't use structured outputs — the response can be either shape,
        so we use format=json and parse leniently.
        """
        from app.bounded_agency import TOOLS_DESCRIPTION
        messages = self._build_prompt(alert, context, drain_summary, history_context, correlated, metric_facts)
        messages[-1]["content"] += (
            "\n\n## YOUR FIRST PASS WAS DATA-STARVED\n\n"
            "Your first response hedged with 'insufficient data' or similar. You now have "
            "the chance to request ONE additional MCP query before committing to a verdict.\n\n"
            + TOOLS_DESCRIPTION
            + "\n\nEmit either `{\"tool_request\": {\"name\": ..., \"args\": {...}}}` OR "
            "the normal decision JSON. Choose the tool that is MOST likely to resolve your uncertainty. "
            "Don't use a tool if the current evidence already suffices."
        )

        start = time.monotonic()
        # Use format=json (not structured schema) — the response can be
        # either shape (tool_request or decision).
        try:
            resp = await self._client.post(
                f"{settings.ollama_url}/api/chat",
                json={
                    "model": settings.ollama_model,
                    "messages": messages,
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0, "num_ctx": 16384},
                },
            )
            resp.raise_for_status()
            data = resp.json()
            raw = data.get("message", {}).get("content", "")
        except Exception as exc:
            logger.warning("Agency LLM call failed: %s", exc)
            return None, int((time.monotonic() - start) * 1000)

        duration_ms = int((time.monotonic() - start) * 1000)
        try:
            parsed = json.loads(raw)
        except Exception:
            # Fallback: strip markdown if present
            text = raw.strip()
            if text.startswith("```"):
                text = "\n".join(text.split("\n")[1:-1])
            try:
                parsed = json.loads(text)
            except Exception:
                return None, duration_ms
        return parsed, duration_ms

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_prompt(
        self,
        alert: GrafanaAlert,
        context: GatheredContext,
        drain_summary: str,
        history_context: str,
        correlated: list[dict] | None = None,
        metric_facts=None,
    ) -> list[dict]:
        rule_expr = alert.annotations.get("expr", "") or "(rule expression not provided — ask the alert owner to add annotations.expr)"
        observed_value = _format_observed_value(alert.values)
        signal = alert.labels.get("signal", "unknown")
        component = alert.labels.get("component", "unknown")
        timeframe = alert.labels.get("timeframe", "10m")

        # If the webhook came in without any observed value, tell the LLM that
        # explicitly — don't let it pretend nothing happened. Grafana usually
        # fills `values` with {"<refId>": <number>} when the rule fires.
        value_line = f"{observed_value}" if observed_value else "(no observed value in webhook payload)"

        # P1.1 — Pre-LLM metric interpreter. The one-liner is authoritative
        # ground truth (computed deterministically from PromQL + values).
        # LLM should cite it verbatim, not re-derive it.
        interpreter_block = ""
        deployment_type = "unknown"
        if metric_facts is not None:
            interpreter_block = (
                "\n## Pre-computed metric facts (ground truth — cite verbatim)\n"
                + metric_facts.as_prompt_block()
                + "\n\nDO NOT re-derive these numbers. DO NOT re-interpret the unit. "
                "The interpretation line IS the answer to 'what does the observed value mean.'"
            )
            deployment_type = metric_facts.deployment_type

        # P1.4 — Correlated alerts as first-class prompt section. Moved out of
        # history_context so the prompt rule H about explaining the
        # relationship has a clear place to bind to.
        correlated_block = ""
        if correlated:
            lines = [
                f"\n## Neighboring alerts (±5 min of this one) — {len(correlated)} found",
                "You MUST address these in your RCA per rule H. Options: (a) this caused them, "
                "(b) they caused this, (c) common cause, (d) coincidence (explicitly stated).\n",
            ]
            for c in correlated[:8]:
                lines.append(
                    f"  - {c.get('timestamp','?')[:19]}  {c.get('alert_name','?')}  "
                    f"service={c.get('affected_service','?')}  "
                    f"verdict={c.get('llm_verdict') or '-'}  "
                    f"quality={c.get('rca_quality') or '-'}"
                )
            correlated_block = "\n".join(lines) + "\n"

        user_content = f"""## Alert Details
- **Name:** {alert.alertname}
- **Severity:** {alert.severity}
- **Service:** {alert.service}  (deployment_type: {deployment_type})
- **Component:** {component}
- **Primary signal:** {signal}  (prioritise the matching pillar when investigating)
- **Instance:** {alert.instance}
- **Status:** {alert.status}
- **Started:** {alert.startsAt}
- **Lookback suggested:** {timeframe}
- **Summary:** {alert.annotations.get("summary", "N/A")}
- **Description:** {alert.annotations.get("description", "N/A")}

## Rule fired because of THIS metric
- **PromQL:** `{rule_expr}`
- **Observed value at fire time:** {value_line}
{interpreter_block}
{correlated_block}
The observed value above is ground-truth signal from Prometheus at the moment the rule's threshold was crossed. Cite this value explicitly in your RCA — do not say "insufficient data" if the alert itself carries a value.

## Pre-Gathered Context

### Metrics (Prometheus, last {settings.prometheus_range_minutes}min)
{json.dumps(context.metrics, indent=2) if context.metrics else "[Prometheus] returned no series for service=" + alert.service + " — rare-but-possible, treat as MCP miss not app silence. The alert value above is still authoritative."}

### Logs ({"⚠ AMBIENT FALLBACK — NOT ALERT-SPECIFIC" if context.loki_is_fallback else "Loki, service-scoped, Drain3-annotated"}, last {settings.loki_log_limit} lines)
{("AMBIENT CONTEXT ONLY — these lines are from ALL services in the recent window, NOT filtered to the alerting service. They are background noise to help you judge whether the system is generally healthy; do NOT cite specific lines or counts here as evidence of the alert's root cause, and do NOT treat the line-count as the alert's observed metric (the Observed value above is the only authoritative signal).\n\n" + chr(10).join(context.annotated_logs)) if (context.annotated_logs and context.loki_is_fallback) else chr(10).join(context.annotated_logs) if context.annotated_logs else "[Loki] returned 0 lines for service=" + alert.service + ". If this is a node-level alert (service=k3s-node etc.), no service-scoped logs are expected — the host doesn't log through the app pipeline. Reason about the metric alone, using the Observed value above."}

### {drain_summary}

### Traces (Jaeger, last {settings.jaeger_trace_limit} traces)
{json.dumps(context.traces, indent=2, default=str) if context.traces else "[Jaeger] returned 0 traces for service=" + alert.service + ". Likely normal for infrastructure alerts; a traced request-path would have surfaced a spring-boot/kong service here."}

### Context Gathering Stats
- Sources available: {context.sources_available}/3
- Prometheus: {context.prometheus_ms}ms, Loki: {context.loki_ms}ms, Jaeger: {context.jaeger_ms}ms
{chr(10).join(context.errors) if context.errors else ""}

## Prior decisions for this alert
{history_context if history_context else "No prior RCA records for this alert."}

Analyze this alert using the context above. Respond with ONLY valid JSON. Start your RCA by restating the observed value and PromQL."""

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

    # JSON schema for Ollama's structured outputs (format=<schema>). Ollama
    # >=0.5 enforces this at decode time so invalid JSON is impossible, not
    # just unlikely. The schema mirrors LLMDecision but is hand-written here
    # to keep it inline-simple (no $defs/$refs, which some Ollama versions
    # don't follow cleanly). Keep this in sync with LLMDecision in models.py.
    _RESPONSE_SCHEMA = {
        "type": "object",
        "properties": {
            "decision": {"type": "string", "enum": ["ESCALATE", "DISMISS", "INCONCLUSIVE"]},
            "severity": {"type": "string", "enum": ["critical", "warning", "info"]},
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "reason": {"type": "string"},
            "rca": {"type": "string"},
            "anomaly_summary": {"type": "string"},
            "suggested_actions": {"type": "array", "items": {"type": "string"}},
            "evidence": {"type": "array", "items": {"type": "string"}},
        },
        "required": [
            "decision", "severity", "confidence", "reason", "rca",
            "anomaly_summary", "suggested_actions", "evidence",
        ],
    }

    async def _call_ollama(self, messages: list[dict]) -> str:
        """Make a single HTTP request to the Ollama chat API.

        Uses three 2026-04-24 behaviors (P0.5):
          - temperature=0 — default 0.8 is far too random for triage; same
            alert should produce same verdict unless context actually differs.
          - num_ctx=16384 — explicit context window. qwen2.5:7b advertises
            32K but effective degrades past ~16K; 500 Loki lines + traces
            can push us close. Cap explicitly.
          - format=schema (not just format="json") — Ollama enforces the
            JSON schema at decode time. Invalid JSON is impossible, which
            eliminates the parse-retry path entirely.
        """
        start = time.monotonic()
        try:
            resp = await self._client.post(
                f"{settings.ollama_url}/api/chat",
                json={
                    "model": settings.ollama_model,
                    "messages": messages,
                    "stream": False,
                    "format": self._RESPONSE_SCHEMA,
                    "options": {
                        "temperature": 0,
                        "num_ctx": 16384,
                    },
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
