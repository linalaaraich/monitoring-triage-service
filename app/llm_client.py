import asyncio
import json
import logging
import time

import httpx

from app.circuit_breaker import CircuitBreaker
from app.config import settings
from app import exemplars as exemplars_lib
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

A0. **The `human_cause` field is the operator's first line of sight — human
   English ONLY, no formulas.** Every email banner, every dashboard "why" cell,
   every detail-page H1 renders `human_cause` verbatim. It MUST be a single
   plain-English sentence that an SRE can read in under 3 seconds and know
   what is broken. NO PromQL. NO backticked metric expressions. NO `metric{...}
   = value`. NO `histogram_quantile(...)` blocks. NO raw ratios like "0.984"
   without a human unit. Numbers are OK only when carried by human prose
   ("CPU sustained at 95% for 6 min", "error rate spiked to 47%", "p95 jumped
   to 8.5 seconds"). Examples:
     GOOD: "Error 500 from /api/users at 47% rate — frontend is failing fast."
     GOOD: "spring-boot pod is in an OOM-kill loop; restarting every 12 minutes."
     GOOD: "Loki disk is 98% full — ingest will stop dropping logs in ~7 minutes."
     BAD : "histogram_quantile(0.95, sum(rate(...))) = 8487.9 reported above threshold."
     BAD : "container_memory_working_set_bytes / spec_memory_limit_bytes = 0.984"
     BAD : "The PromQL expression `up == 0` returned 0 for instance 10.0.1.68:9100."
   Put any of the technical expressions (PromQL, raw metric values, label
   selectors, trace IDs) in the `evidence` array — they're rendered below
   the human banner, in service of it. Operators want to READ a cause, not
   parse a formula.

A. **Start the RCA prose with the CAUSE, not the symptom.** The alert already told
   the operator a metric crossed a threshold — restating that is not analysis. Your
   job is to NAME what is broken: a component, link, process, queue, connection pool,
   deploy, config change, dependency, or saturation point. The first sentence must
   say WHAT failed and WHY; the metric / log / trace evidence comes after, in
   service of that conclusion.
   BAD lede: "PromQL `histogram_quantile(...)` reported 8487 ms, which is significantly
             above the adaptive baseline. This indicates that there are requests
             experiencing unusually high latencies."
   GOOD lede: "Kong upstream-connection pool to spring-boot is saturated: 95% of
             requests are queueing >8 s waiting for a backend slot, while spring-boot
             handlers themselves complete in <200 ms (Jaeger trace 7f3a2c). Likely
             cause: spring-boot's JDBC pool (max=20) exhausted by long-running
             queries — connection waits cascade up to kong's upstream layer."
   Telemetry is the means, not the end. If the only thing you can say is "value above
   threshold," that is INCONCLUSIVE — name it as such and propose what additional
   evidence would resolve it; do not dress up a symptom as a diagnosis.

J. **Translate raw expressions into plain language.** Don't paste a `histogram_quantile`
   / `rate` / `sum by` PromQL block as the lede and expect the operator to mentally
   parse it. The PromQL goes in `evidence`; the prose names the human-meaningful
   quantity. Examples:
     - "p95 latency 8487ms" → "95% of requests took longer than 8.5 seconds — user-visible slowness"
     - "container_memory_working_set_bytes / spec_memory_limit_bytes = 0.984" → "the pod is sitting at 98% of its memory cap"
     - "up{instance=...} = 0" → "Prometheus has not been able to reach this scrape target for 2+ minutes"
   The PromQL still appears in the evidence list; what changes is that the prose
   explains what it MEANS for a human reader.

B. If any pre-gathered pillar (metrics/logs/traces) is empty, name WHICH pillar returned nothing and WHY that might be (e.g. "Loki returned 0 lines for service={{SERVICE_NAME}} — possible causes: service not emitting logs, wrong label, shipper down"). Never write the phrase "insufficient data" as a standalone conclusion — always pair it with a named missing source and a concrete hypothesis to test next.
C. If the "Prior decisions for this alert" section below shows past decisions that hedged (tagged data_starved), DO NOT repeat the same hedge. Use the available signal — even if thin — to propose a specific hypothesis, and suggest concrete remediation the human can check.
D. Prefer ESCALATE over INCONCLUSIVE when you can at least name a probable cause. INCONCLUSIVE should be rare and always accompanied by a specific remediation: what query to run, what label to add, which shipper to restart.

E. suggested_actions MUST be REMEDIATIONS (state-changing fixes), NEVER investigations or queries.
   The triage service has ALREADY queried Prometheus, Loki, Jaeger, and Drain3 to build the context
   you see above. That data is in `evidence` and the RCA. Asking the operator to re-run queries
   or to check what the triage system already checked is useless. Operators want a fix, not homework.

   Every action MUST change system state. Acceptable remediation verbs include:
     - kubectl rollout restart / kubectl scale / kubectl set resources / kubectl set env
     - kubectl patch / kubectl delete pod / kubectl drain / kubectl cordon
     - helm rollback / helm upgrade
     - docker restart / docker compose restart / docker compose up -d --force-recreate
     - systemctl restart / systemctl reload
     - git revert + redeploy / terraform apply (rollback)
     - kill / pkill (specific PID identified in evidence)
     - Direct config-file edit + reload (with the exact path and command)
   Reject these as suggested_actions (NEVER emit):
     - "Check ...", "Verify ...", "Confirm ...", "Investigate ...", "Examine ...", "Inspect ...",
       "See ...", "Find ...", "Identify ...", "Look at ...", "Look into ...", "Review ...",
       "Monitor ...", "Audit ...", "Ask ..." — these are tasks, not fixes.
     - "kubectl get|describe|top|logs|exec" — read-only, the triage service already did this.
     - "docker logs|ps|stats|inspect|exec" — read-only, same reason.
     - "Query Grafana|Prometheus|Loki|Jaeger: ..." — the triage service is the one that queries
       the observability stack. If a query result was needed, request it via tool_call below;
       do NOT pass it back to the operator.
     - "ssh ... 'top'", "ssh ... 'df -h'", "ssh ... 'ps aux'", "ssh ... 'tail|head|cat|grep|free|du'"
     - Any open-ended "look at X" or "watch the dashboard" guidance.

   GOOD examples (emit these):
     - "kubectl rollout restart deploy/spring-boot -n app — clears the in-process connection pool"
     - "kubectl set resources deploy/spring-boot -n app --limits=memory=2Gi — current 1Gi causes OOMKill"
     - "kubectl scale deploy/kong-kong -n network --replicas=3 — current 1 replica is saturated at p95"
     - "helm rollback spring-boot $(helm history spring-boot -n app -o json | jq -r '.[-2].revision') -n app"
     - "ssh deploy@observability-rca-monitoring 'docker compose -f /opt/monitoring/compose.yml restart loki'"

   If you cannot identify a concrete remediation given the evidence, emit ONE empty list `[]` — the
   pipeline will fall back to per-alert templates. An empty list is fine; investigation requests are not.

I. (Investigation gate.) Investigation results belong in `evidence` and `rca`, not `suggested_actions`.
   If you find yourself wanting to write "the operator should query X" or "verify Y" — instead, request
   that query yourself using the tool_call protocol (when available), then put the result in evidence,
   then emit a remediation in suggested_actions based on what you found.
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
  "human_cause": "<ONE plain-English sentence: what is broken, in human prose. NO PromQL, NO `metric{...}=value`, NO formulas. This is what the operator reads first. See rule A0.>",
  "reason": "<one-line summary that NAMES a cause, not a symptom; may be terser than human_cause but must still be formula-free>",
  "rca": "<2-5 sentences; first sentence names a specific cause (component / link / process / config / change). Metric/log/trace evidence follows in support>",
  "anomaly_summary": "<Drain3 findings or '' if none>",
  "suggested_actions": [<2-4 concrete commands/queries/URLs — see rule E>],
  "evidence": [<specific metric values / log lines / trace IDs — see rule F. THIS is where PromQL expressions, raw metric formulas, and `metric{...}=value` strings go.>]
}

## Few-shot examples

The three examples below show expected quality. Match this shape, not just the schema.

### Example 1 — ESCALATE with clear remediation path (OOMKill-loop on a Java service)

INPUT:
  alertname=HighMemoryUsage, service=spring-boot, deployment_type=k8s
  observed_value=98.4 (refId=B), threshold=85, unit=percent
  metric interpretation: container memory_usage = 98.4%, 13pp above 85% threshold, sustained 8 min
  loki: 4 lines `[ANOMALY] java.lang.OutOfMemoryError: Java heap space` in last 60s
  jaeger: 12 traces, slowest 11.2s — GC pauses visible at request boundaries
  prior decisions: 3 prior fires same pod — 2 ESCALATE, 1 timeout. Restart count for pod = 45.
  correlated: HighP95Latency same service +90s

EXPECTED OUTPUT:
{
  "decision": "ESCALATE",
  "severity": "critical",
  "confidence": 0.92,
  "human_cause": "spring-boot is in an OOM-kill loop, restarting every 12 minutes because the JVM heap is capped at only 256 MB.",
  "reason": "spring-boot is in an OOM-kill loop because the JVM is using its default heap fraction (~25% of the cgroup) instead of a tuned value — the 1Gi container limit produces only ~256 MB effective heap, which normal traffic exhausts.",
  "rca": "spring-boot is in a steady-state OOM-kill loop: the JVM heap is sized as a fraction of the cgroup, but JAVA_TOOL_OPTIONS is unset so the JVM falls back to its default of ~25% of the 1 GiB container limit — about 256 MB of effective heap, which normal traffic exhausts every ~12 minutes. The pod has restarted 45 times. Loki shows the smoking gun: 4 `OutOfMemoryError: Java heap space` lines in the last minute, and the working-set memory is sitting at 98% of the container cap (sustained 8 minutes). The correlated HighP95Latency on the same service is downstream of this — Java GC pauses block request threads while the heap is being reclaimed, inflating p95 every time the cycle approaches the limit.",
  "anomaly_summary": "",
  "suggested_actions": [
    "kubectl set resources deploy/spring-boot -n app --limits=memory=2Gi --requests=memory=1Gi — raise headroom out of OOMKill range",
    "kubectl set env deploy/spring-boot -n app JAVA_TOOL_OPTIONS='-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError' — pin heap to 75% of container limit instead of JVM default",
    "kubectl rollout restart deploy/spring-boot -n app — apply env+limit changes and clear in-process state"
  ],
  "evidence": [
    "container_memory_working_set_bytes / container_spec_memory_limit_bytes = 0.984 (98.4%)",
    "Loki: `[ANOMALY] java.lang.OutOfMemoryError: Java heap space` x4 in last 60s",
    "Pod restart count = 45 — steady-state OOMKill loop",
    "Correlated HighP95Latency same service +90s — GC-pause downstream effect"
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
  "human_cause": "Single-sample latency blip on spring-boot — p95 jumped to 1.02 s for one scrape, then recovered to 340 ms. No real slowdown.",
  "reason": "Single-sample bucket-edge artifact, not a real latency event — p95 returned to 340 ms within one scrape interval and no individual request exceeded the threshold.",
  "rca": "This is a single-scrape statistical artifact, not a real slowdown. p95 briefly read 1020 ms (2% over the 1000 ms threshold) for one 10-second sample, then dropped back to 340 ms on the very next scrape. The slowest Jaeger trace in the alert window was 340 ms — i.e., no actual request was over threshold; the histogram bucket edge moved the p95 estimate above 1000 ms transiently. Loki returned 50 lines of clean INFO logs with no error or exception. The same single-sample blip has fired 14 times in the last 24 h on this rule and been dismissed every time, which is itself the signal that the threshold is too tight for the bucket distribution.",
  "anomaly_summary": "0 of 50 lines anomalous",
  "suggested_actions": [
    "Edit monitoring-project/roles/grafana/templates/alertrules.yml.j2: raise HighP95Latency threshold from 1000 to 1200, then run `ansible-playbook -i inventory/tailnet.yml playbooks/grafana.yml` — current threshold fires on 14 false positives in 24h",
    "Add `for: 2m` to the rule (same file, same alert) — requires sustained breach, drops single-sample spikes"
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
  "human_cause": "node-exporter on the monitoring VM is unreachable for 2+ minutes — the container is likely stopped or crashed.",
  "reason": "node-exporter on the monitoring VM is unreachable to Prometheus — most likely the container stopped or crashed; secondary candidates are network-path break or Prometheus scrape config drift.",
  "rca": "node-exporter on the monitoring VM (10.0.1.68:9100) is the failing component: Prometheus has been unable to reach its scrape endpoint for 2+ minutes. The pillar pattern matches 'target itself is down' — Prometheus can't pull metrics from the dead target, and Loki has no service=monitoring lines because the monitoring stack runs via docker-compose (deployment_type=docker-vm) and ships logs through docker's own pipeline rather than through the app log shipper. Ranked causes: (1) the node-exporter container is stopped or crashed (most likely — single-target failure with no upstream symptoms); (2) network path between Prometheus and the monitoring VM is broken (would also affect grafana/loki/jaeger scrapes — verify these are still up); (3) Prometheus scrape config drift after a recent monitoring-project deploy.",
  "anomaly_summary": "",
  "suggested_actions": [
    "ssh deploy@observability-rca-monitoring 'docker compose -f /opt/monitoring/compose.yml up -d --force-recreate node-exporter' — redeploy the container; first action covers both \"stopped\" and \"unhealthy\" cases",
    "If the redeploy fails: ssh deploy@observability-rca-monitoring 'sudo systemctl restart docker' — recover docker daemon if it's stuck",
    "If still down 5 min after that: re-run terraform apply -target=module.monitoring_vm to redeploy the VM from a known-good state"
  ],
  "evidence": [
    "up{instance=\\"10.0.1.68:9100\\"} = 0 (target unreachable for 2+ min)",
    "Loki empty: expected for service=monitoring (deployment_type=docker-vm, no app log pipeline)"
  ]
}

---

## Reference exemplar library (canonical good RCAs)

A curated library of best-practice RCA scenarios is maintained at
`docs/happy-path-scenarios.md` in the triage-service repo (with structured
versions in `app/exemplars/library.yaml`). Eleven archetypes are covered:
OOM-loop, upstream-latency attribution, synthetic-blip dismiss, cascade
incidents, Drain3 novelty post-deploy, bounded-agency retry, adaptive-threshold
no-op, closed-loop feedback, CrashLoopBackOff from bad config, network/firewall
attribution, and pre-failure TLS expiry.

For every alert, the prompt builder pre-selects the exemplar that best matches
on alertname + service + deployment_type + signal, and injects it into the
user message below as `## Reference exemplar`. **Read it first.** Use it as a
structural target — the SHAPE of the RCA prose (cause-first, plain-language,
mechanism-naming), the kind of evidence to cite (specific metric values, log
templates, trace span breakdowns), and the kind of state-changing remediation
to suggest. Do NOT copy its facts. THIS alert's facts come from the
pre-gathered context (metrics, logs, traces, Drain3, observed value). The
exemplar's lede is calibrated to lead with a named cause — match that, not
"<symptom> is above threshold."

If the injected exemplar's archetype clearly does not fit (your evidence
points elsewhere), say so explicitly in the RCA and reason from the actual
evidence. The exemplar is a calibration aid, not a verdict.

Additional archetypes can be requested at retry time via the
`rca_history.list_exemplars` and `rca_history.get_exemplar` MCP tools — but
the pre-injected one is usually the right reference; only reach for another
if you have a specific reason to.

---

Respond with valid JSON only. Your RCA's first sentence MUST name a probable cause (a component / link / process / queue / config / change). Cite metrics, logs, and traces as supporting evidence after the diagnosis — never as the diagnosis itself."""


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


def build_prior_decision_block(prior_decision: dict | None) -> str:
    """DA-3 — render the cross-row verdict-coherence prompt section.

    `prior_decision` is the most-recent prior LLM decision for THIS exact
    fingerprint within the coherence window (see
    RCAStore.get_recent_decision_for_fingerprint). Returns "" when there's
    no prior decision so the caller can skip the section entirely.

    Why this exists: a flapping alert fires repeatedly. Each fire is a fresh
    LLM call with no memory of the last one, so the model can — and in the
    2026-05 audits did — emit a different, contradictory cause each time
    ("JVM heap exhausted" on fire 1, "network blip" on fire 2). The operator
    then can't trust any single RCA. By quoting the prior cause back to the
    model with an explicit coherence rule, we force one of three coherent
    outcomes: reuse the prior cause (situation unchanged), explicitly revise
    it ("changed my mind because…"), or declare recovery ("condition
    resolved"). The model still owns the verdict — we only forbid silent
    contradiction.
    """
    if not prior_decision:
        return ""
    prior_verdict = (prior_decision.get("llm_verdict") or "unknown").upper()
    prior_when = (prior_decision.get("timestamp") or "")[:19] or "recently"
    # The prior cause is the RCA prose; fall back to the reasoning line if the
    # RCA was empty (older / thin rows). Trim so a long prior RCA doesn't blow
    # the prompt budget — the lede sentence carries the named cause.
    prior_cause = (prior_decision.get("rca_report") or prior_decision.get("llm_reasoning") or "").strip()
    prior_cause = prior_cause.replace("\n", " ")
    if len(prior_cause) > 600:
        prior_cause = prior_cause[:600].rstrip() + " …"
    if not prior_cause:
        prior_cause = "(no cause text recorded on the prior decision)"

    return (
        "\n## Prior investigation summary (within DA-3 window, may be incomplete)\n"
        f"  - Prior verdict: {prior_verdict}\n"
        f"  - Prior cause: {prior_cause}\n"
        f"  - Prior was decided at: {prior_when}\n\n"
        "Use this as a starting hypothesis but verify against fresh evidence below. "
        "If the fresh evidence contradicts the prior, name a NEW cause and note that "
        "the prior should be corrected (frame it as 'changed my mind because …' and "
        "say what new evidence overturned the prior diagnosis). If the alert is now "
        "RECOVERING / the breach has cleared, say 'condition resolved' in your RCA "
        "and DISMISS. Do not blindly reuse — your job is fresh analysis informed by "
        "history, not parroting.\n"
    )


def _build_fallback_decision() -> LLMDecision:
    """Return a safe NEEDS_HUMAN_REVIEW fallback when the LLM is unavailable."""
    return LLMDecision(
        decision=Decision.ESCALATE,
        severity="warning",
        confidence=0.0,
        reason="LLM unavailable \u2014 automatic escalation for human review",
        human_cause="AI triage could not reach the LLM - alert forwarded without analysis.",
        rca="AI triage could not complete analysis. Raw alert forwarded for manual review.",
        suggested_actions=[
            "ssh deploy@adolin-wsl 'docker compose -f ~/cires-ai/docker-compose.yml restart ai-ollama' — recover the local LLM",
            "If ollama keeps crashing: docker compose pull ai-ollama && docker compose up -d ai-ollama --force-recreate",
        ],
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
        prior_decision: dict | None = None,  # DA-3 cross-row coherence anchor
    ) -> tuple[LLMDecision, int]:
        """Run LLM investigation. Returns (decision, duration_ms).

        If tool_result_block is given, it's appended to the user_content as
        additional evidence from a bounded-agency retry (see app.bounded_agency).

        If prior_decision is given (DA-3), the prior cause for this exact
        fingerprint is injected with a coherence instruction so consecutive
        fires of a flapping alert don't produce contradictory RCAs.
        """
        messages = self._build_prompt(
            alert, context, drain_summary, history_context, correlated,
            metric_facts, prior_decision=prior_decision,
        )
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
        prior_decision: dict | None = None,  # DA-3 cross-row coherence anchor
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
        messages = self._build_prompt(
            alert, context, drain_summary, history_context, correlated,
            metric_facts, prior_decision=prior_decision,
        )
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
        prior_decision: dict | None = None,
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

        # Drain3-specific playbook (added 2026-04-27 after Lina's audit).
        # Drain3 alerts have different operational semantics from metric alerts:
        # they signal log-template novelty, which is meaningful as a SIGNAL
        # but rarely actionable in isolation. The right play is investigate
        # → correlate → verdict, with two structured outcomes:
        #   - if correlations point to a known failure → ESCALATE + remediation
        #   - if no correlation → DISMISS as "shelved pending recurrence"
        # Recurrence is the second-chance escalation: same template firing
        # ≥3 times in 7 days is itself a real signal even without per-fire
        # correlation, and earns ESCALATE.
        drain3_playbook_block = ""
        if alert.alertname == "Drain3AnomalyDetected":
            drain3_playbook_block = (
                "\n## Drain3 alert playbook (this alert is a log-template novelty, NOT a metric breach)\n"
                "Drain3 fires when a never-before-seen log template appears or a known-rare template "
                "spikes in frequency. The anomaly_summary above lists the new templates. Your job:\n"
                "  1. INSPECT the anomaly: read the templates in anomaly_summary. What kind of failure "
                "do they describe? (OOM? JDBC pool exhaust? deserialization error? request timeout?)\n"
                "  2. CORRELATE with the other pillars in the ±10 min window: do Prometheus metrics "
                "show a CPU/memory/latency spike on the same service? Do Jaeger traces show error spans? "
                "Are there correlated alerts in the section above?\n"
                "  3. VERDICT — choose ONE:\n"
                "     (a) Concrete cause identified (correlation supports a specific failure mode) → "
                "ESCALATE + remediation suggested_actions. Confidence ≥0.6.\n"
                "     (b) No concrete correlation, but recurrence is high (this alert fired ≥3 times "
                "in the last 7 days — see 'Prior decisions' below): ESCALATE anyway. The pattern is "
                "real even without per-fire evidence. reason: 'recurring drain3 anomaly: <template> "
                "fired Nx in 7d — pattern is real, no transient cause'. confidence ≥0.55.\n"
                "     (c) No concrete correlation AND not recurring (<3 fires in 7d): DISMISS with "
                "reason='shelved pending recurrence — anomaly #N in 7d window, no correlation found'. "
                "Confidence 0.5-0.65. suggested_actions=[] (the pipeline will fill the shelve template).\n"
                "DO NOT emit a generic 'kubectl rollout restart' as your only suggestion when you have "
                "no concrete cause — that's not a fix, that's a guess. Either justify the action with a "
                "correlation, or shelve it.\n"
            )

        # Exemplar injection — pick the best-matching canonical RCA from
        # app/exemplars/library.yaml and render it as a structural reference.
        # See app/exemplars/__init__.py for matching logic and decisions-log.html#D17
        # for why this lives in its own library (not in rca_history.db).
        exemplar = exemplars_lib.find_for_alert(
            alertname=alert.alertname,
            service=alert.service,
            deployment_type=deployment_type,
            signal=signal,
            severity=alert.severity,
        )
        exemplar_block = ""
        if exemplar:
            rendered = exemplars_lib.format_for_prompt(exemplar)
            if rendered:
                exemplar_block = "\n" + rendered + "\n"

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

        # DA-3 — cross-row verdict-coherence block. Empty string when there's
        # no recent prior decision for this exact fingerprint.
        prior_decision_block = build_prior_decision_block(prior_decision)

        # Loki block: precomputed in plain Python so the long literal with
        # `\n\n` lives outside the f-string expression. Python 3.12 (PEP 701)
        # allows backslashes inside f-string expressions; 3.11 does not. Audit
        # routines run on 3.11 — keeping this block out of the f-string keeps
        # the module importable in either env.
        _AMBIENT_LOKI_PREAMBLE = (
            "AMBIENT CONTEXT ONLY — these lines are from ALL services in the "
            "recent window, NOT filtered to the alerting service. They are "
            "background noise to help you judge whether the system is generally "
            "healthy; do NOT cite specific lines or counts here as evidence of "
            "the alert's root cause, and do NOT treat the line-count as the "
            "alert's observed metric (the Observed value above is the only "
            "authoritative signal).\n\n"
        )
        if context.annotated_logs and context.loki_is_fallback:
            loki_block = _AMBIENT_LOKI_PREAMBLE + "\n".join(context.annotated_logs)
        elif context.annotated_logs:
            loki_block = "\n".join(context.annotated_logs)
        else:
            loki_block = (
                f"[Loki] returned 0 lines for service={alert.service}. If this "
                "is a node-level alert (service=k3s-node etc.), no service-scoped "
                "logs are expected — the host doesn't log through the app "
                "pipeline. Reason about the metric alone, using the Observed "
                "value above."
            )

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
{drain3_playbook_block}
{correlated_block}
{prior_decision_block}
The observed value above is ground-truth signal from Prometheus at the moment the rule's threshold was crossed. Cite this value explicitly in your RCA — do not say "insufficient data" if the alert itself carries a value.
{exemplar_block}
## Pre-Gathered Context

### Metrics (Prometheus, last {settings.prometheus_range_minutes}min)
{json.dumps(context.metrics, indent=2) if context.metrics else "[Prometheus] returned no series for service=" + alert.service + " — rare-but-possible, treat as MCP miss not app silence. The alert value above is still authoritative."}

### Logs ({"⚠ AMBIENT FALLBACK — NOT ALERT-SPECIFIC" if context.loki_is_fallback else "Loki, service-scoped, Drain3-annotated"}, last {settings.loki_log_limit} lines)
{loki_block}

### {drain_summary}

### Traces (Jaeger, last {settings.jaeger_trace_limit} traces)
{json.dumps(context.traces, indent=2, default=str) if context.traces else "[Jaeger] returned 0 traces for service=" + alert.service + ". Likely normal for infrastructure alerts; a traced request-path would have surfaced a spring-boot/kong service here."}
{(
    chr(10) + "### Trace span breakdown (the slowest trace, drilled to per-span detail)" + chr(10) +
    "This is the keystone evidence for latency-flavoured alerts: per-span durations, db.statement (PII-sanitized), http.target, error tags. Use it to NAME what's slow, not just say upstream is slow." + chr(10) +
    "```json" + chr(10) +
    json.dumps(context.deep_trace, indent=2, default=str) + chr(10) +
    "```" + chr(10)
) if context.deep_trace else ""}
### Context Gathering Stats
- Sources available: {context.sources_available}/3
- Prometheus: {context.prometheus_ms}ms, Loki: {context.loki_ms}ms, Jaeger: {context.jaeger_ms}ms
{chr(10).join(context.errors) if context.errors else ""}

## Prior decisions for this alert
{history_context if history_context else "No prior RCA records for this alert."}

Analyze this alert using the context above. Respond with ONLY valid JSON. Start your RCA by restating the observed value and PromQL."""

        # Substitute the actual service name into the SYSTEM_PROMPT's rule-B
        # example so the small model doesn't copy-paste the literal "service=X"
        # placeholder verbatim into every empty-pillar RCA.
        service_name = alert.service or "this-service"
        system_prompt = SYSTEM_PROMPT.replace("{{SERVICE_NAME}}", service_name)

        return [
            {"role": "system", "content": system_prompt},
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
    # Schema enforced at decode-time by Ollama. The 2026-06-02 addition of
    # `human_cause` is REQUIRED — every fresh response must include the
    # plain-English single-sentence cause that the email banner + dashboard
    # "why" cell will render verbatim. PromQL / metric formulas belong in
    # `evidence` only. See app/prose_helpers.py for the renderer contract.
    _RESPONSE_SCHEMA = {
        "type": "object",
        "properties": {
            "decision": {"type": "string", "enum": ["ESCALATE", "DISMISS", "INCONCLUSIVE"]},
            "severity": {"type": "string", "enum": ["critical", "warning", "info"]},
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "reason": {"type": "string"},
            "human_cause": {"type": "string"},
            "rca": {"type": "string"},
            "anomaly_summary": {"type": "string"},
            "suggested_actions": {"type": "array", "items": {"type": "string"}},
            "evidence": {"type": "array", "items": {"type": "string"}},
        },
        "required": [
            "decision", "severity", "confidence", "reason", "human_cause", "rca",
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
            # 2026-06-02 — human_cause refactor backstop. If the model didn't
            # populate `human_cause` (legacy schema, retry without the new
            # field), derive a plain-English lede from `rca` so the email
            # banner + dashboard "why" cell never go blank. Any PromQL /
            # metric formulas embedded in the RCA prose get peeled into
            # `evidence` so they're still surfaced — just below the human
            # banner, not in front of it.
            from app.prose_helpers import split_human_cause_and_evidence
            if not (data.get("human_cause") or "").strip():
                derived_cause, extra_evidence = split_human_cause_and_evidence(
                    data.get("rca", "") or data.get("reason", "")
                )
                if derived_cause:
                    data["human_cause"] = derived_cause
                if extra_evidence:
                    existing_ev = data.get("evidence") or []
                    if not isinstance(existing_ev, list):
                        existing_ev = [str(existing_ev)]
                    # Merge new fragments without disturbing existing entries
                    seen_ev = {str(e).strip() for e in existing_ev}
                    for e in extra_evidence:
                        if e not in seen_ev:
                            existing_ev.append(e)
                            seen_ev.add(e)
                    data["evidence"] = existing_ev

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
