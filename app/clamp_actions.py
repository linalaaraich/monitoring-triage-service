"""Diagnostic-only verb generator for F-4 confidence clamp (US-3.9 / Tier 0).

When the pipeline clamps confidence to 0.4 (surface-only / data_starved /
templated actions), `suggested_actions` is no longer trustworthy. This
module produces alert-aware read-only diagnostic verbs that point the
on-call at the right place to investigate, instead of letting bad
templated remediations ship.

Triggered by the 2026-04-29 HighKongP95Latency 0b215ef3 incident, where
the LLM emitted `kubectl set resources --limits=memory=2Gi` for a Kong
p95 latency alert. F-4 clamped confidence to 0.4 but did NOT strip the
actions — they shipped at 0.4 confidence anyway.

Design rules:
- Every verb here is READ-ONLY. No kubectl rollout / scale / set / patch.
- Verbs name a specific thing to look at (Jaeger trace, PromQL query,
  log query) so the on-call has a starting point, not a homework list.
- The final verb is always an explicit "do NOT run kubectl rollout/scale/set"
  to make clear that the absence of remediation is intentional.

This module is the safety net: when the LLM struggles, we fall back to
investigation prompts rather than guessing at fixes.
"""
from __future__ import annotations

from app.models import GrafanaAlert


def diagnostic_steps_for_clamp(
    alert: GrafanaAlert,
    rca: str,
    quality: str,
    actions_source: str,
) -> list[str]:
    """Generate diagnostic-only verbs for a clamped decision.

    `quality` is the post-classification rca_quality ("actionable" /
    "data_starved" / "needs_review"). `actions_source` is "llm" /
    "template" — used to skew the wording in the explanatory line.
    `rca` is the LLM's RCA prose so the verbs can reference what the
    LLM (correctly) identified before falling apart on remediation.
    """
    service = (alert.service or "unknown").strip()
    alertname = alert.alertname or "unknown"

    steps: list[str] = []

    # Step 1: always — link the on-call into Jaeger for the affected
    # service so they can see what the pipeline didn't drill into.
    if service in {"spring-boot", "kong", "otel-collector"}:
        steps.append(
            f"Open Jaeger and inspect the slowest trace for service=`{service}` "
            f"in the last 15 min — drill into spans to locate the dominant "
            f"duration owner (operation, db.statement, http.target)."
        )
    else:
        steps.append(
            f"Open Grafana Explore and pull the last 15 min of metrics + logs "
            f"for service=`{service}` — look for a step change at the alert "
            f"start time."
        )

    # Step 2..N: alert-aware PromQL pivots that point at common causes.
    # Latency alerts → JDBC pool, GC pauses, upstream comparison.
    if alertname in ("HighP95Latency", "HighKongP95Latency"):
        if service == "spring-boot":
            steps.append(
                "Check JDBC pool saturation: PromQL "
                "`hikaricp_connections_active{service=\"spring-boot\"} "
                "/ hikaricp_connections_max{service=\"spring-boot\"}` — "
                "values > 0.8 indicate pool exhaustion under load."
            )
            steps.append(
                "Check GC pauses: PromQL "
                "`rate(jvm_gc_pause_seconds_sum{service=\"spring-boot\"}[5m])` "
                "— spikes correlate directly with stop-the-world latency."
            )
        elif service == "kong":
            steps.append(
                "Compare Kong proxy vs upstream latency: PromQL "
                "`histogram_quantile(0.95, rate(kong_upstream_latency_ms_bucket[5m]))` "
                "vs `histogram_quantile(0.95, rate(kong_proxy_latency_ms_bucket[5m]))` "
                "— if upstream dominates, the cause is the upstream service, not Kong."
            )
            steps.append(
                "Once upstream is confirmed: rerun the diagnostic steps for "
                "service=`spring-boot` (or whichever upstream Kong is fronting)."
            )
        else:
            steps.append(
                f"Latency on a non-traced service ({service}) — check the "
                f"alert's PromQL expression in Grafana, then look at the "
                f"upstream caller and downstream callees in the service map."
            )

    # CPU/Memory pressure alerts → look at the actual saturating dimension.
    elif alertname.endswith(("CpuUsage", "MemoryUsage")) or "PodHigh" in alertname:
        signal = "CPU" if "Cpu" in alertname else "memory"
        steps.append(
            f"Identify the dominant {signal} consumer: PromQL "
            f"`topk(5, rate(container_cpu_usage_seconds_total{{namespace=\"app\"}}[5m]))` "
            f"if CPU, or `topk(5, container_memory_working_set_bytes{{namespace=\"app\"}})` "
            f"if memory. Pod-level breakdown shows whether this is one process or fleet-wide."
        )
        if signal == "memory":
            steps.append(
                "If a JVM service: check heap vs cgroup limit — "
                "`jvm_memory_used_bytes{area=\"heap\"} / container_spec_memory_limit_bytes` "
                "— values > 0.85 mean the JVM is fighting the cgroup, not actual leak."
            )

    # TargetDown — verify reachability + recent rollout activity.
    elif alertname == "TargetDown":
        steps.append(
            f"Check kube events: `kubectl get events -n app --sort-by=.metadata.creationTimestamp` "
            f"— recent CrashLoopBackOff / FailedScheduling / OOMKilled "
            f"tells you why the pod went down."
        )
        steps.append(
            f"Check probe success: PromQL "
            f"`up{{service=\"{service}\"}}` over the last 30 min — gives you "
            f"the exact disappearance window."
        )

    # Drain3 anomaly — the cluster IS the signal; point at the lines.
    elif alertname == "Drain3AnomalyDetected":
        steps.append(
            "Read the new template strings + sample anomalous lines in the "
            "alert description above. Drain3's signal IS the template "
            "novelty — there's no metric to drill into."
        )
        steps.append(
            "Decide manually: is the new template a deploy artifact, "
            "a real failure mode, or noise? If real, file a regular alert "
            "rule that catches the same shape going forward."
        )

    # Catch-all for unknown alertnames.
    else:
        steps.append(
            f"This alert ({alertname}) doesn't have a known diagnostic "
            f"playbook. Look at the alert's PromQL expression, the observed "
            f"value, and the rule's `description` annotation — those usually "
            f"point at the right metric to chase."
        )

    # Step N: always end with the explicit "do NOT remediate" stop sign.
    # This is the verbal contract — clamped confidence means "investigate
    # first, remediate after." The wording is intentionally blunt.
    steps.append(
        f"Do NOT run `kubectl rollout/scale/set` or restart `{service}` until "
        f"a specific cause (slow query / GC pause / pool exhaustion / "
        f"downstream timeout) is named with trace or metric evidence."
    )
    return steps


__all__ = ["diagnostic_steps_for_clamp"]
