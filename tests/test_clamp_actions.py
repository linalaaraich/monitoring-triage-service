"""US-3.9 (Tier 0) — Diagnostic-only verb generator tests.

Validates that app/clamp_actions.py produces alert-aware read-only
verbs that point the on-call at the right investigation step, with
no state-changing kubectl commands. This is the safety net invoked
when the F-4 confidence clamp fires.
"""
from __future__ import annotations

import re

from app.clamp_actions import diagnostic_steps_for_clamp
from app.models import GrafanaAlert


def _alert(alertname: str, service: str = "spring-boot") -> GrafanaAlert:
    return GrafanaAlert(
        labels={
            "alertname": alertname,
            "service": service,
            "instance": "10.0.1.50:8080",
        },
    )


# Patterns that must NOT appear in any diagnostic step (state-changing).
# Read-only diagnostic verbs are PromQL queries, log queries, Jaeger
# drills, and observation prompts — never kubectl rollout/scale/set.
_FORBIDDEN_PATTERNS = (
    re.compile(r"\bkubectl\s+rollout\s+restart\b", re.I),
    re.compile(r"\bkubectl\s+scale\b", re.I),
    re.compile(r"\bkubectl\s+set\s+resources\b", re.I),
    re.compile(r"\bkubectl\s+set\s+env\b", re.I),
    re.compile(r"\bkubectl\s+patch\b", re.I),
    re.compile(r"\bkubectl\s+delete\s+pod\b", re.I),
    re.compile(r"\bsystemctl\s+restart\b", re.I),
    re.compile(r"\bdocker\s+restart\b", re.I),
    re.compile(r"\bdocker\s+compose\s+restart\b", re.I),
    re.compile(r"\bhelm\s+rollback\b", re.I),
)


def _assert_all_read_only(steps: list[str]):
    joined = "\n".join(steps)
    for pat in _FORBIDDEN_PATTERNS:
        m = pat.search(joined)
        # Allow forbidden patterns ONLY in the explicit "do NOT" warning line —
        # detect via the literal "Do NOT run" prefix on the offending line.
        if m:
            offending_line = next(
                (line for line in steps if pat.search(line)), ""
            )
            assert "Do NOT" in offending_line or "do NOT" in offending_line, (
                f"State-changing pattern {pat.pattern!r} found in non-warning line: "
                f"{offending_line!r}"
            )


def test_high_kong_p95_emits_upstream_proxy_pivot():
    steps = diagnostic_steps_for_clamp(
        alert=_alert("HighKongP95Latency", service="kong"),
        rca="The high p95 latency for Kong requests is attributed to upstream.",
        quality="actionable",
        actions_source="template",
    )
    joined = " ".join(steps)
    assert "Open Jaeger" in joined
    assert "kong_upstream_latency_ms" in joined
    assert "kong_proxy_latency_ms" in joined
    _assert_all_read_only(steps)


def test_high_p95_on_spring_boot_emits_hikari_and_gc_pivots():
    steps = diagnostic_steps_for_clamp(
        alert=_alert("HighP95Latency", service="spring-boot"),
        rca="spring-boot is slow; possibly a regressed query or saturated pool.",
        quality="actionable",
        actions_source="template",
    )
    joined = " ".join(steps)
    assert "hikaricp_connections_active" in joined
    assert "jvm_gc_pause_seconds" in joined
    _assert_all_read_only(steps)


def test_memory_alert_emits_topk_pivot():
    steps = diagnostic_steps_for_clamp(
        alert=_alert("HighMemoryUsage", service="spring-boot"),
        rca="Memory pressure on spring-boot.",
        quality="data_starved",
        actions_source="llm",
    )
    joined = " ".join(steps)
    assert "container_memory_working_set_bytes" in joined
    assert "topk" in joined
    _assert_all_read_only(steps)


def test_target_down_emits_kube_events_pivot():
    steps = diagnostic_steps_for_clamp(
        alert=_alert("TargetDown", service="spring-boot"),
        rca="The service is unreachable.",
        quality="actionable",
        actions_source="template",
    )
    joined = " ".join(steps)
    assert "kubectl get events" in joined
    assert "up{" in joined
    _assert_all_read_only(steps)


def test_drain3_anomaly_does_not_invent_metric_pivot():
    """Drain3 alerts have no metric to drill into — the cluster IS the signal.
    Diagnostic steps should NOT propose a PromQL query."""
    steps = diagnostic_steps_for_clamp(
        alert=_alert("Drain3AnomalyDetected", service="spring-boot"),
        rca="Novel log template detected.",
        quality="data_starved",
        actions_source="llm",
    )
    joined = " ".join(steps)
    # No PromQL invention
    assert "histogram_quantile" not in joined
    assert "rate(" not in joined
    # But still mention reading the template/lines
    assert "template" in joined.lower() or "lines" in joined.lower()
    _assert_all_read_only(steps)


def test_unknown_alertname_falls_back_to_generic_pivot():
    steps = diagnostic_steps_for_clamp(
        alert=_alert("WeirdNewAlert", service="some-service"),
        rca="something happened",
        quality="data_starved",
        actions_source="llm",
    )
    joined = " ".join(steps)
    # Generic guidance should reference the alert's PromQL / observed value
    assert "PromQL" in joined or "observed value" in joined or "annotation" in joined
    _assert_all_read_only(steps)


def test_every_call_ends_with_explicit_do_not_warning():
    """The contract: every diagnostic step list ends with an explicit
    'Do NOT run kubectl rollout/scale/set' to make the no-remediation
    intent unambiguous."""
    for alertname, service in (
        ("HighKongP95Latency", "kong"),
        ("HighP95Latency", "spring-boot"),
        ("HighMemoryUsage", "spring-boot"),
        ("TargetDown", "spring-boot"),
        ("Drain3AnomalyDetected", "spring-boot"),
        ("UnknownAlert", "x"),
    ):
        steps = diagnostic_steps_for_clamp(
            alert=_alert(alertname, service=service),
            rca="...",
            quality="actionable",
            actions_source="llm",
        )
        last = steps[-1]
        assert last.startswith("Do NOT"), (
            f"Last diagnostic step for {alertname} should start with 'Do NOT', "
            f"got: {last!r}"
        )
        assert service in last, (
            f"Last step should name the alert's service: {last!r}"
        )


def test_no_kubectl_rollout_in_kong_diagnostic_steps_for_0b215ef3_replay():
    """Direct regression test: the failed 0b215ef3 decision was a
    HighKongP95Latency on kong with a hypothesis-only RCA. Replay
    should produce diagnostic steps with NO `kubectl rollout`,
    NO `kubectl set resources`, NO `kubectl scale` — only
    investigation pivots."""
    steps = diagnostic_steps_for_clamp(
        alert=_alert("HighKongP95Latency", service="kong"),
        rca=(
            "The high p95 latency for Kong requests (8204 ms) is attributed "
            "to the upstream service, likely a spring-boot application or "
            "another backend... possibly due to a regressed query or "
            "saturated connection pool."
        ),
        quality="actionable",
        actions_source="template",
    )
    joined = " ".join(steps)
    # Exact bad-action signatures from the incident must not be reproduced
    assert "deploy/spring-boot -n app --limits=memory=2Gi" not in joined
    assert "rollout restart deploy/spring-boot" not in joined
    # And the read-only contract holds
    _assert_all_read_only(steps)
