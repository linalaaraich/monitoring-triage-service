"""Tests for the surface-only RCA prose check added 2026-04-28.

Background: the prior SYSTEM_PROMPT rule A told the LLM to start each RCA
by restating the PromQL and observed value. That produced outputs that
restate the alert in different words instead of naming a cause — exactly
what an RCA should NOT do. Rule A was rewritten to demand a cause-first
lede; this test file locks in the validator-side enforcement.
"""
from __future__ import annotations

from app.models import LLMDecision
from app.response_validator import validate


def _decision(rca: str, reason: str = "ok") -> LLMDecision:
    return LLMDecision(
        decision="ESCALATE",
        severity="warning",
        confidence=0.85,
        reason=reason,
        rca=rca,
        suggested_actions=["kubectl rollout restart deploy/frontend -n app"],
        evidence=["histogram_quantile(0.95, ...) = 8487 ms"],
    )


def test_surface_only_lede_promql_expression_is_rejected():
    rca = (
        "PromQL `histogram_quantile(0.95, sum(rate(kong_request_latency_ms_bucket[5m])) "
        "by (le))` reported a p95 latency of 8487.9 ms at the time of firing, which is "
        "significantly above the adaptive baseline."
    )
    report = validate(_decision(rca), deployment_type="k8s")
    assert any("surface-only RCA lede" in v for v in report.violations), report.violations
    assert report.should_retry is True


def test_surface_only_lede_with_the_promql_expression_prefix_is_rejected():
    rca = (
        "The PromQL expression `up == 0` returned 0 for instance 10.0.1.68:9100, "
        "indicating the target is unreachable."
    )
    report = validate(_decision(rca), deployment_type="docker-vm")
    assert any("surface-only RCA lede" in v for v in report.violations), report.violations


def test_surface_only_hedge_indicates_that_there_are_X_experiencing_Y_is_rejected():
    rca = (
        "spring-boot is showing memory pressure. This indicates that there are "
        "requests experiencing slowdowns."
    )
    report = validate(_decision(rca), deployment_type="k8s")
    assert any("surface-only hedge" in v for v in report.violations), report.violations
    assert report.should_retry is True


def test_cause_first_lede_passes_even_with_promql_in_evidence_section():
    """The lede must name a cause; PromQL in later sentences (evidence) is fine."""
    rca = (
        "spring-boot is in an OOM-kill loop because the JVM heap defaults to ~25% of "
        "the cgroup limit. Container memory has saw-toothed twice in the last 30 min, "
        "with PromQL `container_memory_working_set_bytes` hitting 98% of the limit. "
        "Loki shows 4 OutOfMemoryError lines in the last 60s."
    )
    report = validate(_decision(rca), deployment_type="k8s")
    surface_only_hits = [v for v in report.violations if "surface-only" in v]
    assert surface_only_hits == [], f"Cause-first lede should pass, got: {surface_only_hits}"


def test_metric_equals_value_lede_is_rejected():
    """Just pasting `metric{...} = value` as the opening counts as surface-only."""
    rca = (
        "container_memory_working_set_bytes = 0.984. The pod is at 98% of its limit "
        "and approaching OOM."
    )
    report = validate(_decision(rca), deployment_type="k8s")
    assert any("surface-only RCA lede" in v for v in report.violations), report.violations


def test_normal_diagnostic_prose_does_not_trigger_hedge_check():
    """Make sure we don't flag legitimate prose that mentions experiencing high latency."""
    # Specific cause + named mechanism — should not match the hedge regex
    rca = (
        "Kong's upstream connection pool to spring-boot is saturated. Trace 7f3a2c "
        "shows 7800ms wait in kong_upstream_lookup before spring-boot's 200ms handler "
        "starts. Probable cause: spring-boot's JDBC pool (max=20) is exhausted by "
        "long-running queries."
    )
    report = validate(_decision(rca), deployment_type="k8s")
    surface_only_hits = [v for v in report.violations if "surface-only" in v]
    assert surface_only_hits == [], f"Specific cause-first prose flagged: {surface_only_hits}"
