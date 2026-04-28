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


# -----------------------------------------------------------------------------
# Patterns added 2026-04-28 after live HighP95Latency rows surfaced regressions
# the original (narrow) regexes missed. The two real cases are reproduced below
# verbatim from the production triage at 10:12 and 10:13 — both must be flagged.
# -----------------------------------------------------------------------------

def test_real_regression_1_based_on_repeated_log_entries():
    """Live HighP95Latency RCA at 2026-04-28T10:12:28."""
    rca = (
        "Based on the repeated log entries for actuator health and prometheus "
        "queries, it appears that there is a recurring issue with the system's "
        "health checks or metrics collection. The logs indicate that these "
        "requests are being made frequently without any errors, suggesting "
        "potential performance degradation or resource contention issues."
    )
    report = validate(_decision(rca), deployment_type="k8s")
    hits = [v for v in report.violations if "surface-only" in v]
    assert hits, f"Expected surface-only violation, got none: {report.violations}"
    assert report.should_retry is True


def test_real_regression_2_based_on_observed_metric_values():
    """Live HighP95Latency RCA at 2026-04-28T10:13:59."""
    rca = (
        "Based on the observed metric values and PromQL queries, it appears that "
        "the Spring Boot application is frequently querying actuator endpoints "
        "such as /actuator/health and /actuator/prometheus. This behavior "
        "suggests that either the application itself is performing these "
        "checks for monitoring purposes, or there might be an external system "
        "(e.g., a monitoring tool) making these requests. The repeated nature "
        "of this activity over multiple days indicates a persistent issue that "
        "requires further investigation."
    )
    report = validate(_decision(rca), deployment_type="k8s")
    hits = [v for v in report.violations if "surface-only" in v]
    assert hits, f"Expected surface-only violation, got none: {report.violations}"
    assert report.should_retry is True


def test_appears_that_there_is_recurring_issue_is_flagged():
    rca = (
        "It appears that there is a recurring issue with health-check timing. "
        "The system shows repeated query patterns."
    )
    report = validate(_decision(rca), deployment_type="k8s")
    hits = [v for v in report.violations if "surface-only" in v]
    assert hits, f"Expected hedge match, got: {report.violations}"


def test_suggesting_potential_performance_degradation_is_flagged():
    rca = (
        "The frontend pod restarted twice in the last 5 minutes. This pattern "
        "is suggesting potential performance degradation in the upstream link."
    )
    report = validate(_decision(rca), deployment_type="k8s")
    hits = [v for v in report.violations if "surface-only" in v]
    assert hits, f"Expected hedge match, got: {report.violations}"


def test_could_be_indicative_of_is_flagged():
    rca = (
        "Spring-boot p95 spiked at 14:32. This could be indicative of either "
        "GC pressure or a slow downstream call."
    )
    report = validate(_decision(rca), deployment_type="k8s")
    hits = [v for v in report.violations if "surface-only" in v]
    assert hits, f"Expected hedge match, got: {report.violations}"


def test_requires_further_investigation_is_flagged():
    rca = (
        "p95 latency rose to 8487 ms over the last 5 minutes on spring-boot. "
        "The repeated nature of this activity requires further investigation "
        "of the upstream service."
    )
    report = validate(_decision(rca), deployment_type="k8s")
    hits = [v for v in report.violations if "surface-only" in v]
    assert hits, f"Expected hedge match, got: {report.violations}"


def test_named_cause_with_indicates_does_not_match_recurring_issue_pattern():
    """`indicates that the JDBC pool is exhausted` is a NAMED cause and must pass.

    The "indicates a persistent issue" regex must not false-positive on legitimate
    diagnostic prose that uses 'indicates' to introduce a specific mechanism.
    """
    rca = (
        "spring-boot's JDBC connection pool is exhausted. Jaeger trace 7f3a2c "
        "shows the slowest request waited 7800 ms in kong's upstream-lookup "
        "before the spring-boot handler ran in 200 ms; this indicates that the "
        "pool's max=20 setting is the bottleneck under current load."
    )
    report = validate(_decision(rca), deployment_type="k8s")
    hits = [v for v in report.violations if "surface-only" in v]
    assert hits == [], f"Cause-first prose with 'indicates' was wrongly flagged: {hits}"


# -----------------------------------------------------------------------------
# Live-verify regressions caught 2026-04-28 PM:
# Drain3 RCAs at 12:19:11 + 13:11:49 used "Based on the context provided, ..."
# which my widened regex set didn't catch. These lock in the wider noun list.
# -----------------------------------------------------------------------------

def test_based_on_context_provided_is_now_caught():
    """Real production regression 2026-04-28T13:11:49."""
    rca = (
        "Based on the context provided, there are no anomalous log entries or "
        "trace data indicating an issue specific to the spring-boot service."
    )
    report = validate(_decision(rca), deployment_type="k8s")
    hits = [v for v in report.violations if "surface-only RCA lede" in v]
    assert hits, f"Expected lede match for 'Based on the context provided'; got: {report.violations}"


def test_based_on_information_provided_is_caught():
    rca = "Based on the information provided, this is unusual."
    report = validate(_decision(rca), deployment_type="k8s")
    hits = [v for v in report.violations if "surface-only RCA lede" in v]
    assert hits


def test_based_on_history_is_caught():
    rca = "Based on history, there is a pattern of similar fires."
    report = validate(_decision(rca), deployment_type="k8s")
    hits = [v for v in report.violations if "surface-only RCA lede" in v]
    assert hits


def test_based_on_prior_decisions_is_caught():
    rca = "Based on prior decisions, the alert appears benign."
    report = validate(_decision(rca), deployment_type="k8s")
    hits = [v for v in report.violations if "surface-only RCA lede" in v]
    assert hits


def test_the_alert_indicates_lede_is_caught():
    """Real production regression at 2026-04-28T13:21:56 — RCA opened
    'The alert indicates that there are no valid latency samples...'
    The original 'The metric/query/value' regex didn't include 'alert'."""
    rca = "The alert indicates that there are no valid latency samples for Kong's request processing."
    report = validate(_decision(rca), deployment_type="k8s")
    hits = [v for v in report.violations if "surface-only RCA lede" in v]
    assert hits


def test_the_alert_for_service_lede_is_caught():
    rca = "The alert HighP95Latency for service=kong fired."
    report = validate(_decision(rca), deployment_type="k8s")
    hits = [v for v in report.violations if "surface-only RCA lede" in v]
    assert hits
