"""F-3 per-alert hallucination blocklist tests.

Reproduces the live regression case (HighP95Latency citing /actuator/*
log frequency as a cause) and verifies the validator rejects it via
the per-alert blocklist.
"""
from __future__ import annotations

from app.models import Decision, LLMDecision
from app.response_validator import find_hallucination_hits, validate


def _decision(rca: str) -> LLMDecision:
    return LLMDecision(
        decision=Decision.ESCALATE,
        severity="warning",
        confidence=0.85,
        reason="ok",
        rca=rca,
        suggested_actions=["kubectl rollout restart deploy/spring-boot -n app"],
        evidence=["something=42"],
    )


def test_high_p95_actuator_log_frequency_is_rejected():
    """The exact live regression: blaming /actuator/health log frequency
    for HighP95Latency is a wrong-evidence hallucination."""
    rca = (
        "spring-boot is repeatedly serving /actuator/health and "
        "/actuator/prometheus, suggesting a self-monitoring loop."
    )
    hits = find_hallucination_hits(rca, "HighP95Latency")
    assert hits, "Expected /actuator/* match for HighP95Latency"


def test_high_p95_clean_rca_passes():
    """Cause-first prose with no actuator citation must pass cleanly."""
    rca = (
        "spring-boot's JDBC connection pool is saturated. Trace 7f3a2c "
        "shows 7800 ms wait in the upstream pool acquisition before the "
        "actual handler runs in 200 ms."
    )
    hits = find_hallucination_hits(rca, "HighP95Latency")
    assert hits == []


def test_blocklist_does_not_trigger_for_unrelated_alertname():
    """An /actuator/health citation in a HighMemoryUsage RCA is NOT
    flagged — the blocklist is per-alert. (Could be added later if it
    becomes a problem there too.)"""
    rca = "Memory pressure on /actuator/health endpoint serving."
    hits = find_hallucination_hits(rca, "HighMemoryUsage")
    assert hits == []


def test_validator_integration_records_violation_with_alertname():
    rca = (
        "Looking at /actuator/prometheus call frequency, the application "
        "appears to be repeatedly polling itself."
    )
    decision = _decision(rca)
    report = validate(decision, deployment_type="k8s", alertname="HighP95Latency")
    assert report.has_hallucination
    assert any("hallucinated cause" in v for v in report.violations)
    assert report.should_retry is True


def test_validator_no_alertname_skips_blocklist():
    """Backwards-compat: callers without an alertname don't trigger the F-3 check."""
    rca = "Looking at /actuator/prometheus call frequency, system seems busy."
    decision = _decision(rca)
    report = validate(decision, deployment_type="k8s")  # no alertname
    assert not report.has_hallucination


def test_kong_p95_actuator_also_rejected():
    """The blocklist applies to HighKongP95Latency too — same scrape-noise issue."""
    rca = "Kong is serving /actuator/health frequently."
    hits = find_hallucination_hits(rca, "HighKongP95Latency")
    assert hits


def test_repeated_log_entries_to_health_pattern_rejected():
    rca = (
        "The system has frequent log entries for health endpoints. "
        "These repeated requests for metrics suggest it's busy."
    )
    hits = find_hallucination_hits(rca, "HighP95Latency")
    assert hits, "Expected 'frequent ... requests for metrics' hedge match"


# -----------------------------------------------------------------------------
# Drain3-specific blocklist (added 2026-04-28 PM after live-verify caught the
# model hallucinating Prometheus/PromQL mechanisms for what's actually a
# log-template anomaly)
# -----------------------------------------------------------------------------

def test_drain3_promql_hallucination_rejected():
    """Real production regression at 2026-04-28T13:11:49 — RCA cited
    'Prometheus query: {alertname="Drain3Alert"} == 8 times in the last 7
    days'. Drain3 doesn't use PromQL."""
    rca = (
        "Based on history, the Prometheus query indicates this Drain3 alert "
        "fired 8 times. PromQL data shows no anomalies."
    )
    hits = find_hallucination_hits(rca, "Drain3AnomalyDetected")
    assert hits


def test_drain3_fake_alertname_rejected():
    rca = "The Prometheus query {alertname=\"Drain3Alert\"} == 8 was used."
    hits = find_hallucination_hits(rca, "Drain3AnomalyDetected")
    assert hits


def test_drain3_clean_rca_passes():
    rca = (
        "The drain3 ingest detected 5 brand-new log templates first appearing "
        "today: JDBC pool exhausted at OrderService.findByDate, Tomcat thread "
        "pool reached maxThreads=200 — these are spring-boot regressions."
    )
    hits = find_hallucination_hits(rca, "Drain3AnomalyDetected")
    assert hits == [], f"Cause-first Drain3 prose was flagged: {hits}"
