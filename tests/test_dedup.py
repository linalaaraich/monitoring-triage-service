"""Tests for DedupManager — fingerprint-window deduplication.

The manager keys on Grafana's stable fingerprint (hash over the alert's
labels), not on (alertname, instance). This correctly collapses flapping
rules even when some labels are missing, and respects label combinations
that an alertname-only key would conflate.

`check()` returns (is_duplicate, first_decision_id). The decision id is
populated by `record_first_decision()` after the pipeline persists the
initial RCA — None means "first occurrence, no RCA yet" or "first RCA
hasn't finished persisting".
"""
import asyncio

import pytest

from app.dedup import ALERT_FAMILIES, DedupManager, drain3_fingerprint, family_dedup_key
from app.models import GrafanaAlert


# Stable fingerprints for use across the suite. In production these are
# Grafana hashes over the alert's labels — any unique string works for
# tests, just keep them distinct between alerts that should NOT collapse.
FP_LATENCY_INST_30 = "fp-highp95-30"
FP_LATENCY_INST_31 = "fp-highp95-31"
FP_CPU_INST_30 = "fp-highcpu-30"


@pytest.fixture
def dedup():
    return DedupManager(window_seconds=2)


@pytest.mark.asyncio
async def test_first_alert_not_duplicate(dedup):
    is_dup, _ = await dedup.check(FP_LATENCY_INST_30, "firing")
    assert is_dup is False


@pytest.mark.asyncio
async def test_second_alert_is_duplicate(dedup):
    await dedup.check(FP_LATENCY_INST_30, "firing")
    is_dup, _ = await dedup.check(FP_LATENCY_INST_30, "firing")
    assert is_dup is True


@pytest.mark.asyncio
async def test_different_alert_not_duplicate(dedup):
    await dedup.check(FP_LATENCY_INST_30, "firing")
    is_dup, _ = await dedup.check(FP_CPU_INST_30, "firing")
    assert is_dup is False


@pytest.mark.asyncio
async def test_different_instance_not_duplicate(dedup):
    """Different instances produce different Grafana fingerprints (the
    instance label is part of the labels-hash). Two different fingerprints
    must not collapse."""
    await dedup.check(FP_LATENCY_INST_30, "firing")
    is_dup, _ = await dedup.check(FP_LATENCY_INST_31, "firing")
    assert is_dup is False


@pytest.mark.asyncio
async def test_expired_window_not_duplicate(dedup):
    await dedup.check(FP_LATENCY_INST_30, "firing")
    await asyncio.sleep(2.1)
    is_dup, _ = await dedup.check(FP_LATENCY_INST_30, "firing")
    assert is_dup is False


@pytest.mark.asyncio
async def test_resolved_then_refired_reprocessed(dedup):
    """A resolve within the window does NOT clear the window for the
    immediate-next firing — but a `firing` after a recorded `resolved`
    starts a fresh window so the re-fire is treated as a new alert."""
    await dedup.check(FP_LATENCY_INST_30, "firing")
    await dedup.check(FP_LATENCY_INST_30, "resolved")
    is_dup, _ = await dedup.check(FP_LATENCY_INST_30, "firing")
    assert is_dup is False


@pytest.mark.asyncio
async def test_concurrent_checks_safe(dedup):
    """Multiple concurrent checks on the same fingerprint must produce
    exactly one non-duplicate result (the first to land); the rest are
    duplicates. Guarantees the asyncio.Lock keeps the dedup table sane."""
    results = await asyncio.gather(
        *[dedup.check(FP_LATENCY_INST_30, "firing") for _ in range(10)]
    )
    is_dup_flags = [r[0] for r in results]
    assert is_dup_flags.count(False) == 1
    assert is_dup_flags.count(True) == 9


@pytest.mark.asyncio
async def test_record_first_decision_links_back():
    """After the pipeline persists the first RCA, dedup hits should
    return the linking decision_id so the dashboard can show
    'suppressed_duplicate → see RCA xyz' rather than a silent drop."""
    dedup = DedupManager(window_seconds=10)
    await dedup.check(FP_LATENCY_INST_30, "firing")
    await dedup.record_first_decision(FP_LATENCY_INST_30, "rca-uuid-123")
    is_dup, prior_id = await dedup.check(FP_LATENCY_INST_30, "firing")
    assert is_dup is True
    assert prior_id == "rca-uuid-123"


@pytest.mark.asyncio
async def test_empty_fingerprint_treated_as_fresh(dedup):
    """An alert without a Grafana fingerprint cannot be deduped reliably —
    treat it as fresh rather than collapse all unfingerprinted alerts."""
    is_dup1, _ = await dedup.check("", "firing")
    is_dup2, _ = await dedup.check("", "firing")
    assert is_dup1 is False
    assert is_dup2 is False


# DA-5 — alertname-family dedupe. The 2026-05-21 dashboard audit surfaced
# HighCpuUsage + CriticalCpuUsage on the same node within ~1 min as two
# separate RCAs. These tests pin the family-key behaviour so the operator
# only ever sees the canonical row per (family, scope).

def _alert(alertname: str, instance: str = "node-30", service: str = "node-exporter",
           fingerprint: str | None = None) -> GrafanaAlert:
    return GrafanaAlert(
        status="firing",
        labels={"alertname": alertname, "instance": instance, "service": service},
        fingerprint=fingerprint if fingerprint is not None else f"grafana-fp-{alertname}-{instance}",
    )


def test_family_dedup_key_collapses_cpu_severity_tiers():
    """Medium/High/Critical CPU on the same instance → one synthetic key."""
    keys = {
        family_dedup_key(_alert("MediumCpuUsage")),
        family_dedup_key(_alert("HighCpuUsage")),
        family_dedup_key(_alert("CriticalCpuUsage")),
    }
    assert keys == {"family:cpu:node-30"}


def test_family_dedup_key_preserves_instance_scope():
    """Same family on different instances must stay distinct — node-30 ≠ node-31."""
    k_a = family_dedup_key(_alert("HighCpuUsage", instance="node-30"))
    k_b = family_dedup_key(_alert("HighCpuUsage", instance="node-31"))
    assert k_a != k_b
    assert k_a == "family:cpu:node-30"
    assert k_b == "family:cpu:node-31"


def test_family_dedup_key_falls_back_to_fingerprint_for_unknown_alertname():
    """Alertnames outside ALERT_FAMILIES (e.g. latency alerts, custom rules)
    must keep the Grafana fingerprint as the dedup key — no surprise collapses."""
    alert = _alert("HighP95Latency", fingerprint="grafana-fp-latency-abc")
    assert "HighP95Latency" not in ALERT_FAMILIES  # guard against accidental family growth
    assert family_dedup_key(alert) == "grafana-fp-latency-abc"


def test_family_dedup_key_falls_back_to_service_when_instance_missing():
    """Host-level rules always carry `instance`, but if it's missing the
    family scope must degrade to `service` rather than collapsing every
    unscoped alert in the family into a single key."""
    alert = GrafanaAlert(
        status="firing",
        labels={"alertname": "HighCpuUsage", "service": "spring-boot"},
        fingerprint="fp-anything",
    )
    assert family_dedup_key(alert) == "family:cpu:spring-boot"


# DA-4 — content-aware Drain3 fingerprints. The legacy `drain3-{service}`
# key collapsed every Drain3 batch on the same service into one dedup
# window, so unrelated anomaly patterns silently merged.

def test_drain3_fingerprint_is_stable_for_same_templates():
    """Same service + same top-3 templates must produce the same hash —
    otherwise repeated fires of the same anomaly would re-trigger full RCAs."""
    fp1 = drain3_fingerprint("spring-boot", ["TplA", "TplB", "TplC"], [])
    fp2 = drain3_fingerprint("spring-boot", ["TplA", "TplB", "TplC"], [])
    assert fp1 == fp2
    assert fp1.startswith("drain3-spring-boot-")


def test_drain3_fingerprint_differs_for_different_templates():
    """Different anomaly patterns on the same service must NOT collapse."""
    oom_like = drain3_fingerprint(
        "spring-boot", ["OutOfMemoryError: Java heap space", "GC overhead limit exceeded"], [],
    )
    conn_like = drain3_fingerprint(
        "spring-boot", ["Connection refused: tcp/5432", "HikariPool timeout acquiring connection"], [],
    )
    assert oom_like != conn_like


def test_drain3_fingerprint_separates_services():
    """Even with identical templates, different services produce different keys."""
    fp_a = drain3_fingerprint("spring-boot", ["TplA"], [])
    fp_b = drain3_fingerprint("kong", ["TplA"], [])
    assert fp_a != fp_b
    assert "spring-boot" in fp_a
    assert "kong" in fp_b


def test_drain3_fingerprint_falls_back_to_lines_when_no_templates():
    """No novel templates → use the first few anomalous lines so each
    visually-distinct batch still gets its own key."""
    fp_with_templates = drain3_fingerprint("svc", [], ["ERROR: db down at 10:00:01", "ERROR: db down at 10:00:02"])
    fp_other = drain3_fingerprint("svc", [], ["INFO: shutting down", "INFO: graceful exit"])
    assert fp_with_templates != fp_other


def test_drain3_fingerprint_graceful_when_everything_empty():
    """Empty templates AND empty lines → fall back to the legacy plain key
    rather than crash. Better-than-nothing dedup beats a 500 in the pipeline."""
    fp = drain3_fingerprint("svc", [], [])
    assert fp == "drain3-svc"


def test_drain3_fingerprint_ignores_whitespace_only_templates():
    """Whitespace-only entries must be filtered before hashing — otherwise
    a stray empty string changes the digest and breaks idempotency."""
    fp1 = drain3_fingerprint("svc", ["TplA", "   ", "TplB"], [])
    fp2 = drain3_fingerprint("svc", ["TplA", "TplB"], [])
    assert fp1 == fp2


@pytest.mark.asyncio
async def test_dedup_collapses_family_siblings_end_to_end():
    """Integration: HighCpuUsage fires, then CriticalCpuUsage fires on the
    same instance within the window — second one must be flagged duplicate
    and link back to the first's decision_id."""
    mgr = DedupManager(window_seconds=10)
    high = _alert("HighCpuUsage", instance="node-30")
    crit = _alert("CriticalCpuUsage", instance="node-30")

    is_dup_first, _ = await mgr.check(family_dedup_key(high), "firing")
    await mgr.record_first_decision(family_dedup_key(high), "rca-high-001")
    is_dup_second, prior_id = await mgr.check(family_dedup_key(crit), "firing")

    assert is_dup_first is False
    assert is_dup_second is True
    assert prior_id == "rca-high-001"
