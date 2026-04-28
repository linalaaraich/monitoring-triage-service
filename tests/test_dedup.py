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

from app.dedup import DedupManager


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
