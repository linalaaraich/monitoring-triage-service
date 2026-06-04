"""SF-5 — sustained-vs-spike verdict modifier (Sprint 4 §14 W2 Fri stretch).

Locks in the contract from sprint4-status.html:
  > 90s CPU spike → action_taken=shelved with quality=transient_spike;
  > sustained 10-min stress → escalates normally.

Plus the design choices in the spec:
  - composes with DA-5 family dedup (MediumCpu → HighCpu within window
    on the same host counts as the "same" alert),
  - reuses DA-3's get_recent_decision_for_fingerprint / a new family-
    scope lookup (MCP-only invariant — canonical store reads),
  - cheap path: gate runs BEFORE LLM call, no context-gather cost,
  - configurable + default-on for cpu/memory/disk/loki-disk/latency-p95,
  - disabled-knob bypasses cleanly,
  - family-not-in-list never shelves (TargetDown / DeadMansSwitch are
    out of scope by design).

All deterministic — no real Ollama / MCP traffic. The LLM client is
asserted NOT-called on transient cases (proves the cheap-path skip).
"""
from __future__ import annotations

import os
import tempfile
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from app.config import settings
from app.models import Decision, GatheredContext, GrafanaAlert, LLMDecision, RCARecord
from app.pipeline import TriagePipeline
from app.rca_store import RCAStore, _utc_now
from app.transient_spike import (
    classify_family,
    is_transient_spike,
    TransientSpikeVerdict,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def store():
    db_path = os.path.join(tempfile.gettempdir(), "test_sf5_transient_spike.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


def _make_alert(
    name: str = "HighCpuUsage",
    service: str = "spring-boot",
    fingerprint: str = "fp-sf5-cpu",
    instance: str = "10.0.1.194:9100",
) -> GrafanaAlert:
    return GrafanaAlert(
        status="firing",
        labels={
            "alertname": name,
            "service": service,
            "severity": "warning",
            "signal": "metric",
            "instance": instance,
        },
        annotations={"summary": "cpu high", "description": "cpu over 80%"},
        startsAt="2026-05-31T10:30:00Z",
        fingerprint=fingerprint,
    )


async def _save_prior(
    store: RCAStore,
    *,
    seconds_ago: float,
    alert_name: str = "HighCpuUsage",
    service: str = "spring-boot",
    instance: str = "10.0.1.194:9100",
    fingerprint: str = "fp-sf5-cpu",
) -> RCARecord:
    rec = RCARecord(
        alert_name=alert_name,
        affected_service=service,
        alert_instance=instance,
        alert_fingerprint=fingerprint,
        triage_decision="investigate",
        llm_verdict="escalate",
        rca_report="prior cpu spike",
        llm_reasoning="prior",
        action_taken="emailed",
        rca_quality="actionable",
    )
    rec.timestamp = _utc_now() - timedelta(seconds=seconds_ago)
    await store.save_decision(rec)
    return rec


# ---------------------------------------------------------------------------
# Unit tests — classify_family + is_transient_spike (pure logic)
# ---------------------------------------------------------------------------


def test_classify_family_known_alerts():
    """SF-5 family map covers cpu/memory/disk/loki-disk/latency-p95."""
    assert classify_family(_make_alert(name="HighCpuUsage")) == "cpu"
    assert classify_family(_make_alert(name="MediumCpuUsage")) == "cpu"
    assert classify_family(_make_alert(name="CriticalCpuUsage")) == "cpu"
    assert classify_family(_make_alert(name="HighMemoryUsage")) == "memory"
    assert classify_family(_make_alert(name="HighDiskUsage")) == "disk"
    assert classify_family(_make_alert(name="LokiHighDiskUsage")) == "loki-disk"
    assert classify_family(_make_alert(name="HighP95Latency")) == "latency-p95"
    assert classify_family(_make_alert(name="HighKongP95Latency")) == "latency-p95"


def test_classify_family_unknown_alerts_return_none():
    """Out-of-scope alerts (binary / heartbeat / app-specific) → None."""
    assert classify_family(_make_alert(name="TargetDown")) is None
    assert classify_family(_make_alert(name="DeadMansSwitch")) is None
    assert classify_family(_make_alert(name="Drain3AnomalyDetected")) is None
    assert classify_family(_make_alert(name="CustomBusinessAlert")) is None


def test_is_transient_spike_within_window_shelves():
    """90s gap (default 120s window) → shelved as transient_spike."""
    alert = _make_alert(name="HighCpuUsage")
    prior = {
        "id": "prior-1",
        "timestamp": (_utc_now() - timedelta(seconds=90)).isoformat(),
        "alert_name": "HighCpuUsage",
    }
    verdict = is_transient_spike(
        alert,
        prior_decision=prior,
        window_seconds=120,
        enabled_families=["cpu", "memory", "disk", "loki-disk", "latency-p95"],
    )
    assert verdict.is_transient is True
    assert verdict.family == "cpu"
    assert verdict.prior_decision_id == "prior-1"
    assert "transient spike" in verdict.reason.lower()
    assert "90s" in verdict.reason or "90s ago" in verdict.reason or "90s," in verdict.reason


def test_is_transient_spike_outside_window_does_not_shelve():
    """11-min gap → over the 120s window → NOT transient → falls through."""
    alert = _make_alert(name="HighCpuUsage")
    prior = {
        "id": "prior-2",
        "timestamp": (_utc_now() - timedelta(minutes=11)).isoformat(),
    }
    verdict = is_transient_spike(
        alert, prior_decision=prior, window_seconds=120,
        enabled_families=["cpu", "memory", "disk", "loki-disk", "latency-p95"],
    )
    assert verdict.is_transient is False


def test_is_transient_spike_no_prior_does_not_shelve():
    """First-occurrence (no prior) → NOT transient. Need duration evidence."""
    alert = _make_alert(name="HighCpuUsage")
    verdict = is_transient_spike(
        alert, prior_decision=None, window_seconds=120,
        enabled_families=["cpu", "memory", "disk", "loki-disk", "latency-p95"],
    )
    assert verdict.is_transient is False


def test_is_transient_spike_unknown_family_does_not_shelve():
    """Family not in SF-5 list (e.g. TargetDown) → never transient even
    with a 5s gap. Refuse to guess on un-validated archetypes."""
    alert = _make_alert(name="TargetDown")
    prior = {
        "id": "prior-3",
        "timestamp": (_utc_now() - timedelta(seconds=5)).isoformat(),
    }
    verdict = is_transient_spike(
        alert, prior_decision=prior, window_seconds=120,
        enabled_families=["cpu", "memory", "disk", "loki-disk", "latency-p95"],
    )
    assert verdict.is_transient is False


def test_is_transient_spike_family_disabled_in_config_does_not_shelve():
    """A family present in the SF-5 map but excluded from
    enabled_families (operator dialled it back) → not transient."""
    alert = _make_alert(name="HighCpuUsage")
    prior = {
        "id": "prior-4",
        "timestamp": (_utc_now() - timedelta(seconds=30)).isoformat(),
    }
    # Operator turned off CPU spike-shelving but kept the others
    verdict = is_transient_spike(
        alert, prior_decision=prior, window_seconds=120,
        enabled_families=["memory", "disk"],
    )
    assert verdict.is_transient is False


def test_is_transient_spike_garbled_prior_timestamp_does_not_shelve():
    """Defensive: an unparseable prior timestamp must fall through,
    not silently flip to shelved."""
    alert = _make_alert(name="HighCpuUsage")
    prior = {"id": "prior-5", "timestamp": "garbage-not-iso"}
    verdict = is_transient_spike(
        alert, prior_decision=prior, window_seconds=120,
        enabled_families=["cpu"],
    )
    assert verdict.is_transient is False


def test_is_transient_spike_future_prior_does_not_shelve():
    """Clock skew / test backdating: a prior with a timestamp in the
    FUTURE must not auto-shelve."""
    alert = _make_alert(name="HighCpuUsage")
    prior = {
        "id": "prior-6",
        "timestamp": (_utc_now() + timedelta(seconds=60)).isoformat(),
    }
    verdict = is_transient_spike(
        alert, prior_decision=prior, window_seconds=120,
        enabled_families=["cpu"],
    )
    assert verdict.is_transient is False


# ---------------------------------------------------------------------------
# Store lookup — get_recent_decision_for_family_scope (DA-5 composition)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_store_family_scope_finds_tier_sibling_within_window(store):
    """MediumCpu at T+0 → HighCpu at T+90s on the same host: the family-
    scope lookup must find the MediumCpu row even though fingerprints
    and alertnames differ."""
    await _save_prior(
        store,
        seconds_ago=90,
        alert_name="MediumCpuUsage",
        instance="10.0.1.194:9100",
        fingerprint="fp-medium-cpu",
    )
    prior = await store.get_recent_decision_for_family_scope(
        alertnames=["MediumCpuUsage", "HighCpuUsage", "CriticalCpuUsage"],
        affected_service="spring-boot",
        alert_instance="10.0.1.194:9100",
        window_seconds=120,
    )
    assert prior is not None
    assert prior["alert_name"] == "MediumCpuUsage"


@pytest.mark.asyncio
async def test_store_family_scope_excludes_different_host(store):
    """A prior fire on host-A must not shelve a fresh fire on host-B."""
    await _save_prior(
        store, seconds_ago=30, alert_name="HighCpuUsage",
        instance="10.0.1.68:9100",  # different host
    )
    prior = await store.get_recent_decision_for_family_scope(
        alertnames=["HighCpuUsage"],
        affected_service="spring-boot",
        alert_instance="10.0.1.194:9100",  # the host we're checking
        window_seconds=120,
    )
    assert prior is None


@pytest.mark.asyncio
async def test_store_family_scope_excludes_synthetic_fingerprints(store):
    """audit-live-* / chaos-* fires must not seed an SF-5 shelving."""
    rec = RCARecord(
        alert_name="HighCpuUsage",
        affected_service="spring-boot",
        alert_instance="10.0.1.194:9100",
        alert_fingerprint="audit-live-2026-05-31-cpu",
        triage_decision="investigate",
        llm_verdict="escalate",
        action_taken="emailed",
    )
    rec.timestamp = _utc_now() - timedelta(seconds=30)
    await store.save_decision(rec)
    prior = await store.get_recent_decision_for_family_scope(
        alertnames=["HighCpuUsage"],
        affected_service="spring-boot",
        alert_instance="10.0.1.194:9100",
        window_seconds=120,
    )
    assert prior is None


@pytest.mark.asyncio
async def test_store_family_scope_falls_back_to_service_when_instance_unknown(store):
    """If alert_instance is "unknown" (label sparse), the lookup must
    fall back to affected_service — matching family_dedup_key's
    fallback order."""
    await _save_prior(
        store, seconds_ago=30, alert_name="HighCpuUsage",
        service="kong", instance="unknown",
    )
    prior = await store.get_recent_decision_for_family_scope(
        alertnames=["HighCpuUsage"],
        affected_service="kong",
        alert_instance="unknown",
        window_seconds=120,
    )
    assert prior is not None
    assert prior["affected_service"] == "kong"


# ---------------------------------------------------------------------------
# Pipeline integration — full flow with stubbed LLM/notifier/context
# ---------------------------------------------------------------------------


def _make_pipeline(store: RCAStore) -> tuple[TriagePipeline, MagicMock, MagicMock]:
    """Pipeline with a stub LLM (asserted NOT-called on transient cases)
    and a stub notifier (asserted NOT-called on transient cases).
    """
    llm = MagicMock()
    llm.investigate = AsyncMock(
        return_value=(
            LLMDecision(
                decision=Decision.ESCALATE,
                severity="warning",
                confidence=0.85,
                reason="ok",
                rca="real RCA — would normally page",
                suggested_actions=["kubectl rollout restart deploy/x"],
                evidence=["evidence"],
            ),
            10,
        )
    )
    llm.request_tool_or_decide = AsyncMock(return_value=(None, 0))

    ctx_gatherer = MagicMock()
    ctx_gatherer.gather = AsyncMock(return_value=GatheredContext())

    drain = MagicMock()
    drain.annotate_lines = MagicMock(return_value=([], ""))
    drain.get_stats = MagicMock(return_value={"total_clusters": 0})

    notifier = MagicMock(
        send_escalation=AsyncMock(),
        send_timeout_alert=AsyncMock(),
    )

    pipeline = TriagePipeline(
        rca_store=store,
        drain=drain,
        context_gatherer=ctx_gatherer,
        llm_client=llm,
        notifier=notifier,
        dedup=MagicMock(
            check=AsyncMock(return_value=(False, None)),
            record_first_decision=AsyncMock(),
            window=600,
        ),
    )
    return pipeline, llm, notifier


@pytest.mark.asyncio
async def test_pipeline_90s_spike_shelved_without_llm(store, monkeypatch):
    """The acceptance test from sprint4-status.html: 90s CPU spike →
    action_taken=shelved with quality=transient_spike, LLM never called."""
    monkeypatch.setattr(settings, "sf5_transient_spike_enabled", True)
    monkeypatch.setattr(settings, "sf5_transient_spike_window_seconds", 120)
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)

    # Prior fire 90s ago on the same host+service
    await _save_prior(store, seconds_ago=90, fingerprint="fp-prior-cpu")

    pipeline, llm, notifier = _make_pipeline(store)
    alert = _make_alert(name="HighCpuUsage", fingerprint="fp-new-cpu")
    await pipeline._process_alert(alert, source="grafana")

    # LLM never invoked, no email sent
    llm.investigate.assert_not_called()
    notifier.send_escalation.assert_not_called()

    # Row persisted with the right shape — 2 rows in the store (prior + shelved)
    rows = await store.get_decisions(limit=10)
    assert len(rows) == 2
    # Latest row is the SF-5-shelved one (ORDER BY timestamp DESC)
    shelved = rows[0]
    assert shelved["action_taken"] == "shelved"
    assert shelved["rca_quality"] == "transient_spike"
    assert shelved["triage_decision"] == "spike_shelved"
    assert shelved["llm_verdict"] is None  # short-path: no LLM
    assert "transient spike" in (shelved["rca_report"] or "").lower()


@pytest.mark.asyncio
async def test_pipeline_sustained_10min_breach_escalates_normally(store, monkeypatch):
    """11-min gap → over the window → normal investigate path → LLM called."""
    monkeypatch.setattr(settings, "sf5_transient_spike_enabled", True)
    monkeypatch.setattr(settings, "sf5_transient_spike_window_seconds", 120)
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)

    await _save_prior(store, seconds_ago=11 * 60, fingerprint="fp-old-cpu")

    pipeline, llm, notifier = _make_pipeline(store)
    alert = _make_alert(name="HighCpuUsage", fingerprint="fp-new-cpu-sustained")
    await pipeline._process_alert(alert, source="grafana")

    # LLM IS called — sustained breach hits the normal investigate path
    # call_count ≥ 1 — retry path may invoke twice on a stubbed RCA the
    # quality classifier flags as data_starved. The point of THIS test
    # is "LLM was reached, not short-circuited by SF-5."
    assert llm.investigate.call_count >= 1
    rows = await store.get_decisions(limit=10)
    # Latest is the LLM-investigated row, not a spike_shelved short-path
    assert rows[0]["triage_decision"] != "spike_shelved"
    assert rows[0]["rca_quality"] != "transient_spike"


@pytest.mark.asyncio
async def test_pipeline_no_prior_first_fire_escalates_normally(store, monkeypatch):
    """No prior decision → first occurrence → LLM called normally."""
    monkeypatch.setattr(settings, "sf5_transient_spike_enabled", True)
    monkeypatch.setattr(settings, "sf5_transient_spike_window_seconds", 120)
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)

    pipeline, llm, notifier = _make_pipeline(store)
    alert = _make_alert(name="HighCpuUsage", fingerprint="fp-first-fire")
    await pipeline._process_alert(alert, source="grafana")

    # call_count ≥ 1 — retry path may invoke twice on a stubbed RCA the
    # quality classifier flags as data_starved. The point of THIS test
    # is "LLM was reached, not short-circuited by SF-5."
    assert llm.investigate.call_count >= 1


@pytest.mark.asyncio
async def test_pipeline_target_down_never_shelved(store, monkeypatch):
    """TargetDown (out of SF-5 scope) with a 30s prior fire: must NOT
    shelve. Binary alerts don't have "transient spike" semantics."""
    monkeypatch.setattr(settings, "sf5_transient_spike_enabled", True)
    monkeypatch.setattr(settings, "sf5_transient_spike_window_seconds", 120)
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)

    await _save_prior(
        store, seconds_ago=30,
        alert_name="TargetDown",
        fingerprint="fp-target-down-prior",
    )
    pipeline, llm, notifier = _make_pipeline(store)
    alert = _make_alert(name="TargetDown", fingerprint="fp-target-down-new")
    await pipeline._process_alert(alert, source="grafana")

    # TargetDown is out of SF-5 scope → LLM IS called
    # call_count ≥ 1 — retry path may invoke twice on a stubbed RCA the
    # quality classifier flags as data_starved. The point of THIS test
    # is "LLM was reached, not short-circuited by SF-5."
    assert llm.investigate.call_count >= 1


def test_sf5_deprecated_disabled_by_default():
    """DEPRECATED 2026-06-04 (audit issue #4): SF-5 is structurally
    unreachable (120s window ⊂ 300s dedup window that runs first) and is
    now DISABLED BY DEFAULT. This locks in the deprecation so a future
    edit can't silently re-enable an unreachable gate.

    The fresh-default value is asserted from a fresh Settings() instance
    (not the process-global `settings`, which other tests monkeypatch).
    """
    from app.config import Settings

    fresh = Settings()
    assert fresh.sf5_transient_spike_enabled is False, (
        "SF-5 transient_spike is deprecated (audit #4) and must default to "
        "disabled — its 120s window is a strict subset of the 300s dedup "
        "window, so it can never fire in production."
    )
    # The window field is retained (not removed) for the safe-deprecation
    # path; it stays at its documented default.
    assert fresh.sf5_transient_spike_window_seconds == 120


@pytest.mark.asyncio
async def test_pipeline_default_settings_never_shelves_spike(store, monkeypatch):
    """With the SHIPPED default (sf5_transient_spike_enabled=False, NOT
    monkeypatched True), even a fresh 30s prior in the window must NOT
    produce a spike_shelved row — the deprecated gate stays inert and the
    alert reaches the normal investigate path."""
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)
    # NB: deliberately do NOT set sf5_transient_spike_enabled — exercise
    # the real shipped default.

    await _save_prior(store, seconds_ago=30, fingerprint="fp-deprecated-default")
    pipeline, llm, notifier = _make_pipeline(store)
    alert = _make_alert(name="HighCpuUsage", fingerprint="fp-deprecated-default-new")
    await pipeline._process_alert(alert, source="grafana")

    # LLM IS reached — SF-5 did not short-circuit.
    assert llm.investigate.call_count >= 1
    rows = await store.get_decisions(limit=10)
    assert rows[0]["triage_decision"] != "spike_shelved"
    assert rows[0]["rca_quality"] != "transient_spike"


@pytest.mark.asyncio
async def test_pipeline_disabled_knob_skips_shelving(store, monkeypatch):
    """Disabled-knob: even with a fresh prior in the window, SF-5 does
    nothing → LLM called normally. (Now also the shipped default — see
    test_sf5_deprecated_disabled_by_default; this test pins the knob
    explicitly to keep the explicit-disable contract covered.)"""
    monkeypatch.setattr(settings, "sf5_transient_spike_enabled", False)
    monkeypatch.setattr(settings, "sf5_transient_spike_window_seconds", 120)
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)

    await _save_prior(store, seconds_ago=30, fingerprint="fp-disabled")
    pipeline, llm, notifier = _make_pipeline(store)
    alert = _make_alert(name="HighCpuUsage", fingerprint="fp-disabled-new")
    await pipeline._process_alert(alert, source="grafana")

    # call_count ≥ 1 — retry path may invoke twice on a stubbed RCA the
    # quality classifier flags as data_starved. The point of THIS test
    # is "LLM was reached, not short-circuited by SF-5."
    assert llm.investigate.call_count >= 1


@pytest.mark.asyncio
async def test_pipeline_da5_composition_medium_then_high_cpu(store, monkeypatch):
    """DA-5 composition: MediumCpuUsage at T+0 → HighCpuUsage at T+90s on
    the SAME host. Even though the alertnames + fingerprints differ, SF-5
    must shelve the second fire as a transient spike (same family +
    scope + within window)."""
    monkeypatch.setattr(settings, "sf5_transient_spike_enabled", True)
    monkeypatch.setattr(settings, "sf5_transient_spike_window_seconds", 120)
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)

    # Prior MediumCpu fire 90s ago on host-A
    await _save_prior(
        store,
        seconds_ago=90,
        alert_name="MediumCpuUsage",
        instance="10.0.1.194:9100",
        fingerprint="fp-medium-cpu-tier",
    )
    pipeline, llm, notifier = _make_pipeline(store)
    # Now a HighCpu fires on the SAME host
    alert = _make_alert(
        name="HighCpuUsage",
        instance="10.0.1.194:9100",
        fingerprint="fp-high-cpu-tier",  # different fingerprint!
    )
    await pipeline._process_alert(alert, source="grafana")

    # Family-scope lookup must catch this → shelved, no LLM call
    llm.investigate.assert_not_called()
    rows = await store.get_decisions(limit=10)
    assert rows[0]["triage_decision"] == "spike_shelved"
    assert rows[0]["rca_quality"] == "transient_spike"


@pytest.mark.asyncio
async def test_pipeline_counter_increments_per_family(store, monkeypatch):
    """transient_spikes_shelved_total{family=...} bumps once per shelving."""
    from app.metrics import transient_spikes_shelved_total

    monkeypatch.setattr(settings, "sf5_transient_spike_enabled", True)
    monkeypatch.setattr(settings, "sf5_transient_spike_window_seconds", 120)
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)

    # Snapshot the counter BEFORE — Prometheus client counters accumulate
    # across tests, so we read the delta.
    before = transient_spikes_shelved_total.labels(family="cpu")._value.get()

    await _save_prior(store, seconds_ago=60, fingerprint="fp-counter-prior")
    pipeline, llm, _ = _make_pipeline(store)
    alert = _make_alert(name="HighCpuUsage", fingerprint="fp-counter-new")
    await pipeline._process_alert(alert, source="grafana")

    after = transient_spikes_shelved_total.labels(family="cpu")._value.get()
    assert after - before == 1


@pytest.mark.asyncio
async def test_pipeline_persisted_row_has_rich_alert_fields(store, monkeypatch):
    """The shelved short-path row should carry instance/component/signal
    so the dashboard renders it the same as full RCA rows (not as a
    naked "shelved" with no context)."""
    monkeypatch.setattr(settings, "sf5_transient_spike_enabled", True)
    monkeypatch.setattr(settings, "sf5_transient_spike_window_seconds", 120)
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)

    await _save_prior(store, seconds_ago=60, fingerprint="fp-rich-prior")
    pipeline, llm, _ = _make_pipeline(store)
    alert = GrafanaAlert(
        status="firing",
        labels={
            "alertname": "HighCpuUsage",
            "service": "spring-boot",
            "severity": "warning",
            "signal": "metric",
            "component": "api",
            "instance": "10.0.1.194:9100",
        },
        annotations={"summary": "cpu high"},
        startsAt="2026-05-31T10:30:00Z",
        fingerprint="fp-rich-new",
    )
    await pipeline._process_alert(alert, source="grafana")

    rows = await store.get_decisions(limit=10)
    shelved = rows[0]
    assert shelved["alert_instance"] == "10.0.1.194:9100"
    assert shelved["alert_component"] == "api"
    assert shelved["alert_signal"] == "metric"
