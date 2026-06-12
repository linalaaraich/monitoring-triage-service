"""Critical-flap suppression (2026-06-12).

TargetDown blips (the service's own deploy restarts + k3s API-server scrape
timeouts under induced load) burned 67 full GPU investigations in ~36h —
every one honestly dismissed — because the e10e341d criticals-bypass keyed
on severity alone. These tests pin the scoped behavior:

  - A FRESH critical outage (no recent dismissal streak) always
    investigates — the e10e341d guarantee.
  - An ESTABLISHED FLAPPER (>= threshold honest dismissals in the window,
    latest investigated verdict a dismiss) is Layer-2 suppressed.
  - Every sample_every-th fire is investigated anyway (regime-change probe).
  - An escalate as the latest investigated verdict disables suppression.
  - The feature flag disables the whole path.
"""
import os
import tempfile
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from app.config import settings
from app.models import GrafanaAlert, RCARecord
from app.pipeline import TriagePipeline
from app.rca_store import RCAStore

FP = "flapfp000000001"


@pytest_asyncio.fixture
async def fresh_store():
    db_path = os.path.join(tempfile.gettempdir(), "test_critical_flap.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    os.unlink(db_path)


def make_pipeline(store: RCAStore) -> TriagePipeline:
    return TriagePipeline(
        rca_store=store,
        drain=MagicMock(),
        context_gatherer=MagicMock(),
        llm_client=MagicMock(),
        notifier=MagicMock(send_escalation=AsyncMock(), send_timeout_alert=AsyncMock()),
        dedup=MagicMock(check=AsyncMock(return_value=False)),
    )


def make_critical(name="TargetDown", service="monitoring", fingerprint=FP) -> GrafanaAlert:
    a = GrafanaAlert(
        status="firing",
        labels={"alertname": name, "service": service, "severity": "critical"},
        annotations={"summary": "x", "description": "y"},
        startsAt="2026-06-12T19:55:50Z",
    )
    a.fingerprint = fingerprint
    return a


def dismiss_row(fingerprint=FP, name="TargetDown", service="monitoring") -> RCARecord:
    return RCARecord(
        alert_name=name,
        affected_service=service,
        alert_fingerprint=fingerprint,
        triage_decision="investigate",
        llm_verdict="dismiss",
        llm_reasoning="transient scrape blip, target back up",
        action_taken="suppressed",
    )


def suppressed_row(fingerprint=FP, name="TargetDown", service="monitoring") -> RCARecord:
    return RCARecord(
        alert_name=name,
        affected_service=service,
        alert_fingerprint=fingerprint,
        triage_decision="triage_suppressed",
        llm_verdict=None,
        action_taken="suppressed",
    )


@pytest.mark.asyncio
async def test_fresh_critical_always_investigates(fresh_store):
    # e10e341d guarantee: 0 prior rows → bypass → investigate.
    pipeline = make_pipeline(fresh_store)
    assert await pipeline._check_suppression(make_critical()) is None


@pytest.mark.asyncio
async def test_critical_below_streak_threshold_investigates(fresh_store):
    for _ in range(settings.critical_flap_dismiss_threshold - 1):
        await fresh_store.save_decision(dismiss_row())
    pipeline = make_pipeline(fresh_store)
    assert await pipeline._check_suppression(make_critical()) is None


@pytest.mark.asyncio
async def test_established_flapper_is_suppressed(fresh_store):
    for _ in range(settings.critical_flap_dismiss_threshold):
        await fresh_store.save_decision(dismiss_row())
    pipeline = make_pipeline(fresh_store)
    reason = await pipeline._check_suppression(make_critical())
    assert reason is not None and reason.startswith("critical_flap")


@pytest.mark.asyncio
async def test_sampled_reinvestigation_after_budget(fresh_store):
    for _ in range(settings.critical_flap_dismiss_threshold):
        await fresh_store.save_decision(dismiss_row())
    for _ in range(settings.critical_flap_sample_every - 1):
        await fresh_store.save_decision(suppressed_row())
    pipeline = make_pipeline(fresh_store)
    # budget exhausted → this fire samples through to a real investigation
    assert await pipeline._check_suppression(make_critical()) is None


@pytest.mark.asyncio
async def test_suppression_continues_under_budget(fresh_store):
    for _ in range(settings.critical_flap_dismiss_threshold):
        await fresh_store.save_decision(dismiss_row())
    for _ in range(settings.critical_flap_sample_every - 2):
        await fresh_store.save_decision(suppressed_row())
    pipeline = make_pipeline(fresh_store)
    reason = await pipeline._check_suppression(make_critical())
    assert reason is not None and reason.startswith("critical_flap")


@pytest.mark.asyncio
async def test_escalate_as_latest_verdict_breaks_the_streak(fresh_store):
    for _ in range(settings.critical_flap_dismiss_threshold):
        await fresh_store.save_decision(dismiss_row())
    escalated = dismiss_row()
    escalated.llm_verdict = "escalate"
    escalated.action_taken = "emailed"
    await fresh_store.save_decision(escalated)
    pipeline = make_pipeline(fresh_store)
    # regime changed — the flapper became real; keep investigating
    assert await pipeline._check_suppression(make_critical()) is None


@pytest.mark.asyncio
async def test_different_fingerprint_not_suppressed(fresh_store):
    for _ in range(settings.critical_flap_dismiss_threshold):
        await fresh_store.save_decision(dismiss_row())
    pipeline = make_pipeline(fresh_store)
    other = make_critical(fingerprint="otherfp00000002")
    assert await pipeline._check_suppression(other) is None


@pytest.mark.asyncio
async def test_flag_disables_critical_flap(fresh_store, monkeypatch):
    for _ in range(settings.critical_flap_dismiss_threshold):
        await fresh_store.save_decision(dismiss_row())
    monkeypatch.setattr(settings, "critical_flap_suppression_enabled", False)
    pipeline = make_pipeline(fresh_store)
    assert await pipeline._check_suppression(make_critical()) is None


@pytest.mark.asyncio
async def test_missing_fingerprint_never_suppresses(fresh_store):
    for _ in range(settings.critical_flap_dismiss_threshold):
        await fresh_store.save_decision(dismiss_row())
    pipeline = make_pipeline(fresh_store)
    a = make_critical(fingerprint="")
    assert await pipeline._check_suppression(a) is None


@pytest.mark.asyncio
async def test_warning_path_unchanged(fresh_store):
    # non-criticals keep the plain lookback suppression
    await fresh_store.save_decision(
        RCARecord(
            alert_name="MediumCpuUsage",
            affected_service="k3s-host",
            triage_decision="investigate",
            llm_verdict="dismiss",
            action_taken="suppressed",
        )
    )
    pipeline = make_pipeline(fresh_store)
    warn = GrafanaAlert(
        status="firing",
        labels={"alertname": "MediumCpuUsage", "service": "k3s-host", "severity": "warning"},
        annotations={"summary": "x", "description": "y"},
        startsAt="2026-06-12T19:55:50Z",
    )
    assert await pipeline._check_suppression(warn) == "recent_dismissed_history"
