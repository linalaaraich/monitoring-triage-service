"""Backend audit 2026-06-04 — issues #1 (drain3 noise gate) and #3 (stale rca_quality).

Issue #1: a drain3 self-fire that carries NO new templates and an anomaly_rate
below the configured floor is a data-starved "cannot determine" fire. It used
to spawn a full ~100s LLM `investigate` row that resolved to a hedge. The
noise-suppression gate in `process_drain3_webhook` now short-paths these to a
cheap `drain3_noise_suppressed` record with no LLM call — while ANY batch that
introduces a brand-new template is always investigated (conservatism).

Issue #3: `rca_quality` used to be snapshotted at first-pass (and hard-set to
"actionable" on retry-success), then the clamp/DA-2 gates stripped the
suggested_actions the classifier reads — so a row that ends up data-starved
persisted a stale "actionable". The pipeline now recomputes rca_quality from
the FINAL decision before persistence. These tests pin the classifier outcome
for the clamped-to-empty case and assert the gate end-to-end.
"""
from __future__ import annotations

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from app.config import settings
from app.models import Decision, Drain3Webhook, LLMDecision, RCARecord
from app.pipeline import TriagePipeline
from app.rca_store import RCAStore, _classify_rca_quality


@pytest_asyncio.fixture
async def fresh_store():
    db_path = os.path.join(tempfile.gettempdir(), "test_drain3_noise_stale.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


def _make_pipeline(store: RCAStore) -> TriagePipeline:
    return TriagePipeline(
        rca_store=store,
        drain=MagicMock(),
        context_gatherer=MagicMock(),
        llm_client=MagicMock(),
        notifier=MagicMock(send_escalation=AsyncMock()),
        dedup=MagicMock(
            check=AsyncMock(return_value=(False, None)),
            record_first_decision=AsyncMock(),
        ),
    )


# ── Issue #1 — noise-suppression gate ────────────────────────────────────

@pytest.mark.asyncio
async def test_low_rate_no_templates_is_suppressed_without_llm(fresh_store, monkeypatch):
    """No new templates + anomaly_rate below floor → cheap suppressed row,
    and _process_alert (the LLM path) is never reached."""
    monkeypatch.setattr(settings, "drain3_noise_suppress_enabled", True)
    monkeypatch.setattr(settings, "drain3_noise_suppress_rate_floor", 0.05)
    pipeline = _make_pipeline(fresh_store)
    # Tripwire: if the gate fails, the full LLM path would run.
    pipeline._process_alert = AsyncMock(side_effect=AssertionError("LLM path reached"))

    await pipeline.process_drain3_webhook(Drain3Webhook(
        service="spring-boot",
        anomaly_rate=0.03,
        new_templates=[],
        anomalous_lines=["DEBUG Writing Employee id=1", "DEBUG Writing Employee id=2"],
    ))

    pipeline._process_alert.assert_not_awaited()
    rows = await fresh_store.get_decisions(limit=5)
    assert len(rows) == 1
    assert rows[0]["triage_decision"] == "drain3_noise_suppressed"
    assert rows[0]["rca_quality"] == "data_starved"
    assert rows[0]["investigation_duration_ms"] == 0


@pytest.mark.asyncio
async def test_new_template_always_investigated(fresh_store, monkeypatch):
    """A batch with a brand-new template is NEVER suppressed — even at a low
    rate — so genuinely novel anomalies always reach the LLM."""
    monkeypatch.setattr(settings, "drain3_noise_suppress_enabled", True)
    monkeypatch.setattr(settings, "drain3_noise_suppress_rate_floor", 0.05)
    pipeline = _make_pipeline(fresh_store)
    pipeline._process_alert = AsyncMock()

    await pipeline.process_drain3_webhook(Drain3Webhook(
        service="spring-boot",
        anomaly_rate=0.01,
        new_templates=["OutOfMemoryError: Java heap space"],
        anomalous_lines=["OutOfMemoryError: Java heap space"],
    ))

    pipeline._process_alert.assert_awaited_once()
    # No cheap suppressed row was written for this path.
    rows = await fresh_store.get_decisions(limit=5)
    assert all(r["triage_decision"] != "drain3_noise_suppressed" for r in rows)


@pytest.mark.asyncio
async def test_high_rate_no_templates_still_investigated(fresh_store, monkeypatch):
    """No new templates but anomaly_rate ABOVE the floor → still investigated
    (a high-volume known-template burst may be a real incident)."""
    monkeypatch.setattr(settings, "drain3_noise_suppress_enabled", True)
    monkeypatch.setattr(settings, "drain3_noise_suppress_rate_floor", 0.05)
    pipeline = _make_pipeline(fresh_store)
    pipeline._process_alert = AsyncMock()

    await pipeline.process_drain3_webhook(Drain3Webhook(
        service="spring-boot",
        anomaly_rate=0.40,
        new_templates=[],
        anomalous_lines=["ERROR connection pool exhausted"],
    ))

    pipeline._process_alert.assert_awaited_once()


@pytest.mark.asyncio
async def test_gate_disabled_investigates(fresh_store, monkeypatch):
    """With the gate disabled the noise case falls through to the LLM path."""
    monkeypatch.setattr(settings, "drain3_noise_suppress_enabled", False)
    pipeline = _make_pipeline(fresh_store)
    pipeline._process_alert = AsyncMock()

    await pipeline.process_drain3_webhook(Drain3Webhook(
        service="spring-boot", anomaly_rate=0.01, new_templates=[],
        anomalous_lines=["DEBUG noise"],
    ))

    pipeline._process_alert.assert_awaited_once()


# ── Issue #3 — rca_quality recomputed from the FINAL decision ─────────────

def test_classifier_demotes_clamped_decision_off_actionable():
    """The confidence clamp strips suggested_actions; with no actions AND no
    evidence the classifier (re-run by the pipeline at persist time) must NOT
    return the stale 'actionable' — it demotes to a review-worthy quality.
    This is the core of issue #3: the persisted rca_quality reflects the FINAL
    (clamped) artifacts, not the first-pass snapshot."""
    clamped = LLMDecision(
        decision=Decision.ESCALATE,
        confidence=0.4,
        reason="additional investigation needed",
        rca="Cannot determine the root cause with confidence — additional investigation needed.",
        suggested_actions=[],   # clamp stripped these
        evidence=[],
    )
    q = _classify_rca_quality(
        clamped.rca, clamped.reason, clamped.suggested_actions, clamped.evidence,
    )
    assert q != "actionable"
    assert q in ("needs_review", "data_starved")


def test_classifier_data_starved_on_hedge_with_actions_present():
    """When the prose hedges ('cannot determine') but actions/evidence are
    present (so Rule 1 doesn't short-circuit), the classifier returns
    data_starved — the value the recompute persists instead of a stale
    actionable."""
    hedged = LLMDecision(
        decision=Decision.ESCALATE,
        confidence=0.4,
        reason="",
        rca="Cannot determine the root cause; insufficient data in the logs.",
        suggested_actions=["check the logs manually"],
        evidence=["Loki returned 0 lines for service=drain3"],
    )
    q = _classify_rca_quality(
        hedged.rca, hedged.reason, hedged.suggested_actions, hedged.evidence,
    )
    assert q == "data_starved"


def test_classifier_actionable_when_grounded_with_actions():
    """Sanity: a grounded RCA with real actions still classifies actionable,
    so the recompute doesn't over-demote good rows."""
    good = LLMDecision(
        decision=Decision.ESCALATE,
        confidence=0.85,
        reason="JDBC connection pool exhausted on spring-boot",
        rca="The HikariCP connection pool on spring-boot is exhausted; all 10 "
            "connections are checked out and new requests block until timeout.",
        suggested_actions=["Increase spring.datasource.hikari.maximum-pool-size"],
        evidence=["pool.ActiveConnections == pool.MaxConnections for 5m"],
    )
    q = _classify_rca_quality(
        good.rca, good.reason, good.suggested_actions, good.evidence,
    )
    assert q == "actionable"
