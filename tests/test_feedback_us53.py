"""US-5.3 closed-loop feedback — storage layer + override gate.

Tests the feedback table CRUD plus the time-of-day-aware override matching
that the pipeline uses to flip DISMISS verdicts to ESCALATE.
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta

import pytest
import pytest_asyncio

from app.models import RCARecord
from app.rca_store import RCAStore


@pytest_asyncio.fixture
async def store():
    db_path = os.path.join(tempfile.gettempdir(), "test_feedback_us53.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    os.unlink(db_path)


async def _make_decision(
    store: RCAStore,
    *,
    decision_id: str = "dec-001",
    alert_name: str = "HighP95Latency",
    service: str = "spring-boot",
    verdict: str = "dismiss",
    timestamp: datetime | None = None,
):
    rec = RCARecord(
        id=decision_id,
        timestamp=timestamp or datetime.utcnow(),
        alert_source="grafana",
        alert_name=alert_name,
        alert_fingerprint=f"fp-{decision_id}",
        affected_service=service,
        severity="warning",
        triage_decision="investigate",
        llm_verdict=verdict,
        action_taken="suppressed" if verdict == "dismiss" else "emailed",
    )
    await store.save_decision(rec)
    return rec


# -----------------------------------------------------------------------------
# Schema + basic CRUD
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_record_override_creates_row_with_active_until(store):
    await _make_decision(store)
    saved = await store.record_feedback(
        feedback_id="fb-001",
        decision_id="dec-001",
        feedback_type="override",
        operator_note="Real incident",
        active_for_days=14,
    )
    assert saved["feedback_type"] == "override"
    assert saved["active_until"] is not None
    # active_until should be ~14 days after created_at
    created = datetime.fromisoformat(saved["created_at"])
    active_until = datetime.fromisoformat(saved["active_until"])
    delta_days = (active_until - created).days
    assert 13 <= delta_days <= 14


@pytest.mark.asyncio
async def test_record_confirm_has_no_active_until(store):
    await _make_decision(store)
    saved = await store.record_feedback(
        feedback_id="fb-001",
        decision_id="dec-001",
        feedback_type="confirm",
        operator_note="Yes, real",
    )
    assert saved["feedback_type"] == "confirm"
    assert saved["active_until"] is None


@pytest.mark.asyncio
async def test_idempotent_repost_updates_in_place(store):
    await _make_decision(store)
    first = await store.record_feedback(
        feedback_id="fb-001",
        decision_id="dec-001",
        feedback_type="override",
        operator_note="First note",
    )
    second = await store.record_feedback(
        feedback_id="fb-001",
        decision_id="dec-001",
        feedback_type="override",
        operator_note="Updated note",
    )
    assert first["id"] == second["id"]
    assert second["operator_note"] == "Updated note"
    # Only one row total
    rows = await store.get_feedback_for_decision("dec-001")
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_record_invalid_feedback_type_raises(store):
    await _make_decision(store)
    with pytest.raises(ValueError, match="must be 'override' or 'confirm'"):
        await store.record_feedback(
            feedback_id="fb-001",
            decision_id="dec-001",
            feedback_type="reject",
            operator_note=None,
        )


@pytest.mark.asyncio
async def test_decision_can_have_both_override_and_confirm(store):
    """At most one row per (decision_id, feedback_type) — but a decision can
    legitimately accumulate one override AND one confirm over time.
    """
    await _make_decision(store)
    await store.record_feedback("fb-1", "dec-001", "override", "First")
    await store.record_feedback("fb-2", "dec-001", "confirm", "Then ratified")
    rows = await store.get_feedback_for_decision("dec-001")
    assert len(rows) == 2
    types = {r["feedback_type"] for r in rows}
    assert types == {"override", "confirm"}


# -----------------------------------------------------------------------------
# Pre-LLM override gate — alertname + service + time-of-day matching
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_override_gate_matches_when_alertname_and_service_align(store):
    # Pin override created_at to the same TOD as the alert so the ±2h check
    # always passes regardless of when the test runs.
    override_time = datetime(2026, 4, 26, 14, 30)
    alert_time = datetime(2026, 4, 28, 14, 30)
    await _make_decision(store, decision_id="dec-001", timestamp=override_time - timedelta(hours=1))
    await store.record_feedback("fb-1", "dec-001", "override", "Real")
    await store._db.execute(
        "UPDATE feedback SET created_at = ?, active_until = ? WHERE decision_id = ?",
        (override_time.isoformat(), (override_time + timedelta(days=14)).isoformat(), "dec-001"),
    )
    await store._db.commit()
    overrides = await store.get_active_overrides_for_alert(
        alert_name="HighP95Latency",
        affected_service="spring-boot",
        current_time=alert_time,
    )
    assert len(overrides) == 1
    assert overrides[0]["decision_id"] == "dec-001"


@pytest.mark.asyncio
async def test_override_gate_excludes_different_alertname(store):
    now = datetime.utcnow()
    await _make_decision(store, decision_id="dec-001", alert_name="HighP95Latency")
    await store.record_feedback("fb-1", "dec-001", "override", "Real")
    overrides = await store.get_active_overrides_for_alert(
        alert_name="HighMemoryUsage",  # different alert
        affected_service="spring-boot",
        current_time=now,
    )
    assert overrides == []


@pytest.mark.asyncio
async def test_override_gate_excludes_different_service(store):
    now = datetime.utcnow()
    await _make_decision(store, decision_id="dec-001", service="spring-boot")
    await store.record_feedback("fb-1", "dec-001", "override", "Real")
    overrides = await store.get_active_overrides_for_alert(
        alert_name="HighP95Latency",
        affected_service="frontend",  # different service
        current_time=now,
    )
    assert overrides == []


@pytest.mark.asyncio
async def test_override_gate_excludes_expired(store):
    now = datetime.utcnow()
    await _make_decision(store, decision_id="dec-001", timestamp=now - timedelta(days=30))
    await store.record_feedback("fb-1", "dec-001", "override", "Real", active_for_days=5)
    # Force active_until into the past — the row exists but is expired.
    past = (now - timedelta(days=2)).isoformat()
    await store._db.execute(
        "UPDATE feedback SET active_until = ? WHERE decision_id = ?",
        (past, "dec-001"),
    )
    await store._db.commit()
    overrides = await store.get_active_overrides_for_alert(
        alert_name="HighP95Latency",
        affected_service="spring-boot",
        current_time=now,
    )
    assert overrides == []


@pytest.mark.asyncio
async def test_override_gate_excludes_outside_time_of_day_window(store):
    # Override created at 14:30, alert fires at 03:00 — outside ±2h window.
    override_time = datetime(2026, 4, 28, 14, 30)
    alert_time = datetime(2026, 4, 28, 3, 0)
    await _make_decision(store, decision_id="dec-001", timestamp=override_time - timedelta(hours=1))
    # Manually compose the feedback row with the desired created_at by patching
    # in a record + timestamp control.
    await store.record_feedback("fb-1", "dec-001", "override", "Real")
    # The recorded created_at is "now-ish" not 14:30; we need to overwrite it
    # for this test. Direct UPDATE — easier than mocking time everywhere.
    await store._db.execute(
        "UPDATE feedback SET created_at = ?, active_until = ? WHERE decision_id = ?",
        (override_time.isoformat(), (override_time + timedelta(days=14)).isoformat(), "dec-001"),
    )
    await store._db.commit()
    overrides = await store.get_active_overrides_for_alert(
        alert_name="HighP95Latency",
        affected_service="spring-boot",
        current_time=alert_time,
    )
    assert overrides == []


@pytest.mark.asyncio
async def test_override_gate_includes_inside_time_of_day_window(store):
    # Override created at 14:30; alert fires at 16:00 (90 min later TOD) —
    # within ±2h window.
    override_time = datetime(2026, 4, 28, 14, 30)
    alert_time = datetime(2026, 5, 1, 16, 0)  # different day, within TOD
    await _make_decision(store, decision_id="dec-001", timestamp=override_time - timedelta(hours=1))
    await store.record_feedback("fb-1", "dec-001", "override", "Real")
    await store._db.execute(
        "UPDATE feedback SET created_at = ?, active_until = ? WHERE decision_id = ?",
        (override_time.isoformat(), (override_time + timedelta(days=14)).isoformat(), "dec-001"),
    )
    await store._db.commit()
    overrides = await store.get_active_overrides_for_alert(
        alert_name="HighP95Latency",
        affected_service="spring-boot",
        current_time=alert_time,
    )
    assert len(overrides) == 1


@pytest.mark.asyncio
async def test_override_gate_handles_midnight_wrap_around(store):
    # Override at 23:30, alert at 00:30 — TOD distance = 60 min, not 1380 min.
    override_time = datetime(2026, 4, 28, 23, 30)
    alert_time = datetime(2026, 4, 29, 0, 30)
    await _make_decision(store, decision_id="dec-001", timestamp=override_time - timedelta(hours=1))
    await store.record_feedback("fb-1", "dec-001", "override", "Real")
    await store._db.execute(
        "UPDATE feedback SET created_at = ?, active_until = ? WHERE decision_id = ?",
        (override_time.isoformat(), (override_time + timedelta(days=14)).isoformat(), "dec-001"),
    )
    await store._db.commit()
    overrides = await store.get_active_overrides_for_alert(
        alert_name="HighP95Latency",
        affected_service="spring-boot",
        current_time=alert_time,
    )
    assert len(overrides) == 1


# -----------------------------------------------------------------------------
# Counts for precision/recall metrics
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_count_feedback_in_window(store):
    await _make_decision(store, decision_id="dec-1")
    await _make_decision(store, decision_id="dec-2")
    await store.record_feedback("fb-1", "dec-1", "override", None)
    await store.record_feedback("fb-2", "dec-2", "confirm", None)
    assert await store.count_feedback_in_window("override", window_days=7) == 1
    assert await store.count_feedback_in_window("confirm", window_days=7) == 1


@pytest.mark.asyncio
async def test_count_decisions_by_verdict(store):
    await _make_decision(store, decision_id="dec-e1", verdict="escalate")
    await _make_decision(store, decision_id="dec-e2", verdict="escalate")
    await _make_decision(store, decision_id="dec-d1", verdict="dismiss")
    assert await store.count_decisions_by_verdict("escalate", window_days=7) == 2
    assert await store.count_decisions_by_verdict("dismiss", window_days=7) == 1
