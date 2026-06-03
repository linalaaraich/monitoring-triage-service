"""Phase 6 (2026-06-03) — proactive corrective-feedback block.

Covers the prompt-builder helper `build_corrective_feedback_block` and the
RCAStore lookup `get_high_value_feedback_for_family` that feeds it.

The hybrid feedback-loop design always injects HIGH-VALUE operator
feedback (verdict_was_right='no' OR non-empty actual_cause) into the
initial LLM prompt — these tests lock in:
  - the block formatting (header, bullets, trust instruction)
  - empty-list returns empty string (no header on absent input)
  - the high-value filter at the store level (rate-only / positive-only
    rows do not surface; rows with actual_cause or verdict_was_right=no
    do surface)
  - service-scoped vs alert-name-only queries both work
"""
from __future__ import annotations

import os
import tempfile
import uuid

import pytest
import pytest_asyncio

from app.llm_client import build_corrective_feedback_block
from app.rca_store import RCAStore


# ---------------------------------------------------------------------------
# Block formatter — pure-function tests, no DB.
# ---------------------------------------------------------------------------


def test_block_empty_list_returns_empty_string():
    """No rows → empty string (no header, no trust instruction)."""
    assert build_corrective_feedback_block([]) == ""
    assert build_corrective_feedback_block(None) == ""


def test_block_renders_verdict_was_wrong_row():
    rows = [
        {
            "alert_name": "MediumCpuUsage",
            "affected_service": "k3s-node",
            "created_at": "2026-05-30T14:22:00",
            "verdict_was_right": "no",
            "action_was_right": None,
            "actual_cause": "Cron job at :05 of every hour spikes CPU for 3 min. Ignore.",
            "notes": None,
        }
    ]
    block = build_corrective_feedback_block(rows)
    assert "OPERATOR CORRECTIVE FEEDBACK ON SIMILAR PAST ALERTS" in block
    assert "2026-05-30" in block
    assert "MediumCpuUsage" in block
    assert "k3s-node" in block
    assert "verdict was WRONG" in block
    assert "Cron job at :05" in block
    assert "Trust this feedback HEAVILY" in block


def test_block_renders_action_was_wrong_row():
    rows = [
        {
            "alert_name": "HighMemoryUsage",
            "affected_service": "spring-boot",
            "created_at": "2026-05-25T09:12:00",
            "verdict_was_right": "yes",
            "action_was_right": "no",
            "actual_cause": None,
            "notes": "Restart fixed it but only as workaround; real cause was JVM heap leak.",
        }
    ]
    block = build_corrective_feedback_block(rows)
    assert "action was WRONG" in block
    assert "JVM heap leak" in block


def test_block_truncates_long_actual_cause():
    """Bound prompt budget — long actual_cause cut at ~300 chars + ellipsis."""
    big = "x" * 500
    rows = [
        {
            "alert_name": "A",
            "affected_service": "s",
            "created_at": "2026-05-30T00:00:00",
            "verdict_was_right": "no",
            "actual_cause": big,
        }
    ]
    block = build_corrective_feedback_block(rows)
    assert "..." in block
    # The block carries a header + closing instruction (~250 chars combined)
    # plus the trimmed cause; total should be well under 1000 chars.
    assert len(block) < 1000


def test_block_renders_multiple_rows():
    rows = [
        {
            "alert_name": "MediumCpuUsage",
            "affected_service": "k3s-node",
            "created_at": "2026-05-30T14:22:00",
            "verdict_was_right": "no",
            "actual_cause": "cron blip",
        },
        {
            "alert_name": "HighMemoryUsage",
            "affected_service": "spring-boot",
            "created_at": "2026-05-25T09:12:00",
            "action_was_right": "no",
            "notes": "heap leak masked by restart",
        },
    ]
    block = build_corrective_feedback_block(rows)
    assert block.count("  - ") == 2
    assert "MediumCpuUsage" in block
    assert "HighMemoryUsage" in block


# ---------------------------------------------------------------------------
# Store lookup — exercises the JOIN + high-value filter.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def store():
    db_path = os.path.join(tempfile.gettempdir(), "test_corrective_feedback.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


async def _insert_decision(store, *, decision_id, alert_name, service):
    """Insert minimal rca_history row by raw SQL (bypassing the model so
    we can pin decision_id deterministically)."""
    from app.rca_store import _utc_now
    await store._db.execute(
        """INSERT INTO rca_history
           (id, timestamp, alert_source, alert_name, alert_fingerprint,
            affected_service, severity, triage_decision, llm_verdict,
            action_taken)
           VALUES (?, ?, 'grafana', ?, 'fp', ?, 'warning', 'investigate', 'dismiss', 'suppressed')""",
        (decision_id, _utc_now().isoformat(), alert_name, service),
    )
    await store._db.commit()


@pytest.mark.asyncio
async def test_high_value_filter_includes_verdict_wrong(store):
    """A row with verdict_was_right='no' MUST surface even with empty actual_cause."""
    await _insert_decision(store, decision_id="d1", alert_name="MediumCpuUsage", service="k3s-node")
    await store.record_v2_feedback(
        feedback_id=str(uuid.uuid4()),
        decision_id="d1",
        rating="no",
        verdict_was_right="no",
        action_was_right=None,
        actual_cause=None,
        tags=[],
        notes=None,
        rater="alice",
    )
    rows = await store.get_high_value_feedback_for_family(
        alert_name="MediumCpuUsage", affected_service="k3s-node",
    )
    assert len(rows) == 1
    assert rows[0]["verdict_was_right"] == "no"


@pytest.mark.asyncio
async def test_high_value_filter_includes_actual_cause(store):
    """A row with non-empty actual_cause MUST surface even if verdict_was_right is not 'no'."""
    await _insert_decision(store, decision_id="d2", alert_name="HighMemoryUsage", service="spring-boot")
    await store.record_v2_feedback(
        feedback_id=str(uuid.uuid4()),
        decision_id="d2",
        rating="partial",
        verdict_was_right="maybe",
        action_was_right="partial",
        actual_cause="JVM heap leak — restart only masked it.",
        tags=["root-cause-was-different"],
        notes=None,
        rater="bob",
    )
    rows = await store.get_high_value_feedback_for_family(
        alert_name="HighMemoryUsage", affected_service="spring-boot",
    )
    assert len(rows) == 1
    assert "JVM heap leak" in rows[0]["actual_cause"]


@pytest.mark.asyncio
async def test_high_value_filter_excludes_positive_thumbs(store):
    """A bare rating=yes with verdict_was_right=yes and no actual_cause MUST NOT surface."""
    await _insert_decision(store, decision_id="d3", alert_name="HighDiskUsage", service="node-1")
    await store.record_v2_feedback(
        feedback_id=str(uuid.uuid4()),
        decision_id="d3",
        rating="yes",
        verdict_was_right="yes",
        action_was_right="yes",
        actual_cause=None,
        tags=[],
        notes=None,
        rater="carol",
    )
    # Plus a too-short actual_cause (≤5 chars) — also filtered out
    await _insert_decision(store, decision_id="d4", alert_name="HighDiskUsage", service="node-1")
    await store.record_v2_feedback(
        feedback_id=str(uuid.uuid4()),
        decision_id="d4",
        rating="yes",
        verdict_was_right="yes",
        action_was_right="yes",
        actual_cause="ok",   # too short — filter requires > 5 chars
        tags=[],
        notes=None,
        rater="dave",
    )
    rows = await store.get_high_value_feedback_for_family(
        alert_name="HighDiskUsage", affected_service="node-1",
    )
    assert rows == []


@pytest.mark.asyncio
async def test_high_value_filter_scopes_to_service(store):
    """Service mismatch must drop the row from results."""
    await _insert_decision(store, decision_id="d5", alert_name="MediumCpuUsage", service="other-service")
    await store.record_v2_feedback(
        feedback_id=str(uuid.uuid4()),
        decision_id="d5",
        rating="no",
        verdict_was_right="no",
        action_was_right=None,
        actual_cause=None,
        tags=[],
        notes=None,
        rater="eve",
    )
    rows = await store.get_high_value_feedback_for_family(
        alert_name="MediumCpuUsage", affected_service="k3s-node",
    )
    assert rows == []
    # Without service filter, the row surfaces.
    rows = await store.get_high_value_feedback_for_family(
        alert_name="MediumCpuUsage", affected_service=None,
    )
    assert len(rows) == 1
