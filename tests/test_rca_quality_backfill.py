"""One-shot rca_quality backfill (2026-06-04).

The live rca_quality recompute is forward-only — rows written before the
Issue #3 persist-time recompute landed (or by paths that stamped a stale
snapshot) carry a stale / never-computed rca_quality. Those inflate the
"actionable %" KPI and poison the hedge/feedback loop.

`app.startup_backfill.backfill_rca_quality` sweeps the whole table, recomputing
quality with the SAME canonical classifier (_classify_rca_quality) the live
pipeline uses, updating ONLY rows whose value differs and ONLY the rca_quality
column. These tests prove:

  - stale rows get corrected to the canonical value
  - already-correct rows are left untouched (idempotent / no-op on re-run)
  - the excluded_from_lookup quarantine flag is never flipped
  - no other column is mutated
"""
from __future__ import annotations

import json
import os
import tempfile
import uuid

import pytest
import pytest_asyncio

from app.models import RCARecord
from app.rca_store import RCAStore, _classify_rca_quality, _utc_now
from app.startup_backfill import backfill_rca_quality


@pytest_asyncio.fixture
async def store():
    db_path = os.path.join(tempfile.gettempdir(), f"test_qbackfill_{uuid.uuid4().hex}.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


async def _insert_raw(store, *, row_id, rca_report, reasoning, suggested_actions,
                      evidence, rca_quality, excluded=0):
    """Insert a row with a DELIBERATE rca_quality (possibly stale) via raw SQL
    so we bypass save_decision's auto-classify and can plant stale values."""
    rec = RCARecord(
        alert_name="HighP95Latency",
        affected_service="spring-boot",
        alert_fingerprint=f"fp-{row_id}",
        triage_decision="investigate",
        llm_verdict="escalate",
        rca_report=rca_report,
        llm_reasoning=reasoning,
        action_taken="emailed",
        severity="warning",
    )
    rec.id = row_id
    rec.timestamp = _utc_now()
    # Build the INSERT directly so we control rca_quality + the artifact cols.
    await store._db.execute(
        """INSERT INTO rca_history
           (id, timestamp, alert_source, alert_name, alert_fingerprint,
            affected_service, severity, triage_decision, llm_verdict,
            rca_report, llm_reasoning, action_taken, rca_quality,
            suggested_actions, evidence, excluded_from_lookup)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            rec.id, rec.timestamp.isoformat(), "grafana", rec.alert_name,
            rec.alert_fingerprint, rec.affected_service, rec.severity,
            rec.triage_decision, rec.llm_verdict, rec.rca_report,
            rec.llm_reasoning, rec.action_taken, rca_quality,
            suggested_actions, evidence, excluded,
        ),
    )
    await store._db.commit()
    return row_id


async def _quality_of(store, row_id):
    cur = await store._db.execute(
        "SELECT rca_quality FROM rca_history WHERE id = ?", (row_id,)
    )
    row = await cur.fetchone()
    return row["rca_quality"]


async def _excluded_of(store, row_id):
    cur = await store._db.execute(
        "SELECT excluded_from_lookup FROM rca_history WHERE id = ?", (row_id,)
    )
    row = await cur.fetchone()
    return row["excluded_from_lookup"]


@pytest.mark.asyncio
async def test_stale_actionable_row_corrected_to_data_starved(store):
    """A hedging RCA stored as 'actionable' is recomputed to 'data_starved'."""
    # Hedge prose + concrete artifacts so Rule 1 (needs_review) doesn't fire;
    # the hedge phrase drives data_starved.
    rid = await _insert_raw(
        store, row_id="stale1",
        rca_report="We cannot determine the root cause from the available data.",
        reasoning="insufficient data to conclude",
        suggested_actions=json.dumps(["check logs"]),
        evidence=json.dumps(["cpu=0.9"]),
        rca_quality="actionable",  # STALE
    )
    canonical = _classify_rca_quality(
        "We cannot determine the root cause from the available data.",
        "insufficient data to conclude",
        json.dumps(["check logs"]),
        json.dumps(["cpu=0.9"]),
    )
    assert canonical == "data_starved"  # sanity on the canonical rule

    result = await backfill_rca_quality(store)
    assert result["scanned"] == 1
    assert result["changed"] == 1
    assert result["unchanged"] == 0
    assert await _quality_of(store, rid) == "data_starved"


@pytest.mark.asyncio
async def test_never_computed_null_row_gets_classified(store):
    """A row with rca_quality NULL (never computed) gets a real tag."""
    rid = await _insert_raw(
        store, row_id="null1",
        rca_report="JVM heap exhausted; GC thrashing on node-3.",
        reasoning="clear cause",
        suggested_actions=json.dumps(["restart pod", "raise -Xmx"]),
        evidence=json.dumps(["heap=98%"]),
        rca_quality=None,  # never computed
    )
    result = await backfill_rca_quality(store)
    assert result["changed"] == 1
    assert await _quality_of(store, rid) == "actionable"


@pytest.mark.asyncio
async def test_already_correct_rows_untouched_and_idempotent(store):
    """Rows whose stored quality already matches the canonical value are NOT
    counted as changed, and a second run is a pure no-op."""
    await _insert_raw(
        store, row_id="ok1",
        rca_report="Connection pool exhausted at OrderService.findByDate.",
        reasoning="root cause identified",
        suggested_actions=json.dumps(["increase pool size"]),
        evidence=json.dumps(["active=200/200"]),
        rca_quality="actionable",  # already correct
    )
    first = await backfill_rca_quality(store)
    assert first["scanned"] == 1
    assert first["changed"] == 0
    assert first["unchanged"] == 1

    # Re-run: still a no-op.
    second = await backfill_rca_quality(store)
    assert second["changed"] == 0


@pytest.mark.asyncio
async def test_backfill_does_not_flip_excluded_quarantine_flag(store):
    """A quarantined (excluded_from_lookup=1) row keeps its flag even when its
    quality is corrected."""
    rid = await _insert_raw(
        store, row_id="quar1",
        rca_report="cannot determine root cause",
        reasoning="insufficient data",
        suggested_actions=json.dumps(["look"]),
        evidence=json.dumps(["x=1"]),
        rca_quality="actionable",  # stale -> will become data_starved
        excluded=1,
    )
    assert await _excluded_of(store, rid) == 1
    await backfill_rca_quality(store)
    assert await _quality_of(store, rid) == "data_starved"
    # Quarantine flag preserved.
    assert await _excluded_of(store, rid) == 1


@pytest.mark.asyncio
async def test_backfill_only_mutates_quality_column(store):
    """No column other than rca_quality is changed by the backfill."""
    rid = await _insert_raw(
        store, row_id="mut1",
        rca_report="cannot determine root cause from logs",
        reasoning="insufficient context",
        suggested_actions=json.dumps(["a"]),
        evidence=json.dumps(["b"]),
        rca_quality="actionable",
    )
    cur = await store._db.execute("SELECT * FROM rca_history WHERE id = ?", (rid,))
    before = dict(await cur.fetchone())

    await backfill_rca_quality(store)

    cur = await store._db.execute("SELECT * FROM rca_history WHERE id = ?", (rid,))
    after = dict(await cur.fetchone())

    changed_cols = {k for k in before if before[k] != after[k]}
    assert changed_cols == {"rca_quality"}
    assert after["rca_quality"] == "data_starved"


@pytest.mark.asyncio
async def test_mixed_table_counts(store):
    """Mixed table: some stale, some correct -> correct counters, only stale
    rows mutated."""
    await _insert_raw(
        store, row_id="m_ok",
        rca_report="DB deadlock on payments table; clear cause.",
        reasoning="root cause found",
        suggested_actions=json.dumps(["retry txn"]),
        evidence=json.dumps(["lock=1"]),
        rca_quality="actionable",  # correct
    )
    await _insert_raw(
        store, row_id="m_stale",
        rca_report="insufficient data to identify the cause",
        reasoning="",
        suggested_actions=json.dumps(["x"]),
        evidence=json.dumps(["y"]),
        rca_quality="actionable",  # stale -> data_starved
    )
    result = await backfill_rca_quality(store)
    assert result["scanned"] == 2
    assert result["changed"] == 1
    assert result["unchanged"] == 1
    assert await _quality_of(store, "m_ok") == "actionable"
    assert await _quality_of(store, "m_stale") == "data_starved"
