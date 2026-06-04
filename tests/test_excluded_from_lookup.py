"""Stage E (2026-06-04) — soft-quarantine via excluded_from_lookup column.

The Stage A.5 audit found that 10/10 of the most recent RCAs were
"insufficient data" hedges, plus older rows contained the literal
service=X parroting bug and inconclusive+data_starved combos. These
rows poison the LLM feedback loop — the model would see them via
DA-3, similar-decisions, and the high-value feedback path and learn
to repeat the same hedges.

Soft-quarantine (not delete) so the audit trail + dashboard still
show full history. Only LLM-context lookups skip excluded rows.

This module locks in:
  - the column exists post-init_db (lazy ALTER migration)
  - every LLM-context lookup skips excluded_from_lookup=1
  - operator-facing dashboard reads (get_decisions, count_decisions,
    get_service_summary, get_alert_summary) deliberately do NOT skip
  - the canonical marking SQL works against a fresh in-memory DB
"""
from __future__ import annotations

import os
import tempfile
import uuid
from datetime import timedelta

import pytest
import pytest_asyncio

from app.models import RCARecord
from app.rca_store import RCAStore, _utc_now


@pytest_asyncio.fixture
async def store():
    db_path = os.path.join(tempfile.gettempdir(), f"test_excluded_{uuid.uuid4().hex}.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


async def _save(
    store: RCAStore,
    *,
    alert_name: str = "HighP95Latency",
    service: str = "spring-boot",
    fingerprint: str = "fp-quarantine",
    rca: str = "JVM heap exhausted - clear actionable cause.",
    reasoning: str = "prior reasoning",
    verdict: str = "escalate",
    quality: str = "actionable",
    triage_decision: str = "investigate",
    minutes_ago: float = 5.0,
    excluded: int = 0,
) -> str:
    """Insert a deterministic row, optionally pre-marked as excluded.

    Returns the row id so the test can mutate excluded_from_lookup
    after the fact via raw SQL when needed.
    """
    rec = RCARecord(
        alert_name=alert_name,
        affected_service=service,
        alert_fingerprint=fingerprint,
        triage_decision=triage_decision,
        llm_verdict=verdict,
        rca_report=rca,
        llm_reasoning=reasoning,
        action_taken="emailed",
        rca_quality=quality,
        severity="warning",
    )
    rec.timestamp = _utc_now() - timedelta(minutes=minutes_ago)
    await store.save_decision(rec)
    if excluded:
        await store._db.execute(
            "UPDATE rca_history SET excluded_from_lookup = 1 WHERE id = ?",
            (rec.id,),
        )
        await store._db.commit()
    return rec.id


# ---------------------------------------------------------------------------
# Column existence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_excluded_from_lookup_column_exists_post_init(store):
    """Lazy ALTER must add the column on init_db so existing prod DBs
    don't blow up on the first read after deploy."""
    cursor = await store._db.execute("PRAGMA table_info(rca_history)")
    cols = {row["name"] for row in await cursor.fetchall()}
    assert "excluded_from_lookup" in cols


@pytest.mark.asyncio
async def test_excluded_from_lookup_defaults_to_zero(store):
    """New rows must default to 0 (included) — quarantine is opt-in."""
    await _save(store)
    cursor = await store._db.execute(
        "SELECT excluded_from_lookup FROM rca_history"
    )
    row = await cursor.fetchone()
    assert row["excluded_from_lookup"] == 0


# ---------------------------------------------------------------------------
# LLM-context lookups SKIP excluded rows
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_da3_lookup_skips_excluded_row(store):
    """get_recent_decision_for_fingerprint must hide quarantined priors."""
    fp = "fp-da3-skip"
    await _save(store, fingerprint=fp, excluded=1)
    prior = await store.get_recent_decision_for_fingerprint(fp, window_minutes=30)
    assert prior is None, "excluded row must not surface as DA-3 anchor"


@pytest.mark.asyncio
async def test_da3_lookup_returns_kept_row(store):
    """Sanity: with no exclusion the prior still surfaces."""
    fp = "fp-da3-keep"
    await _save(store, fingerprint=fp, excluded=0)
    prior = await store.get_recent_decision_for_fingerprint(fp, window_minutes=30)
    assert prior is not None
    assert prior["llm_verdict"] == "escalate"


@pytest.mark.asyncio
async def test_family_scope_lookup_skips_excluded_row(store):
    """SF-5 family-scope lookup must hide quarantined priors too."""
    fp = "fp-family-skip"
    await _save(
        store,
        alert_name="MediumCpuUsage",
        service="k3s-node",
        fingerprint=fp,
        excluded=1,
    )
    prior = await store.get_recent_decision_for_family_scope(
        alertnames=["MediumCpuUsage", "HighCpuUsage"],
        affected_service="k3s-node",
        alert_instance=None,
        window_seconds=600,
    )
    assert prior is None


@pytest.mark.asyncio
async def test_data_starved_rcas_skips_excluded_row(store):
    """The hedge-feedback path must not quote a quarantined hedge back."""
    await _save(
        store,
        alert_name="LokiIngestionRateLow",
        service="loki",
        rca="insufficient data to determine cause",
        quality="data_starved",
        excluded=1,
    )
    rows = await store.get_recent_data_starved_rcas(
        alert_name="LokiIngestionRateLow", affected_service="loki", limit=5,
    )
    assert rows == [], "excluded data_starved row must not feed back into prompt"


@pytest.mark.asyncio
async def test_high_value_feedback_skips_excluded_decision(store):
    """The Phase 6 feedback-loop join must skip feedback whose underlying
    decision row is quarantined — otherwise we leak operator feedback
    pointing at known-garbage decisions."""
    decision_id = await _save(
        store,
        alert_name="HighMemoryUsage",
        service="spring-boot",
        excluded=1,
    )
    await store.record_v2_feedback(
        feedback_id=str(uuid.uuid4()),
        decision_id=decision_id,
        rating="no",
        verdict_was_right="no",
        action_was_right=None,
        actual_cause=None,
        tags=[],
        notes=None,
        rater="alice",
    )
    rows = await store.get_high_value_feedback_for_family(
        alert_name="HighMemoryUsage", affected_service="spring-boot",
    )
    assert rows == []


# ---------------------------------------------------------------------------
# Operator-facing dashboard reads STILL SHOW excluded rows
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_get_decisions_still_returns_excluded(store):
    """Operators must see the full audit trail — quarantine is an
    LLM-context concept only."""
    await _save(store, alert_name="A", excluded=0)
    await _save(store, alert_name="B", excluded=1)
    decisions = await store.get_decisions(limit=100)
    names = sorted(d["alert_name"] for d in decisions)
    assert names == ["A", "B"], "dashboard must surface excluded rows"


@pytest.mark.asyncio
async def test_dashboard_count_decisions_still_counts_excluded(store):
    """The dashboard footer count must match the visible rows — including
    quarantined ones."""
    await _save(store, alert_name="A", excluded=0)
    await _save(store, alert_name="B", excluded=1)
    n = await store.count_decisions()
    assert n == 2


@pytest.mark.asyncio
async def test_service_summary_still_counts_excluded(store):
    """Per-service KPI rollup is operator-facing — keep showing excluded
    rows so the totals match the dashboard table."""
    await _save(store, service="svc-x", excluded=0)
    await _save(store, service="svc-x", excluded=1)
    summary = await store.get_service_summary(days=7)
    by_svc = {b["service"]: b for b in summary}
    assert by_svc["svc-x"]["total"] == 2


@pytest.mark.asyncio
async def test_alert_summary_still_counts_excluded(store):
    """Per-alertname rollup is operator-facing — same principle."""
    await _save(store, alert_name="HighP95Latency", excluded=0)
    await _save(store, alert_name="HighP95Latency", excluded=1)
    summary = await store.get_alert_summary(days=7)
    by_name = {a["alert_name"]: a for a in summary}
    assert by_name["HighP95Latency"]["fires"] == 2


# ---------------------------------------------------------------------------
# Canonical marking SQL works on a fresh DB
# ---------------------------------------------------------------------------


_QUARANTINE_SQL = """
UPDATE rca_history SET excluded_from_lookup = 1 WHERE (
  rca_report LIKE '%insufficient data%'
  OR llm_reasoning LIKE '%insufficient data%'
  OR rca_report LIKE '%could not determine%'
  OR llm_reasoning LIKE '%could not determine%'
  OR rca_report LIKE '%cannot determine%'
  OR llm_reasoning LIKE '%cannot determine%'
  OR rca_report LIKE '%service=X%'
  OR evidence LIKE '%service=X%'
  OR rca_report LIKE '%could not reach the LLM%'
  OR (llm_verdict = 'inconclusive' AND rca_quality IN ('data_starved','needs_review'))
  OR (alert_fingerprint LIKE 'backfill_%' AND timestamp < datetime('now','-3 days'))
)
"""


@pytest.mark.asyncio
async def test_marking_sql_quarantines_each_pattern(store):
    """One row per pattern — every one must end up excluded."""
    # insufficient_data
    await _save(store, fingerprint="fp-a",
                rca="insufficient data to determine the root cause")
    # cannot_determine
    await _save(store, fingerprint="fp-b",
                rca="cannot determine the root cause from available metrics")
    # could_not_determine
    await _save(store, fingerprint="fp-c",
                rca="we could not determine the cause this time")
    # literal_X parroting bug
    await _save(store, fingerprint="fp-d",
                rca="The alert fired on service=X with no data")
    # could_not_reach_llm
    await _save(store, fingerprint="fp-e",
                rca="Triage skipped: could not reach the LLM")
    # inconclusive + data_starved
    await _save(store, fingerprint="fp-f",
                verdict="inconclusive", quality="data_starved",
                rca="some non-matching prose")
    # backfill_* older than 3 days
    await _save(store, fingerprint="backfill_old_one",
                minutes_ago=60 * 24 * 5,  # 5 days ago
                rca="some non-matching prose")
    # control: clean actionable row that must NOT be quarantined
    await _save(store, fingerprint="fp-clean",
                rca="JVM heap exhausted - full GC every 4s.")

    await store._db.execute(_QUARANTINE_SQL)
    await store._db.commit()

    cursor = await store._db.execute(
        "SELECT alert_fingerprint, excluded_from_lookup FROM rca_history"
    )
    by_fp = {row["alert_fingerprint"]: row["excluded_from_lookup"]
             for row in await cursor.fetchall()}

    expected_excluded = {
        "fp-a", "fp-b", "fp-c", "fp-d", "fp-e", "fp-f", "backfill_old_one",
    }
    for fp in expected_excluded:
        assert by_fp[fp] == 1, f"row {fp} should be quarantined"
    assert by_fp["fp-clean"] == 0, "clean row must stay included"


# ---------------------------------------------------------------------------
# Stage E follow-up (2026-06-04) — save_decision honours excluded_from_lookup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_save_decision_persists_excluded_from_lookup_flag(store):
    """RCARecord(excluded_from_lookup=1) must be written to the row.
    Pipeline.py sets this when the final RCA is data_starved or carries
    unresolved banned-phrase / parrot-placeholder hits — the row must
    actually arrive in the DB with the flag set, not silently default to 0.
    """
    rec = RCARecord(
        alert_name="MediumCpuUsage",
        affected_service="k3s-node",
        alert_fingerprint="fp-write-quarantine",
        triage_decision="investigate",
        llm_verdict="escalate",
        rca_report='{"human_cause": "Insufficient data ...", "rca": "...", "schema": "v2"}',
        llm_reasoning="hedged",
        action_taken="emailed",
        rca_quality="data_starved",
        severity="warning",
        excluded_from_lookup=1,
    )
    await store.save_decision(rec)
    cursor = await store._db.execute(
        "SELECT excluded_from_lookup FROM rca_history WHERE id = ?",
        (rec.id,),
    )
    row = await cursor.fetchone()
    assert row["excluded_from_lookup"] == 1


@pytest.mark.asyncio
async def test_save_decision_defaults_excluded_to_zero_when_unset(store):
    """RCARecord without excluded_from_lookup must default to 0 — backward
    compat with every existing call-site that doesn't know about the flag."""
    rec = RCARecord(
        alert_name="HighMemoryUsage",
        affected_service="spring-boot",
        alert_fingerprint="fp-write-clean",
        triage_decision="investigate",
        llm_verdict="escalate",
        rca_report="JVM heap exhausted - full GC every 4s.",
        action_taken="emailed",
        severity="warning",
    )
    await store.save_decision(rec)
    cursor = await store._db.execute(
        "SELECT excluded_from_lookup FROM rca_history WHERE id = ?",
        (rec.id,),
    )
    row = await cursor.fetchone()
    assert row["excluded_from_lookup"] == 0


@pytest.mark.asyncio
async def test_da3_lookup_skips_write_time_quarantined_row(store):
    """End-to-end: a row written with excluded_from_lookup=1 must not
    surface in the DA-3 prior-decision lookup. Closes the loop on the
    write-time-quarantine + read-time-skip contract."""
    rec = RCARecord(
        alert_name="MediumCpuUsage",
        affected_service="k3s-node",
        alert_fingerprint="fp-da3-write-quarantine",
        triage_decision="investigate",
        llm_verdict="escalate",
        rca_report='{"human_cause": "Insufficient data", "rca": "..."}',
        action_taken="emailed",
        rca_quality="data_starved",
        severity="warning",
        excluded_from_lookup=1,
    )
    await store.save_decision(rec)
    prior = await store.get_recent_decision_for_fingerprint(
        "fp-da3-write-quarantine", window_minutes=30,
    )
    assert prior is None


@pytest.mark.asyncio
async def test_quarantine_is_reversible(store):
    """Setting excluded_from_lookup back to 0 must restore visibility in
    LLM-context lookups — quarantine is a soft flag, not a delete."""
    fp = "fp-reverse"
    rec_id = await _save(store, fingerprint=fp, excluded=1)
    assert await store.get_recent_decision_for_fingerprint(fp, window_minutes=30) is None

    await store._db.execute(
        "UPDATE rca_history SET excluded_from_lookup = 0 WHERE id = ?",
        (rec_id,),
    )
    await store._db.commit()

    prior = await store.get_recent_decision_for_fingerprint(fp, window_minutes=30)
    assert prior is not None
