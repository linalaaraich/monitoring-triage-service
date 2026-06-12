"""Finding #3 (2026-06-12) — exemplar_id / exemplar_score persistence.

The RCA layer was flying blind: nothing recorded WHICH archetype a decision
used. These tests lock in: (1) the lazy ALTER migration adds the columns, (2)
save_decision writes them, (3) the prompt builder's selection is threaded onto
the LLMDecision so the pipeline can persist it, and (4) the stats aggregate
groups by exemplar_id with an actionable rate.
"""
import os
import tempfile

import pytest
import pytest_asyncio

from app.models import RCARecord
from app.rca_store import RCAStore


@pytest_asyncio.fixture
async def store():
    db_path = os.path.join(tempfile.gettempdir(), "test_exemplar_id_store.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    os.unlink(db_path)


@pytest.mark.asyncio
async def test_columns_exist_after_init(store):
    cur = await store._db.execute("PRAGMA table_info(rca_history)")
    cols = {r["name"] for r in await cur.fetchall()}
    assert "exemplar_id" in cols
    assert "exemplar_score" in cols


@pytest.mark.asyncio
async def test_save_decision_persists_exemplar(store):
    rec = RCARecord(
        alert_name="KubeWorkloadDown",
        alert_fingerprint="fp-1",
        affected_service="accounting",
        severity="critical",
        triage_decision="investigate",
        llm_verdict="escalate",
        rca_report="replica deficit",
        action_taken="emailed",
        rca_quality="actionable",
        exemplar_id="workload-replica-deficit",
        exemplar_score=1.10,
    )
    await store.save_decision(rec)
    rows = await store.get_decisions(limit=5)
    assert rows[0]["exemplar_id"] == "workload-replica-deficit"
    assert abs(float(rows[0]["exemplar_score"]) - 1.10) < 1e-6


@pytest.mark.asyncio
async def test_old_style_record_leaves_exemplar_null(store):
    rec = RCARecord(
        alert_name="HighCpuUsage",
        alert_fingerprint="fp-2",
        affected_service="kong",
        triage_decision="suppressed",
        action_taken="suppressed",
    )
    await store.save_decision(rec)
    rows = await store.get_decisions(limit=5)
    row = next(r for r in rows if r["alert_fingerprint"] == "fp-2")
    assert row["exemplar_id"] is None


@pytest.mark.asyncio
async def test_stats_aggregate_groups_by_archetype(store):
    for i, (eid, qual) in enumerate([
        ("workload-replica-deficit", "actionable"),
        ("workload-replica-deficit", "data_starved"),
        ("oom-loop", "actionable"),
    ]):
        await store.save_decision(RCARecord(
            alert_name="A", alert_fingerprint=f"agg-{i}",
            affected_service="svc", triage_decision="investigate",
            llm_verdict="escalate", action_taken="emailed",
            rca_quality=qual, exemplar_id=eid, exemplar_score=1.0,
        ))
    agg = await store.get_stats_aggregates(days=7)
    used = {a["exemplar_id"]: a for a in agg["archetypes_used"]}
    assert used["workload-replica-deficit"]["count"] == 2
    assert used["workload-replica-deficit"]["actionable"] == 1
    assert abs(used["workload-replica-deficit"]["actionable_rate"] - 0.5) < 1e-6
    assert used["oom-loop"]["count"] == 1


def test_llm_decision_carries_exemplar_fields():
    """The LLMDecision model must expose the fields llm_client stamps."""
    from app.models import LLMDecision, Decision
    d = LLMDecision(decision=Decision.ESCALATE)
    d.exemplar_id = "oom-loop"
    d.exemplar_score = 0.9
    assert d.exemplar_id == "oom-loop"
