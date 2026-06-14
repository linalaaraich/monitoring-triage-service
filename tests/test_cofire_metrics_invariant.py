"""Co-fire metrics coherence (Loop 2 audit, 2026-06-13).

Consolidation must keep the aggregates honest: a consolidated escalation
sent NO email but it IS still an escalation. So email counters must exclude
it (they key on action_taken='emailed') while escalation/verdict counts
must include it (they key on llm_verdict='escalate'). Net story the
dashboard tells: same escalations as before co-fire, fewer emails. This
test pins that so a future refactor can't silently double-count emails or
drop escalations.
"""
from __future__ import annotations

import os
import tempfile

import pytest
import pytest_asyncio

from app.models import RCARecord
from app.rca_store import RCAStore


@pytest_asyncio.fixture
async def store():
    db = os.path.join(tempfile.gettempdir(), "test_cofire_metrics.db")
    if os.path.exists(db):
        os.unlink(db)
    s = RCAStore(db)
    await s.init_db()
    # workload-down incident for service 'ad': Down emailed (primary),
    # Deficit consolidated into it (no email). Both are escalate verdicts.
    await s.save_decision(RCARecord(
        id="down-1", alert_name="KubeWorkloadDown", affected_service="ad",
        alert_fingerprint="fp-down", severity="critical",
        triage_decision="investigate", llm_verdict="escalate",
        action_taken="emailed",
    ))
    await s.save_decision(RCARecord(
        id="def-1", alert_name="KubeWorkloadReplicasDeficit", affected_service="ad",
        alert_fingerprint="fp-def", severity="critical",
        triage_decision="investigate", llm_verdict="escalate",
        action_taken="consolidated", consolidated_into="down-1",
    ))
    yield s
    await s.close()
    if os.path.exists(db):
        os.unlink(db)


@pytest.mark.asyncio
async def test_consolidated_excluded_from_email_counts(store):
    summary = {r["alert_name"]: r for r in await store.get_alert_summary(days=7)}
    # the consolidated alert sent no email
    assert summary["KubeWorkloadReplicasDeficit"]["emails"] == 0
    assert summary["KubeWorkloadReplicasDeficit"]["fires"] == 1
    # the primary did email
    assert summary["KubeWorkloadDown"]["emails"] == 1


@pytest.mark.asyncio
async def test_consolidated_included_in_escalation_counts(store):
    agg = await store.get_stats_aggregates(days=7)
    by_service = {r["service"]: r["escalates"] for r in agg["escalated_services"]}
    # both rows are escalate verdicts → the service shows 2 escalations,
    # exactly as it did before co-fire (consolidation changes emails, not escalations)
    assert by_service.get("ad") == 2
