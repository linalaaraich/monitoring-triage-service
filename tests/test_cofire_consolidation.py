"""Co-fire consolidation (2026-06-12, Lina).

One root cause fires several alert TYPES for the same workload
(KubeWorkloadDown + KubeWorkloadReplicasDeficit 37s apart in the 06-11
battery) → used to page separately. These tests pin the consolidation
behavior end-to-end:

  - registry: first family escalation claims primary, the sibling
    consolidates, claims expire with the window, a failed email releases
    the claim.
  - pipeline: same-service sibling consolidates; different service /
    non-family / flag-off always page; DB fallback consolidates after a
    process restart wiped the registry.
  - email: the primary's body NAMES every co-fired contributor.
  - feed: a consolidated sibling renders INSIDE the primary's row (one
    incident row, not N) and keeps its own tag + detail page.
"""
from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as app_main
from app.config import settings
from app.correlation import CofireRegistry, cofire_family
from app.models import GrafanaAlert, RCARecord
from app.pipeline import TriagePipeline
from app.rca_store import RCAStore


@pytest_asyncio.fixture
async def fresh_store():
    db_path = os.path.join(tempfile.gettempdir(), "test_cofire.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


def make_pipeline(store: RCAStore) -> TriagePipeline:
    return TriagePipeline(
        rca_store=store,
        drain=MagicMock(),
        context_gatherer=MagicMock(),
        llm_client=MagicMock(),
        notifier=MagicMock(send_escalation=AsyncMock(), send_timeout_alert=AsyncMock()),
        dedup=MagicMock(check=AsyncMock(return_value=(False, None))),
    )


def make_alert(name="KubeWorkloadDown", service="ad", fp="fp-down-1") -> GrafanaAlert:
    a = GrafanaAlert(
        status="firing",
        labels={"alertname": name, "service": service, "severity": "critical"},
        annotations={"summary": "x", "description": "y"},
        startsAt="2026-06-12T20:00:00Z",
    )
    a.fingerprint = fp
    return a


def make_record(rid="rec-1") -> RCARecord:
    return RCARecord(id=rid, alert_name="KubeWorkloadDown", affected_service="ad",
                     triage_decision="investigate", llm_verdict="escalate",
                     action_taken="emailed")


@pytest.fixture(autouse=True)
def _fresh_registry(monkeypatch):
    """Each test gets its own registry so module-level state can't leak."""
    reg = CofireRegistry()
    import app.correlation as corr
    monkeypatch.setattr(corr, "registry", reg)
    yield reg


# ---------------------------------------------------------------------------
# Registry semantics
# ---------------------------------------------------------------------------

def test_family_mapping():
    assert cofire_family("KubeWorkloadDown") == "workload-down"
    assert cofire_family("KubeWorkloadReplicasDeficit") == "workload-down"
    assert cofire_family("PodCrashLooping") == "workload-down"
    assert cofire_family("MediumCpuUsage") is None
    assert cofire_family(None) is None


def test_first_claim_is_primary_sibling_consolidates(_fresh_registry):
    reg = _fresh_registry
    assert reg.claim_primary("KubeWorkloadDown", "ad", "d1", 600) is None
    existing = reg.claim_primary("KubeWorkloadReplicasDeficit", "ad", "d2", 600)
    assert existing is not None and existing.decision_id == "d1"


def test_claim_expires_with_window(_fresh_registry):
    reg = _fresh_registry
    assert reg.claim_primary("KubeWorkloadDown", "ad", "d1", 600) is None
    # force the recorded claim into the past beyond the window
    key = ("workload-down", "ad")
    reg._primaries[key].emailed_at -= 9999
    assert reg.claim_primary("KubeWorkloadDown", "ad", "d2", 600) is None


def test_different_service_never_groups(_fresh_registry):
    reg = _fresh_registry
    assert reg.claim_primary("KubeWorkloadDown", "ad", "d1", 600) is None
    assert reg.claim_primary("KubeWorkloadReplicasDeficit", "cart", "d2", 600) is None


def test_release_primary_reopens_the_claim(_fresh_registry):
    reg = _fresh_registry
    assert reg.claim_primary("KubeWorkloadDown", "ad", "d1", 600) is None
    reg.release_primary("KubeWorkloadDown", "ad", "d1")
    assert reg.claim_primary("KubeWorkloadReplicasDeficit", "ad", "d2", 600) is None


def test_siblings_in_flight_naming(_fresh_registry):
    reg = _fresh_registry
    reg.track_arrival("KubeWorkloadDown", "ad", "fp-down")
    reg.track_arrival("KubeWorkloadReplicasDeficit", "ad", "fp-def")
    sibs = reg.siblings_in_flight("KubeWorkloadDown", "ad", "fp-down")
    assert [s["alertname"] for s in sibs] == ["KubeWorkloadReplicasDeficit"]
    reg.untrack("KubeWorkloadReplicasDeficit", "ad", "fp-def")
    assert reg.siblings_in_flight("KubeWorkloadDown", "ad", "fp-down") == []


# ---------------------------------------------------------------------------
# Pipeline claim-or-consolidate
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pipeline_sibling_consolidates(fresh_store, _fresh_registry):
    pipeline = make_pipeline(fresh_store)
    down = make_alert("KubeWorkloadDown", "ad", "fp-down")
    deficit = make_alert("KubeWorkloadReplicasDeficit", "ad", "fp-def")
    assert await pipeline._cofire_claim_or_consolidate(down, make_record("d1")) is None
    primary = await pipeline._cofire_claim_or_consolidate(deficit, make_record("d2"))
    assert primary is not None
    assert primary["decision_id"] == "d1"
    assert primary["alertname"] == "KubeWorkloadDown"


@pytest.mark.asyncio
async def test_pipeline_different_service_pages(fresh_store, _fresh_registry):
    pipeline = make_pipeline(fresh_store)
    assert await pipeline._cofire_claim_or_consolidate(
        make_alert("KubeWorkloadDown", "ad"), make_record("d1")) is None
    assert await pipeline._cofire_claim_or_consolidate(
        make_alert("KubeWorkloadReplicasDeficit", "cart"), make_record("d2")) is None


@pytest.mark.asyncio
async def test_pipeline_non_family_alert_untouched(fresh_store, _fresh_registry):
    pipeline = make_pipeline(fresh_store)
    assert await pipeline._cofire_claim_or_consolidate(
        make_alert("HighP95Latency", "ad"), make_record("d1")) is None
    assert await pipeline._cofire_claim_or_consolidate(
        make_alert("HighP95Latency", "ad"), make_record("d2")) is None


@pytest.mark.asyncio
async def test_pipeline_flag_off_disables(fresh_store, _fresh_registry, monkeypatch):
    monkeypatch.setattr(settings, "cofire_consolidation_enabled", False)
    pipeline = make_pipeline(fresh_store)
    assert await pipeline._cofire_claim_or_consolidate(
        make_alert("KubeWorkloadDown", "ad"), make_record("d1")) is None
    assert await pipeline._cofire_claim_or_consolidate(
        make_alert("KubeWorkloadReplicasDeficit", "ad"), make_record("d2")) is None


@pytest.mark.asyncio
async def test_pipeline_db_fallback_after_restart(fresh_store, _fresh_registry):
    """A primary paged, then the process restarted (registry wiped): the DB
    row must still consolidate the sibling instead of re-paging."""
    await fresh_store.save_decision(RCARecord(
        id="primary-db", alert_name="KubeWorkloadDown", affected_service="ad",
        alert_fingerprint="fp-down", triage_decision="investigate",
        llm_verdict="escalate", action_taken="emailed",
    ))
    pipeline = make_pipeline(fresh_store)
    primary = await pipeline._cofire_claim_or_consolidate(
        make_alert("KubeWorkloadReplicasDeficit", "ad", "fp-def"), make_record("d2"))
    assert primary is not None and primary["decision_id"] == "primary-db"


@pytest.mark.asyncio
async def test_pipeline_old_db_primary_outside_window_pages(fresh_store, _fresh_registry):
    old = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=2)
    await fresh_store.save_decision(RCARecord(
        id="primary-old", timestamp=old, alert_name="KubeWorkloadDown",
        affected_service="ad", triage_decision="investigate",
        llm_verdict="escalate", action_taken="emailed",
    ))
    pipeline = make_pipeline(fresh_store)
    assert await pipeline._cofire_claim_or_consolidate(
        make_alert("KubeWorkloadReplicasDeficit", "ad"), make_record("d2")) is None


def test_contributors_from_in_flight_and_correlated(fresh_store, _fresh_registry):
    pipeline = make_pipeline(fresh_store)
    _fresh_registry.track_arrival("KubeWorkloadDown", "ad", "fp-down")
    _fresh_registry.track_arrival("KubeWorkloadReplicasDeficit", "ad", "fp-def")
    correlated = [
        {"alert_name": "PodCrashLooping", "affected_service": "ad"},
        {"alert_name": "PodCrashLooping", "affected_service": "cart"},  # other service
        {"alert_name": "HighP95Latency", "affected_service": "ad"},     # not family
    ]
    out = pipeline._cofire_contributors(make_alert("KubeWorkloadDown", "ad", "fp-down"), correlated)
    names = sorted(c["alertname"] for c in out)
    assert names == ["KubeWorkloadReplicasDeficit", "PodCrashLooping"]


# ---------------------------------------------------------------------------
# Email body
# ---------------------------------------------------------------------------

def test_email_body_names_cofired_contributors(fresh_store):
    from app.notifier import EmailNotifier
    from app.models import Decision, LLMDecision
    n = EmailNotifier()
    alert = make_alert("KubeWorkloadDown", "ad")
    decision = LLMDecision(
        decision=Decision.ESCALATE, confidence=0.95, severity="critical",
        rca="ad deployment has 0 ready replicas", reason="pods unschedulable",
        human_cause="The ad workload is down — its pods cannot be scheduled.",
    )
    record = make_record("d1")
    body = n._build_v2_escalation_body(
        alert, decision, record, 1, None, [],
        cofire=[{"alertname": "KubeWorkloadReplicasDeficit", "fingerprint": "fp-def"}],
    )
    assert "Same incident" in body
    assert "KubeWorkloadReplicasDeficit" in body
    assert "no separate email will follow" in body


def test_email_body_no_block_without_cofire(fresh_store):
    from app.notifier import EmailNotifier
    from app.models import Decision, LLMDecision
    n = EmailNotifier()
    alert = make_alert("KubeWorkloadDown", "ad")
    decision = LLMDecision(
        decision=Decision.ESCALATE, confidence=0.95, severity="critical",
        rca="x", reason="y", human_cause="z",
    )
    body = n._build_v2_escalation_body(alert, decision, make_record("d1"), 1, None, [])
    assert "Same incident" not in body


# ---------------------------------------------------------------------------
# Feed grouping (route-level, real store)
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def cofire_feed_store():
    db_path = os.path.join(tempfile.gettempdir(), "test_cofire_feed.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    now = datetime.now(UTC).replace(tzinfo=None)
    await s.save_decision(RCARecord(
        id="11111111-aaaa-bbbb-cccc-000000000001",
        timestamp=now - timedelta(minutes=5),
        alert_name="KubeWorkloadDown", alert_fingerprint="fp-down",
        affected_service="ad", severity="critical",
        triage_decision="investigate", llm_verdict="escalate",
        action_taken="emailed", rca_report="ad is down",
    ))
    await s.save_decision(RCARecord(
        id="22222222-aaaa-bbbb-cccc-000000000002",
        timestamp=now - timedelta(minutes=4),
        alert_name="KubeWorkloadReplicasDeficit", alert_fingerprint="fp-def",
        affected_service="ad", severity="critical",
        triage_decision="investigate", llm_verdict="escalate",
        action_taken="consolidated", rca_report="ad replica deficit",
        consolidated_into="11111111-aaaa-bbbb-cccc-000000000001",
    ))
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.mark.asyncio
async def test_feed_groups_consolidated_sibling(cofire_feed_store):
    saved = app_main._store
    app_main._store = cofire_feed_store
    try:
        transport = ASGITransport(app=app_main.app)
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            resp = await c.get("/dashboard")
        assert resp.status_code == 200
        html = resp.text
        import json as _json
        import re as _re
        m = _re.search(r"window\.CIRES_ALERTS\s*=\s*(\[.*?\]);\n", html, _re.S)
        assert m, "CIRES_ALERTS not embedded"
        alerts = _json.loads(m.group(1))
        # sibling folded into the primary — ONE top-level row
        top_names = [a["alertName"] for a in alerts]
        assert "KubeWorkloadDown" in top_names
        assert "KubeWorkloadReplicasDeficit" not in top_names
        primary = next(a for a in alerts if a["alertName"] == "KubeWorkloadDown")
        assert len(primary["consolidated"]) == 1
        sib = primary["consolidated"][0]
        assert sib["alertName"] == "KubeWorkloadReplicasDeficit"
        assert sib["id"] == "22222222"
    finally:
        app_main._store = saved


@pytest.mark.asyncio
async def test_consolidated_row_keeps_tag_and_detail(cofire_feed_store):
    saved = app_main._store
    app_main._store = cofire_feed_store
    try:
        transport = ASGITransport(app=app_main.app)
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            resp = await c.get("/dashboard/alert/22222222")
        assert resp.status_code == 200
        assert "consolidatedInto" in resp.text
        assert "11111111-aaaa-bbbb-cccc-000000000001" in resp.text
    finally:
        app_main._store = saved
