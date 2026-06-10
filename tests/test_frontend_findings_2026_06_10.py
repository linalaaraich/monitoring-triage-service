"""2026-06-10 — regression tests for the four open frontend findings of the
2026-06-09 general-cycle audit (MASTER_PLAN F-2..F-5):

  F-2  feed vs detail fireCount disagreed: the feed derived fireCount from the
       500-row/15-day slab (len(prior)+1) while the detail route reconciled
       against incidents.fire_count. Fix: reconciliation moved INTO
       _v2_transform_row (the shared transform) fed by ONE bulk
       get_fire_counts_for_fingerprints query per page render. Companion:
       the feed's hardcoded "in last 24 h" copy is dropped (the count is the
       incident's all-time figure).
  F-3  legacy `suppressed_duplicate` triage enum had no humanizer case and no
       v2-visible surface. Fix: _humanize_triage_path case ("Recurrence
       (suppressed)") + a "recurrence-suppressed" tag on the v2 transform.
  F-4  /dashboard/incidents rows had no click-through to the alert detail.
       Fix: get_incidents now returns latest_decision_id (newest rca_history
       row per fingerprint); the Alert cell links /dashboard/alert/{short_id};
       the detail route gains an id-prefix fallback so links to rows older
       than its 15-day scan window still resolve.
  F-5  orphaned mock NsDropdown (+ dead namespace filter input/state) shipped
       in the JS bundle. Fix: removed.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as app_main
from app.main import _humanize_triage_path, _v2_transform_row
from app.models import RCARecord
from app.rca_store import RCAStore

_DESIGN_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "app", "static", "design",
)


def _extract_payload(html: str, var: str):
    """Pull a window.CIRES_* JSON payload out of rendered HTML."""
    m = re.search(rf"window\.{var}\s*=\s*", html)
    assert m, f"window.{var} payload missing from page"
    obj, _ = json.JSONDecoder().raw_decode(html[m.end():])
    return obj


@pytest_asyncio.fixture
async def store():
    db_path = os.path.join(
        tempfile.gettempdir(), f"test_fe_findings_{uuid.uuid4().hex}.db"
    )
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest_asyncio.fixture
async def client(store):
    saved = app_main._store
    app_main._store = store
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app_main._store = saved


def _record(fp: str, *, ts: datetime, name="TargetDown", svc="monitoring-vm",
            decision="investigate", verdict="escalate", action="emailed",
            rid: str | None = None) -> RCARecord:
    return RCARecord(
        id=rid or str(uuid.uuid4()),
        alert_name=name, alert_fingerprint=fp, affected_service=svc,
        severity="warning", triage_decision=decision, llm_verdict=verdict,
        action_taken=action, timestamp=ts,
        rca_report="Scrape target down: node-exporter not responding.",
    )


# ── F-2: feed fireCount == detail fireCount == incidents.fire_count ────────

@pytest.mark.asyncio
async def test_f2_bulk_fire_counts_accessor(store):
    now = datetime.utcnow()
    await store.save_decision(_record("fp-bulk-1", ts=now))
    await store.save_decision(_record("fp-bulk-1", ts=now + timedelta(minutes=5)))
    await store.save_decision(_record("fp-bulk-2", ts=now))
    out = await store.get_fire_counts_for_fingerprints(
        ["fp-bulk-1", "fp-bulk-2", "fp-missing", ""]
    )
    assert out == {"fp-bulk-1": 2, "fp-bulk-2": 1}
    assert await store.get_fire_counts_for_fingerprints([]) == {}
    assert await store.get_fire_counts_for_fingerprints(["", None]) == {}


@pytest.mark.asyncio
async def test_f2_feed_detail_and_incident_agree(store, client):
    """2 real feed rows + 3 dedup-absorbed recurrences = incident fire_count 5.
    The slab only sees the 2 rows; BOTH pages must still render 5."""
    now = datetime.utcnow()
    await store.save_decision(_record("fp-f2", ts=now - timedelta(hours=2)))
    latest = _record("fp-f2", ts=now - timedelta(hours=1))
    await store.save_decision(latest)
    for i in range(3):
        out = await store.record_recurrence(
            fingerprint="fp-f2",
            at_iso=(now - timedelta(minutes=30 - i)).isoformat(),
            severity="warning", alert_name="TargetDown",
            affected_service="monitoring-vm",
        )
    assert out["fire_count"] == 5

    feed = await client.get("/dashboard?range=15d")
    assert feed.status_code == 200
    alerts = _extract_payload(feed.text, "CIRES_ALERTS")
    row = next(a for a in alerts if a["uuid"] == latest.id)
    assert row["fireCount"] == 5, "feed must use the incident fire_count"
    assert row["indicator"] == "recurring"

    detail = await client.get(f"/dashboard/alert/{latest.id[:8]}")
    assert detail.status_code == 200
    a = _extract_payload(detail.text, "CIRES_ALERT")
    assert a["fireCount"] == 5, "detail must agree with the feed"
    assert a["indicator"] == "recurring"


def test_f2_transform_reconciles_with_max_semantics():
    """Incident count only ever RAISES the slab count (a stale/missing
    incident row must never under-count what the slab can see)."""
    row = {"id": "abcd1234-0000-4000-8000-000000000000",
           "alert_fingerprint": "fp-x", "alert_name": "A",
           "affected_service": "s", "timestamp": "2026-06-10T00:00:00"}
    base = _v2_transform_row(row, incident_fire_counts={"fp-x": 7})
    assert base["fireCount"] == 7
    assert base["indicator"] == "recurring"
    lower = _v2_transform_row(row, incident_fire_counts={"fp-x": 0})
    assert lower["fireCount"] == 1
    absent = _v2_transform_row(row, incident_fire_counts={})
    assert absent["fireCount"] == 1
    garbage = _v2_transform_row(row, incident_fire_counts={"fp-x": "nope"})
    assert garbage["fireCount"] == 1


def test_f2_feed_copy_drops_24h_claim():
    src = open(os.path.join(_DESIGN_DIR, "dashboard.jsx")).read()
    assert "in last 24 h" not in src, (
        "fireCount is the incident's all-time count — the row copy must not "
        "claim a 24 h window"
    )
    assert "Fired {a.fireCount} times" in src


# ── F-3: legacy suppressed_duplicate humanized ──────────────────────────────

def test_f3_humanizer_has_suppressed_duplicate_case():
    label, tip = _humanize_triage_path("suppressed_duplicate")
    assert label == "Recurrence (suppressed)"
    assert "no LLM" in tip
    # Unknown enums still fall through raw (unchanged catch-all).
    assert _humanize_triage_path("weird_enum") == ("weird_enum", "weird_enum")


@pytest.mark.asyncio
async def test_f3_legacy_row_renders_humanized_tag(store, client):
    now = datetime.utcnow()
    rec = _record(
        "fp-f3", ts=now - timedelta(hours=1), decision="suppressed_duplicate",
        verdict=None, action="see_previous_rca:deadbeef",
    )
    await store.save_decision(rec)
    detail = await client.get(f"/dashboard/alert/{rec.id[:8]}")
    assert detail.status_code == 200
    a = _extract_payload(detail.text, "CIRES_ALERT")
    assert "recurrence-suppressed" in a["tags"]
    # The tag is in the payload the page renders; raw enum must not be the label.
    assert "recurrence-suppressed" in detail.text


# ── F-4: incidents table click-through ──────────────────────────────────────

@pytest.mark.asyncio
async def test_f4_get_incidents_carries_latest_decision_id(store):
    now = datetime.utcnow()
    older = _record("fp-f4", ts=now - timedelta(hours=3))
    newest = _record("fp-f4", ts=now - timedelta(hours=1))
    await store.save_decision(older)
    await store.save_decision(newest)
    incs = await store.get_incidents(limit=10)
    inc = next(i for i in incs if i["fingerprint"] == "fp-f4")
    assert inc["latest_decision_id"] == newest.id


@pytest.mark.asyncio
async def test_f4_incidents_page_links_resolve_to_detail(store, client):
    now = datetime.utcnow()
    rec = _record("fp-f4b", ts=now - timedelta(hours=1), name="HighDiskUsage")
    await store.save_decision(rec)
    page = await client.get("/dashboard/incidents")
    assert page.status_code == 200
    href = f"/dashboard/alert/{rec.id[:8]}"
    assert f'<a href="{href}">HighDiskUsage</a>' in page.text
    detail = await client.get(href)
    assert detail.status_code == 200
    assert "HighDiskUsage" in detail.text


@pytest.mark.asyncio
async def test_f4_detail_resolves_rows_older_than_scan_window(store, client):
    """An incident's latest fire can predate the detail route's 15-day scan —
    the id-prefix fallback must keep the click-through resolving 200."""
    old = _record("fp-f4c", ts=datetime.utcnow() - timedelta(days=40),
                  name="AncientAlert")
    await store.save_decision(old)
    detail = await client.get(f"/dashboard/alert/{old.id[:8]}")
    assert detail.status_code == 200
    assert "AncientAlert" in detail.text


@pytest.mark.asyncio
async def test_f4_orphan_incident_renders_plain_text(store, client):
    """Recurrence-only incident (no rca_history row) → no href, no crash."""
    await store.record_recurrence(
        fingerprint="fp-orphan", at_iso=datetime.utcnow().isoformat(),
        severity="warning", alert_name="OrphanIncident",
        affected_service="svc-x",
    )
    page = await client.get("/dashboard/incidents")
    assert page.status_code == 200
    assert "OrphanIncident" in page.text
    assert ">OrphanIncident</a>" not in page.text


@pytest.mark.asyncio
async def test_f4_decision_by_id_prefix(store):
    rec = _record("fp-prefix", ts=datetime.utcnow() - timedelta(days=30))
    await store.save_decision(rec)
    hit = await store.get_decision_by_id_prefix(rec.id[:8])
    assert hit is not None and hit["id"] == rec.id
    assert isinstance(hit["suggested_actions"], list)  # decoded like get_decisions
    assert await store.get_decision_by_id_prefix("ffffffff") is None
    assert await store.get_decision_by_id_prefix("") is None


# ── F-5: dead mock NsDropdown removed ───────────────────────────────────────

def test_f5_nsdropdown_and_dead_filter_removed():
    src = open(os.path.join(_DESIGN_DIR, "dashboard.jsx")).read()
    assert "NsDropdown" not in src
    assert "Filter namespaces" not in src
    # The dead, never-read filter-state keys went with it.
    assert "service_type: new Set()" not in src
    # Real namespace DISPLAY (NsPill on the row) stays.
    assert "NsPill" in src


def test_f5_no_other_page_references_nsdropdown():
    for fname in os.listdir(_DESIGN_DIR):
        if fname.endswith(".jsx"):
            src = open(os.path.join(_DESIGN_DIR, fname)).read()
            assert "NsDropdown" not in src, f"{fname} references removed component"
