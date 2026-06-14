"""Frontend overhaul - 2026-06-02.

Covers the three deliverables of the frontend overhaul pass:

  1. /dashboard partial-refresh: ?_partial=1 returns a JSON fragment
     (not the full HTML page), the meta-refresh tag is gone, and the
     partial payload carries the same shape the client poll expects.

  2. Sprint 5 placeholder routes return 200 (not 404) and carry the
     "coming Sprint 5" copy plus a CTA back to /dashboard so the
     operator never lands on a dead end.

  3. Detail page injects window.CIRES_LINKS with grafana/loki/jaeger
     URLs from settings so the React Grafana/Loki/Jaeger buttons have
     real hrefs.

The store is shared via the same _store global the dashboard route
reads; we monkeypatch it with a small fixture-loaded RCAStore so the
test is hermetic against whatever lives in the real SQLite file.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as app_main
from app.models import RCARecord
from app.rca_store import RCAStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def overhaul_store():
    """Small RCAStore with a couple of recent rows so /dashboard renders
    a non-empty alerts payload (the partial endpoint still works on an
    empty store; we just want to also exercise the row-shape path)."""
    db_path = os.path.join(tempfile.gettempdir(), "test_frontend_overhaul.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()

    now = datetime.now(UTC).replace(tzinfo=None)
    rows = [
        ("overhaul-1", 0.5, "HighCPUUsage",       "critical", "escalate", "emailed"),
        ("overhaul-2", 1.0, "PodHighMemoryUsage", "warning",  "dismiss",  "suppressed"),
    ]
    for rid, hours_ago, name, sev, verdict, action in rows:
        rec = RCARecord(
            id=rid,
            timestamp=now - timedelta(hours=hours_ago),
            alert_name=name,
            alert_fingerprint=f"fp-{rid}",
            affected_service="spring-boot",
            severity=sev,
            triage_decision="investigate",
            llm_verdict=verdict,
            action_taken=action,
            investigation_duration_ms=1200,
        )
        await s.save_decision(rec)
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest_asyncio.fixture
async def overhaul_client(overhaul_store):
    """ASGI client wired to overhaul_store."""
    saved = app_main._store
    app_main._store = overhaul_store
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app_main._store = saved


# ---------------------------------------------------------------------------
# 1. Partial-refresh endpoint
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dashboard_partial_returns_json_envelope(overhaul_client):
    """?_partial=1 returns JSON (not HTML) with the expected envelope keys."""
    r = await overhaul_client.get("/dashboard?_partial=1")
    assert r.status_code == 200
    ct = r.headers.get("content-type", "")
    assert "application/json" in ct, f"expected JSON, got {ct!r}"
    payload = r.json()
    # Envelope contract - the inline poll script in /dashboard reads
    # exactly these keys. Adding fields is fine; removing breaks the UI.
    for key in ("alerts", "dashboard_stats", "sidebar_badges",
                "pagination", "filters", "now_local"):
        assert key in payload, f"missing key {key!r} in partial payload"
    assert isinstance(payload["alerts"], list)
    assert isinstance(payload["dashboard_stats"], dict)


@pytest.mark.asyncio
async def test_dashboard_partial_is_not_full_page(overhaul_client):
    """Partial fragment must not contain the <html>/<body> chrome."""
    r = await overhaul_client.get("/dashboard?_partial=1")
    body = r.text
    # JSON serializes "<" as-is inside strings; ensure no DOCTYPE shell.
    assert "<!DOCTYPE html>" not in body
    assert "<html" not in body
    assert "<body" not in body


@pytest.mark.asyncio
async def test_dashboard_html_response_has_no_meta_refresh(overhaul_client):
    """The /dashboard HTML response must NOT contain a meta-refresh tag.

    The previous full-page reload caused the operator to lose scroll
    position, expanded-row state, and filter focus every 60 seconds.
    The frontend overhaul replaces it with a fetch+swap poll.
    """
    r = await overhaul_client.get("/dashboard")
    assert r.status_code == 200
    assert 'http-equiv="refresh"' not in r.text, \
        "meta-refresh tag must be gone from /dashboard - use partial-refresh poll instead"
    # Sanity: the partial poll wiring is present.
    assert "cires_partial_refresh" in r.text
    assert "_partial=1" in r.text or "_partial" in r.text


@pytest.mark.asyncio
async def test_dashboard_partial_honors_filters(overhaul_client):
    """?_partial=1 must respect the same URL filters as the HTML page so
    the poll doesn't widen the operator's view back to the unfiltered set."""
    r = await overhaul_client.get("/dashboard?_partial=1&verdict=escalate&range=24h")
    assert r.status_code == 200
    payload = r.json()
    assert payload["filters"]["verdict"] == "escalate"
    # Every returned alert should have verdict ESCALATE.
    for a in payload["alerts"]:
        assert a.get("verdict") == "ESCALATE", f"unexpected verdict {a.get('verdict')!r}"


# ---------------------------------------------------------------------------
# 2. Sprint 5 placeholder routes
# ---------------------------------------------------------------------------

# Every Sprint-5 sidebar item lands on a real page (not a 404). Three of
# them (incidents/anomalies/stats) became real pages in Sprint 5 EPIC14;
# the remaining two are still placeholders carrying the "coming Sprint 5" copy.
SPRINT5_ROUTES = [
    "/dashboard/incidents",
    "/dashboard/anomalies",
    "/dashboard/drain3",
    "/dashboard/integrations",
]
# EPIC14 shipped these as real pages — they no longer carry placeholder copy.
SPRINT5_BUILT_ROUTES = [
    "/dashboard/incidents",
    "/dashboard/anomalies",
]
# Out-of-EPIC14 scope — still placeholders.
SPRINT5_PLACEHOLDER_ROUTES = [
    "/dashboard/drain3",
    "/dashboard/integrations",
]


@pytest.mark.parametrize("route", SPRINT5_ROUTES)
@pytest.mark.asyncio
async def test_sprint5_placeholder_returns_200(overhaul_client, route):
    """Every Sprint-5 sidebar item lands on a real page (not a 404)."""
    r = await overhaul_client.get(route)
    assert r.status_code == 200, f"{route} returned {r.status_code}, expected 200"


@pytest.mark.parametrize("route", SPRINT5_ROUTES)
@pytest.mark.asyncio
async def test_sprint5_route_links_back_to_dashboard(overhaul_client, route):
    """Every Sprint-5 route (real page or placeholder) must link back to
    /dashboard so the operator can return to a working surface without using
    the browser back button."""
    r = await overhaul_client.get(route)
    assert 'href="/dashboard"' in r.text, f"{route} missing back-to-feed CTA"


@pytest.mark.parametrize("route", SPRINT5_PLACEHOLDER_ROUTES)
@pytest.mark.asyncio
async def test_sprint5_placeholder_carries_sprint5_copy(overhaul_client, route):
    """Out-of-scope routes are still placeholders carrying 'Sprint 5' copy."""
    r = await overhaul_client.get(route)
    assert "Sprint 5" in r.text, f"{route} missing 'Sprint 5' messaging"


@pytest.mark.parametrize("route", SPRINT5_ROUTES)
@pytest.mark.asyncio
async def test_sprint5_route_uses_design_tokens(overhaul_client, route):
    """Every Sprint-5 route must load tokens.css so the look matches the rest
    of the dashboard rather than rendering as a bare unstyled page."""
    r = await overhaul_client.get(route)
    assert "/static/design/tokens.css" in r.text


# ---------------------------------------------------------------------------
# 3. Detail page link wiring
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detail_page_injects_cires_links(overhaul_client):
    """/dashboard/alert/{short_id} must inject window.CIRES_LINKS with
    grafana/loki/jaeger URLs from settings so the React DetailHeader
    buttons have real hrefs (not "#" dead anchors)."""
    # Use the 8-char prefix of overhaul-1.
    r = await overhaul_client.get("/dashboard/alert/overhaul")
    assert r.status_code == 200, f"detail page returned {r.status_code}: {r.text[:300]}"
    body = r.text
    assert "window.CIRES_LINKS" in body, "detail page missing CIRES_LINKS injection"
    # All three external services must have URLs populated.
    for key in ("grafana", "loki", "jaeger"):
        assert f'"{key}"' in body, f"CIRES_LINKS missing {key} URL"


@pytest.mark.asyncio
async def test_detail_page_emoji_stripped(overhaul_client):
    """The detail-page banner copy-UUID widget previously had emoji
    characters. Project rules forbid emoji in UI."""
    r = await overhaul_client.get("/dashboard/alert/overhaul")
    body = r.text
    # The two specific emoji that lived in the banner copy widget.
    assert "\U0001f4cb" not in body, "clipboard emoji must be removed"
    assert "✓" not in body, "check-mark emoji must be removed"
