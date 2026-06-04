"""WS-2 frontend audit fixes - 2026-06-04.

Per Lina's 2026-06-04 night complaint:

  > "in individual alert pages you get at the top a stupid line that's
  > useless, the button that I specified in the frontend design meant
  > to get me back to the dashboard is not functional, same for many
  > other buttons including feedback. feedback pages are not
  > accessible."

This file pins the four user-visible fixes so a future refactor that
deletes a wiring or re-introduces the useless banner fails CI:

  1. Detail page (/dashboard/alert/{id}) no longer renders the
     `.page-banner` chrome strip ("stupid useless line").
  2. /rate page no longer renders the `.page-banner` chrome strip
     AND it now ships the platform Sidebar + TopBar chrome.
  3. Server-rendered sidebars on /dashboard/kpi, /dashboard/services,
     /dashboard/alerts link Incidents/Anomalies/Stats/Drain3/
     Integrations to their stub routes (not back to /dashboard).
  4. /rate page injects CIRES_DASHBOARD_STATS + CIRES_SIDEBAR_BADGES
     so the TopBar / Sidebar render the same numbers as detail.

Static-asset assertions (detail.jsx, feedback.jsx) cover the
remaining bits Lina pointed at:

  5. detail.jsx's back-arrow renders as an anchor to /dashboard.
  6. detail.jsx's "Open full feedback form" link has a real href.
  7. feedback.jsx's confirmation-page buttons are real anchors.
"""
from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as app_main
from app.models import RCARecord
from app.rca_store import RCAStore


@pytest_asyncio.fixture
async def ws2_store():
    db_path = os.path.join(tempfile.gettempdir(), "test_ws2_frontend.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    now = datetime.now(UTC).replace(tzinfo=None)
    rec = RCARecord(
        id="ws2alert-aaaa-bbbb-cccc-ddddeeeeffff",
        timestamp=now - timedelta(minutes=12),
        alert_name="HighCPUUsage",
        alert_fingerprint="fp-ws2-1",
        affected_service="spring-boot",
        severity="critical",
        triage_decision="investigate",
        llm_verdict="escalate",
        action_taken="emailed",
        investigation_duration_ms=1500,
    )
    await s.save_decision(rec)
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest_asyncio.fixture
async def ws2_client(ws2_store):
    saved = app_main._store
    app_main._store = ws2_store
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app_main._store = saved


# ---------------------------------------------------------------------------
# F-001 - detail page useless banner strip
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detail_page_has_no_page_banner_strip(ws2_client):
    """Lina 2026-06-04: 'stupid line that's useless' was a 30px purple
    strip rendered ABOVE the React TopBar with the text 'detail page',
    a click-to-copy UUID widget, and a 'back to feed' anchor. The
    TopBar + DetailHeader below it already convey all that info. The
    strip is gone."""
    r = await ws2_client.get("/dashboard/alert/ws2alert")
    assert r.status_code == 200
    body = r.text
    assert 'class="page-banner"' not in body, \
        "the useless 'detail page' banner strip must NOT be re-introduced"
    assert ">detail page<" not in body, \
        "the literal 'detail page' chrome label must NOT be re-introduced"


# ---------------------------------------------------------------------------
# F-007 + F-008 - /rate page banner removed, chrome added
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rate_page_has_no_page_banner_strip(ws2_client):
    """Same useless chrome strip used to live on the rate page too."""
    r = await ws2_client.get("/dashboard/alert/ws2alert/rate")
    assert r.status_code == 200
    body = r.text
    assert 'class="page-banner"' not in body
    assert ">rate alert<" not in body, \
        "the literal 'rate alert' chrome label must NOT be re-introduced"


@pytest.mark.asyncio
async def test_rate_page_ships_topbar_and_sidebar_chrome(ws2_client):
    """The rate page now wraps FeedbackEmpty in Sidebar + TopBar so the
    operator can navigate to other pages without browser-back."""
    r = await ws2_client.get("/dashboard/alert/ws2alert/rate")
    body = r.text
    # The wrapper App uses these symbols (sourced from atoms.jsx +
    # sidebar.jsx). If they are not referenced the form is stranded.
    assert "window.Sidebar" in body
    assert "<TopBar" in body
    assert "CIRES_DASHBOARD_STATS" in body, \
        "TopBar needs CIRES_DASHBOARD_STATS to render uptime + counters"
    assert "CIRES_SIDEBAR_BADGES" in body, \
        "Sidebar needs CIRES_SIDEBAR_BADGES to render the nav badges"


# ---------------------------------------------------------------------------
# F-012 - server-rendered sidebar dead links on KPI/Services/Alerts
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("route", [
    "/dashboard/kpi",
    "/dashboard/services",
    "/dashboard/alerts",
])
@pytest.mark.asyncio
async def test_sidebar_sprint5_links_are_wired(ws2_client, route):
    """KPI/Services/Alerts each render a server-side <a class='kpi-
    sidebar__item'> for Incidents/Anomalies/Stats/Drain3/Integrations.
    Prior to this fix all five hrefs pointed back at /dashboard (a
    silent bounce). They now point at the matching Sprint-5 stub."""
    r = await ws2_client.get(route)
    assert r.status_code == 200
    body = r.text
    expectations = {
        ">Incidents<":     'href="/dashboard/incidents"',
        ">Anomalies<":     'href="/dashboard/anomalies"',
        ">Stats<":         'href="/dashboard/stats"',
        ">Drain3 engine<": 'href="/dashboard/drain3"',
        ">Integrations<":  'href="/dashboard/integrations"',
    }
    for label, expected_href in expectations.items():
        # The label appears in the sidebar; we want the surrounding
        # anchor href to match.
        anchor_idx = body.rfind(expected_href, 0, body.find(label))
        assert anchor_idx != -1, (
            f"{route}: label {label!r} not preceded by {expected_href!r} - "
            f"sidebar item still bounces to /dashboard?"
        )


# ---------------------------------------------------------------------------
# Static-asset assertions (detail.jsx + feedback.jsx)
# ---------------------------------------------------------------------------

REPO = Path(__file__).resolve().parent.parent


def test_detail_jsx_back_arrow_is_anchor_to_dashboard():
    """detail.jsx DetailHeader: back-arrow button used to be a bare
    <button> with no onClick/href. Now it is an <a href='/dashboard'>."""
    src = (REPO / "app" / "static" / "design" / "detail.jsx").read_text()
    # The arrow icon now lives inside an <a>, not a <button>.
    assert 'href="/dashboard"' in src
    # Heuristic: the literal Icon.arrowL is followed by a closing </a>
    # not </button>.
    idx = src.find("Icon.arrowL")
    assert idx != -1
    tail = src[idx:idx + 200]
    assert "</a>" in tail, "back-arrow must close as </a> not </button>"


def test_detail_jsx_open_full_feedback_link_has_href():
    """The 'Open full feedback form' link previously had no href so
    the feedback page was unreachable from the detail page (Lina's
    'feedback pages not accessible')."""
    src = (REPO / "app" / "static" / "design" / "detail.jsx").read_text()
    # Look for the new wiring: href to /dashboard/alert/${a.id}/rate
    assert "/rate" in src
    assert "Open full feedback form" in src
    # Find the LAST occurrence (the rendered JSX, not the comment).
    label_idx = src.rfind("Open full feedback form")
    window = src[max(0, label_idx - 400):label_idx]
    assert "href=" in window, \
        "'Open full feedback form' link must have an href to the rate page"
    assert "/rate" in window, \
        "the href must target the /rate route"


def test_detail_jsx_thumbs_buttons_post_to_feedback_rate():
    """The thumbs up / thumbs down buttons in the detail-page sidebar
    used to be no-op. They now POST to /feedback/rate/{short_id}."""
    src = (REPO / "app" / "static" / "design" / "detail.jsx").read_text()
    # The new FeedbackCard component issues a fetch to that endpoint.
    assert "/feedback/rate/" in src
    assert "FeedbackCard" in src


def test_feedback_jsx_confirmation_buttons_are_anchors():
    """After successful submit the confirmation screen used to show
    two dead buttons. They are now real <a> anchors back to feed +
    back to this alert's detail."""
    src = (REPO / "app" / "static" / "design" / "feedback.jsx").read_text()
    assert "Back to dashboard" in src
    # Look for the anchor element right around the label
    label_idx = src.find("Back to dashboard")
    window = src[max(0, label_idx - 300):label_idx + 100]
    assert 'href="/dashboard"' in window, \
        "confirmation 'Back to dashboard' must be an anchor to /dashboard"
    # And the detail anchor with a dynamic short id.
    detail_idx = src.find("View this alert's detail")
    window2 = src[max(0, detail_idx - 400):detail_idx]
    assert "href=" in window2 and "/dashboard/alert/" in window2, \
        "'View this alert's detail' must be an anchor to the detail page"
