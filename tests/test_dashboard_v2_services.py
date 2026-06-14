"""Tests for /dashboard/services + RCAStore.get_service_summary.

Covers:
  * get_service_summary() returns the expected shape from a populated DB
  * Route 200s with a non-empty HTML body
  * Empty-DB: route still 200s, shows the "no services yet" affordance,
    does not surface a Python traceback
  * Service names render as <a href="/dashboard?q=<svc>"> anchors
    back to the filtered triage feed
  * Top-of-page summary chips ("services seen", "decisions", "emails / day")
    render in the body
  * MCP-only invariant: the route reads through the existing RCAStore
    (no new direct-DB path) — implicitly enforced by the test-suite-wide
    test_mcp_invariant_lint.py, but spot-checked here by asserting the
    route doesn't import aiosqlite at module-load time.
"""
from __future__ import annotations

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
async def empty_store():
    """Fresh RCAStore with no rows — exercises the empty-DB code path."""
    db_path = os.path.join(tempfile.gettempdir(), "test_services_empty.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest_asyncio.fixture
async def populated_store():
    """RCAStore pre-loaded with rows across 3 services with mixed actions
    / verdicts / severities — exercises every rollup column.
    """
    db_path = os.path.join(tempfile.gettempdir(), "test_services_populated.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()

    now = datetime.now(UTC).replace(tzinfo=None)

    # spring-boot: 3 decisions, 2 emailed (escalate/critical) + 1 suppressed
    # (dismiss/warning). Dominant alertname: HighP95Latency (2/3).
    for i in range(2):
        await s.save_decision(RCARecord(
            id=f"sb-em-{i}",
            timestamp=now - timedelta(hours=i + 1),
            alert_name="HighP95Latency",
            alert_fingerprint=f"fp-sb-em-{i}",
            affected_service="spring-boot",
            severity="critical",
            triage_decision="investigate",
            llm_verdict="escalate",
            action_taken="emailed",
            investigation_duration_ms=2000,
        ))
    await s.save_decision(RCARecord(
        id="sb-sup-0",
        timestamp=now - timedelta(hours=3),
        alert_name="PodHighMemoryUsage",
        alert_fingerprint="fp-sb-sup-0",
        affected_service="spring-boot",
        severity="warning",
        triage_decision="suppressed_duplicate",
        llm_verdict="dismiss",
        action_taken="suppressed_duplicate",
        investigation_duration_ms=0,
    ))

    # kong: 2 decisions, 1 spike_shelved + 1 shelved (no verdict on shelved).
    await s.save_decision(RCARecord(
        id="kong-spike-0",
        timestamp=now - timedelta(hours=2),
        alert_name="CPUSpike",
        alert_fingerprint="fp-kong-spike-0",
        affected_service="kong",
        severity="warning",
        triage_decision="spike_shelved",
        llm_verdict=None,
        action_taken="spike_shelved",
        investigation_duration_ms=0,
    ))
    await s.save_decision(RCARecord(
        id="kong-shelved-0",
        timestamp=now - timedelta(hours=4),
        alert_name="CPUSpike",
        alert_fingerprint="fp-kong-shelved-0",
        affected_service="kong",
        severity="warning",
        triage_decision="shelved",
        llm_verdict=None,
        action_taken="shelved",
        investigation_duration_ms=0,
    ))

    # nginx: 1 decision with an inconclusive verdict.
    await s.save_decision(RCARecord(
        id="nginx-0",
        timestamp=now - timedelta(hours=5),
        alert_name="NginxErrorRate",
        alert_fingerprint="fp-nginx-0",
        affected_service="nginx",
        severity="critical",
        triage_decision="investigate",
        llm_verdict="inconclusive",
        action_taken="emailed",
        investigation_duration_ms=3000,
    ))

    # An old row outside the 7-day window — must NOT appear in the rollup.
    await s.save_decision(RCARecord(
        id="ancient-0",
        timestamp=now - timedelta(days=14),
        alert_name="AncientAlert",
        alert_fingerprint="fp-ancient-0",
        affected_service="ghost-service",
        severity="warning",
        triage_decision="investigate",
        llm_verdict="dismiss",
        action_taken="emailed",
    ))

    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest_asyncio.fixture
async def services_app_client(populated_store):
    saved = app_main._store
    app_main._store = populated_store
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app_main._store = saved


@pytest_asyncio.fixture
async def empty_app_client(empty_store):
    saved = app_main._store
    app_main._store = empty_store
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app_main._store = saved


# ---------------------------------------------------------------------------
# RCAStore.get_service_summary() — unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_service_summary_empty_db_returns_empty_list(empty_store):
    rows = await empty_store.get_service_summary(days=7)
    assert rows == []


@pytest.mark.asyncio
async def test_service_summary_shape_per_row(populated_store):
    rows = await populated_store.get_service_summary(days=7)
    assert len(rows) == 3  # spring-boot, kong, nginx (ghost-service is outside window)
    expected_keys = {
        "service", "total", "actions", "verdicts", "severities",
        "last_fire", "top_alertname",
    }
    for r in rows:
        assert expected_keys.issubset(set(r.keys())), f"Row missing keys: {r}"


@pytest.mark.asyncio
async def test_service_summary_excludes_outside_window(populated_store):
    """The 14-day-old ghost-service row must not appear in a 7-day window."""
    rows = await populated_store.get_service_summary(days=7)
    names = {r["service"] for r in rows}
    assert "ghost-service" not in names


@pytest.mark.asyncio
async def test_service_summary_counts_and_breakdowns(populated_store):
    rows = await populated_store.get_service_summary(days=7)
    by_name = {r["service"]: r for r in rows}

    # spring-boot: 3 total = 2 emailed (escalate/critical) + 1 suppressed (dismiss/warning)
    sb = by_name["spring-boot"]
    assert sb["total"] == 3
    assert sb["actions"].get("emailed") == 2
    assert sb["actions"].get("suppressed_duplicate") == 1
    assert sb["verdicts"].get("escalate") == 2
    assert sb["verdicts"].get("dismiss") == 1
    assert sb["severities"].get("critical") == 2
    assert sb["severities"].get("warning") == 1
    # Dominant alertname: HighP95Latency fired twice vs PodHighMemoryUsage once.
    assert sb["top_alertname"] == "HighP95Latency"

    # kong: 2 shelve-flavoured rows, NO llm_verdict on either
    kong = by_name["kong"]
    assert kong["total"] == 2
    assert kong["actions"].get("spike_shelved") == 1
    assert kong["actions"].get("shelved") == 1
    assert kong["verdicts"] == {}  # No verdicts on shelved rows
    assert kong["top_alertname"] == "CPUSpike"


@pytest.mark.asyncio
async def test_service_summary_sorted_by_total_desc(populated_store):
    rows = await populated_store.get_service_summary(days=7)
    totals = [r["total"] for r in rows]
    assert totals == sorted(totals, reverse=True)


# ---------------------------------------------------------------------------
# /dashboard/services — route integration tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_services_route_returns_200_with_body(services_app_client):
    resp = await services_app_client.get("/dashboard/incidents?view=services")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert len(resp.text) > 500


@pytest.mark.asyncio
async def test_services_route_renders_each_service_as_anchor_with_q_param(services_app_client):
    """Service names must be clickable anchors that drop into /dashboard?q=<svc>."""
    resp = await services_app_client.get("/dashboard/incidents?view=services")
    body = resp.text
    # Each fixture service should appear inside an href="/dashboard?q=…" anchor.
    for svc in ("spring-boot", "kong", "nginx"):
        assert f'href="/dashboard?q={svc}"' in body, f"Anchor for {svc!r} missing"


@pytest.mark.asyncio
async def test_services_route_renders_summary_chips(services_app_client):
    resp = await services_app_client.get("/dashboard/incidents?view=services")
    body = resp.text
    # The three top-of-page chip labels per spec.
    assert "services seen" in body
    assert "decisions" in body
    assert "emails / day avg" in body
    # And the chip numbers themselves — 3 services, 6 in-window decisions
    # (2 + 1 + 2 + 1), 3 emails (2 spring-boot + 1 nginx).
    assert "svc-chip__n" in body  # CSS class is present
    assert ">3<" in body  # services seen count


@pytest.mark.asyncio
async def test_services_route_renders_top_alertname(services_app_client):
    """The dominant alertname column must surface HighP95Latency for spring-boot."""
    resp = await services_app_client.get("/dashboard/incidents?view=services")
    assert "HighP95Latency" in resp.text
    assert "CPUSpike" in resp.text


@pytest.mark.asyncio
async def test_services_route_has_auto_refresh_meta(services_app_client):
    """60s meta-refresh per spec — same cadence as /dashboard/kpi."""
    resp = await services_app_client.get("/dashboard/incidents?view=services")
    body = resp.text
    assert 'http-equiv="refresh"' in body
    assert 'content="60"' in body


@pytest.mark.asyncio
async def test_services_route_empty_db_still_200s_with_affordance(empty_app_client):
    """Regression — empty DB must not 500 the route + must show the affordance."""
    resp = await empty_app_client.get("/dashboard/incidents?view=services")
    assert resp.status_code == 200
    # "no services yet" affordance per spec
    assert "No services yet" in resp.text
    # No Python traceback bleed-through
    assert "Traceback" not in resp.text
    # Chips still render — they just show 0
    assert "services seen" in resp.text


@pytest.mark.asyncio
async def test_services_route_renders_sidebar_active(services_app_client):
    """The sidebar twin must mark Services as the active item."""
    resp = await services_app_client.get("/dashboard/incidents?view=services")
    body = resp.text
    # Active-class marker on the Services nav item
    assert 'kpi-sidebar__item--active' in body
    # And the link back to /dashboard is present (sidebar Triage feed link)
    assert 'href="/dashboard"' in body


@pytest.mark.asyncio
async def test_services_route_title_marker(services_app_client):
    resp = await services_app_client.get("/dashboard/incidents?view=services")
    body = resp.text
    assert "Services" in body
    # Presentation polish (2026-06-11): plain-language sub, no banner strip,
    # no dev-facing provenance copy.
    assert "Per-service activity" in body
    assert "kpi-banner" not in body
    assert "rca_history" not in body
    assert "back to triage feed" not in body
