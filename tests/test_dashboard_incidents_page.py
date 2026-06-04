"""S5-INC-02 — /dashboard/incidents real page.

SSR-verified via the ASGI transport (render, not curl): the page is
server-rendered HTML, so driving it through httpx+ASGITransport renders the
full document without a browser. Asserts 200, theme head-script present, and a
seeded incident row rendered. Also asserts dismissed incidents are hidden.
"""
import os
import tempfile
from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as app_main
from app.models import RCARecord
from app.rca_store import RCAStore


@pytest_asyncio.fixture
async def client_with_incidents():
    db_path = os.path.join(tempfile.gettempdir(), "test_dash_incidents.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    store = RCAStore(db_path)
    await store.init_db()

    t0 = datetime(2026, 6, 1, 10, 0, 0)
    # Incident A — escalate, two fires (so duration is non-zero).
    await store.save_decision(RCARecord(
        alert_name="HighP95Latency", alert_fingerprint="fp-A",
        affected_service="spring-boot", severity="warning",
        triage_decision="investigate", llm_verdict="escalate",
        action_taken="emailed", timestamp=t0))
    await store.save_decision(RCARecord(
        alert_name="HighP95Latency", alert_fingerprint="fp-A",
        affected_service="spring-boot", severity="critical",
        triage_decision="investigate", llm_verdict="escalate",
        action_taken="emailed", timestamp=t0 + timedelta(hours=2)))
    # Incident B — dismissed, must be hidden.
    await store.save_decision(RCARecord(
        alert_name="FlappyDisk", alert_fingerprint="fp-B",
        affected_service="kong", severity="warning",
        triage_decision="investigate", llm_verdict="dismiss",
        action_taken="suppressed", timestamp=t0))

    saved = app_main._store
    app_main._store = store
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app_main._store = saved
    await store.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.mark.asyncio
async def test_incidents_page_renders(client_with_incidents):
    r = await client_with_incidents.get("/dashboard/incidents")
    assert r.status_code == 200
    body = r.text
    # Theme head-script (FE-L1).
    head = body.split("</head>", 1)[0]
    assert "obs-rca-theme" in head
    assert 'setAttribute("data-theme"' in head
    # Escalated incident row rendered.
    assert "HighP95Latency" in body
    assert "spring-boot" in body
    # Fire count of 2 shows.
    assert ">2<" in body
    # Dismissed incident hidden.
    assert "FlappyDisk" not in body


@pytest.mark.asyncio
async def test_incidents_page_empty_db_does_not_500():
    db_path = os.path.join(tempfile.gettempdir(), "test_dash_incidents_empty.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    store = RCAStore(db_path)
    await store.init_db()
    saved = app_main._store
    app_main._store = store
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    try:
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/dashboard/incidents")
        assert r.status_code == 200
        assert "No open incidents" in r.text
    finally:
        app_main._store = saved
        await store.close()
        if os.path.exists(db_path):
            os.unlink(db_path)
