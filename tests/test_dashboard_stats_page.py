"""S5-INC-03 — /dashboard/stats real page (aggregate insights).

SSR-verified through the ASGI transport (render, not curl). Asserts 200, theme
head-script in <head>, and at least one aggregate rendered (a seeded noisiest
alert + an escalated service).
"""
import os
import tempfile
from datetime import datetime

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as app_main
from app.models import RCARecord
from app.rca_store import RCAStore


@pytest_asyncio.fixture
async def client_with_stats():
    db_path = os.path.join(tempfile.gettempdir(), "test_dash_stats.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    store = RCAStore(db_path)
    await store.init_db()

    now = datetime.utcnow()
    # Two escalates on spring-boot for HighP95Latency, one dismiss on kong.
    for i in range(2):
        await store.save_decision(RCARecord(
            alert_name="HighP95Latency", alert_fingerprint=f"fp-x{i}",
            affected_service="spring-boot", severity="warning",
            triage_decision="investigate", llm_verdict="escalate",
            action_taken="emailed", timestamp=now))
    await store.save_decision(RCARecord(
        alert_name="DiskNoise", alert_fingerprint="fp-y",
        affected_service="kong", severity="warning",
        triage_decision="investigate", llm_verdict="dismiss",
        action_taken="suppressed", timestamp=now))

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
async def test_stats_page_renders_aggregates(client_with_stats):
    r = await client_with_stats.get("/dashboard/stats")
    assert r.status_code == 200
    body = r.text
    head = body.split("</head>", 1)[0]
    assert "obs-rca-theme" in head
    assert 'setAttribute("data-theme"' in head
    # Noisiest alerts aggregate rendered.
    assert "HighP95Latency" in body
    # Most-escalated services aggregate rendered.
    assert "spring-boot" in body
    # False-positive proxy section present.
    assert "False-positive proxy" in body


@pytest.mark.asyncio
async def test_stats_aggregates_store_method():
    db_path = os.path.join(tempfile.gettempdir(), "test_stats_agg.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    store = RCAStore(db_path)
    await store.init_db()
    try:
        now = datetime.utcnow()
        await store.save_decision(RCARecord(
            alert_name="A", alert_fingerprint="fp1", affected_service="svc1",
            llm_verdict="escalate", action_taken="emailed", timestamp=now))
        agg = await store.get_stats_aggregates(days=7)
        assert agg["noisiest_alerts"][0]["alert_name"] == "A"
        assert agg["escalated_services"][0]["service"] == "svc1"
        # No ratings → false-positive proxy not wired.
        assert agg["false_positive"]["wired"] is False
        assert agg["false_positive"]["rate"] is None
    finally:
        await store.close()
        if os.path.exists(db_path):
            os.unlink(db_path)
