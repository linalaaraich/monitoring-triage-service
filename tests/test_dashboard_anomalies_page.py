"""S5-INC-04 — /dashboard/anomalies real page (detective signals).

SSR-verified through the ASGI transport (render, not curl). Asserts 200, theme
head-script in <head>, all four signal sections present, and that the
recurrence-gate signal renders a seeded persisted fire. Signals (b) and (d)
carry the honest "not yet persisted" note.
"""
import os
import tempfile
from datetime import datetime

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as app_main
from app.rca_store import RCAStore


@pytest_asyncio.fixture
async def client_with_anomalies():
    db_path = os.path.join(tempfile.gettempdir(), "test_dash_anomalies.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    store = RCAStore(db_path)
    await store.init_db()

    # Seed a persisted recurrence-gate fire (signal c).
    now = datetime.utcnow().isoformat()
    await store._db.execute(
        """INSERT INTO rca_history
           (id, timestamp, alert_source, alert_name, alert_fingerprint,
            affected_service, severity, triage_decision, action_taken)
           VALUES ('rg1', ?, 'grafana', 'FlappyCPU', 'fp-rg',
                   'kong', 'warning', 'recurrence_gated_pre_llm', 'suppressed')""",
        (now,),
    )
    await store._db.commit()

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
async def test_anomalies_page_renders_all_sections(client_with_anomalies):
    r = await client_with_anomalies.get("/dashboard/anomalies")
    assert r.status_code == 200
    body = r.text
    head = body.split("</head>", 1)[0]
    assert "obs-rca-theme" in head
    assert 'setAttribute("data-theme"' in head
    # All four signal sections present.
    assert "Drain3 novel templates" in body
    assert "Recurrence-gate fires" in body
    assert "Entity-baseline" in body
    assert "Adaptive-threshold" in body
    # Honest "not yet persisted" note on the two unpersisted signals.
    assert "not yet persisted for historical view" in body
    # Seeded recurrence-gate fire surfaced.
    assert "FlappyCPU" in body


@pytest.mark.asyncio
async def test_recurrence_gate_fires_store_method():
    db_path = os.path.join(tempfile.gettempdir(), "test_rgfires.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    store = RCAStore(db_path)
    await store.init_db()
    try:
        now = datetime.utcnow().isoformat()
        for i in range(2):
            await store._db.execute(
                """INSERT INTO rca_history
                   (id, timestamp, alert_source, alert_name, alert_fingerprint,
                    affected_service, severity, triage_decision, action_taken)
                   VALUES (?, ?, 'grafana', 'A', 'fp', 'svc', 'warning',
                           'recurrence_gated_pre_llm', 'suppressed')""",
                (f"r{i}", now),
            )
        await store._db.commit()
        out = await store.get_recurrence_gate_fires(hours=24)
        assert out["total"] == 2
        assert out["by_alert"][0]["alert_name"] == "A"
        assert out["by_alert"][0]["count"] == 2
    finally:
        await store.close()
        if os.path.exists(db_path):
            os.unlink(db_path)
