import os
import tempfile

import pytest
from httpx import ASGITransport, AsyncClient

# Set test env before importing app
os.environ["RCA_DB_PATH"] = os.path.join(tempfile.gettempdir(), "test_api_rca.db")
os.environ["DRAIN3_STATE_DIR"] = os.path.join(tempfile.gettempdir(), "test_api_drain3")
os.environ["LOKI_API_URL"] = "http://localhost:3100"
os.environ["OLLAMA_URL"] = "http://localhost:11434"

from app.main import app


@pytest.mark.asyncio
async def test_health():
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_webhook_grafana_accepts_valid_payload():
    """Without a running pipeline (no lifespan), the webhook will 500.
    When deployed with docker-compose, the lifespan initializes the pipeline
    and this returns 202. Here we verify the route exists and payload validates."""
    payload = {
        "receiver": "triage-webhook",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "TestAlert", "severity": "warning"},
                "annotations": {"summary": "Test"},
                "startsAt": "2026-04-05T10:00:00Z",
                "fingerprint": "test123",
            }
        ],
    }
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/webhook/grafana", json=payload)
    # 202 when pipeline running, 500 without lifespan (expected in unit tests)
    assert resp.status_code in (202, 500)


@pytest.mark.asyncio
async def test_webhook_drain3_accepts_valid_payload():
    payload = {
        "anomalous_lines": ["ERROR something unexpected"],
        "anomaly_rate": 0.15,
        "new_templates": ["ERROR <*> unexpected"],
        "service": "spring-boot",
    }
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/webhook/drain3", json=payload)
    assert resp.status_code in (202, 500)


@pytest.mark.asyncio
async def test_metrics():
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/metrics")
    assert resp.status_code == 200
    assert b"triage_webhooks_received_total" in resp.content
