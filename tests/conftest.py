import os
import tempfile

import pytest
import pytest_asyncio

# Use temp DB for tests
os.environ["RCA_DB_PATH"] = os.path.join(tempfile.gettempdir(), "test_rca.db")
os.environ["DRAIN3_STATE_DIR"] = os.path.join(tempfile.gettempdir(), "test_drain3")
os.environ["LOKI_API_URL"] = "http://localhost:3100"
os.environ["OLLAMA_URL"] = "http://localhost:11434"

from app.models import GrafanaAlert, GrafanaWebhook


@pytest.fixture
def sample_alert() -> GrafanaAlert:
    return GrafanaAlert(
        status="firing",
        labels={
            "alertname": "HighP95Latency",
            "instance": "10.0.2.30:8080",
            "severity": "warning",
            "job": "app-spring-actuator",
        },
        annotations={
            "summary": "P95 request latency exceeds 1s",
            "description": "The 95th percentile latency has been above 1000ms for 2 minutes.",
        },
        startsAt="2026-04-05T10:30:00Z",
        fingerprint="abc123",
    )


@pytest.fixture
def sample_webhook(sample_alert) -> GrafanaWebhook:
    return GrafanaWebhook(
        receiver="triage-webhook",
        status="firing",
        alerts=[sample_alert],
        groupLabels={"alertname": "HighP95Latency"},
        commonLabels={"severity": "warning"},
    )
