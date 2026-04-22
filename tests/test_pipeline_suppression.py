"""Layer 2 pre-LLM suppression tests."""
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from app.config import settings
from app.models import Decision, GrafanaAlert, LLMDecision, RCARecord
from app.pipeline import TriagePipeline
from app.rca_store import RCAStore


@pytest_asyncio.fixture
async def fresh_store():
    db_path = os.path.join(tempfile.gettempdir(), "test_suppression.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    os.unlink(db_path)


def make_pipeline(store: RCAStore) -> TriagePipeline:
    return TriagePipeline(
        rca_store=store,
        drain=MagicMock(),
        context_gatherer=MagicMock(),
        llm_client=MagicMock(),
        notifier=MagicMock(send_escalation=AsyncMock(), send_timeout_alert=AsyncMock()),
        dedup=MagicMock(check=AsyncMock(return_value=False)),
    )


def make_alert(name="PostSchemaFix_v2", service="spring-boot") -> GrafanaAlert:
    return GrafanaAlert(
        status="firing",
        labels={"alertname": name, "service": service, "severity": "warning"},
        annotations={"summary": "x", "description": "y"},
        startsAt="2026-04-22T15:46:30Z",
    )


@pytest.mark.asyncio
async def test_suppresses_when_recent_dismiss_exists(fresh_store):
    await fresh_store.save_decision(
        RCARecord(
            alert_name="PostSchemaFix_v2",
            affected_service="spring-boot",
            triage_decision="investigate",
            llm_verdict="dismiss",
            action_taken="suppressed",
        )
    )
    pipeline = make_pipeline(fresh_store)
    alert = make_alert()
    reason = await pipeline._check_suppression(alert)
    assert reason == "recent_dismissed_history"


@pytest.mark.asyncio
async def test_does_not_suppress_when_no_prior_decision(fresh_store):
    pipeline = make_pipeline(fresh_store)
    alert = make_alert()
    reason = await pipeline._check_suppression(alert)
    assert reason is None


@pytest.mark.asyncio
async def test_does_not_suppress_when_prior_escalate(fresh_store):
    await fresh_store.save_decision(
        RCARecord(
            alert_name="PostSchemaFix_v2",
            affected_service="spring-boot",
            triage_decision="investigate",
            llm_verdict="escalate",
            action_taken="emailed",
        )
    )
    pipeline = make_pipeline(fresh_store)
    alert = make_alert()
    reason = await pipeline._check_suppression(alert)
    assert reason is None


@pytest.mark.asyncio
async def test_suppresses_on_prior_triage_suppression(fresh_store):
    await fresh_store.save_decision(
        RCARecord(
            alert_name="PostSchemaFix_v2",
            affected_service="spring-boot",
            triage_decision="triage_suppressed",
            llm_verdict=None,
            action_taken="suppressed",
        )
    )
    pipeline = make_pipeline(fresh_store)
    alert = make_alert()
    reason = await pipeline._check_suppression(alert)
    assert reason == "recent_suppressed_history"


@pytest.mark.asyncio
async def test_disabled_flag_respected(fresh_store, monkeypatch):
    await fresh_store.save_decision(
        RCARecord(
            alert_name="PostSchemaFix_v2",
            affected_service="spring-boot",
            triage_decision="investigate",
            llm_verdict="dismiss",
            action_taken="suppressed",
        )
    )
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)
    pipeline = make_pipeline(fresh_store)
    alert = make_alert()
    reason = await pipeline._check_suppression(alert)
    assert reason is None
