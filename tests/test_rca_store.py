import os
import tempfile

import pytest
import pytest_asyncio

from app.models import RCARecord
from app.rca_store import RCAStore


@pytest_asyncio.fixture
async def store():
    db_path = os.path.join(tempfile.gettempdir(), "test_rca_store.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    os.unlink(db_path)


@pytest.mark.asyncio
async def test_save_and_retrieve(store):
    record = RCARecord(
        alert_name="HighP95Latency",
        alert_fingerprint="abc123",
        affected_service="spring-boot",
        severity="warning",
        triage_decision="investigate",
        llm_verdict="valid",
        rca_report="DB pool exhausted",
        action_taken="emailed",
        investigation_duration_ms=5000,
    )
    await store.save_decision(record)

    decisions = await store.get_decisions(limit=10)
    assert len(decisions) == 1
    assert decisions[0]["alert_name"] == "HighP95Latency"
    assert decisions[0]["action_taken"] == "emailed"


@pytest.mark.asyncio
async def test_filter_by_alert_name(store):
    for name in ["HighP95Latency", "HighCpuUsage", "HighP95Latency"]:
        await store.save_decision(
            RCARecord(alert_name=name, triage_decision="investigate", action_taken="emailed")
        )

    all_decisions = await store.get_decisions(limit=50)
    assert len(all_decisions) == 3

    filtered = await store.get_decisions(limit=50, alert_name="HighP95Latency")
    assert len(filtered) == 2


@pytest.mark.asyncio
async def test_alert_frequency(store):
    for _ in range(5):
        await store.save_decision(
            RCARecord(alert_name="TargetDown", triage_decision="investigate", action_taken="emailed")
        )

    freq = await store.get_alert_frequency("TargetDown", days=7)
    assert freq["count"] == 5
    assert freq["last_seen"] is not None


@pytest.mark.asyncio
async def test_alert_frequency_empty(store):
    freq = await store.get_alert_frequency("NonExistent", days=7)
    assert freq["count"] == 0
    assert freq["last_seen"] is None


@pytest.mark.asyncio
async def test_recent_decision_lookup_hits(store):
    # Fresh decision from a minute ago should be returned
    await store.save_decision(
        RCARecord(
            alert_name="PostSchemaFix_v2",
            affected_service="spring-boot",
            triage_decision="investigate",
            llm_verdict="dismiss",
            action_taken="suppressed",
        )
    )
    recent = await store.get_recent_decision_for_alert(
        alert_name="PostSchemaFix_v2",
        affected_service="spring-boot",
        lookback_minutes=15,
    )
    assert recent is not None
    assert recent["llm_verdict"] == "dismiss"


@pytest.mark.asyncio
async def test_recent_decision_lookup_service_mismatch(store):
    await store.save_decision(
        RCARecord(
            alert_name="PostSchemaFix_v2",
            affected_service="spring-boot",
            triage_decision="investigate",
            llm_verdict="dismiss",
            action_taken="suppressed",
        )
    )
    # Different service -> no match
    recent = await store.get_recent_decision_for_alert(
        alert_name="PostSchemaFix_v2",
        affected_service="kong",
        lookback_minutes=15,
    )
    assert recent is None
