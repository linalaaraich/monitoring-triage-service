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
async def test_get_decisions_decodes_json_columns(store):
    """Regression for the API-shape bug found 2026-04-28 PM-late.

    `suggested_actions` and `evidence` are stored as TEXT (JSON-encoded
    list-of-strings — the RCARecord model carries them as Optional[str]
    so callers serialize before saving). The /decisions handler used to
    return the raw row dict, leaking the storage shape — external
    consumers got a STRING `'["kubectl rollout restart..."]'` instead
    of a real list. The audit-live cron's mechanical-check
    `(.suggested_actions | length)` ended up counting characters not
    items (84 chars looked like 84 actions).

    get_decisions() now decodes both columns at the boundary."""
    import json as _json
    record = RCARecord(
        alert_name="HighKongP95Latency",
        triage_decision="investigate",
        suggested_actions=_json.dumps([
            "kubectl rollout restart deploy/kong-kong -n network",
            "kubectl scale deploy/kong-kong -n network --replicas=2",
        ]),
        evidence=_json.dumps([
            "histogram_quantile(0.95, ...) = 8487 ms",
            "kong upstream latency p95 = 8.4s",
        ]),
        action_taken="emailed",
    )
    await store.save_decision(record)

    decisions = await store.get_decisions(limit=10)
    assert len(decisions) == 1
    row = decisions[0]

    assert isinstance(row["suggested_actions"], list), (
        f"suggested_actions must be a list, got {type(row['suggested_actions']).__name__}"
    )
    assert len(row["suggested_actions"]) == 2
    assert "kubectl rollout restart deploy/kong-kong -n network" in row["suggested_actions"]

    assert isinstance(row["evidence"], list)
    assert len(row["evidence"]) == 2
    assert any("histogram_quantile" in e for e in row["evidence"])


@pytest.mark.asyncio
async def test_get_decisions_tolerates_empty_and_null_columns(store):
    """Defensive: rows with NULL or empty-JSON suggested_actions / evidence
    (legacy rows, dedup short-paths) shouldn't 500. The boundary decoder
    leaves None alone except to default it to []."""
    import json as _json
    record = RCARecord(
        alert_name="TargetDown",
        triage_decision="triage_suppressed",
        suggested_actions=_json.dumps([]),
        evidence=_json.dumps([]),
        action_taken="suppressed",
    )
    await store.save_decision(record)

    decisions = await store.get_decisions(limit=10)
    assert len(decisions) == 1
    # Empty input round-trips as []
    assert decisions[0]["suggested_actions"] == []
    assert decisions[0]["evidence"] == []


@pytest.mark.asyncio
async def test_get_decisions_tolerates_malformed_json(store):
    """Pre-fix rows persisted with a non-JSON string in the action/evidence
    columns shouldn't make the API 500. Decoder leaves the raw string in
    place rather than failing the whole request."""
    record = RCARecord(
        alert_name="Drain3AnomalyDetected",
        triage_decision="investigate",
        # Simulate a legacy row where someone wrote raw text instead of JSON
        suggested_actions="raw legacy free-text action",
        evidence="raw legacy free-text evidence",
        action_taken="emailed",
    )
    await store.save_decision(record)

    decisions = await store.get_decisions(limit=10)
    assert len(decisions) == 1
    # Raw non-JSON string is preserved, not parsed
    assert decisions[0]["suggested_actions"] == "raw legacy free-text action"
    assert decisions[0]["evidence"] == "raw legacy free-text evidence"


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
