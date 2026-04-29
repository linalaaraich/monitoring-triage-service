import os
import tempfile
from datetime import datetime, timedelta

import pytest
import pytest_asyncio

from app.models import RCARecord
from app.rca_store import RCAStore


@pytest_asyncio.fixture
async def store():
    db_path = os.path.join(tempfile.gettempdir(), "test_dashboard_pagination.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    os.unlink(db_path)


def _record(alert_name: str = "HighP95Latency") -> RCARecord:
    return RCARecord(
        alert_name=alert_name,
        alert_fingerprint=f"fp-{alert_name}",
        affected_service="spring-boot",
        severity="warning",
        triage_decision="investigate",
        llm_verdict="escalate",
        rca_report="seed",
        action_taken="emailed",
        investigation_duration_ms=1000,
    )


async def _backdate(store: RCAStore, decision_id: str, days_ago: int) -> None:
    """Rewrite the timestamp on a freshly-saved row so we can simulate
    decisions that pre-date the current since_days window. Uses the
    store's open connection rather than opening a second one (sqlite
    locking)."""
    ts = (datetime.utcnow() - timedelta(days=days_ago)).isoformat()
    await store._db.execute(
        "UPDATE rca_history SET timestamp = ? WHERE id = ?",
        (ts, decision_id),
    )
    await store._db.commit()


async def _save(store: RCAStore, alert_name: str = "HighP95Latency") -> str:
    rec = _record(alert_name)
    await store.save_decision(rec)
    return rec.id


@pytest.mark.asyncio
async def test_offset_pagination(store):
    ids = [await _save(store, f"Alert{i}") for i in range(5)]

    page1 = await store.get_decisions(limit=2, offset=0)
    page2 = await store.get_decisions(limit=2, offset=2)
    page3 = await store.get_decisions(limit=2, offset=4)

    assert len(page1) == 2
    assert len(page2) == 2
    assert len(page3) == 1
    # No row should appear on two pages.
    seen = {r["id"] for r in page1} | {r["id"] for r in page2} | {r["id"] for r in page3}
    assert len(seen) == 5
    assert seen == set(ids)


@pytest.mark.asyncio
async def test_since_days_filter_excludes_old_rows(store):
    fresh_id = await _save(store, "Fresh")
    old_id = await _save(store, "Old")
    await _backdate(store, old_id, days_ago=30)

    fifteen_day = await store.get_decisions(limit=50, since_days=15)
    thirty_day = await store.get_decisions(limit=50, since_days=45)

    fifteen_ids = {r["id"] for r in fifteen_day}
    thirty_ids = {r["id"] for r in thirty_day}
    assert fresh_id in fifteen_ids
    assert old_id not in fifteen_ids
    assert old_id in thirty_ids


@pytest.mark.asyncio
async def test_count_decisions_respects_window(store):
    for i in range(3):
        await _save(store, f"Recent{i}")
    old_id = await _save(store, "Stale")
    await _backdate(store, old_id, days_ago=20)

    assert await store.count_decisions() == 4
    assert await store.count_decisions(since_days=15) == 3
    assert await store.count_decisions(since_days=30) == 4


@pytest.mark.asyncio
async def test_count_decisions_respects_alert_name(store):
    await _save(store, "Foo")
    await _save(store, "Foo")
    await _save(store, "Bar")

    assert await store.count_decisions(alert_name="Foo") == 2
    assert await store.count_decisions(alert_name="Bar") == 1
    assert await store.count_decisions(alert_name="Missing") == 0
