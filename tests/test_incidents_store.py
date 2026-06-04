"""S5-INC-01 (Sprint 5 EPIC14) — incident entity table, write-time
maintenance, and idempotent backfill.

Covers:
  - incident created on a fingerprint's first fire (fire_count=1)
  - fire_count increments + last_seen advances on a repeat fingerprint
  - backfill_incidents() is idempotent (run twice → identical counts, no dupes)
  - rows with NULL/empty fingerprint are skipped (no incident, counted)
  - backfill leaves excluded_from_lookup untouched
"""
import os
import tempfile
from datetime import datetime, timedelta

import pytest
import pytest_asyncio

from app.models import RCARecord
from app.rca_store import RCAStore


@pytest_asyncio.fixture
async def store():
    db_path = os.path.join(tempfile.gettempdir(), "test_incidents_store.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    os.unlink(db_path)


def _rec(fp, **kw):
    base = dict(
        alert_name="HighP95Latency",
        alert_fingerprint=fp,
        affected_service="spring-boot",
        severity="warning",
        triage_decision="investigate",
        llm_verdict="escalate",
        action_taken="emailed",
    )
    base.update(kw)
    return RCARecord(**base)


@pytest.mark.asyncio
async def test_incident_created_on_first_fire(store):
    await store.save_decision(_rec("fp-aaa"))
    cur = await store._db.execute(
        "SELECT * FROM incidents WHERE fingerprint = ?", ("fp-aaa",)
    )
    row = await cur.fetchone()
    assert row is not None
    assert row["fire_count"] == 1
    assert row["first_seen"] == row["last_seen"]
    assert row["current_verdict"] == "escalate"
    assert row["alert_name"] == "HighP95Latency"
    assert row["affected_service"] == "spring-boot"

    # rca_history row got back-linked to the incident.
    cur = await store._db.execute(
        "SELECT incident_id FROM rca_history WHERE alert_fingerprint = ?", ("fp-aaa",)
    )
    rh = await cur.fetchone()
    assert rh["incident_id"] == row["id"]


@pytest.mark.asyncio
async def test_repeat_fingerprint_bumps_count_and_last_seen(store):
    t0 = datetime(2026, 6, 1, 10, 0, 0)
    t1 = datetime(2026, 6, 1, 12, 30, 0)
    await store.save_decision(_rec("fp-bbb", timestamp=t0, llm_verdict="escalate"))
    await store.save_decision(_rec("fp-bbb", timestamp=t1, llm_verdict="dismiss",
                                   severity="critical"))

    cur = await store._db.execute(
        "SELECT * FROM incidents WHERE fingerprint = ?", ("fp-bbb",)
    )
    row = await cur.fetchone()
    assert row["fire_count"] == 2
    assert row["first_seen"] == t0.isoformat()
    assert row["last_seen"] == t1.isoformat()
    # current_* reflects the most-recent fire.
    assert row["current_verdict"] == "dismiss"
    assert row["current_severity"] == "critical"

    # Exactly one incident for this fingerprint (UNIQUE held).
    cur = await store._db.execute(
        "SELECT COUNT(*) AS n FROM incidents WHERE fingerprint = ?", ("fp-bbb",)
    )
    assert (await cur.fetchone())["n"] == 1


@pytest.mark.asyncio
async def test_null_fingerprint_skips_incident_linkage(store):
    await store.save_decision(_rec("", llm_verdict="escalate"))  # empty fp
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM incidents")
    assert (await cur.fetchone())["n"] == 0
    cur = await store._db.execute(
        "SELECT incident_id FROM rca_history ORDER BY timestamp DESC LIMIT 1"
    )
    assert (await cur.fetchone())["incident_id"] is None


@pytest.mark.asyncio
async def test_backfill_idempotent_and_correct(store):
    # Seed rows directly so we exercise the backfill path (not write-time).
    t0 = datetime(2026, 6, 1, 9, 0, 0)
    for i in range(3):
        await store._db.execute(
            """INSERT INTO rca_history
               (id, timestamp, alert_source, alert_name, alert_fingerprint,
                affected_service, severity, triage_decision, llm_verdict,
                action_taken)
               VALUES (?, ?, 'grafana', 'HighCPUUsage', 'fp-ccc',
                       'kong', ?, 'investigate', ?, 'emailed')""",
            (f"row-c{i}", (t0 + timedelta(minutes=i * 10)).isoformat(),
             "warning" if i < 2 else "critical",
             "escalate" if i < 2 else "dismiss"),
        )
    # Two NULL-fingerprint rows that must be skipped.
    for i in range(2):
        await store._db.execute(
            """INSERT INTO rca_history
               (id, timestamp, alert_source, alert_name, alert_fingerprint,
                affected_service, severity, triage_decision, action_taken)
               VALUES (?, ?, 'grafana', 'NoFp', NULL, 'svc', 'warning',
                       'suppressed', 'suppressed')""",
            (f"row-null{i}", (t0 + timedelta(minutes=i)).isoformat()),
        )
    await store._db.commit()

    r1 = await store.backfill_incidents()
    assert r1 == {"incidents": 1, "rows_linked": 3, "skipped_no_fingerprint": 2}

    cur = await store._db.execute(
        "SELECT * FROM incidents WHERE fingerprint = ?", ("fp-ccc",)
    )
    inc = await cur.fetchone()
    assert inc["fire_count"] == 3
    assert inc["first_seen"] == t0.isoformat()
    assert inc["last_seen"] == (t0 + timedelta(minutes=20)).isoformat()
    # Most-recent row (i=2) → dismiss / critical.
    assert inc["current_verdict"] == "dismiss"
    assert inc["current_severity"] == "critical"

    # Second run → identical counts, no duplicate incident.
    r2 = await store.backfill_incidents()
    assert r2 == r1
    cur = await store._db.execute("SELECT COUNT(*) AS n FROM incidents")
    assert (await cur.fetchone())["n"] == 1


@pytest.mark.asyncio
async def test_backfill_does_not_touch_excluded_from_lookup(store):
    t0 = datetime(2026, 6, 1, 9, 0, 0)
    await store._db.execute(
        """INSERT INTO rca_history
           (id, timestamp, alert_source, alert_name, alert_fingerprint,
            affected_service, severity, triage_decision, llm_verdict,
            action_taken, excluded_from_lookup)
           VALUES ('row-q', ?, 'grafana', 'A', 'fp-q', 'svc', 'warning',
                   'investigate', 'escalate', 'emailed', 1)""",
        (t0.isoformat(),),
    )
    await store._db.commit()
    await store.backfill_incidents()
    cur = await store._db.execute(
        "SELECT excluded_from_lookup FROM rca_history WHERE id = 'row-q'"
    )
    assert (await cur.fetchone())["excluded_from_lookup"] == 1
