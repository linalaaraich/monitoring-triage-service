import json
import logging
from datetime import datetime, timedelta

import aiosqlite

from app.models import RCARecord

logger = logging.getLogger(__name__)

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS rca_history (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    alert_source TEXT NOT NULL,
    alert_name TEXT NOT NULL,
    alert_fingerprint TEXT,
    affected_service TEXT,
    severity TEXT,
    triage_decision TEXT NOT NULL,
    llm_verdict TEXT,
    llm_confidence TEXT,
    rca_report TEXT,
    llm_reasoning TEXT,
    action_taken TEXT NOT NULL,
    related_alerts TEXT,
    investigation_duration_ms INTEGER DEFAULT 0
)
"""


class RCAStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def init_db(self):
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute(CREATE_TABLE)
        await self._db.commit()
        logger.info("RCA history database initialized at %s", self.db_path)

    async def close(self):
        if self._db:
            await self._db.close()

    async def save_decision(self, record: RCARecord):
        await self._db.execute(
            """INSERT INTO rca_history
               (id, timestamp, alert_source, alert_name, alert_fingerprint,
                affected_service, severity, triage_decision, llm_verdict,
                llm_confidence, rca_report, llm_reasoning, action_taken,
                related_alerts, investigation_duration_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.id,
                record.timestamp.isoformat(),
                record.alert_source,
                record.alert_name,
                record.alert_fingerprint,
                record.affected_service,
                record.severity,
                record.triage_decision,
                record.llm_verdict,
                record.llm_confidence,
                record.rca_report,
                record.llm_reasoning,
                record.action_taken,
                record.related_alerts,
                record.investigation_duration_ms,
            ),
        )
        await self._db.commit()
        logger.info("Saved RCA decision %s for alert %s", record.id, record.alert_name)

    async def get_decisions(
        self, limit: int = 50, alert_name: str | None = None
    ) -> list[dict]:
        if alert_name:
            cursor = await self._db.execute(
                "SELECT * FROM rca_history WHERE alert_name = ? ORDER BY timestamp DESC LIMIT ?",
                (alert_name, limit),
            )
        else:
            cursor = await self._db.execute(
                "SELECT * FROM rca_history ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_alert_frequency(self, alert_name: str, days: int = 7) -> dict:
        since = (datetime.utcnow() - timedelta(days=days)).isoformat()
        cursor = await self._db.execute(
            "SELECT COUNT(*) as count FROM rca_history WHERE alert_name = ? AND timestamp > ?",
            (alert_name, since),
        )
        row = await cursor.fetchone()
        count = row["count"] if row else 0

        cursor = await self._db.execute(
            "SELECT timestamp FROM rca_history WHERE alert_name = ? ORDER BY timestamp DESC LIMIT 1",
            (alert_name,),
        )
        last = await cursor.fetchone()
        last_seen = last["timestamp"] if last else None

        return {"count": count, "days": days, "last_seen": last_seen}
