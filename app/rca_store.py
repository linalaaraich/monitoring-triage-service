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
    investigation_duration_ms INTEGER DEFAULT 0,
    rca_quality TEXT
)
"""


def _classify_rca_quality(rca_report: str | None, reasoning: str | None) -> str:
    """Tag a decision as 'actionable' or 'data_starved'.

    Pure regex-based post-hoc classifier — runs on the final RCA text AFTER
    the LLM produces it. 'data_starved' means the model hedged with
    phrases like 'insufficient data', 'no recent data', 'cannot determine'
    rather than naming a cause. These records get surfaced in future
    prompts so the model sees its past hedges and doesn't default to them.

    Keep the classifier simple — missing a tag (false negative) is much
    cheaper than a false positive that teaches the LLM to avoid the right
    phrases. Err on the side of NOT flagging.
    """
    import re
    combined = " ".join(filter(None, [rca_report or "", reasoning or ""])).lower()
    if not combined.strip():
        return "data_starved"

    # Phrases that nearly always mean the LLM gave up. Be strict about the
    # pattern — "data" alone is common in good RCAs, so we anchor on
    # explicit hedge words before/after it.
    hedge_patterns = [
        r"\binsufficient (?:data|information|context)\b",
        r"\bno (?:recent |available )?(?:metrics|logs|traces|data)\b",
        r"\b(?:cannot|unable to) (?:determine|identify|conclude)\b",
        r"\bnot enough (?:data|information|context)\b",
        r"\black(?:s|ing)? (?:sufficient |enough )?(?:data|context|information)\b",
        r"\bempty (?:metrics|logs|traces|context)\b",
    ]
    for pat in hedge_patterns:
        if re.search(pat, combined):
            return "data_starved"
    return "actionable"


class RCAStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def init_db(self):
        self._db = await aiosqlite.connect(self.db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute(CREATE_TABLE)
        # Additive migration for pre-existing databases that predate the
        # rca_quality column. SQLite has no IF NOT EXISTS for ADD COLUMN,
        # so we probe the schema first.
        cursor = await self._db.execute("PRAGMA table_info(rca_history)")
        cols = {row["name"] for row in await cursor.fetchall()}
        if "rca_quality" not in cols:
            logger.info("Migrating rca_history: adding rca_quality column")
            await self._db.execute("ALTER TABLE rca_history ADD COLUMN rca_quality TEXT")
        await self._db.commit()
        logger.info("RCA history database initialized at %s", self.db_path)

    async def close(self):
        if self._db:
            await self._db.close()

    async def save_decision(self, record: RCARecord):
        # Classify on write so every row has a quality tag, regardless of
        # whether the producer thought to set it. Keeps the pipeline code
        # from having to know about the classifier.
        if record.rca_quality is None:
            record.rca_quality = _classify_rca_quality(record.rca_report, record.llm_reasoning)

        await self._db.execute(
            """INSERT INTO rca_history
               (id, timestamp, alert_source, alert_name, alert_fingerprint,
                affected_service, severity, triage_decision, llm_verdict,
                llm_confidence, rca_report, llm_reasoning, action_taken,
                related_alerts, investigation_duration_ms, rca_quality)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                record.rca_quality,
            ),
        )
        await self._db.commit()
        logger.info(
            "Saved RCA decision %s for alert %s (quality=%s)",
            record.id, record.alert_name, record.rca_quality,
        )

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

    async def get_recent_decision_for_alert(
        self, alert_name: str, affected_service: str, lookback_minutes: int
    ) -> dict | None:
        """Most recent decision for (alert_name, service) within the lookback window.

        Used by Layer 2 pre-LLM triage to skip the Ollama call when the same
        alert was recently processed — if we just dismissed it, dismiss again;
        if we just suppressed it, suppress again.
        """
        since = (datetime.utcnow() - timedelta(minutes=lookback_minutes)).isoformat()
        cursor = await self._db.execute(
            """SELECT triage_decision, llm_verdict, action_taken, rca_report, timestamp
               FROM rca_history
               WHERE alert_name = ? AND affected_service = ? AND timestamp > ?
               ORDER BY timestamp DESC LIMIT 1""",
            (alert_name, affected_service, since),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

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

        # Also count data_starved hedges in the window — these are the ones
        # that should push the model to do better next time. Surfaced into
        # the LLM prompt via pipeline.py.
        cursor = await self._db.execute(
            """SELECT COUNT(*) as count FROM rca_history
               WHERE alert_name = ? AND timestamp > ? AND rca_quality = 'data_starved'""",
            (alert_name, since),
        )
        row = await cursor.fetchone()
        data_starved_count = row["count"] if row else 0

        return {
            "count": count,
            "days": days,
            "last_seen": last_seen,
            "data_starved_count": data_starved_count,
        }

    async def get_recent_data_starved_rcas(
        self, alert_name: str, affected_service: str, limit: int = 3
    ) -> list[dict]:
        """Return the N most recent data_starved RCA texts for this alert.

        Used to teach the LLM what hedges it's been producing so it can
        avoid repeating them — the prompt quotes these back verbatim
        with explicit instruction to do better.
        """
        cursor = await self._db.execute(
            """SELECT timestamp, rca_report, llm_reasoning
               FROM rca_history
               WHERE alert_name = ?
                 AND affected_service = ?
                 AND rca_quality = 'data_starved'
               ORDER BY timestamp DESC
               LIMIT ?""",
            (alert_name, affected_service, limit),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
