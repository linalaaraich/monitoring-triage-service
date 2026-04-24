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


def _is_empty_json_list(s) -> bool:
    """True if the value is missing, or represents an empty list.

    Accepts both JSON-serialized strings (as stored in the DB) and raw
    Python lists (as emitted by the LLM parser). The classifier is called
    from both the pipeline (raw lists) and the store (JSON strings).
    """
    if s is None:
        return True
    if isinstance(s, (list, tuple)):
        return len(s) == 0
    if isinstance(s, str):
        s = s.strip()
        return s in ("", "null", "[]")
    return False


def _classify_rca_quality(
    rca_report: str | None,
    reasoning: str | None,
    suggested_actions: str | None = None,
    evidence: str | None = None,
) -> str:
    """Tag a decision as 'actionable', 'data_starved', or 'needs_review'.

    Ordering matters — most severe tag wins:
    1. needs_review: the LLM produced no actions AND no evidence. The RCA
       prose may SOUND confident, but without a single concrete action
       or cited value an operator can't act on it. We would rather surface
       this as "a human should look" than pretend it's actionable.
    2. data_starved: the RCA text explicitly hedged with phrases like
       "insufficient data", "cannot determine". These get surfaced in
       future prompts so the LLM sees its past hedges and doesn't repeat.
    3. actionable: everything else.

    Missing a tag (false negative) is cheaper than a false positive that
    teaches the LLM to avoid the right phrases — err on NOT flagging.
    """
    import re
    combined = " ".join(filter(None, [rca_report or "", reasoning or ""])).lower()
    if not combined.strip():
        return "data_starved"

    # Rule 1: no actions + no evidence -> needs_review regardless of prose.
    # The dashboard's prior behavior was to call empty-but-confident RCAs
    # "actionable," which lied to the operator. Either the LLM emitted
    # zero concrete artifacts or the parser dropped them — either way the
    # human needs to look at it, not trust the tag.
    if _is_empty_json_list(suggested_actions) and _is_empty_json_list(evidence):
        return "needs_review"

    # Rule 2: hedge phrases anywhere in the narrative.
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
        # Additive migrations for pre-existing databases. SQLite has no
        # IF NOT EXISTS for ADD COLUMN so we probe the schema first. Each
        # column here must be nullable — we never back-fill historical
        # rows, we just let them stay NULL until they age out.
        cursor = await self._db.execute("PRAGMA table_info(rca_history)")
        cols = {row["name"] for row in await cursor.fetchall()}
        new_columns = [
            ("rca_quality",       "TEXT"),
            ("alert_instance",    "TEXT"),
            ("alert_component",   "TEXT"),
            ("alert_signal",      "TEXT"),
            ("observed_value",    "TEXT"),
            ("promql_expr",       "TEXT"),
            ("suggested_actions", "TEXT"),  # JSON list
            ("evidence",          "TEXT"),  # JSON list
            ("anomaly_summary",   "TEXT"),
            ("correlated_alerts", "TEXT"),  # JSON list
        ]
        for name, sql_type in new_columns:
            if name not in cols:
                logger.info("Migrating rca_history: adding column %s", name)
                await self._db.execute(
                    f"ALTER TABLE rca_history ADD COLUMN {name} {sql_type}"
                )
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
            record.rca_quality = _classify_rca_quality(
                record.rca_report,
                record.llm_reasoning,
                record.suggested_actions,
                record.evidence,
            )

        await self._db.execute(
            """INSERT INTO rca_history
               (id, timestamp, alert_source, alert_name, alert_fingerprint,
                affected_service, severity, triage_decision, llm_verdict,
                llm_confidence, rca_report, llm_reasoning, action_taken,
                related_alerts, investigation_duration_ms, rca_quality,
                alert_instance, alert_component, alert_signal, observed_value,
                promql_expr, suggested_actions, evidence, anomaly_summary,
                correlated_alerts)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                       ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                record.alert_instance,
                record.alert_component,
                record.alert_signal,
                record.observed_value,
                record.promql_expr,
                record.suggested_actions,
                record.evidence,
                record.anomaly_summary,
                record.correlated_alerts,
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

    async def get_correlated_alerts(
        self, fingerprint: str, at: datetime, window_minutes: int = 5
    ) -> list[dict]:
        """Return other alerts fired within ±window_minutes of `at`, excluding
        the one identified by `fingerprint` (the alert currently being processed).

        Used to give the LLM context on cascades — e.g. if MediumCpuUsage and
        HighP95Latency fire within 90s of each other, the LLM should reason
        about them together rather than treating either in isolation.

        Time window is bidirectional because Grafana notifications can lag the
        actual fire time by the evaluation interval + alertmanager debounce,
        so a "following" alert may have a slightly earlier timestamp than the
        one we're processing.
        """
        start = (at - timedelta(minutes=window_minutes)).isoformat()
        end = (at + timedelta(minutes=window_minutes)).isoformat()
        cursor = await self._db.execute(
            """SELECT timestamp, alert_name, affected_service, severity,
                      llm_verdict, rca_quality
               FROM rca_history
               WHERE timestamp BETWEEN ? AND ?
                 AND (alert_fingerprint != ? OR alert_fingerprint IS NULL)
               ORDER BY timestamp DESC
               LIMIT 20""",
            (start, end, fingerprint or ""),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

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
