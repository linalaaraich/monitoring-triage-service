import json
import logging
from datetime import UTC, datetime, timedelta

import aiosqlite

from app.models import RCARecord

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    """Naive UTC timestamp matching the wire format already in the DB.

    Returns a tzinfo-stripped datetime so .isoformat() produces bare ISO
    strings (no +00:00 suffix), matching every other timestamp already
    persisted in rca_history.timestamp. Drop-in replacement for the
    deprecated _utc_now() — silences DeprecationWarnings without
    changing the wire format.
    """
    return datetime.now(UTC).replace(tzinfo=None)

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

# US-5.3 closed-loop feedback. One row per (decision_id, feedback_type) —
# operators can ratify a decision with /feedback/confirm or override it
# with /feedback/override. Overrides have an active window during which
# similar future alerts force-escalate (the pre-LLM similarity gate);
# confirms are timeless ratifications used for precision/recall metrics.
#
# active_until is nullable: confirms don't expire, overrides do (default 14
# days from create). The pre-LLM gate filters on `feedback_type='override'
# AND active_until > now`.
CREATE_FEEDBACK_TABLE = """
CREATE TABLE IF NOT EXISTS feedback (
    id TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL,
    feedback_type TEXT NOT NULL,
    operator_note TEXT,
    created_at TEXT NOT NULL,
    active_until TEXT,
    FOREIGN KEY(decision_id) REFERENCES rca_history(id),
    UNIQUE(decision_id, feedback_type)
)
"""

CREATE_FEEDBACK_INDEX_DECISION = """
CREATE INDEX IF NOT EXISTS idx_feedback_decision ON feedback(decision_id)
"""

CREATE_FEEDBACK_INDEX_ACTIVE = """
CREATE INDEX IF NOT EXISTS idx_feedback_active ON feedback(feedback_type, active_until)
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
    # 2026-06-02 — rca_report may now be a JSON envelope (human-first reason
    # refactor: {"human_cause": "...", "rca": "...", "schema": "v2"}). Decode
    # to scan both fields for hedge phrases; legacy raw-text rows fall
    # through the try/except and get scanned as-is.
    rca_text_for_scan = rca_report or ""
    if rca_text_for_scan.startswith("{"):
        try:
            envelope = json.loads(rca_text_for_scan)
            if isinstance(envelope, dict) and ("rca" in envelope or "human_cause" in envelope):
                rca_text_for_scan = " ".join(
                    filter(None, [envelope.get("human_cause", ""), envelope.get("rca", "")])
                )
        except (ValueError, TypeError):
            pass
    combined = " ".join(filter(None, [rca_text_for_scan, reasoning or ""])).lower()
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
            ("diagnostic_steps",  "TEXT"),  # JSON list (US-3.9 / Tier 0)
            ("anomaly_summary",   "TEXT"),
            ("correlated_alerts", "TEXT"),  # JSON list
            # 2026-06-02 - first-class env column. Resolved by env_resolver
            # at pipeline write time so dashboard / email / filter all read
            # one persisted value. "unknown" is the explicit gap value.
            ("env",               "TEXT"),
        ]
        for name, sql_type in new_columns:
            if name not in cols:
                logger.info("Migrating rca_history: adding column %s", name)
                await self._db.execute(
                    f"ALTER TABLE rca_history ADD COLUMN {name} {sql_type}"
                )

        # US-5.3: feedback table for closed-loop operator decisions.
        await self._db.execute(CREATE_FEEDBACK_TABLE)
        await self._db.execute(CREATE_FEEDBACK_INDEX_DECISION)
        await self._db.execute(CREATE_FEEDBACK_INDEX_ACTIVE)

        # SF-7 (2026-05-23): extend the feedback table with the rich
        # rate-this-alert fields the v2 feedback page collects. Detect
        # missing columns + ALTER TABLE ADD COLUMN per the rca_history
        # migration pattern above.
        feedback_cols = set()
        async with self._db.execute("PRAGMA table_info(feedback)") as cur:
            async for row in cur:
                feedback_cols.add(row[1])
        feedback_new_columns = [
            ("rating",             "TEXT"),  # useful: yes / no / partial
            ("verdict_was_right",  "TEXT"),  # yes / no / maybe
            ("action_was_right",   "TEXT"),  # yes / no / partial / n_a
            ("actual_cause",       "TEXT"),  # free text, optional
            ("tags",               "TEXT"),  # JSON list (chip selections)
            ("notes",              "TEXT"),  # textarea, ≤280 chars
            ("rater",              "TEXT"),  # operator identifier
        ]
        for name, sql_type in feedback_new_columns:
            if name not in feedback_cols:
                logger.info("Migrating feedback: adding column %s", name)
                await self._db.execute(
                    f"ALTER TABLE feedback ADD COLUMN {name} {sql_type}"
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

        # 2026-06-02 - auto-fill env via the resolver when the caller didn't
        # set one. Pipeline writes typically pre-resolve env (with full alert
        # context), but short-path / legacy writers may not - in that case
        # we infer from the service token alone so the persisted row still
        # carries a value the dashboard / email can read.
        if not record.env:
            from app.v2_mappings import env_resolver
            record.env = env_resolver(service=record.affected_service)

        await self._db.execute(
            """INSERT INTO rca_history
               (id, timestamp, alert_source, alert_name, alert_fingerprint,
                affected_service, severity, triage_decision, llm_verdict,
                llm_confidence, rca_report, llm_reasoning, action_taken,
                related_alerts, investigation_duration_ms, rca_quality,
                alert_instance, alert_component, alert_signal, observed_value,
                promql_expr, suggested_actions, evidence, diagnostic_steps,
                anomaly_summary, correlated_alerts, env)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                       ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                record.diagnostic_steps,
                record.anomaly_summary,
                record.correlated_alerts,
                record.env,
            ),
        )
        await self._db.commit()
        logger.info(
            "Saved RCA decision %s for alert %s (quality=%s)",
            record.id, record.alert_name, record.rca_quality,
        )

    async def get_decisions(
        self,
        limit: int = 50,
        alert_name: str | None = None,
        offset: int = 0,
        since_days: int | None = None,
        since_hours: float | None = None,
        verdict: str | None = None,
        severity: str | None = None,
        alert_name_like: str | None = None,
        env: str | None = None,
    ) -> list[dict]:
        """Fetch decisions with optional column filters.

        New (2026-05-27 — Sprint 4 §14 W2 Wed) filter kwargs back the
        /dashboard/v2 URL-filter persistence work. Each translates to an
        additional WHERE clause on the same existing query — no new data
        path, no second connection. The MCP-only invariant lint stays
        clean (this file is the canonical writer / the rca-history-mcp
        already reads through here).

        - ``since_hours`` is the finer-grained sibling of ``since_days``.
          Use it for sub-day windows (1h / 6h). If both are given,
          ``since_hours`` wins (it's strictly more specific).
        - ``verdict`` matches ``llm_verdict`` case-insensitively. None
          means "no filter".
        - ``severity`` matches ``severity`` case-insensitively.
        - ``alert_name_like`` is a substring match on ``alert_name``
          (case-insensitive). Used by the v2 dashboard's "family" filter
          (e.g. ``Cpu`` matches HighCPUUsage / CpuSpike / KongCPUSpike).
        """
        clauses: list[str] = []
        params: list = []
        if alert_name:
            clauses.append("alert_name = ?")
            params.append(alert_name)
        # since_hours takes precedence over since_days when both are set.
        if since_hours is not None:
            since = (_utc_now() - timedelta(hours=since_hours)).isoformat()
            clauses.append("timestamp >= ?")
            params.append(since)
        elif since_days is not None:
            since = (_utc_now() - timedelta(days=since_days)).isoformat()
            clauses.append("timestamp >= ?")
            params.append(since)
        if verdict:
            clauses.append("LOWER(COALESCE(llm_verdict, '')) = LOWER(?)")
            params.append(verdict)
        if severity:
            clauses.append("LOWER(COALESCE(severity, '')) = LOWER(?)")
            params.append(severity)
        if alert_name_like:
            clauses.append("LOWER(COALESCE(alert_name, '')) LIKE LOWER(?)")
            params.append(f"%{alert_name_like}%")
        if env:
            clauses.append("LOWER(COALESCE(env, '')) = LOWER(?)")
            params.append(env)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        cursor = await self._db.execute(
            f"SELECT * FROM rca_history {where_sql} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            tuple(params),
        )
        rows = await cursor.fetchall()
        # Decode the JSON-as-TEXT columns at the API boundary so consumers
        # get real lists, not double-encoded strings. The dashboard parses
        # inline at render time but the public /decisions JSON API was
        # leaking the storage shape — audit-live.sh mechanical checks
        # counted string length instead of list length, and external
        # graders couldn't iterate. Defensive: tolerate missing columns,
        # malformed JSON, and pre-fix rows that were never decoded.
        decoded: list[dict] = []
        for row in rows:
            d = dict(row)
            for col in ("suggested_actions", "evidence", "diagnostic_steps", "correlated_alerts"):
                v = d.get(col)
                if isinstance(v, str) and v:
                    try:
                        parsed = json.loads(v)
                        if isinstance(parsed, list):
                            d[col] = parsed
                    except (ValueError, TypeError):
                        # Leave the raw string in place rather than failing the
                        # whole request — old rows persisted before the
                        # serialization fix may carry non-JSON text.
                        pass
                elif v is None:
                    d[col] = []
            decoded.append(d)
        return decoded

    async def count_decisions(
        self,
        alert_name: str | None = None,
        since_days: int | None = None,
        since_hours: float | None = None,
        verdict: str | None = None,
        severity: str | None = None,
        alert_name_like: str | None = None,
        env: str | None = None,
    ) -> int:
        """Count decisions matching the same filter set as get_decisions().

        Kept in lockstep with get_decisions() so the v2 dashboard's
        "X alerts in window" footer matches the filtered table.
        """
        clauses: list[str] = []
        params: list = []
        if alert_name:
            clauses.append("alert_name = ?")
            params.append(alert_name)
        if since_hours is not None:
            since = (_utc_now() - timedelta(hours=since_hours)).isoformat()
            clauses.append("timestamp >= ?")
            params.append(since)
        elif since_days is not None:
            since = (_utc_now() - timedelta(days=since_days)).isoformat()
            clauses.append("timestamp >= ?")
            params.append(since)
        if verdict:
            clauses.append("LOWER(COALESCE(llm_verdict, '')) = LOWER(?)")
            params.append(verdict)
        if severity:
            clauses.append("LOWER(COALESCE(severity, '')) = LOWER(?)")
            params.append(severity)
        if alert_name_like:
            clauses.append("LOWER(COALESCE(alert_name, '')) LIKE LOWER(?)")
            params.append(f"%{alert_name_like}%")
        if env:
            clauses.append("LOWER(COALESCE(env, '')) = LOWER(?)")
            params.append(env)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        cursor = await self._db.execute(
            f"SELECT COUNT(*) AS n FROM rca_history {where_sql}",
            tuple(params),
        )
        row = await cursor.fetchone()
        return int(row["n"]) if row else 0

    async def backfill_env_from_service(self) -> int:
        """One-off SQL migration helper - resolve env for rows where it is
        NULL or empty, using env_resolver(service=affected_service).

        Returns the number of rows updated. Idempotent: a second run touches
        zero rows (the first run filled them all). Called manually after the
        2026-06-02 env-column migration to back-fill historical rows; the
        live pipeline writes env at save_decision time so new rows never
        need this path.
        """
        from app.v2_mappings import env_resolver

        cursor = await self._db.execute(
            """SELECT id, affected_service FROM rca_history
               WHERE env IS NULL OR env = ''"""
        )
        rows = await cursor.fetchall()
        updated = 0
        for row in rows:
            svc = row["affected_service"] or ""
            env = env_resolver(service=svc)
            await self._db.execute(
                "UPDATE rca_history SET env = ? WHERE id = ?",
                (env, row["id"]),
            )
            updated += 1
        if updated:
            await self._db.commit()
        logger.info("backfill_env_from_service: updated %d rows", updated)
        return updated

    async def get_recent_decision_for_alert(
        self, alert_name: str, affected_service: str, lookback_minutes: int
    ) -> dict | None:
        """Most recent decision for (alert_name, service) within the lookback window.

        Used by Layer 2 pre-LLM triage to skip the Ollama call when the same
        alert was recently processed — if we just dismissed it, dismiss again;
        if we just suppressed it, suppress again.

        Synthetic-test fires (audit-live cron, chaos harness) are excluded
        from the lookup so their dismisses do not poison the suppression
        cache for real fires (P2 fix, 2026-05-19 — one synthetic dismiss
        was silencing 4+ real fires of the same alert).
        """
        since = (_utc_now() - timedelta(minutes=lookback_minutes)).isoformat()
        cursor = await self._db.execute(
            """SELECT triage_decision, llm_verdict, action_taken, rca_report, timestamp
               FROM rca_history
               WHERE alert_name = ? AND affected_service = ? AND timestamp > ?
                 AND (alert_fingerprint IS NULL
                      OR (alert_fingerprint NOT LIKE 'audit-live-%'
                          AND alert_fingerprint NOT LIKE 'chaos-%'))
               ORDER BY timestamp DESC LIMIT 1""",
            (alert_name, affected_service, since),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_recent_decision_for_fingerprint(
        self, fingerprint: str, window_minutes: int
    ) -> dict | None:
        """Most-recent LLM decision for a fingerprint within the window (DA-3).

        Cross-row verdict coherence needs the PRIOR cause for the exact same
        fingerprint — not the (alert_name, service) match used by Layer-2
        suppression — so consecutive fires of one flapping rule reuse (or
        explicitly revise) the same diagnosis instead of contradicting it.

        Returns the prior decision's verdict + RCA + reasoning + quality so
        the pipeline can decide whether to inject it (and the prompt builder
        can quote the prior cause back to the model). Only rows that carry a
        real LLM verdict are considered — short-path dedup / suppression /
        gate rows have llm_verdict NULL and have no cause to be coherent with.

        Synthetic-test fires (audit-live cron, chaos harness) are excluded so
        their decisions don't seed a coherence anchor for real fires — mirrors
        the same exclusion in get_recent_decision_for_alert.

        Low-quality priors are filtered out so they don't poison the next
        prompt: an inconclusive verdict / spike_shelved triage row / a
        data_starved or needs_review RCA carries no usable cause to be
        coherent with. Quoting them back to the LLM as "REUSE this prior"
        teaches the model to repeat the same hedge. If no usable prior
        exists, the lookup returns None and the prompt simply omits the
        DA-3 block (the model reasons from fresh evidence).
        """
        if not fingerprint:
            return None
        since = (_utc_now() - timedelta(minutes=window_minutes)).isoformat()
        cursor = await self._db.execute(
            """SELECT id, timestamp, alert_name, affected_service,
                      triage_decision, llm_verdict, rca_report, llm_reasoning,
                      rca_quality
               FROM rca_history
               WHERE alert_fingerprint = ? AND timestamp > ?
                 AND llm_verdict IS NOT NULL
                 AND alert_fingerprint NOT LIKE 'audit-live-%'
                 AND alert_fingerprint NOT LIKE 'chaos-%'
                 AND llm_verdict NOT IN ('inconclusive')
                 AND triage_decision NOT IN ('spike_shelved')
                 AND (rca_quality IS NULL
                      OR rca_quality NOT IN ('data_starved', 'needs_review'))
               ORDER BY timestamp DESC LIMIT 1""",
            (fingerprint, since),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_recent_decision_for_family_scope(
        self,
        alertnames: list[str] | tuple[str, ...],
        affected_service: str | None,
        alert_instance: str | None,
        window_seconds: int,
    ) -> dict | None:
        """SF-5 — most-recent decision for any alert in `alertnames` on the
        same scope within `window_seconds`.

        Used by the sustained-vs-spike modifier so a tier-bump within the
        SF-5 window (e.g. MediumCpuUsage at T+0 → HighCpuUsage at T+90s on
        host-1) is correctly identified as the same flapping condition,
        not a fresh alert. `get_recent_decision_for_fingerprint` can't do
        this because tier siblings have different Grafana fingerprints.

        Scope match prefers `alert_instance` (the most precise scope —
        a single host:port) but falls back to `affected_service` when the
        instance is unknown or labels were sparse. The same fallback
        order the dedup's `family_dedup_key` uses, so the two stay
        consistent across the platform.

        Synthetic fires (audit-live / chaos) are excluded for the same
        reason as the DA-3 lookup — their decisions must not seed an
        SF-5 shelving for real fires.
        """
        if not alertnames:
            return None
        # Pick the scope column with the same precedence as family_dedup_key.
        scope_col = None
        scope_val = None
        if alert_instance and alert_instance != "unknown":
            scope_col = "alert_instance"
            scope_val = alert_instance
        elif affected_service:
            scope_col = "affected_service"
            scope_val = affected_service
        if scope_val is None:
            return None

        since = (_utc_now() - timedelta(seconds=window_seconds)).isoformat()
        placeholders = ",".join("?" * len(alertnames))
        params: list = [*alertnames, scope_val, since]
        cursor = await self._db.execute(
            f"""SELECT id, timestamp, alert_name, affected_service,
                       alert_instance, alert_fingerprint, triage_decision,
                       llm_verdict, rca_report, llm_reasoning, rca_quality
                FROM rca_history
                WHERE alert_name IN ({placeholders})
                  AND {scope_col} = ?
                  AND timestamp > ?
                  AND (alert_fingerprint IS NULL
                       OR (alert_fingerprint NOT LIKE 'audit-live-%'
                           AND alert_fingerprint NOT LIKE 'chaos-%'))
                ORDER BY timestamp DESC LIMIT 1""",
            tuple(params),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_alert_frequency(self, alert_name: str, days: int = 7) -> dict:
        since = (_utc_now() - timedelta(days=days)).isoformat()
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

    async def get_service_summary(self, days: int = 7) -> list[dict]:
        """Per-service rollup over the last `days` for the /dashboard/v2/services page.

        Returns one dict per distinct `affected_service` (non-empty), sorted by
        total decisions DESC. Each dict carries the counts the services page
        renders directly — no further aggregation needed at render time.

        Shape per row:
            {
              "service": str,                       # affected_service
              "total": int,                         # all decisions in window
              "actions":  {action_taken: int, ...}, # emailed / suppressed / shelved / suppressed_duplicate / spike_shelved
              "verdicts": {llm_verdict: int, ...},  # escalate / dismiss / inconclusive (NULL skipped)
              "severities": {severity: int, ...},   # critical / warning / etc (NULL skipped)
              "last_fire": str | None,              # ISO timestamp of most recent decision
              "top_alertname": str | None,          # dominant alert_name for this service
            }

        Single pass over the windowed slice — buckets the counts in Python so
        we don't have to issue 4 separate GROUP BY queries per service. The
        rca_history table tops out around a few thousand rows in the 7-day
        window the page covers, so the pass is cheap (≤ low-millisecond).
        """
        since = (_utc_now() - timedelta(days=days)).isoformat()
        cursor = await self._db.execute(
            """SELECT affected_service, action_taken, llm_verdict, severity,
                      timestamp, alert_name
               FROM rca_history
               WHERE timestamp >= ?
                 AND affected_service IS NOT NULL
                 AND affected_service != ''""",
            (since,),
        )
        rows = await cursor.fetchall()

        buckets: dict[str, dict] = {}
        # Track per-(service, alert_name) frequency so we can pick the dominant
        # alertname after the single pass.
        alertname_counts: dict[str, dict[str, int]] = {}
        for row in rows:
            svc = row["affected_service"]
            b = buckets.get(svc)
            if b is None:
                b = {
                    "service": svc,
                    "total": 0,
                    "actions": {},
                    "verdicts": {},
                    "severities": {},
                    "last_fire": None,
                    "top_alertname": None,
                }
                buckets[svc] = b
                alertname_counts[svc] = {}

            b["total"] += 1
            action = row["action_taken"] or ""
            if action:
                b["actions"][action] = b["actions"].get(action, 0) + 1
            verdict = row["llm_verdict"]
            if verdict:
                b["verdicts"][verdict] = b["verdicts"].get(verdict, 0) + 1
            sev = row["severity"]
            if sev:
                b["severities"][sev] = b["severities"].get(sev, 0) + 1
            ts = row["timestamp"]
            if ts and (b["last_fire"] is None or ts > b["last_fire"]):
                b["last_fire"] = ts
            aname = row["alert_name"] or ""
            if aname:
                alertname_counts[svc][aname] = alertname_counts[svc].get(aname, 0) + 1

        # Resolve dominant alertname per service (top 1 by frequency).
        for svc, counts in alertname_counts.items():
            if counts:
                buckets[svc]["top_alertname"] = max(counts.items(), key=lambda kv: kv[1])[0]

        out = list(buckets.values())
        out.sort(key=lambda d: d["total"], reverse=True)
        return out

    # ------------------------------------------------------------------
    # US-5.3 closed-loop feedback
    # ------------------------------------------------------------------

    async def record_feedback(
        self,
        feedback_id: str,
        decision_id: str,
        feedback_type: str,
        operator_note: str | None,
        active_for_days: int | None = 14,
    ) -> dict:
        """UPSERT a feedback row for the given decision + feedback_type.

        Idempotent on (decision_id, feedback_type) — re-posting from the
        operator updates the row in place rather than creating a duplicate.
        Returns the resulting row as a dict so the API can echo it back.

        feedback_type must be 'override' or 'confirm'. For 'confirm' the
        active_for_days argument is ignored — confirms are timeless. For
        'override' the active_until is set to created_at + active_for_days.
        """
        if feedback_type not in ("override", "confirm"):
            raise ValueError(f"feedback_type must be 'override' or 'confirm', got {feedback_type!r}")

        now = _utc_now()
        active_until = None
        if feedback_type == "override":
            window = active_for_days if active_for_days is not None else 14
            active_until = (now + timedelta(days=window)).isoformat()

        # SQLite UPSERT on the unique (decision_id, feedback_type) constraint.
        # On conflict, refresh operator_note + active_until + created_at so
        # the operator's most-recent intent wins.
        await self._db.execute(
            """INSERT INTO feedback (id, decision_id, feedback_type, operator_note, created_at, active_until)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(decision_id, feedback_type) DO UPDATE SET
                   operator_note = excluded.operator_note,
                   created_at = excluded.created_at,
                   active_until = excluded.active_until""",
            (feedback_id, decision_id, feedback_type, operator_note, now.isoformat(), active_until),
        )
        await self._db.commit()

        # Read back the (possibly-existing) row so the API returns the canonical id
        cursor = await self._db.execute(
            """SELECT id, decision_id, feedback_type, operator_note, created_at, active_until
               FROM feedback WHERE decision_id = ? AND feedback_type = ?""",
            (decision_id, feedback_type),
        )
        row = await cursor.fetchone()
        logger.info(
            "Recorded feedback: decision_id=%s type=%s active_until=%s",
            decision_id, feedback_type, active_until,
        )
        return dict(row)

    async def record_v2_feedback(
        self,
        feedback_id: str,
        decision_id: str,
        rating: str | None,
        verdict_was_right: str | None,
        action_was_right: str | None,
        actual_cause: str | None,
        tags: list | None,
        notes: str | None,
        rater: str | None,
    ) -> dict:
        """SF-7 (2026-05-23) — UPSERT a richer 'rate' feedback row.

        Uses feedback_type='rate' to share the (decision_id, feedback_type)
        UNIQUE constraint with the existing override/confirm rows — operators
        can both rate an alert AND confirm/override it, without one
        clobbering the other. Re-rating the same alert updates the row in
        place (last rating wins).
        """
        import json as _json
        now = _utc_now()
        tags_json = _json.dumps(tags or [])
        # Clamp notes to 280 chars defensively (frontend already enforces).
        notes_clamped = (notes or "")[:280]

        await self._db.execute(
            """INSERT INTO feedback (
                   id, decision_id, feedback_type, operator_note,
                   created_at, active_until,
                   rating, verdict_was_right, action_was_right,
                   actual_cause, tags, notes, rater
               )
               VALUES (?, ?, 'rate', ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(decision_id, feedback_type) DO UPDATE SET
                   operator_note    = excluded.operator_note,
                   created_at       = excluded.created_at,
                   rating           = excluded.rating,
                   verdict_was_right= excluded.verdict_was_right,
                   action_was_right = excluded.action_was_right,
                   actual_cause     = excluded.actual_cause,
                   tags             = excluded.tags,
                   notes            = excluded.notes,
                   rater            = excluded.rater""",
            (
                feedback_id, decision_id, notes_clamped, now.isoformat(),
                rating, verdict_was_right, action_was_right,
                actual_cause, tags_json, notes_clamped, rater,
            ),
        )
        await self._db.commit()

        cursor = await self._db.execute(
            """SELECT id, decision_id, feedback_type, created_at,
                      rating, verdict_was_right, action_was_right,
                      actual_cause, tags, notes, rater
               FROM feedback WHERE decision_id = ? AND feedback_type = 'rate'""",
            (decision_id,),
        )
        row = await cursor.fetchone()
        logger.info(
            "Recorded v2 rating: decision_id=%s rating=%s tags=%s rater=%s",
            decision_id, rating, tags_json, rater,
        )
        return dict(row) if row else {}

    async def get_active_overrides_for_alert(
        self,
        alert_name: str,
        affected_service: str,
        current_time: datetime,
        time_of_day_window_hours: float = 2.0,
    ) -> list[dict]:
        """Return active operator overrides matching this alert's shape.

        Match criteria:
          - feedback_type = 'override'
          - active_until > current_time (still in the active window)
          - The original decision (joined via decision_id) has the same
            alert_name AND the same affected_service
          - The override's created_at falls within ±time_of_day_window_hours
            of the current time-of-day (regardless of date)

        Used by the pre-LLM similarity gate: if any rows return, the
        pipeline forces ESCALATE on a DISMISS verdict for this alert.

        Returns rows with fields: feedback_id, decision_id, feedback_type,
        operator_note, created_at, active_until, alert_name,
        affected_service, llm_verdict (the prior verdict that got
        overridden), rca_report (the prior RCA the operator disagreed with).
        """
        now_iso = current_time.isoformat()
        cursor = await self._db.execute(
            """SELECT f.id AS feedback_id, f.decision_id, f.feedback_type,
                      f.operator_note, f.created_at, f.active_until,
                      r.alert_name, r.affected_service, r.llm_verdict,
                      r.rca_report
               FROM feedback f
               JOIN rca_history r ON r.id = f.decision_id
               WHERE f.feedback_type = 'override'
                 AND f.active_until > ?
                 AND r.alert_name = ?
                 AND r.affected_service = ?
               ORDER BY f.created_at DESC""",
            (now_iso, alert_name, affected_service),
        )
        rows = await cursor.fetchall()

        # Time-of-day filter — done in Python because SQLite has no native
        # "extract hour-of-day modulo 24h" with wrap-around. Runs over a small
        # candidate set (active overrides for one alert+service combo, usually
        # 0–3 rows in practice).
        current_minutes = current_time.hour * 60 + current_time.minute
        window_minutes = time_of_day_window_hours * 60
        matched = []
        for row in rows:
            try:
                created = datetime.fromisoformat(row["created_at"])
            except (TypeError, ValueError):
                continue
            created_minutes = created.hour * 60 + created.minute
            # Wrap-around aware: distance is min over the circular 24h
            # diff, so 23:30 vs 00:30 has distance 60min, not 1380min.
            raw_diff = abs(current_minutes - created_minutes)
            tod_diff = min(raw_diff, 24 * 60 - raw_diff)
            if tod_diff <= window_minutes:
                matched.append(dict(row))
        return matched

    async def count_feedback_in_window(
        self, feedback_type: str, window_days: int = 7
    ) -> int:
        """Count feedback rows of the given type created within the window.

        Used by the precision/recall metrics: TP+FP comes from confirm
        count + non-overridden ESCALATEs; FN comes from override count.
        """
        if feedback_type not in ("override", "confirm"):
            raise ValueError(f"feedback_type must be 'override' or 'confirm'")
        since = (_utc_now() - timedelta(days=window_days)).isoformat()
        cursor = await self._db.execute(
            "SELECT COUNT(*) AS n FROM feedback WHERE feedback_type = ? AND created_at > ?",
            (feedback_type, since),
        )
        row = await cursor.fetchone()
        return int(row["n"]) if row else 0

    async def count_decisions_by_verdict(
        self, verdict: str, window_days: int = 7
    ) -> int:
        """Count rca_history rows with the given llm_verdict in the window.

        Used as the denominator in precision (escalations) and recall
        calculations.
        """
        since = (_utc_now() - timedelta(days=window_days)).isoformat()
        cursor = await self._db.execute(
            "SELECT COUNT(*) AS n FROM rca_history WHERE llm_verdict = ? AND timestamp > ?",
            (verdict, since),
        )
        row = await cursor.fetchone()
        return int(row["n"]) if row else 0

    async def get_feedback_for_decision(
        self, decision_id: str
    ) -> list[dict]:
        """Return all feedback rows for a given decision (0–2 rows: at most
        one of each type)."""
        cursor = await self._db.execute(
            """SELECT id, decision_id, feedback_type, operator_note, created_at, active_until
               FROM feedback WHERE decision_id = ?""",
            (decision_id,),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def get_alert_summary(self, days: int = 7) -> list[dict]:
        """Per-alertname rollup for the v2 Alerts sidebar page.

        Returns one dict per distinct `alert_name` seen in the last `days`,
        sorted by total fires DESC. Each row carries:

          - alert_name:        the rule name
          - fires:             total rca_history rows in the window
          - emails:            count of rows with action_taken='emailed'
          - dominant_verdict:  most-frequent non-null llm_verdict (lowercased),
                               or "(none)" if every row was a cheap-path
                               short-circuit (suppressed / pre-LLM gated).
          - dominant_severity: most-frequent severity (lowercased)
          - last_fire:         max(timestamp) — bare ISO string as stored
          - email_ratio:       emails / fires (float, 0.0 if no fires)
          - was_gated:         True if any row in the window had
                               triage_decision='recurrence_gated_pre_llm' —
                               proves the rule currently carries a
                               recurrence_gate annotation in Grafana.

        Annotation values themselves are NOT stored on rca_history rows
        (annotations exist only at fire-time on the Grafana payload), so
        the caller must render "(annotation not persisted — check Grafana
        rule)" when surfacing per-rule gate parameters. `was_gated`
        truthiness is the closest honest answer the store can give without
        widening the schema.

        Pure SQL over the existing rca_history table — no new data path,
        MCP-invariant clean.
        """
        since = (_utc_now() - timedelta(days=days)).isoformat()
        # One scan, grouped by alert_name. SQLite SUM(CASE WHEN ...) gives us
        # the per-bucket counts without firing 3 queries per alertname.
        cursor = await self._db.execute(
            """SELECT alert_name,
                      COUNT(*) AS fires,
                      SUM(CASE WHEN action_taken = 'emailed' THEN 1 ELSE 0 END) AS emails,
                      SUM(CASE WHEN triage_decision = 'recurrence_gated_pre_llm' THEN 1 ELSE 0 END) AS gated,
                      MAX(timestamp) AS last_fire
               FROM rca_history
               WHERE timestamp > ?
               GROUP BY alert_name
               ORDER BY fires DESC""",
            (since,),
        )
        groups = await cursor.fetchall()

        out: list[dict] = []
        for grp in groups:
            name = grp["alert_name"] or "(unknown)"
            fires = int(grp["fires"] or 0)
            emails = int(grp["emails"] or 0)
            gated = int(grp["gated"] or 0)
            last_fire = grp["last_fire"] or ""

            # Pull the verdict + severity distributions in two tiny follow-ups
            # — bounded by the alert_name we already know, so the index covers
            # the read. Python-side argmax keeps the SQL trivial.
            v_cursor = await self._db.execute(
                """SELECT LOWER(COALESCE(llm_verdict, '')) AS v, COUNT(*) AS n
                   FROM rca_history
                   WHERE alert_name = ? AND timestamp > ?
                     AND llm_verdict IS NOT NULL AND llm_verdict != ''
                   GROUP BY v ORDER BY n DESC LIMIT 1""",
                (name, since),
            )
            v_row = await v_cursor.fetchone()
            dominant_verdict = (v_row["v"] if v_row else "") or "(none)"

            s_cursor = await self._db.execute(
                """SELECT LOWER(COALESCE(severity, '')) AS s, COUNT(*) AS n
                   FROM rca_history
                   WHERE alert_name = ? AND timestamp > ?
                     AND severity IS NOT NULL AND severity != ''
                   GROUP BY s ORDER BY n DESC LIMIT 1""",
                (name, since),
            )
            s_row = await s_cursor.fetchone()
            dominant_severity = (s_row["s"] if s_row else "") or "(unknown)"

            out.append({
                "alert_name": name,
                "fires": fires,
                "emails": emails,
                "dominant_verdict": dominant_verdict,
                "dominant_severity": dominant_severity,
                "last_fire": last_fire,
                "email_ratio": (emails / fires) if fires > 0 else 0.0,
                "was_gated": gated > 0,
            })
        return out

    # ------------------------------------------------------------------
    # US-5.8 recurrence gate support
    # ------------------------------------------------------------------

    async def count_recent_decisions_by_fingerprint(
        self,
        fingerprint: str,
        llm_verdict: str | None,
        window_seconds: int,
    ) -> int:
        """Count rca_history rows with the given fingerprint within the
        recent window.

        Used by the pre-LLM gate (llm_verdict=None → any verdict) and the
        post-LLM gate (llm_verdict='dismiss' → only count dismisses).

        Window is seconds-from-now. Pure SQL, indexed on timestamp +
        fingerprint pair (existing indices cover this query path).
        """
        if not fingerprint:
            return 0
        since = (_utc_now() - timedelta(seconds=window_seconds)).isoformat()
        if llm_verdict is None:
            cursor = await self._db.execute(
                "SELECT COUNT(*) AS n FROM rca_history WHERE alert_fingerprint = ? AND timestamp > ?",
                (fingerprint, since),
            )
        else:
            cursor = await self._db.execute(
                "SELECT COUNT(*) AS n FROM rca_history WHERE alert_fingerprint = ? AND llm_verdict = ? AND timestamp > ?",
                (fingerprint, llm_verdict, since),
            )
        row = await cursor.fetchone()
        return int(row["n"]) if row else 0
