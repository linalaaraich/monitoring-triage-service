import asyncio
import logging
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DedupEntry:
    first_seen: float
    count: int = 1
    last_status: str = "firing"
    # Decision ID of the full RCA produced for the first occurrence in
    # this window — set by the pipeline after persisting. Used to link
    # short-path suppressed_duplicate records back to the original.
    first_decision_id: str | None = None


class DedupManager:
    """Fingerprint-window deduplication.

    Keys on Grafana's stable fingerprint (hash over labels) instead of
    (alertname, instance) — this correctly collapses flapping rules even
    when some labels (e.g. instance) are missing, and respects label
    combinations that a naive alertname-only key would conflate.

    On the second+ occurrence within the sliding window, the pipeline is
    expected to persist a short-path record linking back to the
    `first_decision_id` of this entry (see pipeline._process_alert).
    That gives operators a visible "suppressed — see original" row on
    the dashboard instead of silent drops.
    """

    def __init__(self, window_seconds: int = 600):
        # 600s (10 min) default — the old 300s missed the 2026-04-23
        # MediumCpuUsage flapping (fires at 0/5/10/15 min apart).
        self.window = window_seconds
        self._entries: dict[str, DedupEntry] = {}
        self._lock = asyncio.Lock()

    async def check(self, fingerprint: str, status: str) -> tuple[bool, str | None]:
        """Check whether an incoming alert duplicates a recent one.

        Returns (is_duplicate, first_decision_id). When is_duplicate=True,
        first_decision_id is the RCA id of the initial fire (may be None
        if the first fire hasn't finished persisting yet — race window).
        """
        if not fingerprint:
            # No fingerprint → can't dedup reliably. Treat as fresh.
            return False, None

        now = time.monotonic()

        async with self._lock:
            self._cleanup(now)

            entry = self._entries.get(fingerprint)
            if entry is None:
                self._entries[fingerprint] = DedupEntry(first_seen=now, last_status=status)
                logger.info("New alert fingerprint: %s — starting dedup window", fingerprint[:12])
                return False, None

            # Resolve event within window — track but don't process again
            if status == "resolved":
                entry.last_status = "resolved"
                logger.info("Alert %s resolved within dedup window", fingerprint[:12])
                return True, entry.first_decision_id

            # Re-fire after resolve → treat as new window
            if status == "firing" and entry.last_status == "resolved":
                self._entries[fingerprint] = DedupEntry(first_seen=now, last_status=status)
                logger.info("Alert %s re-fired after resolve — new window", fingerprint[:12])
                return False, None

            # Firing duplicate within window
            entry.count += 1
            remaining = self.window - (now - entry.first_seen)
            logger.info(
                "Deduplicated alert %s (count=%d, window_remaining=%.0fs, prior_rca=%s)",
                fingerprint[:12], entry.count, remaining, entry.first_decision_id or "pending",
            )
            return True, entry.first_decision_id

    async def record_first_decision(self, fingerprint: str, decision_id: str) -> None:
        """Called by the pipeline after it persists the first RCA for a
        new fingerprint — so subsequent dup checks can return the link."""
        async with self._lock:
            entry = self._entries.get(fingerprint)
            if entry is not None:
                entry.first_decision_id = decision_id

    def _cleanup(self, now: float):
        expired = [
            fp for fp, entry in self._entries.items()
            if now - entry.first_seen > self.window
        ]
        for fp in expired:
            del self._entries[fp]
