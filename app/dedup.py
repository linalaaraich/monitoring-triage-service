import asyncio
import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class DedupEntry:
    first_seen: float
    count: int = 1
    last_status: str = "firing"


class DedupManager:
    def __init__(self, window_seconds: int = 300):
        self.window = window_seconds
        self._entries: dict[tuple[str, str], DedupEntry] = {}
        self._lock = asyncio.Lock()

    async def check(self, alertname: str, instance: str, status: str) -> bool:
        """Returns True if the alert is a duplicate that should be skipped."""
        key = (alertname, instance)
        now = time.monotonic()

        async with self._lock:
            self._cleanup(now)

            if key not in self._entries:
                self._entries[key] = DedupEntry(first_seen=now, last_status=status)
                logger.info(
                    "New alert: %s/%s — starting dedup window", alertname, instance
                )
                return False

            entry = self._entries[key]

            # If alert resolved and re-fired, reset window and re-process
            if status == "firing" and entry.last_status == "resolved":
                entry.first_seen = now
                entry.count = 1
                entry.last_status = status
                logger.info(
                    "Alert %s/%s re-fired after resolve — resetting window",
                    alertname,
                    instance,
                )
                return False

            # Track resolved status but don't skip
            if status == "resolved":
                entry.last_status = "resolved"
                logger.info("Alert %s/%s resolved within dedup window", alertname, instance)
                return True

            # Duplicate within window
            entry.count += 1
            remaining = self.window - (now - entry.first_seen)
            logger.info(
                "Deduplicated alert %s/%s — count=%d, window_remaining=%.0fs",
                alertname,
                instance,
                entry.count,
                remaining,
            )
            return True

    def _cleanup(self, now: float):
        expired = [
            key
            for key, entry in self._entries.items()
            if now - entry.first_seen > self.window
        ]
        for key in expired:
            del self._entries[key]
