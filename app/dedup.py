import asyncio
import hashlib
import logging
import re
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────
# Drain3 fingerprint stabilisation (issue #1, 2026-06-04 backend audit).
#
# The drain3 self-fire fingerprint used to hash the raw novel-template /
# anomalous-line text. That text embeds high-cardinality, per-batch volatile
# tokens — trace IDs, span IDs, entity IDs, timestamps, hex digests — so two
# batches of the SAME underlying anomaly family hashed to DIFFERENT keys
# every fire → never deduped, never recurrence-gated → a fresh `investigate`
# row each time (21 distinct fingerprints / 18 fires in one day, live DB).
#
# Fix: normalise the content to its STABLE template identity before hashing
# (mask the volatile tokens with <*>) so the same anomaly family collapses
# while a genuinely new template still produces a distinct digest. This is
# deliberately CONSERVATIVE — only obviously-volatile token shapes are
# masked, so distinct anomalies are not merged.
# ──────────────────────────────────────────────────────────────────────
# Ordered most-specific → least-specific so e.g. a UUID isn't half-eaten by
# the bare-number rule first.
_DRAIN3_MASK_PATTERNS: list[re.Pattern] = [
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),  # UUID
    re.compile(r"\b[0-9a-fA-F]{16,}\b"),          # long hex (trace/span IDs, digests)
    re.compile(r"\b0x[0-9a-fA-F]+\b"),            # hex literals (0x…)
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),  # ISO timestamps
    re.compile(r"\b\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b"),  # bare clock times
    re.compile(r"\b\d+(?:\.\d+)?\b"),              # decimals / dotted (IPs partially, ratios)
    re.compile(r"\d+"),                            # any remaining digit run (incl. "1234ms", "id=42")
]


def _normalize_drain3_content(text: str) -> str:
    """Collapse a drain3 template / anomalous line to its stable identity.

    Replaces volatile high-cardinality tokens (UUIDs, trace/span IDs, hex
    digests, timestamps, bare integers) with `<*>` so the SAME log template
    masks to the SAME string across batches even when drain3's own masking
    left an embedded id in the `new_templates` text or we fell back to a raw
    `anomalous_lines` sample. Whitespace is squeezed so spacing jitter doesn't
    change the digest.
    """
    masked = text
    for pat in _DRAIN3_MASK_PATTERNS:
        masked = pat.sub("<*>", masked)
    # Collapse runs of the wildcard token (e.g. "<*>:<*>" timestamps) and
    # surrounding whitespace so equivalent templates converge.
    masked = re.sub(r"(?:<\*>[\s:.,/-]*){2,}", "<*> ", masked)
    masked = re.sub(r"\s+", " ", masked).strip()
    # If nothing but wildcards / punctuation survives, the line carried no
    # stable identity (pure ids/timestamps) — treat as empty so the caller
    # falls back to the service-scoped key rather than minting a fake digest.
    if not re.search(r"[A-Za-z]", masked):
        return ""
    return masked


# DA-5 — alertname families. Severity-tier alerts on the same resource
# share a dedup window so Medium/High/Critical for the same condition
# collapse into one operator row instead of three. Surfaced by the
# 2026-05-21 dashboard-output audit (HighCpuUsage + CriticalCpuUsage on
# the same node within ~1 min produced two RCAs).
#
# Pod-level rules (PodHighCpuUsage, PodHighMemoryUsage) are intentionally
# omitted — they have no severity tiers and they target a different scope
# (pod, not host), so collapsing them with host alerts would hide a real
# distinction.
ALERT_FAMILIES: dict[str, str] = {
    "MediumCpuUsage": "cpu",
    "HighCpuUsage": "cpu",
    "CriticalCpuUsage": "cpu",
    "MediumMemoryUsage": "memory",
    "HighMemoryUsage": "memory",
    "CriticalMemoryUsage": "memory",
    "HighDiskUsage": "disk",
    "CriticalDiskUsage": "disk",
    "LokiHighDiskUsage": "loki-disk",
    "LokiCriticalDiskUsage": "loki-disk",
}


def drain3_fingerprint(
    service: str,
    new_templates: list[str] | None,
    anomalous_lines: list[str] | None,
) -> str:
    """DA-4 — content-aware fingerprint for Drain3 self-fires. The legacy
    `drain3-{service}` collapsed every anomaly batch on the same service
    into one dedup window, which the 10 min sliding window then merged
    silently regardless of whether the underlying templates were the same
    (OOM-pattern vs connection-storm both hashed to one row).

    Top-3 novel templates dominate the digest; if none are present we fall
    back to the first three anomalous lines so each visually-distinct
    batch still gets its own key.

    Issue #1 (2026-06-04): the digest is now taken over the NORMALISED
    template identity (`_normalize_drain3_content`), not the raw text, so
    two batches of the same anomaly family — which differ only in embedded
    trace/span/entity IDs and timestamps — produce the SAME fingerprint and
    therefore dedup + recurrence-gate as intended. Genuinely distinct
    templates still mask to distinct strings and stay split.
    """
    templates = [t for t in (new_templates or [])[:3] if t and t.strip()]
    if not templates:
        templates = [l for l in (anomalous_lines or [])[:3] if l and l.strip()]
    if not templates:
        return f"drain3-{service}"
    # Normalise each entry to its stable identity, drop any that mask to
    # nothing (pure-id lines), then sort so batch ordering jitter doesn't
    # change the key. Sorting is safe: order carries no anomaly meaning.
    normed = sorted({n for n in (_normalize_drain3_content(t) for t in templates) if n})
    if not normed:
        return f"drain3-{service}"
    normalized = "\n".join(normed)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]
    return f"drain3-{service}-{digest}"


def family_dedup_key(alert) -> str:
    """Dedup key for `alert`. For severity-tier families returns
    `family:{name}:{instance|service}` so tier alerts collapse on the
    same scope; for unknown alertnames returns the Grafana fingerprint
    unchanged. Only the dedup table uses this — `alert.fingerprint` is
    still what gets persisted on the RCA record.
    """
    family = ALERT_FAMILIES.get(alert.alertname)
    if family is None:
        return alert.fingerprint
    scope = alert.instance if alert.instance != "unknown" else alert.service
    return f"family:{family}:{scope}"


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
