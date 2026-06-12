"""Cross-type co-fire correlation (2026-06-12, Lina's consolidation ask).

One root cause routinely fires SEVERAL alert types for the same workload —
a deleted/unschedulable deployment fires KubeWorkloadDown AND
KubeWorkloadReplicasDeficit (37s apart in the 06-11 battery), and a
crash-looping cascade adds PodCrashLooping. Each used to page separately:
2-3 emails for one fact = alert fatigue.

This module groups those co-fires WITHOUT hiding anything:

  - COFIRE_FAMILIES maps alert types that describe the same incident class.
    Grouping additionally requires the SAME affected service and a tight
    time window — a genuinely different second problem still pages.
  - The CofireRegistry tracks (a) family alerts currently in flight
    (webhook received, investigation running) so the FIRST escalation email
    can NAME its co-fired siblings, and (b) which (family, service) already
    paged, so the sibling's own escalation consolidates into that incident
    instead of sending a second email.

Design choice — no notification hold/delay (Alertmanager-style group_wait
was considered and rejected): siblings arrive within seconds of each other
while an investigation takes ~40s, so by the time the first email is ready
the co-fire is already known. Zero added paging latency, and no held email
to lose on a process restart. The registry is in-memory; after a restart a
sibling would page on its own (fail-open: the failure mode is one extra
email, never a lost page). A DB fallback in the pipeline covers the common
restart case.

The LLM still investigates every alert (each row keeps its own verdict —
"consolidate but never hide"); only the NOTIFICATION and the feed grouping
consolidate.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

# Alert types that describe the same incident class for one workload.
# Keep this conservative: only types that are near-mechanically coupled.
COFIRE_FAMILIES: dict[str, str] = {
    "KubeWorkloadDown": "workload-down",
    "KubeWorkloadReplicasDeficit": "workload-down",
    "PodCrashLooping": "workload-down",
}


def cofire_family(alertname: str | None) -> str | None:
    return COFIRE_FAMILIES.get(alertname or "")


def family_members(family: str) -> list[str]:
    return [a for a, f in COFIRE_FAMILIES.items() if f == family]


@dataclass
class _Arrival:
    alertname: str
    fingerprint: str
    arrived_at: float


@dataclass
class _Primary:
    decision_id: str
    alertname: str
    emailed_at: float


@dataclass
class CofireRegistry:
    """In-process co-fire state. All methods are synchronous and cheap;
    the pipeline serializes claim-or-consolidate through `lock` so two
    siblings finishing simultaneously can't both claim primary."""

    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _in_flight: dict[tuple[str, str], dict[str, _Arrival]] = field(default_factory=dict)
    _primaries: dict[tuple[str, str], _Primary] = field(default_factory=dict)

    @staticmethod
    def _key(alertname: str, service: str | None) -> tuple[str, str] | None:
        fam = cofire_family(alertname)
        if not fam or not service:
            return None
        return (fam, service)

    def track_arrival(self, alertname: str, service: str | None, fingerprint: str) -> None:
        key = self._key(alertname, service)
        if key is None:
            return
        self._in_flight.setdefault(key, {})[fingerprint or alertname] = _Arrival(
            alertname=alertname, fingerprint=fingerprint or "", arrived_at=time.monotonic()
        )

    def untrack(self, alertname: str, service: str | None, fingerprint: str) -> None:
        key = self._key(alertname, service)
        if key is None:
            return
        self._in_flight.get(key, {}).pop(fingerprint or alertname, None)

    def siblings_in_flight(
        self, alertname: str, service: str | None, fingerprint: str,
        max_age_seconds: float = 900.0,
    ) -> list[dict]:
        """Other family alerts for the same service currently being
        processed — the first email names these as co-fires."""
        key = self._key(alertname, service)
        if key is None:
            return []
        now = time.monotonic()
        out = []
        for fp, a in list(self._in_flight.get(key, {}).items()):
            if now - a.arrived_at > max_age_seconds:
                self._in_flight[key].pop(fp, None)  # lazy expiry
                continue
            if fp == (fingerprint or alertname):
                continue
            out.append({"alertname": a.alertname, "fingerprint": a.fingerprint})
        return out

    def claim_primary(
        self, alertname: str, service: str | None, decision_id: str,
        window_seconds: float,
    ) -> _Primary | None:
        """Atomically (under the pipeline's lock) either return the existing
        in-window primary for this (family, service) — meaning the caller
        must CONSOLIDATE — or record the caller as the new primary and
        return None (caller emails)."""
        key = self._key(alertname, service)
        if key is None:
            return None
        now = time.monotonic()
        existing = self._primaries.get(key)
        if existing and (now - existing.emailed_at) <= window_seconds:
            return existing
        self._primaries[key] = _Primary(
            decision_id=decision_id, alertname=alertname, emailed_at=now
        )
        return None

    def release_primary(self, alertname: str, service: str | None, decision_id: str) -> None:
        """Roll back a claim whose email failed to send — otherwise a
        sibling would consolidate into a notification nobody received."""
        key = self._key(alertname, service)
        if key is None:
            return
        existing = self._primaries.get(key)
        if existing and existing.decision_id == decision_id:
            self._primaries.pop(key, None)


# Module-level singleton — one process, one registry.
registry = CofireRegistry()
