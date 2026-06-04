"""SF-5 — sustained-vs-spike verdict modifier.

DEPRECATED 2026-06-04 (audit issue #4, Lina-approved)
-----------------------------------------------------
This gate is DISABLED BY DEFAULT (config.sf5_transient_spike_enabled=False)
and is structurally unreachable in production. SF-5's precondition — a prior
fire 0–120s ago (sf5_transient_spike_window_seconds) — is a STRICT SUBSET of
the 300s dedup window (config.dedup_window_seconds) that runs FIRST in the
pipeline. Any prior fire within 120s is therefore also within 300s, gets
caught by dedup, and SF-5 never sees it. Confirmed empirically: ZERO
`spike_shelved` rows have ever been written despite SF-5 being enabled since
deploy. The canonical noise absorber is the recurrence-gate (US-5.8) + dedup,
not SF-5. The code below is retained (safe deprecation, not a rip-out) so the
unit tests stay green and a future redesign — e.g. an SF-5 window LARGER than
the dedup window, or real "duration above threshold" data from Grafana — can
revive a genuinely-reachable spike gate.

Sprint 4 §14 W2 Fri stretch item. Direct response to the "too many useless
emails" feedback (2026-05-31): short transient breaches that resolve within
~2 min are almost always noise (a 60 s CPU steal blip, a GC pause on a
single pod, a one-off network reshuffle) — paging the operator for them
trains them to ignore alerts. A sustained 10-min stress is real and must
still escalate.

Approach (cheap, MCP-only, no new external signal)
--------------------------------------------------
The Grafana webhook doesn't carry a "duration above threshold" field. But
the rca_store does: every prior fire of the same alert is already
persisted with a timestamp. So:

  1. When a NEW alert in a transient-prone family arrives,
  2. look up the FIRST recent prior decision for the same fingerprint
     OR the same family-scope (cpu/memory/disk on the same instance, so
     a MediumCpu→HighCpu tier-bump within the window also counts),
  3. if the gap between that prior fire and now is < the configurable
     sustained-threshold-seconds (default 120 s), classify the current
     fire as a transient spike and shelve it without calling the LLM.

False-negative bias is intentional. A real sustained breach that
accidentally gets shelved would just re-fire in 5 min and escalate
normally on the second pass. A false-positive shelving would hide a real
incident — strictly worse. Hence the narrow family list, the conservative
default window, and the disable knob.

Composition with sibling features
---------------------------------
  - DA-5 (family_dedup_key): SF-5 reuses the same family map so a
    HighCpuUsage refire 90 s after a MediumCpuUsage on the same host is
    correctly identified as "same condition flapping," not a new alert.
  - DA-3 (get_recent_decision_for_fingerprint): SF-5 reuses the canonical
    prior-decision lookup so we don't introduce a new direct-DB read path
    — the MCP-only invariant holds (the rca-history-mcp tunnels through
    the same store method downstream).
  - Recurrence gate (US-5.8): SF-5 runs INSIDE the investigate path,
    AFTER the pre-LLM recurrence gate but BEFORE the LLM call, so the
    two gates compose cleanly — recurrence-gated alerts never reach
    SF-5, and SF-5-shelved alerts never reach the LLM.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from app.dedup import ALERT_FAMILIES

logger = logging.getLogger(__name__)


# SF-5 family map. Superset of ALERT_FAMILIES (which only covers severity-
# tier siblings) plus latency-p95 alerts — latency alerts have no tier
# siblings in the dedup map but they ARE transient-prone (one slow GC,
# one slow query, one cold cache hit) and routinely refire within 2 min.
#
# Pod-level alerts (PodHighCpuUsage) are intentionally listed even though
# they're not in ALERT_FAMILIES — the dedup wisely keeps pods separate
# from host alerts, but for transient-spike classification a pod that
# spiked twice in 90 s is still a spike worth shelving.
_SF5_ALERT_FAMILY_MAP: dict[str, str] = {
    # CPU
    "MediumCpuUsage":     "cpu",
    "HighCpuUsage":       "cpu",
    "CriticalCpuUsage":   "cpu",
    "PodHighCpuUsage":    "cpu",
    # Memory
    "MediumMemoryUsage":  "memory",
    "HighMemoryUsage":    "memory",
    "CriticalMemoryUsage": "memory",
    "PodHighMemoryUsage": "memory",
    # Disk (host + Loki-specific)
    "HighDiskUsage":      "disk",
    "CriticalDiskUsage":  "disk",
    "LokiHighDiskUsage":  "loki-disk",
    "LokiCriticalDiskUsage": "loki-disk",
    # Latency
    "HighP95Latency":     "latency-p95",
    "HighKongP95Latency": "latency-p95",
    "MediumP95Latency":   "latency-p95",
    "CriticalP95Latency": "latency-p95",
}


def classify_family(alert) -> Optional[str]:
    """Return the SF-5 family string for `alert` or None if out of scope.

    SF-5 covers a deliberately narrow set of transient-prone alert
    archetypes (cpu / memory / disk / loki-disk / latency-p95). Out-of-
    scope alerts (TargetDown, DeadMansSwitch, drain3-anomaly, app-
    specific business alerts) are NEVER classified as transient — they
    represent conditions whose "duration above threshold" semantic
    doesn't hold (TargetDown is binary; you can't have a "transient
    target-down spike", you have either a missing target or you don't).
    """
    return _SF5_ALERT_FAMILY_MAP.get(alert.alertname)


@dataclass(frozen=True)
class TransientSpikeVerdict:
    """Returned by `is_transient_spike`. Both fields are None for the
    "not a spike" outcome so callers can branch on `verdict.is_transient`.
    """
    is_transient: bool
    family: Optional[str] = None
    reason: str = ""
    prior_decision_id: Optional[str] = None


# Sentinel — distinguishes "no prior found" from "prior found but stale"
# in the reason text, useful when debugging false negatives via logs.
_NOT_TRANSIENT = TransientSpikeVerdict(is_transient=False)


def _parse_prior_timestamp(prior_decision: dict) -> Optional[datetime]:
    """Tolerantly parse the prior decision's `timestamp` field.

    The store persists naive ISO strings (no tz suffix) — see
    rca_store._utc_now docstring. We accept either shape so a future
    schema migration that re-emits with `+00:00` doesn't silently break
    this gate.
    """
    raw = prior_decision.get("timestamp")
    if not raw:
        return None
    try:
        # fromisoformat in 3.11+ accepts both naive and tz-aware forms.
        ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        # Strip tz to match the naive "now" we'll compare against.
        return ts.replace(tzinfo=None) if ts.tzinfo is not None else ts
    except (ValueError, AttributeError):
        return None


def is_transient_spike(
    alert,
    prior_decision: Optional[dict],
    window_seconds: int,
    enabled_families: list[str] | tuple[str, ...],
    *,
    now: Optional[datetime] = None,
) -> TransientSpikeVerdict:
    """Decide whether `alert` is a transient spike given `prior_decision`.

    Returns a TransientSpikeVerdict. `is_transient=True` means the
    pipeline should shelve this fire without calling the LLM.

    Rules (ALL must hold for `is_transient=True`):
      1. alert.alertname is in SF-5's family map AND that family is in
         `enabled_families` (the config knob).
      2. `prior_decision` is non-None AND has a parseable timestamp.
      3. (now - prior_timestamp) < window_seconds.

    Edge cases / why each rule is conservative:
      - No prior fire → NOT transient. This is fire #1; we have no
        duration evidence, so we must let the LLM see it.
      - Prior > window ago → NOT transient. The alert was above
        threshold for ≥ window_seconds, which is the sustained case.
      - Family not in SF-5 list → NOT transient. We refuse to guess on
        alert archetypes we haven't validated (TargetDown is binary,
        DeadMansSwitch is a heartbeat, etc.).
      - Unparseable prior timestamp → NOT transient. Defensive: a
        garbled row shouldn't silently flip to shelved.
    """
    family = classify_family(alert)
    if family is None:
        return _NOT_TRANSIENT
    if family not in enabled_families:
        return _NOT_TRANSIENT
    if not prior_decision:
        return _NOT_TRANSIENT

    prior_ts = _parse_prior_timestamp(prior_decision)
    if prior_ts is None:
        return _NOT_TRANSIENT

    now = now or datetime.utcnow()
    delta_seconds = (now - prior_ts).total_seconds()
    # A negative delta would mean the prior_decision is in the future
    # (clock skew, test backdating gone wrong) — treat as not-transient
    # rather than auto-shelving.
    if delta_seconds < 0:
        return _NOT_TRANSIENT

    if delta_seconds < window_seconds:
        reason = (
            f"Transient spike — prior fire of the same {family} family on this scope "
            f"was {delta_seconds:.0f}s ago, under the {window_seconds}s sustained "
            f"threshold. Alert resolved + re-fired faster than a real sustained "
            f"breach would. Shelved without LLM call; will escalate normally on "
            f"the next sustained fire (≥{window_seconds}s above threshold)."
        )
        prior_id = prior_decision.get("id")
        logger.info(
            "SF-5 transient_spike: %s family=%s delta=%.0fs < window=%ds (prior=%s)",
            alert.alertname, family, delta_seconds, window_seconds,
            (prior_id or "?")[:12] if prior_id else "?",
        )
        return TransientSpikeVerdict(
            is_transient=True,
            family=family,
            reason=reason,
            prior_decision_id=prior_id,
        )
    return _NOT_TRANSIENT
