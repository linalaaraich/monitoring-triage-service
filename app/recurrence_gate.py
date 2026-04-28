"""US-5.8 recurrence gate — two-tier hysteresis for known-flappy alerts.

Composes with the existing recurrence-aware features:
  - Fingerprint dedup (D9, 10-min window) — collapses identical refires.
  - Drain3 7d-recurrence (D8, 7-day window) — escalates novel templates
    that recur ≥3 times.

This gate adds a third layer with a ~2h window:
  - PRE-LLM gate: first N fires of an opted-in alert are persisted as
    `recurrence_gated_pre_llm` with no LLM call. Cheap rows on the
    dashboard, no GPU, no email.
  - POST-LLM gate: when the LLM has dismissed the same fingerprint
    M times within the window, the next dismiss is force-flipped to
    ESCALATE. Reasoning: the LLM said "noise" repeatedly and the alert
    keeps firing — there's a real signal the model isn't catching.

Per-rule opt-in via Grafana annotation:
    annotations:
      recurrence_gate: "pre_llm=4,llm_dismiss=2,window=2h"

Rules without the annotation bypass the gate entirely.

CRITICAL-severity alerts (TargetDown, OOMKill, OTelCollectorDown, etc.)
NEVER opt in — for them the customer is in pain on fire #1 and waiting
4 fires is malpractice. Defense-in-depth: even if a misconfigured rule
opts in critical-severity, the gate's _is_critical check bypasses with
a metric counter that surfaces the misconfiguration to operators.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from app.models import Decision, GrafanaAlert, LLMDecision

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Annotation parsing
# -----------------------------------------------------------------------------

_DEFAULT_PRE_LLM_THRESHOLD = 4
_DEFAULT_LLM_DISMISS_THRESHOLD = 2
_DEFAULT_WINDOW_SECONDS = 7200  # 2 hours

_CRITICAL_SEVERITIES = {"critical", "page", "page-now", "p0"}


@dataclass(frozen=True)
class RecurrenceConfig:
    """Parsed recurrence_gate annotation. opted_in=False means the alert
    didn't carry the annotation (or carried a malformed one) and the gate
    must be skipped entirely."""
    opted_in: bool
    pre_llm_threshold: int = _DEFAULT_PRE_LLM_THRESHOLD
    llm_dismiss_threshold: int = _DEFAULT_LLM_DISMISS_THRESHOLD
    window_seconds: int = _DEFAULT_WINDOW_SECONDS

    @classmethod
    def disabled(cls) -> "RecurrenceConfig":
        return cls(opted_in=False)


_WINDOW_PAT = re.compile(r"^(\d+)([smhd])$")


def _parse_window(s: str) -> int | None:
    m = _WINDOW_PAT.match(s.strip())
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def parse_recurrence_annotation(annotation_value: str | None) -> RecurrenceConfig:
    """Parse a `recurrence_gate` annotation value into config.

    Format: comma-separated key=value pairs. Recognised keys:
      pre_llm    — int, fires before LLM is called (default 4)
      llm_dismiss — int, LLM dismisses before force-escalate (default 2)
      window     — duration like '2h' / '90m' / '7200s' (default 2h)

    Examples (all valid):
      "pre_llm=4,llm_dismiss=2,window=2h"   # explicit
      "pre_llm=3"                            # partial, others default
      ""                                     # empty → disabled
      None                                   # absent → disabled

    Malformed values default to disabled (so a typo never silently
    misroutes critical alerts).
    """
    if not annotation_value:
        return RecurrenceConfig.disabled()
    parts = [p.strip() for p in annotation_value.split(",") if p.strip()]
    if not parts:
        return RecurrenceConfig.disabled()

    cfg_kwargs: dict = {"opted_in": True}
    for p in parts:
        if "=" not in p:
            logger.warning("Recurrence-gate annotation has malformed pair %r — disabling gate", p)
            return RecurrenceConfig.disabled()
        k, v = p.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        try:
            if k == "pre_llm":
                cfg_kwargs["pre_llm_threshold"] = int(v)
            elif k == "llm_dismiss":
                cfg_kwargs["llm_dismiss_threshold"] = int(v)
            elif k == "window":
                seconds = _parse_window(v)
                if seconds is None:
                    logger.warning("Recurrence-gate window %r is malformed — disabling gate", v)
                    return RecurrenceConfig.disabled()
                cfg_kwargs["window_seconds"] = seconds
            else:
                logger.warning("Recurrence-gate annotation has unknown key %r — ignoring", k)
        except ValueError:
            logger.warning("Recurrence-gate annotation %r=%r couldn't be parsed — disabling gate", k, v)
            return RecurrenceConfig.disabled()

    # Defense in depth: clamp to sane bounds. Negative thresholds make no
    # sense; absurd windows (>24h) probably indicate misconfiguration.
    cfg_kwargs["pre_llm_threshold"] = max(0, cfg_kwargs.get("pre_llm_threshold", _DEFAULT_PRE_LLM_THRESHOLD))
    cfg_kwargs["llm_dismiss_threshold"] = max(0, cfg_kwargs.get("llm_dismiss_threshold", _DEFAULT_LLM_DISMISS_THRESHOLD))
    cfg_kwargs["window_seconds"] = min(86400, max(60, cfg_kwargs.get("window_seconds", _DEFAULT_WINDOW_SECONDS)))
    return RecurrenceConfig(**cfg_kwargs)


# -----------------------------------------------------------------------------
# Gate result type
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class GateResult:
    """Returned by the gates when they fire. None means no action."""
    triage_decision: str
    reason: str
    metric_label: str  # short tag for Prometheus counter labelling


# -----------------------------------------------------------------------------
# Critical-severity bypass
# -----------------------------------------------------------------------------

def _is_critical(alert: GrafanaAlert) -> bool:
    """Defense-in-depth: even if a critical-severity rule opts into the
    gate by misconfiguration, never gate it. The customer is in pain
    on fire #1 — waiting 4 fires is malpractice.
    """
    sev = (alert.severity or "").lower()
    if sev in _CRITICAL_SEVERITIES:
        return True
    # Some rules carry severity in labels.severity instead of the top-level
    # severity field — defense-in-depth checks both.
    label_sev = (alert.labels.get("severity") or "").lower() if alert.labels else ""
    return label_sev in _CRITICAL_SEVERITIES


# -----------------------------------------------------------------------------
# Pre-LLM gate
# -----------------------------------------------------------------------------

async def pre_llm_gate(
    alert: GrafanaAlert,
    store,
) -> GateResult | None:
    """Decide whether to skip the LLM call for this alert.

    Returns a non-None GateResult if:
      - The alert opted into the gate via annotation
      - The alert is NOT critical-severity
      - Prior fires of the same fingerprint within the window are
        below the configured threshold

    Calling the gate is idempotent — it doesn't write anything.
    """
    if not alert.fingerprint:
        return None
    cfg = parse_recurrence_annotation(
        (alert.annotations or {}).get("recurrence_gate")
    )
    if not cfg.opted_in:
        return None

    if _is_critical(alert):
        # Increment a counter so operators can see the misconfiguration
        try:
            from app.metrics import recurrence_critical_bypassed
            recurrence_critical_bypassed.inc()
        except (ImportError, AttributeError):
            pass
        logger.warning(
            "Recurrence gate: critical-severity alert %s carried opt-in annotation — bypassing gate (rule should drop the annotation)",
            alert.alertname,
        )
        return None

    prior_count = await store.count_recent_decisions_by_fingerprint(
        fingerprint=alert.fingerprint,
        llm_verdict=None,  # any verdict counts toward the pre-LLM cap
        window_seconds=cfg.window_seconds,
    )
    if prior_count < cfg.pre_llm_threshold:
        logger.info(
            "Recurrence pre-LLM gate firing for %s (fingerprint=%s, count=%d/%d)",
            alert.alertname, alert.fingerprint[:12], prior_count, cfg.pre_llm_threshold,
        )
        return GateResult(
            triage_decision="recurrence_gated_pre_llm",
            reason=(
                f"Pre-LLM recurrence gate: this is fire #{prior_count + 1} of {cfg.pre_llm_threshold} "
                f"in the {cfg.window_seconds // 60}-min window. No LLM call, no email — "
                f"persisting as cheap row. The gate releases on fire #{cfg.pre_llm_threshold + 1}."
            ),
            metric_label="pre_llm_under_threshold",
        )
    return None


# -----------------------------------------------------------------------------
# Post-LLM gate
# -----------------------------------------------------------------------------

async def post_llm_gate(
    alert: GrafanaAlert,
    decision: LLMDecision,
    store,
) -> GateResult | None:
    """Decide whether to flip a DISMISS verdict to ESCALATE.

    Fires when:
      - Verdict is DISMISS (escalates and inconclusives are untouched)
      - Alert opted in via annotation
      - NOT critical-severity (defense in depth)
      - LLM-seen dismissals on the same fingerprint within the window
        ≥ llm_dismiss_threshold

    The reasoning: the LLM has dismissed the same alert M times and the
    alert keeps firing. Either there's a real signal the model isn't
    catching, or the alert rule is genuinely too noisy and needs tuning
    — both warrant human attention.
    """
    if decision.decision != Decision.DISMISS:
        return None
    if not alert.fingerprint:
        return None
    cfg = parse_recurrence_annotation(
        (alert.annotations or {}).get("recurrence_gate")
    )
    if not cfg.opted_in:
        return None
    if _is_critical(alert):
        try:
            from app.metrics import recurrence_critical_bypassed
            recurrence_critical_bypassed.inc()
        except (ImportError, AttributeError):
            pass
        return None

    prior_dismisses = await store.count_recent_decisions_by_fingerprint(
        fingerprint=alert.fingerprint,
        llm_verdict="dismiss",
        window_seconds=cfg.window_seconds,
    )
    if prior_dismisses >= cfg.llm_dismiss_threshold:
        logger.info(
            "Recurrence post-LLM gate firing for %s (fingerprint=%s, prior_dismisses=%d/%d)",
            alert.alertname, alert.fingerprint[:12], prior_dismisses, cfg.llm_dismiss_threshold,
        )
        return GateResult(
            triage_decision="recurrence_gated_post_llm_force_escalate",
            reason=(
                f"Post-LLM recurrence gate: the LLM has dismissed this fingerprint "
                f"{prior_dismisses} times in the last {cfg.window_seconds // 60} minutes. "
                f"Forcing ESCALATE so a human can decide whether the rule is too noisy "
                f"or whether there's a real signal the LLM isn't catching."
            ),
            metric_label="post_llm_force_escalate",
        )
    return None
