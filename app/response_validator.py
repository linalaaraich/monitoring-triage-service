"""Programmatic validator for LLMDecision objects.

Runs between the LLM call and persistence. Three checks, ordered by
severity:

  1. Banned-phrase scan on rca + reason. Phrases the prompt explicitly
     forbids (rule B: "insufficient data" etc.) — if present, the LLM
     ignored the rule. Returns the matched phrase so the caller can
     quote it back in a retry prompt.

  2. Vague-action scan on suggested_actions. Entries like "check logs",
     "investigate further" are rejected. The rejected list is returned
     pruned; callers treat a fully-empty result as "no LLM actions —
     consider template fallback" (handled in the pipeline).

  3. Architecture-mismatch scan — if the alert's deployment_type is
     known (k8s/docker-vm/systemd) and the suggested_actions contain
     commands from a DIFFERENT deployment family, those specific
     actions are rejected. The classic audit bug was the LLM emitting
     "kubectl get pods" for service=monitoring (which is Grafana on
     docker-vm, not k3s) — that kind of miss is now caught here.

Output: a ValidationReport with the cleaned decision + a list of
violation reasons. The caller decides what to do with violations
(retry the LLM, rely on template fallback, or just flag the row).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Literal

from app.models import LLMDecision

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Banned phrases — same patterns as rca_quality classifier for consistency.
# ---------------------------------------------------------------------------
_BANNED_PHRASE_PATTERNS: list[re.Pattern] = [
    re.compile(r"\binsufficient (?:data|information|context)\b", re.I),
    re.compile(r"\bno (?:recent |available )?(?:metrics|logs|traces|data)\b", re.I),
    re.compile(r"\b(?:cannot|unable to) (?:determine|identify|conclude)\b", re.I),
    re.compile(r"\bnot enough (?:data|information|context)\b", re.I),
    re.compile(r"\black(?:s|ing)? (?:sufficient |enough )?(?:data|context|information)\b", re.I),
]


# ---------------------------------------------------------------------------
# Vague actions — commands that don't help the operator do anything.
# Pattern: must START with a vague verb AND have no shell/URL/query payload.
# ---------------------------------------------------------------------------
_VAGUE_ACTION_HEAD = re.compile(
    r"^\s*(?:check|monitor|investigate|review|look into|verify|examine|inspect|audit)\s+",
    re.I,
)
_HAS_SPECIFIC_PAYLOAD = re.compile(
    # If the action contains any of these, it's probably concrete:
    #   backticked code, http(s)://, kubectl/ssh/docker/systemctl/curl keywords,
    #   PromQL/LogQL operators
    r"(?:`[^`]+`|https?://|\bkubectl\b|\bssh\b|\bdocker\b|\bsystemctl\b|\bcurl\b|\bjournalctl\b|=~|\{[^}]*=)",
    re.I,
)


# ---------------------------------------------------------------------------
# Architecture mismatch — which command families fit which deployment type.
# ---------------------------------------------------------------------------
_ARCH_COMMAND_SIGNALS: dict[str, tuple[re.Pattern, ...]] = {
    "k8s": (re.compile(r"\bkubectl\b"),),
    "docker-vm": (re.compile(r"\bdocker\s+(?:ps|logs|exec|inspect|stats)\b"),),
    "systemd": (re.compile(r"\bsystemctl\b"), re.compile(r"\bjournalctl\b")),
    "external": (),  # nothing local makes sense
}


def _looks_like_wrong_family(action: str, deployment_type: str) -> str | None:
    """If the action uses a command from a different deployment family than
    this service's, return the mismatched family name. Else None.

    Returns the NAME of the family the action matches — caller can use that
    to explain what went wrong.
    """
    for family, patterns in _ARCH_COMMAND_SIGNALS.items():
        if family == deployment_type:
            continue
        for p in patterns:
            if p.search(action):
                return family
    return None


# ---------------------------------------------------------------------------
# ValidationReport
# ---------------------------------------------------------------------------

@dataclass
class ValidationReport:
    """What validate() returns. Includes the (possibly modified) decision
    and a list of human-readable violation reasons.

    The decision is modified in-place where possible — e.g. vague or
    arch-mismatched actions are removed. But the original fields remain
    accessible for the retry prompt via `rejected_actions`.
    """
    decision: LLMDecision
    violations: list[str] = field(default_factory=list)
    banned_phrase_hits: list[str] = field(default_factory=list)
    rejected_actions: list[tuple[str, str]] = field(default_factory=list)  # (action, why)

    @property
    def is_clean(self) -> bool:
        return not self.violations

    @property
    def should_retry(self) -> bool:
        """True if the violations are severe enough to warrant an LLM retry
        (as opposed to just template-fallback-and-ship)."""
        # Banned phrases in the RCA narrative are severe — the LLM ignored a
        # direct rule. Retry one time to see if it can behave. Everything
        # else we handle silently (prune vague, prune mismatched, log).
        return bool(self.banned_phrase_hits)


def validate(
    decision: LLMDecision,
    deployment_type: str = "unknown",
    confidence_floor: float = 0.3,
) -> ValidationReport:
    """Run the three checks + confidence gate. Returns a ValidationReport
    with (maybe) modified decision and collected violations.

    Pure function — no side effects on the caller, but decision.suggested_actions
    IS mutated in place (we prune rejected entries). That's intentional: the
    caller wants a clean decision to persist.
    """
    report = ValidationReport(decision=decision)

    # --- 1. Banned-phrase scan on rca + reason
    combined = " ".join(filter(None, [decision.rca or "", decision.reason or ""]))
    for pattern in _BANNED_PHRASE_PATTERNS:
        m = pattern.search(combined)
        if m:
            phrase = m.group(0)
            report.banned_phrase_hits.append(phrase)
            report.violations.append(f"banned phrase in rca/reason: {phrase!r}")

    # --- 2. Vague-action scan on suggested_actions
    kept_actions: list[str] = []
    for a in decision.suggested_actions:
        if _VAGUE_ACTION_HEAD.match(a) and not _HAS_SPECIFIC_PAYLOAD.search(a):
            report.rejected_actions.append((a, "vague_verb_no_payload"))
            report.violations.append(f"vague suggested_action: {a!r}")
        else:
            kept_actions.append(a)

    # --- 3. Architecture mismatch
    if deployment_type in _ARCH_COMMAND_SIGNALS:
        filtered = []
        for a in kept_actions:
            wrong_family = _looks_like_wrong_family(a, deployment_type)
            if wrong_family:
                report.rejected_actions.append(
                    (a, f"arch_mismatch:{wrong_family}_command_for_{deployment_type}_service")
                )
                report.violations.append(
                    f"architecture mismatch: {a!r} is a {wrong_family} command "
                    f"but service deployment_type={deployment_type}"
                )
            else:
                filtered.append(a)
        kept_actions = filtered

    # Apply pruning to the decision
    decision.suggested_actions = kept_actions

    # --- 4. Confidence-floor gate (informational — caller writes the tag)
    if decision.confidence < confidence_floor:
        report.violations.append(
            f"confidence {decision.confidence:.2f} below floor {confidence_floor} — "
            f"caller should tag as needs_review"
        )

    if report.violations:
        logger.info(
            "Validator: %d violation(s) on alert decision — %s",
            len(report.violations),
            report.violations[0],
        )

    return report


def build_retry_feedback(report: ValidationReport) -> str:
    """Construct the feedback text appended to the user message on retry.

    Quotes the specific violations back to the LLM so it knows what to fix.
    Used when report.should_retry is True.
    """
    parts = []
    if report.banned_phrase_hits:
        phrases = ", ".join(f"{p!r}" for p in report.banned_phrase_hits)
        parts.append(
            f"Your previous response contained forbidden phrase(s): {phrases}. "
            "The system-prompt rule B forbids these standalone — you MUST name which "
            "pillar returned nothing and WHY, with a concrete hypothesis. Rewrite "
            "without any of the above phrases."
        )
    if report.rejected_actions:
        details = "; ".join(f"{a!r} ({why})" for a, why in report.rejected_actions[:5])
        parts.append(
            f"Your previous suggested_actions had {len(report.rejected_actions)} rejection(s): {details}. "
            "Replace with specific shell commands, PromQL/LogQL queries, or URLs. "
            "Empty list is better than vague advice."
        )
    return "\n\n".join(parts) if parts else ""


__all__ = ["validate", "build_retry_feedback", "ValidationReport"]
