"""Programmatic validator for LLMDecision objects.

Runs between the LLM call and persistence. Four checks:

  1. Banned-phrase scan on rca + reason. Phrases the prompt explicitly
     forbids (rule B: "insufficient data" etc.) — if present, the LLM
     ignored the rule. Returns the matched phrase so the caller can
     quote it back in a retry prompt.

  2a. Vague-action scan on suggested_actions. Entries like "check logs",
     "investigate further" are rejected. The rejected list is returned
     pruned; callers treat a fully-empty result as "no LLM actions —
     consider template fallback" (handled in the pipeline).

  2b. Investigation-only scan (new 2026-04-27, after Lina's audit).
     Actions that READ system state (kubectl get/describe/top/logs,
     docker ps/logs/stats, "Query Grafana: ...", ssh ... 'top|df|ps')
     are rejected. The triage service already runs those queries via
     its MCP servers; the result belongs in rca/evidence, not in
     suggested_actions. suggested_actions must CHANGE state — kubectl
     rollout restart, kubectl set resources, helm rollback, docker
     restart, systemctl restart, etc.

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
    r"^\s*(?:check|monitor|investigate|review|look into|verify|examine|inspect|audit|"
    r"see|find|identify|ask|confirm|consider|look at|understand|determine)\s+",
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
# Investigation-only actions — actions that READ state but don't CHANGE it.
# These belong in the rca/evidence (the triage service does this work
# itself), not in suggested_actions. Lina's audit 2026-04-27 found ~100% of
# rows were emitting these; the prompt was rewritten to forbid them, this
# validator is the safety net.
#
# Detection strategy: match on a tightly-scoped command shape (the exact
# kubectl/docker subverbs that read, the "Query <observability tool>:"
# preface, and certain ssh-and-do-only-readonly forms). Pure regex, no
# AST. False negatives are fine (template fallback will provide a real
# remediation). False positives would be costly so we keep patterns
# specific.
# ---------------------------------------------------------------------------
_INVESTIGATION_ONLY_PATTERNS: tuple[re.Pattern, ...] = (
    # kubectl read-only verbs
    re.compile(r"\bkubectl\s+(?:get|describe|top|logs|exec|explain|api-resources|api-versions|cluster-info|config|version|wait)\b", re.I),
    # docker read-only verbs (logs/ps/stats/inspect/version/info)
    re.compile(r"\bdocker\s+(?:logs|ps|stats|inspect|version|info|images|history|diff|events|top|port|search)\b", re.I),
    # "Query <observability tool>: ..." pattern — the system already queried these
    re.compile(r"\bQuery\s+(?:Grafana|Prometheus|Loki|Jaeger|Tempo|Drain3)\b", re.I),
    re.compile(r"\bOpen\s+(?:Grafana|Prometheus|Loki|Jaeger)\b", re.I),
    re.compile(r"\bCheck\s+(?:Prometheus|Grafana|Loki|Jaeger)\s+(?:targets|panel|page|dashboard|UI)\b", re.I),
    # ssh + read-only shell tools
    re.compile(
        r"\bssh\b[^']*'(?:[^']*\b(?:top|htop|ps|free|df|du|ls|cat|head|tail|grep|awk|sed|nproc|uptime|uname|w|who|last|netstat|ss|lsof|stat|file|wc|sort|tail|find|tree)\b[^']*)'",
        re.I,
    ),
    # curl-as-probe patterns (curl ... | head, curl -s ... metrics, curl -sf ... healthz)
    re.compile(r"\bcurl\b[^|]*\|\s*head\b", re.I),
    re.compile(r"\bcurl\s+-s[fF]?[^|;`]*(?:metrics|healthz|/health|/ready|/status)\b", re.I),
)

# Remediation verbs — if any of these appear, the action is treated as a real
# fix even if it embeds an inspection command (e.g. `kubectl scale --replicas=$(($(kubectl get ...)+1))`
# legitimately reads to compute the new count, but the outer command still
# changes state).
_REMEDIATION_VERB_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"\bkubectl\s+(?:rollout\s+(?:restart|undo)|scale|set\s+(?:resources|env|image)|patch|delete\s+pod|delete\s+(?:replicaset|rs)|drain|cordon|uncordon|edit|apply|create|replace)\b", re.I),
    re.compile(r"\bhelm\s+(?:rollback|upgrade|uninstall|install)\b", re.I),
    re.compile(r"\bdocker\s+(?:restart|kill|rm|stop|start|run)\b", re.I),
    re.compile(r"\bdocker\s+compose\s+(?:restart|down|up|kill|stop|start|rm)\b", re.I),
    re.compile(r"\bsystemctl\s+(?:restart|reload|stop|start|kill|reset-failed)\b", re.I),
    re.compile(r"\bterraform\s+(?:apply|destroy|taint)\b", re.I),
    re.compile(r"\b(?:k|p)ill\b\s+-?[0-9A-Z]+", re.I),  # kill/pkill with target
    re.compile(r"\bgit\s+revert\b", re.I),
    re.compile(r"\bansible-playbook\b", re.I),
    re.compile(r"\bnpm\s+(?:install|run|publish)\b", re.I),
    re.compile(r"\bjournalctl\s+--vacuum", re.I),
    re.compile(r"\bcrictl\s+rmi", re.I),
    re.compile(r"\blogrotate\s+-f", re.I),
    re.compile(r"\bdocker\s+system\s+prune", re.I),
)


def _has_remediation_verb(action: str) -> bool:
    return any(p.search(action) for p in _REMEDIATION_VERB_PATTERNS)


def _looks_like_investigation_only(action: str) -> bool:
    """True if the action only reads state (kubectl get/describe, Query
    Grafana, ssh ... 'top', etc.) — the triage service already did this.

    An action that contains BOTH an investigation pattern AND a remediation
    verb (like `kubectl scale --replicas=$(($(kubectl get ...)+1))`) is NOT
    flagged — the outer command changes state, the embedded read is just
    computing an arg.
    """
    if _has_remediation_verb(action):
        return False
    for p in _INVESTIGATION_ONLY_PATTERNS:
        if p.search(action):
            return True
    return False


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
        # direct rule. Retry one time to see if it can behave.
        # Investigation-only rejections also warrant a retry: the LLM has the
        # context (the queries we already ran are in its prompt); it just
        # picked the wrong abstraction. One feedback round usually fixes it,
        # and template fallback is a coarser substitute.
        if self.banned_phrase_hits:
            return True
        if any("investigation_only" in why for _, why in self.rejected_actions):
            return True
        return False


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

    # --- 2a. Vague-action scan on suggested_actions
    kept_actions: list[str] = []
    for a in decision.suggested_actions:
        if _VAGUE_ACTION_HEAD.match(a) and not _HAS_SPECIFIC_PAYLOAD.search(a):
            report.rejected_actions.append((a, "vague_verb_no_payload"))
            report.violations.append(f"vague suggested_action: {a!r}")
        else:
            kept_actions.append(a)

    # --- 2b. Investigation-only scan (added 2026-04-27 — see philosophy in
    # response_validator module docstring + suggested_actions.yaml header).
    # Reads of state belong in rca/evidence; suggested_actions must change state.
    after_investigation_filter: list[str] = []
    for a in kept_actions:
        if _looks_like_investigation_only(a):
            report.rejected_actions.append((a, "investigation_only_no_remediation"))
            report.violations.append(f"investigation-only suggested_action: {a!r}")
        else:
            after_investigation_filter.append(a)
    kept_actions = after_investigation_filter

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
        investigation_count = sum(1 for _, why in report.rejected_actions if "investigation_only" in why)
        guidance = (
            "Replace with state-CHANGING remediations only — kubectl rollout restart / "
            "kubectl set resources / helm rollback / docker restart / systemctl restart. "
            "READ-ONLY commands (kubectl get/describe/logs, docker ps, Query Grafana, "
            "ssh 'top|df|ps') are forbidden — the triage service already ran those, "
            "their results are in your evidence field. Empty list is acceptable; vague "
            "or investigation-only entries are not."
        )
        parts.append(
            f"Your previous suggested_actions had {len(report.rejected_actions)} rejection(s) "
            f"({investigation_count} were investigation-only): {details}. {guidance}"
        )
    return "\n\n".join(parts) if parts else ""


__all__ = ["validate", "build_retry_feedback", "ValidationReport"]
