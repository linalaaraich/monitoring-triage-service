"""DA-2 — clamp-independent unsafe-action stripping.

When `rca_quality=actionable` AND the RCA prose names no specific
cause-of-cause, strip state-changing remediation verbs (systemctl
restart / kubectl rollout|scale|set|delete|patch / ssh / reboot /
docker restart) from `suggested_actions`. Fires regardless of
confidence — the audit-surfaced failure mode is:

    quality=actionable AND confidence=0.78 AND
    rca="CPU usage is critically high on the node" AND
    suggested_actions=["systemctl restart k3s-node.service"]

The LLM was confident, the validator passed, but the RCA only restates
the alert symptom (`high CPU`) without naming what's burning it. Letting
a destructive restart ship in that state is the operator-trust failure
the §7c.4 audit caught.

This gate is intentionally separate from the F-4 confidence clamp:
- The clamp triggers on (surface-only OR data_starved OR templated
  actions) and replaces actions wholesale with diagnostic verbs.
- DA-2 triggers on (actionable quality AND no named cause) — the
  clamp does NOT fire because the output looks fine, but the action
  is dangerous without grounding. We strip only the unsafe entries
  rather than replacing wholesale, so any specific actions (e.g. a
  PromQL pivot, a Jaeger trace pointer) survive.

Conservatism: false-positive (stripping when cause was named) just
loses a possibly-useful action; false-negative (allowing unsafe action
through when cause wasn't really named) is what we're guarding against.
The cause-keyword list is therefore broad — when in doubt, allow.
"""
from __future__ import annotations

import re


# Action patterns that change state. Hit on any → candidate for strip
# when the RCA doesn't ground the cause.
UNSAFE_ACTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bsystemctl\s+(restart|stop|kill|disable|reload)\b", re.IGNORECASE),
    re.compile(r"\bkubectl\s+(rollout|scale|set|delete|patch|exec|cordon|drain|apply|replace|edit)\b", re.IGNORECASE),
    re.compile(r"^\s*ssh\s+\S+", re.IGNORECASE),
    re.compile(r"\b(reboot|shutdown)\b", re.IGNORECASE),
    re.compile(r"\bdocker\s+(restart|stop|kill|rm)\b", re.IGNORECASE),
    re.compile(r"\bservice\s+\S+\s+(restart|stop|reload)\b", re.IGNORECASE),
    re.compile(r"\brestart\s+\S+\.service\b", re.IGNORECASE),
]

# Cause-of-cause vocabulary. The presence of any of these in the RCA
# prose (case-insensitive substring match) means the LLM grounded the
# diagnosis on a specific subsystem / event / failure mode — not just
# restating the alert symptom. Broad list intentionally: false-allow
# (action survives when it shouldn't have) is recoverable; false-deny
# (action stripped when cause was named) just loses a recommendation.
_CAUSE_KEYWORDS: tuple[str, ...] = (
    # Database / persistence
    "slow query", "slow queries", "n+1", "full table scan", "missing index",
    "deadlock", "lock contention", "row lock", "table lock",
    "jdbc pool", "hikari", "connection pool", "pool exhaustion", "pool saturat",
    # JVM
    "heap", "gc pause", "garbage collect", "gc overhead", "stop-the-world",
    "thread starvation", "thread pool", "thread leak",
    # Memory
    "oom", "out of memory", "memory leak", "cgroup limit",
    # Concurrency
    "race condition", "starvation", "infinite loop", "runaway thread",
    # Deployment / config
    "deploy", "rollout", "regression", "config change", "configuration change",
    "feature flag", "version bump",
    # OS / infra
    "kernel", "swap", "page fault",
    "disk full", "enospc", "no space", "inode",
    "network partition", "packet loss", "tcp retransmit", "dns resolution",
    # App-layer
    "saturation", "rate limit", "circuit breaker", "retry storm",
    "upstream timeout", "downstream timeout", "cascade",
    # Specific cause-of-cause shapes
    "because", "caused by", "due to", "triggered by", "resulting from",
)


def has_named_cause(rca_text: str) -> bool:
    """True when the RCA prose contains at least one cause-of-cause
    keyword — i.e. the LLM grounded the diagnosis on something specific
    rather than restating the alert symptom.
    """
    if not rca_text:
        return False
    rca_lower = rca_text.lower()
    return any(kw in rca_lower for kw in _CAUSE_KEYWORDS)


def strip_unsafe_actions(
    actions: list[str] | None,
    rca_text: str,
) -> tuple[list[str], list[str]]:
    """Return (kept, stripped). If the RCA names a cause-of-cause, no
    stripping happens and all actions survive. Otherwise, any action
    matching an UNSAFE_ACTION_PATTERN is removed."""
    if not actions:
        return [], []
    if has_named_cause(rca_text):
        return list(actions), []

    kept: list[str] = []
    stripped: list[str] = []
    for action in actions:
        if any(p.search(action) for p in UNSAFE_ACTION_PATTERNS):
            stripped.append(action)
        else:
            kept.append(action)
    return kept, stripped


__all__ = ["UNSAFE_ACTION_PATTERNS", "has_named_cause", "strip_unsafe_actions"]
