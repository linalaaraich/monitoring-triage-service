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
)
# NOTE (DA-2 tightening, 2026-06-04): bare causal connectives
# ("because", "due to", "caused by", "triggered by", "resulting from") and
# the generic token "deploy" were REMOVED from _CAUSE_KEYWORDS. A connective
# is not itself a cause — "high CPU, possibly because of load" or "could be
# due to something" contains "because"/"due to" yet names no concrete subject,
# and was false-allowing destructive actions (e.g. `systemctl restart`) past
# the safety clamp. Connectives now only count when followed by a CONCRETE
# subject (see _connective_names_subject) and not inside a hedge.


# A connective grounds a cause only when it introduces a concrete subject.
# These patterns match "<connective> <subject>" where the subject begins with
# a real noun token (3+ alpha chars), explicitly EXCLUDING vague fillers that
# carry no diagnostic content. A hedge like "possibly due to load" or
# "could be because of something" therefore does NOT register as a named cause.
_CONNECTIVE_RE = re.compile(
    r"\b(?:because\s+of|because|caused\s+by|due\s+to|triggered\s+by|"
    r"resulting\s+from|stemming\s+from|attributable\s+to)\s+"
    r"(?:the\s+|a\s+|an\s+|some\s+)?"
    r"(?P<subject>[a-z][a-z0-9\-]{2,})",
    re.IGNORECASE,
)

# Hedge prefixes that void grounding even if a connective+subject follows:
# "possibly due to X", "may be because Y", "could be caused by Z" are
# hypotheses, not a named root cause.
_HEDGE_BEFORE_CONNECTIVE_RE = re.compile(
    r"\b(?:possibly|perhaps|maybe|may\s+be|might\s+be|could\s+be|"
    r"could|likely|probably|seems?\s+to\s+be|appears?\s+to\s+be|"
    r"potentially|presumably|suspected|suspect)\b\s*"
    r"(?:.{0,20}?)?"
    r"(?:because|caused\s+by|due\s+to|triggered\s+by|resulting\s+from)\b",
    re.IGNORECASE,
)

# Vague subjects that, even when introduced by a connective, do not name a
# concrete cause. "due to load", "because of issues" etc. are still symptom-
# level restatements.
_VAGUE_SUBJECTS: frozenset[str] = frozenset({
    "load", "loads", "issue", "issues", "problem", "problems", "error",
    "errors", "something", "factors", "factor", "conditions", "condition",
    "activity", "usage", "traffic", "demand", "stress", "pressure",
    "anomaly", "anomalies", "behaviour", "behavior", "spike", "spikes",
    "this", "that", "it", "them", "various", "multiple", "several",
    "unknown", "unclear", "high", "elevated", "increased", "excessive",
})


def _connective_names_subject(rca_lower: str) -> bool:
    """True when a causal connective in the prose introduces a CONCRETE
    subject (not a vague filler) and is not part of a hedge."""
    if _HEDGE_BEFORE_CONNECTIVE_RE.search(rca_lower):
        return False
    for m in _CONNECTIVE_RE.finditer(rca_lower):
        subject = m.group("subject").lower()
        if subject not in _VAGUE_SUBJECTS:
            return True
    return False


def has_named_cause(rca_text: str) -> bool:
    """True when the RCA prose grounds the diagnosis on something specific.

    Two ways to ground:
      1. A concrete cause-of-cause keyword (heap / jdbc pool / deadlock / ...).
      2. A causal connective that introduces a CONCRETE subject (e.g.
         "because the connection pool was exhausted") — but NOT a bare
         connective ("possibly due to load") which names nothing.

    A bare connective alone no longer counts (DA-2 false-allow fix
    2026-06-04): it was letting destructive actions pass the safety clamp
    on hedged, ungrounded RCAs.
    """
    if not rca_text:
        return False
    rca_lower = rca_text.lower()
    if any(kw in rca_lower for kw in _CAUSE_KEYWORDS):
        return True
    return _connective_names_subject(rca_lower)


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
