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
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Literal

import yaml

from app.config import settings
from app.metrics import triage_validator_retries_total
from app.models import LLMDecision

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-alert hallucination blocklist (F-3)
# ---------------------------------------------------------------------------
# Loaded lazily once at first use. The YAML file lives next to this module so
# operators can add new entries without touching Python. See the file's own
# header for the schema and the rationale.

_BLOCKLIST_PATH = os.path.join(os.path.dirname(__file__), "hallucination_blocklist.yaml")


@dataclass(frozen=True)
class _HallucinationRule:
    pattern: re.Pattern
    reason: str
    hint: str


@lru_cache(maxsize=1)
def _load_blocklist() -> dict[str, list[_HallucinationRule]]:
    """Parse hallucination_blocklist.yaml once, compile the regexes, return
    a dict of alertname → list[_HallucinationRule]. Returns {} on any error
    so the validator never crashes the pipeline because the blocklist
    couldn't be read.
    """
    try:
        with open(_BLOCKLIST_PATH, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as e:
        logger.warning("Could not load hallucination_blocklist.yaml: %s", e)
        return {}

    out: dict[str, list[_HallucinationRule]] = {}
    for alertname, rules in raw.items():
        if not isinstance(rules, list):
            continue
        compiled = []
        for r in rules:
            try:
                compiled.append(_HallucinationRule(
                    pattern=re.compile(r["pattern"], re.I),
                    reason=str(r.get("reason", "")).strip(),
                    hint=str(r.get("hint", "")).strip(),
                ))
            except (KeyError, re.error) as e:
                logger.warning("Skipping malformed blocklist entry under %s: %s", alertname, e)
                continue
        if compiled:
            out[alertname] = compiled
    logger.info(
        "Loaded hallucination blocklist: %d alertname(s), %d total rules",
        len(out), sum(len(v) for v in out.values()),
    )
    return out


def find_hallucination_hits(rca: str, alertname: str) -> list[_HallucinationRule]:
    """Return the rules that matched the rca prose for this alertname."""
    if not rca or not alertname:
        return []
    rules = _load_blocklist().get(alertname, [])
    return [r for r in rules if r.pattern.search(rca)]


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
# Surface-only RCA prose — added 2026-04-28 after operator feedback.
#
# Telemetry data is the means, not the end of an RCA. The LLM's prior shape
# was to lead with the PromQL expression and the observed value, then
# conclude "this indicates that there are <X> experiencing <Y>" — which is
# the alert restating itself, not a diagnosis. SYSTEM_PROMPT rule A and the
# few-shot examples now demand a NAMED cause in the first sentence; this
# validator is the safety net that catches when the model ignores it.
#
# Detection strategy: scan the RCA's first sentence for known surface-only
# lede patterns. We only fire on the OPENING sentence because rule A is
# specifically about how the analysis starts; later mentions of PromQL in
# service of evidence are fine and expected.
# ---------------------------------------------------------------------------
_SURFACE_ONLY_LEDE_PATTERNS: tuple[re.Pattern, ...] = (
    # "PromQL `<expr>` reported|returned <value> above|below threshold..."
    re.compile(r"^\s*(?:The\s+)?PromQL\s+(?:expression\s+)?[`'\"]", re.I),
    # "PromQL <name>(...) reported..."
    re.compile(r"^\s*(?:The\s+)?PromQL\s+\w+\s*\(", re.I),
    # "The metric / The query / The alert <X> reports / shows / returned <value>..."
    # Widened 2026-04-28 PM-late after live-verify saw "The alert indicates that
    # there are no valid latency samples..." slip through.
    re.compile(r"^\s*The\s+(?:metric|query|expression|value|observation|alert|rule|webhook|fire|firing)\s+(?:\S+\s+)?(?:reports|reported|shows|showed|returned|indicates|indicated|signals|signaled)\b", re.I),
    # "The alert <X>" without a verb: "The alert HighP95Latency for service=kong..."
    re.compile(r"^\s*The\s+alert\s+\S+\s+for\b", re.I),
    # Alertname-first form (added 2026-04-28 PM-late after live-verify saw
    # "The Drain3AnomalyDetected alert for service=drain3 indicates..." slip
    # through P3/P4). Same surface-only shape, different word order.
    re.compile(r"^\s*The\s+\S+\s+alert\s+for\b", re.I),
    # "The observed/measured/reported/elevated/recorded value of X" — the LLM
    # leads with the metric reading dressed up as a sentence. Added 2026-04-28
    # PM-late; live-verify saw "The observed value of 3100 ms for p95 latency
    # indicates..." escape both P3 (no verb in the trigger window) and P5.
    re.compile(r"^\s*The\s+(?:observed|measured|reported|recorded|elevated|current|latest)\s+(?:value|reading|sample|datapoint|metric|rate|count)\b", re.I),
    # "<metric_name> = <value>" as the entire opening — raw evaluation pasted as prose
    re.compile(r"^\s*\w+(?:\{[^}]*\})?\s*[=<>]\s*[0-9]", re.I),
    # "Based on (the) observed/repeated/reported/metric/PromQL/log entries..."
    # Widened 2026-04-28 after live HighP95Latency rows (10:12 + 10:13) led
    # with "Based on the repeated log entries..." / "Based on the observed
    # metric values and PromQL queries..." — both were surface restatements
    # of the alert dressed up as analysis.
    re.compile(r"^\s*Based\s+on\s+(?:the\s+)?(?:observed|repeated|reported|metric|PromQL|query|queries|log\s+entries|logs|trace|values?|frequency|rate|elevated|high|increased|recurring|context|information|data|input|history|provided|prompt|alert|prior|available)\b", re.I),
    # "Looking at the metrics / data / observations..." — same shape, different framing.
    re.compile(r"^\s*Looking\s+at\s+(?:the\s+)?(?:metrics?|data|observations?|logs?|traces?)\b", re.I),
)

# Hedge tails that signal the RCA never went past the symptom — "indicates that
# there are requests experiencing high latency" is the alert in different words.
#
# Widened 2026-04-28 (Lina's HighP95Latency investigation): the model's actual
# regression shape was less specific than the original example
# ("indicates that there are X experiencing Y"). Real outputs read more like
# "appears that there is a recurring issue", "suggesting potential performance
# degradation", "could be indicative of either X or Y", "requires further
# investigation". The patterns below cover that broader class without
# false-positiving on legitimate causal prose like "indicates that the JDBC
# pool is exhausted" (which is a NAMED cause).
_SURFACE_ONLY_HEDGE_PATTERNS: tuple[re.Pattern, ...] = (
    # Original — narrow but high-confidence: "indicates that there are requests experiencing X"
    re.compile(r"\bindicates?\s+that\s+there\s+(?:are|is|may\s+be)\s+\S+\s+(?:experiencing|reporting|seeing|having)\b", re.I),
    # "indicates a (persistent|recurring|potential|ongoing) issue"
    re.compile(r"\bindicates?\s+(?:a|an)\s+(?:persistent|recurring|potential|ongoing|possible|likely)\s+(?:issue|problem|concern)\b", re.I),
    # "appears (that|to be) ... issue/problem/concern" — allow 1-4 words between
    # "appears that there is" and the noun ("a recurring issue", "an ongoing problem")
    re.compile(r"\bappears?\s+(?:that\s+there\s+is|to\s+be|that\s+the)\b.{0,50}?\b(?:issue|problem|concern|condition)\b", re.I),
    # "appears to be experiencing|seeing|having (high|elevated|abnormal) X"
    re.compile(r"\b(?:appears|seems)\s+to\s+be\s+(?:experiencing|seeing|having)\s+(?:high|elevated|abnormal)\b", re.I),
    # "suggests/suggesting potential X" — pure hedge
    re.compile(r"\bsuggest(?:s|ing)?\s+(?:that\s+)?(?:a\s+)?(?:potential|possible|some\s+kind\s+of)\b", re.I),
    # "suggests/suggesting (high|elevated|increased|abnormal|unusual) X"
    re.compile(r"\bsuggest(?:s|ing)?\s+(?:that\s+)?(?:high|elevated|increased|abnormal|unusual)\s+\w+\b", re.I),
    # "could be indicative of either/some/various"
    re.compile(r"\bcould\s+be\s+indicative\s+of\b", re.I),
    # "could be (related|due|caused) by/to" without naming what
    re.compile(r"\bcould\s+be\s+(?:related\s+to|due\s+to|caused\s+by)\s+(?:either|some|various|a\s+number\s+of)\b", re.I),
    # "might be (a|an) X (issue|problem|concern)" — pure hedge
    re.compile(r"\bmight\s+be\s+(?:a|an)\s+\S+\s+(?:issue|problem|concern|cause)\b", re.I),
    # "requires further investigation" / "warrants further investigation" — the LLM is asking for help
    re.compile(r"\b(?:requires?|warrants?|needs?)\s+further\s+(?:investigation|review|analysis|examination)\b", re.I),
    # "performance degradation" / "resource contention" — generic SRE filler that says nothing
    re.compile(r"\b(?:potential|possible|likely)\s+(?:performance\s+degradation|resource\s+contention|degraded\s+performance)\b", re.I),
    # "either ... or ..." pattern when both alternatives are vague
    re.compile(r"\beither\s+(?:the|an?)\s+\S+\s+(?:itself\s+is|is\s+performing|might\s+be)\b.{0,80}\bor\s+there\s+might\s+be\b", re.I),
)


# ---------------------------------------------------------------------------
# Hypothesis-menu patterns (S3-HF-03 / Tier 2) — added 2026-04-29 after the
# HighKongP95Latency 0b215ef3 incident.
#
# The 0b215ef3 RCA passed every existing validator: not surface-only (it
# named a layer), no banned hedge phrase, no per-alert hallucination match.
# It still failed because the cause was a HYPOTHESIS MENU instead of a
# diagnosis: "...possibly due to a regressed query or saturated connection
# pool." That sentence offers two alternatives within a layer without
# committing to one. It's a half-finished diagnosis dressed up as analysis.
#
# Patterns target the shape: alternative-marker word + noun phrase +
# disjunction marker (or / comma) + noun phrase. Tight enough to avoid
# false-positiving on legitimate prose like "the JDBC pool was exhausted;
# downstream MySQL also saw lock contention" (no alternative-marker) or
# "either way, the cause is X" (idiomatic, negative-lookahead-guarded).
#
# Gated by settings.triage_hypothesis_menu_strict (default True). Hits
# trigger the existing retry path; Tier 0 clamp (S3-HF-01) is the safety
# net for retries that still emit hypothesis menus.
# ---------------------------------------------------------------------------
_HYPOTHESIS_MENU_PATTERNS: tuple[re.Pattern, ...] = (
    # "possibly X or Y" / "possibly due to A or B" — the prototypical
    # 0b215ef3 shape: "...possibly due to a regressed query or saturated
    # connection pool."
    re.compile(r"\bpossibly\s+(?:due\s+to\s+|caused\s+by\s+)?(?:a|an|the)?\s*\w+(?:\s+\w+){0,5}\s+or\s+(?:a|an|the)?\s*\w+", re.I),
    # "either X or Y" where X and Y are noun phrases. Negative lookahead
    # excludes idiomatic "either way" / "either case".
    re.compile(r"\beither\s+(?!way\b|case\b)(?:a|an|the)?\s*\w+(?:\s+\w+){0,5}\s+or\s+(?:a|an|the)?\s*\w+", re.I),
    # "may be due to (a slow query|pool saturation|GC)" — committee
    # diagnosis with comma-separated or "or"-separated alternatives.
    re.compile(r"\bmay\s+be\s+(?:due\s+to|caused\s+by|attributed\s+to)\s+(?:a|an|the)?\s*\w+(?:\s+\w+){0,3}(?:,|\s+or\s+)\s*(?:a|an|the|or)?\b", re.I),
    # "could be (a slow query|saturated pool|...)" with separator
    re.compile(r"\bcould\s+be\s+(?:due\s+to\s+)?(?:a|an|the)?\s*\w+(?:\s+\w+){0,3}(?:,|\s+or\s+)\s*(?:a|an|the|or)\b", re.I),
    # "one of (slow query|pool saturation|GC)"
    re.compile(r"\bone\s+of\s+(?:a|an|the)?\s*\w+(?:\s+\w+){0,3}(?:,|\s+or\s+)", re.I),
    # "might be (X) or (Y)"
    re.compile(r"\bmight\s+be\s+(?:due\s+to\s+|caused\s+by\s+)?(?:a|an|the)?\s*\w+(?:\s+\w+){0,4}\s+or\s+(?:a|an|the)?\s*\w+", re.I),
    # "(perhaps|maybe) X or Y" — softer hedges in the same shape
    re.compile(r"\b(?:perhaps|maybe)\s+(?:due\s+to\s+)?(?:a|an|the)?\s*\w+(?:\s+\w+){0,4}\s+or\s+(?:a|an|the)?\s*\w+", re.I),
)


# Stopwords for the cause-evidence overlap check. These are tokens too
# generic to count as a "specific cause reference" — the rule wants the
# RCA to share a meaningful diagnostic token (component name, error
# type, query fragment, span operation) with the evidence, not just the
# alert's framing words.
_CAUSE_EVIDENCE_STOPWORDS: frozenset[str] = frozenset({
    # Articles / fillers / common verbs (4+ chars to make _check_cause_evidence_overlap's tokenizer pick them up)
    "this", "that", "these", "those", "with", "from", "have", "been",
    "were", "will", "into", "onto", "than", "then", "when", "where",
    "what", "which", "would", "could", "should", "might", "must",
    # Generic alert/SRE vocabulary that appears on both sides without
    # adding diagnostic information
    "alert", "alerts", "metric", "metrics", "value", "values",
    "system", "service", "issue", "issues", "problem", "problems",
    "above", "below", "shows", "show", "indicates", "indicate",
    "appears", "appear", "seems", "seem", "warning", "error",
    "errors", "request", "requests", "response", "responses",
    "high", "high.", "low", "elevated", "increased", "decreased",
    "rate", "rates", "level", "levels", "count", "counts", "threshold",
    "thresholds", "above", "below", "average", "median", "total",
    "time", "times", "second", "seconds", "minute", "minutes",
    "observed", "reported", "fired", "firing", "trigger", "triggered",
    # Service names — too generic, an RCA mentioning only the service
    # name hasn't named anything within the service
    "kong", "spring", "boot", "spring-boot", "loki", "grafana",
    "prometheus", "jaeger", "drain3", "monitoring",
})


def _check_cause_evidence_overlap(
    rca_text: str,
    evidence: list[str],
) -> bool:
    """Return True if the RCA shares no non-stopword token with the
    evidence list — signals fabrication (RCA cites things that aren't
    in the gathered data). Returns False if there IS overlap or if
    evidence is too thin to ground against.

    Tokens are 4+ char word-class lowercased, stopwords removed.
    """
    if not rca_text or not evidence:
        return False  # caller skips check on empty inputs
    # Letter-only tokenizer: splits underscored metric names naturally
    # (hikaricp_connections_active -> [hikaricp, connections, active]),
    # which is what we want for cross-matching prose and metric labels.
    rca_tokens = set(re.findall(r"[a-z]{4,}", rca_text.lower()))
    evidence_tokens: set[str] = set()
    for e in evidence:
        evidence_tokens.update(re.findall(r"[a-z]{4,}", str(e).lower()))
    # If evidence itself has no specific tokens (only stopwords / numbers),
    # skip the check — the LLM has nothing to ground against.
    evidence_specific = evidence_tokens - _CAUSE_EVIDENCE_STOPWORDS
    if not evidence_specific:
        return False
    overlap = (rca_tokens & evidence_tokens) - _CAUSE_EVIDENCE_STOPWORDS
    return not overlap


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
        # direct rule. Retry one time to see if it can behave. This includes
        # hallucination hits (F-3) — same shape: model cited wrong evidence.
        # Investigation-only rejections also warrant a retry: the LLM has the
        # context (the queries we already ran are in its prompt); it just
        # picked the wrong abstraction. One feedback round usually fixes it,
        # and template fallback is a coarser substitute.
        if self.banned_phrase_hits:
            return True
        if any("investigation_only" in why for _, why in self.rejected_actions):
            return True
        return False

    @property
    def has_hallucination(self) -> bool:
        """True if the F-3 per-alert blocklist matched anything."""
        return any(p.startswith("hallucination[") for p in self.banned_phrase_hits)


def validate(
    decision: LLMDecision,
    deployment_type: str = "unknown",
    confidence_floor: float = 0.3,
    alertname: str = "",
) -> ValidationReport:
    """Run the four checks + confidence gate. Returns a ValidationReport
    with (maybe) modified decision and collected violations.

    Pure function — no side effects on the caller, but decision.suggested_actions
    IS mutated in place (we prune rejected entries). That's intentional: the
    caller wants a clean decision to persist.

    `alertname` enables the per-alert hallucination blocklist (F-3) — pass
    the live alert.alertname so per-alert checks can fire. Defaults empty
    for backwards compat with callers that don't have the alertname handy.
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

    # --- 1c. Per-alert hallucination blocklist scan (F-3, added 2026-04-28).
    # The LLM grasps at scrape-internal log frequency (e.g. /actuator/*) as
    # a "cause" for HighP95Latency despite no causal link. The blocklist
    # rejects RCAs that cite known wrong-evidence patterns.
    if alertname and decision.rca:
        hallucination_hits = find_hallucination_hits(decision.rca, alertname)
        for rule in hallucination_hits:
            report.banned_phrase_hits.append(f"hallucination[{alertname}]: {rule.pattern.pattern!r}")
            # Use only the first line of the reason for the violation message;
            # the full reason + hint go into the retry feedback below.
            short_reason = rule.reason.splitlines()[0] if rule.reason else "hallucinated cause"
            report.violations.append(
                f"hallucinated cause for {alertname}: matched {rule.pattern.pattern!r} — {short_reason}"
            )

    # --- 1b. Surface-only RCA scan (added 2026-04-28 — rule A philosophy update).
    # Catches "PromQL <expr> reported X" ledes and "indicates that there are X
    # experiencing Y" hedge tails — both are tells of a model that restated the
    # alert instead of naming a cause.
    rca_text = (decision.rca or "").strip()
    if rca_text:
        # Take the first sentence (up to first period that's followed by a space
        # or end-of-string). Defensive split — RCAs are short prose.
        first_sentence = re.split(r"\.(?:\s|$)", rca_text, maxsplit=1)[0]
        for pattern in _SURFACE_ONLY_LEDE_PATTERNS:
            if pattern.search(first_sentence):
                hit = first_sentence[:80]
                report.banned_phrase_hits.append(f"surface-only lede: {hit!r}")
                report.violations.append(
                    "surface-only RCA lede — first sentence restates the alert "
                    "(PromQL/metric value) instead of naming a cause. See SYSTEM_PROMPT rule A."
                )
                break
    for pattern in _SURFACE_ONLY_HEDGE_PATTERNS:
        m = pattern.search(combined)
        if m:
            phrase = m.group(0)
            report.banned_phrase_hits.append(f"surface-only hedge: {phrase!r}")
            report.violations.append(
                f"surface-only hedge in rca/reason: {phrase!r} — this is the alert "
                "in different words, not a diagnosis."
            )
            break

    # --- 1d. Hypothesis-menu scan (S3-HF-03 / Tier 2). The RCA names a
    # layer but offers multiple alternative causes within that layer
    # without committing — a half-finished diagnosis. Triggered by the
    # 2026-04-29 0b215ef3 incident: "possibly a regressed query or
    # saturated connection pool" passed all prior validators because it
    # wasn't a surface-only lede AND wasn't a known hedge tail. Gated by
    # settings.triage_hypothesis_menu_strict — disable via env if FP
    # rate (visible on triage_validator_retries_total{reason}) > 5%.
    if settings.triage_hypothesis_menu_strict:
        for pattern in _HYPOTHESIS_MENU_PATTERNS:
            m = pattern.search(combined)
            if m:
                phrase = m.group(0)
                report.banned_phrase_hits.append(f"hypothesis-menu: {phrase!r}")
                report.violations.append(
                    f"hypothesis-menu in rca/reason: {phrase!r} — the RCA lists "
                    "possible causes within a layer instead of naming one. Pick "
                    "ONE cause backed by trace/metric evidence, or admit you "
                    "can't narrow it (data_starved is the right tag for that)."
                )
                triage_validator_retries_total.labels(reason="hypothesis_menu").inc()
                break

    # --- 1e. Cause-must-reference-evidence (S3-HF-03 / Tier 2). The RCA
    # prose must share at least one specific (non-stopword) token with
    # decision.evidence. Catches fabrication: the LLM names a cause but
    # nothing in the gathered data supports it. Skipped when evidence is
    # empty (no signal to ground against) or when evidence has no
    # specific tokens (only stopwords/numbers — the LLM has nothing to
    # ground against). Gated by the same flag.
    if settings.triage_hypothesis_menu_strict and decision.evidence:
        if _check_cause_evidence_overlap(rca_text, decision.evidence):
            report.banned_phrase_hits.append("cause-evidence-mismatch")
            report.violations.append(
                "cause-evidence-mismatch: RCA shares no specific token with "
                "the evidence list — the named cause isn't supported by "
                "anything the pipeline gathered. Either expand evidence to "
                "include what supports the cause, or name a cause that the "
                "gathered evidence actually shows."
            )
            triage_validator_retries_total.labels(reason="cause_evidence_mismatch").inc()

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

    # Hallucination feedback: each rule contributes its specific hint.
    # These are alert-specific so the model gets pointed at what IS the
    # right kind of evidence, not just told it was wrong.
    hallucination_hits = [p for p in report.banned_phrase_hits if p.startswith("hallucination[")]
    if hallucination_hits:
        # Pull the hint text from the loaded blocklist for each match.
        hint_text = []
        for p in hallucination_hits:
            # Format: "hallucination[<alertname>]: <pattern>"
            try:
                alertname_part = p.split("hallucination[", 1)[1].split("]:", 1)[0]
                pattern_part = p.split("]: ", 1)[1].strip("'\"")
                rules = _load_blocklist().get(alertname_part, [])
                for r in rules:
                    if r.pattern.pattern == pattern_part:
                        hint_text.append(f"- {r.reason.splitlines()[0] if r.reason else ''}")
                        if r.hint:
                            hint_text.append(f"  → {r.hint.splitlines()[0]}")
                        break
            except Exception:
                pass
        parts.append(
            "Your previous RCA cited evidence that does NOT support a cause:\n"
            + "\n".join(hint_text or ["- (see blocklist)"]) +
            "\nRewrite naming a specific failing component/process/dependency and "
            "cite evidence that actually supports it."
        )

    if report.banned_phrase_hits and not (len(hallucination_hits) == len(report.banned_phrase_hits)):
        non_halluc = [p for p in report.banned_phrase_hits if not p.startswith("hallucination[")]
        phrases = ", ".join(f"{p!r}" for p in non_halluc)
        # Distinguish surface-only feedback from hypothesis-menu / cause-evidence
        # feedback from data-thin (rule B) feedback — the LLM needs different
        # guidance for each.
        is_surface_only = any("surface-only" in p for p in non_halluc)
        is_hypothesis_menu = any(p.startswith("hypothesis-menu:") for p in non_halluc)
        is_cause_evidence = any(p == "cause-evidence-mismatch" for p in non_halluc)
        if is_hypothesis_menu and not is_surface_only:
            parts.append(
                f"Your previous response listed alternatives instead of naming one cause: {phrases}. "
                "A hypothesis menu is not a diagnosis. Pick ONE cause backed by specific "
                "trace/metric evidence. If you genuinely can't narrow it down, say so "
                "explicitly with `confidence: 0.4` or lower and mark `decision: INCONCLUSIVE` "
                "rather than emitting a both-and answer dressed as a verdict."
            )
        elif is_cause_evidence and not is_surface_only:
            parts.append(
                "Your previous RCA named a cause that shares no specific token with the "
                "evidence you gathered. Either (a) name a cause the evidence actually "
                "supports, OR (b) expand the `evidence` field to include the metric/log/trace "
                "that supports the named cause. The cause and the evidence must match — "
                "fabrication (saying X when nothing in the data shows X) is the failure mode."
            )
        elif is_surface_only:
            parts.append(
                f"Your previous response had a surface-only RCA lede: {phrases}. "
                "Rule A: the first sentence MUST name a cause (a component, link, "
                "process, queue, config, or change), not restate the alert. PromQL "
                "expressions and observed values belong in `evidence`, not as the "
                "diagnosis. Rewrite — first sentence names what is broken and why; "
                "metrics / logs / traces follow as supporting evidence."
            )
        else:
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
