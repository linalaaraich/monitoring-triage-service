"""Plain-English prose helpers for the human-first reason refactor (2026-06-02).

Lina's complaint (paraphrased): "reason is some abstract metric with a big
formula... I need human readability, simplicity, removing obstacles and
lessening mental load of engineer. Instead of seeing some metric that says
some service has net issues, say 'error 500 occurs continuously' or something
like that. It has to be human first."

This module owns the split between the two halves of an RCA:

  - `human_cause` — a 1-sentence plain-English statement of WHAT went wrong.
    Rendered as the email banner, dashboard "Why" cell, and detail-page H1.
    NEVER contains PromQL, backticked metric blocks, `metric{...} = value`,
    histogram_quantile(...) expressions, or raw numeric ratios. Operators
    read this first; mental load must be near zero.

  - `evidence` — the technical supporting list (PromQL, metric values, log
    line counts, trace IDs). Rendered BELOW the human_cause, behind an
    expand/scroll. The model is free to keep these as long and metric-dense
    as it likes — they're not in the operator's first line of sight.

`split_human_cause_and_evidence(rca)` is the back-compat path: pre-refactor
RCAs (single `rca` blob with formulas inlined) get retroactively split into
a clean human_cause + an evidence list. The detector is conservative —
when in doubt, prose stays in human_cause; only obvious metric/PromQL
fragments get peeled into evidence.

`derive_human_cause(decision)` is the renderer's lookup helper. It uses
the LLM-provided `human_cause` field if present, otherwise falls back to
the legacy split. Renderers should never read `decision.rca` directly for
the "why" surface — go through this helper.
"""
from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Patterns that mark a clause as TECHNICAL EVIDENCE (not human prose).
#
# These are the kinds of fragments the LLM tends to dump into rca prose
# verbatim — they pass the SYSTEM_PROMPT validators (because they're not
# surface-only ledes, they appear later in the sentence) but they're still
# cognitive load on the operator. We peel them out into evidence.
#
# Each pattern is anchored loosely so it can match mid-sentence; the
# splitter walks sentence-by-sentence.
# ---------------------------------------------------------------------------

# PromQL function calls — histogram_quantile, sum/rate/avg/max/min by, etc.
_PROMQL_FUNC_PATTERN = re.compile(
    r"\b(?:histogram_quantile|sum|rate|irate|avg|max|min|count|increase|"
    r"delta|deriv|topk|bottomk|quantile_over_time|avg_over_time|"
    r"max_over_time|min_over_time|stddev_over_time|sum_over_time|"
    r"count_over_time|absent|absent_over_time)\s*(?:by\s*\([^)]*\)\s*)?\([^)]{4,}\)",
    re.I,
)

# Backticked code/expressions: `<anything>` where the contents look metric-y
# (contain { or ( or = or _ that's not a normal English word break).
_BACKTICKED_EXPR_PATTERN = re.compile(r"`[^`\n]{3,200}`")

# metric_name{label="value",...} = number — the classic Prom evaluation.
# Tolerates spaces/units/percent signs on the right-hand side.
_METRIC_LABEL_VALUE_PATTERN = re.compile(
    r"\b[a-z_][a-z0-9_]{3,}\{[^}]*\}\s*(?:=|≈|~|>|<|>=|<=)\s*[-+]?[0-9]+(?:\.[0-9]+)?(?:\s*(?:ms|s|%|MB|MiB|GB|GiB|KB|KiB|bytes|B|rps|qps))?",
    re.I,
)

# bare metric_name = value (no labels) — e.g. `up = 0`, `cpu_throttle = 0.984`.
# Tighter than the above; requires at least one underscore in the metric name
# to avoid grabbing English nouns. Anchored to word boundaries.
_BARE_METRIC_VALUE_PATTERN = re.compile(
    r"\b[a-z][a-z0-9]*_[a-z0-9_]+\s*=\s*[-+]?[0-9]+(?:\.[0-9]+)?\b",
    re.I,
)

# LogQL-style label selector: {service="x", job="y"} appearing without a
# metric name (so the above patterns missed it).
_LOGQL_SELECTOR_PATTERN = re.compile(r"\{[a-z_][a-z0-9_]*\s*[=!~]+[\"'][^}\"']+[\"'][^}]*\}", re.I)


def _looks_like_evidence_clause(text: str) -> bool:
    """Return True if a sentence-ish clause is dominated by metric formula
    content rather than human prose. Heuristic — conservative; bias toward
    leaving prose in human_cause when uncertain.
    """
    if not text or len(text.strip()) < 8:
        return False
    # Strong signals: PromQL function call, backticked code with operators
    if _PROMQL_FUNC_PATTERN.search(text):
        return True
    if _METRIC_LABEL_VALUE_PATTERN.search(text):
        return True
    # Backticked content COUNTS only if it contains a metric-y character
    # ({ ( = _ or a digit). A backticked English word ("`spring-boot`") does
    # not make a clause evidence.
    for m in _BACKTICKED_EXPR_PATTERN.finditer(text):
        inner = m.group(0).strip("`")
        if re.search(r"[{(=]|[0-9]", inner) and "_" in inner:
            return True
    # Bare metric=value with underscore is a strong signal too.
    if _BARE_METRIC_VALUE_PATTERN.search(text):
        return True
    return False


def _strip_evidence_fragments(text: str) -> str:
    """Remove the recognised metric / PromQL fragments from a sentence,
    leaving the surrounding prose. Empty-parenthesised remnants (" ()") and
    double spaces are normalised. Used when a sentence is mostly prose but
    has one metric formula awkwardly embedded.
    """
    if not text:
        return text
    out = text
    out = _PROMQL_FUNC_PATTERN.sub("", out)
    out = _METRIC_LABEL_VALUE_PATTERN.sub("", out)
    # For backticked, only strip when the inner looks metric-y
    def _maybe_strip_backtick(m):
        inner = m.group(0).strip("`")
        if re.search(r"[{(=]|[0-9]", inner) and ("_" in inner or "{" in inner):
            return ""
        return m.group(0)
    out = _BACKTICKED_EXPR_PATTERN.sub(_maybe_strip_backtick, out)
    out = _BARE_METRIC_VALUE_PATTERN.sub("", out)
    out = _LOGQL_SELECTOR_PATTERN.sub("", out)
    # Tidy: collapse "  ", strip trailing connectives, strip orphan parens.
    out = re.sub(r"\(\s*\)", "", out)
    out = re.sub(r"\s+,", ",", out)
    out = re.sub(r"\s{2,}", " ", out)
    out = re.sub(r"\s+([.,;:])", r"\1", out)
    # Strip empty trailing connectives like "because , " or "with ."
    out = re.sub(r"\b(?:because|with|where|via|using)\s*[.,;:]", "", out, flags=re.I)
    return out.strip()


def _split_sentences(text: str) -> list[str]:
    """Lightweight sentence splitter — splits on '. ' / '! ' / '? ' / newline.
    Keeps the terminator with the sentence so re-joining preserves the shape.
    Does NOT split on periods inside known abbreviations or numbers (1.5s).
    """
    if not text:
        return []
    # Protect decimals (1.5, 99.9) and a few abbreviations from naive split
    safe = re.sub(r"(\d)\.(\d)", r"\1__DOT__\2", text)
    safe = re.sub(r"\b(e\.g|i\.e|vs|etc)\.\s", r"\1__DOT__ ", safe, flags=re.I)
    pieces = re.split(r"(?<=[.!?])\s+(?=[A-Z])|\n\s*\n", safe)
    pieces = [p.replace("__DOT__", ".").strip() for p in pieces if p and p.strip()]
    return pieces


def split_human_cause_and_evidence(rca: str) -> tuple[str, list[str]]:
    """Split a legacy single-blob RCA into (human_cause_sentence, evidence_list).

    Used for backward compat: pre-refactor rows in rca_history.db and
    LLM responses that didn't emit the new `human_cause` field. The split
    is deliberately conservative — bias toward keeping prose in human_cause
    so the operator never gets less than the model gave them. Evidence is
    only pulled out when a sentence is dominated by metric formulas.

    Returns:
        (human_cause, extra_evidence)
        - human_cause: 1-2 sentence plain-English lead (formulas stripped).
        - extra_evidence: list of metric/PromQL fragments worth surfacing
          separately. May be empty.

    If `rca` is empty or all-evidence, returns ("", evidence_list).
    """
    if not rca or not rca.strip():
        return "", []

    sentences = _split_sentences(rca.strip())
    if not sentences:
        return rca.strip(), []

    human_parts: list[str] = []
    extra_evidence: list[str] = []

    for s in sentences:
        if _looks_like_evidence_clause(s):
            # Sentence is dominated by formulas. Extract any prose left after
            # stripping the formula and keep the formula itself as evidence.
            stripped = _strip_evidence_fragments(s)
            # Capture the raw formula fragments for evidence
            for m in _PROMQL_FUNC_PATTERN.finditer(s):
                extra_evidence.append(m.group(0).strip())
            for m in _METRIC_LABEL_VALUE_PATTERN.finditer(s):
                extra_evidence.append(m.group(0).strip())
            for m in _BARE_METRIC_VALUE_PATTERN.finditer(s):
                extra_evidence.append(m.group(0).strip())
            for m in _BACKTICKED_EXPR_PATTERN.finditer(s):
                inner = m.group(0).strip("`")
                if re.search(r"[{(=]|[0-9]", inner) and ("_" in inner or "{" in inner):
                    extra_evidence.append(m.group(0).strip("`").strip())
            # If meaningful prose remains, keep it as part of the human cause
            if stripped and len(stripped) > 12 and not _looks_like_evidence_clause(stripped):
                human_parts.append(stripped)
        else:
            # Prose sentence — keep it, but still strip any in-line formulas
            # so the human_cause is formula-free even if the surrounding
            # prose was diagnostic.
            cleaned = _strip_evidence_fragments(s)
            if cleaned:
                human_parts.append(cleaned)
            # Also harvest the formulas that were embedded for evidence,
            # so nothing is silently lost.
            for m in _PROMQL_FUNC_PATTERN.finditer(s):
                extra_evidence.append(m.group(0).strip())
            for m in _METRIC_LABEL_VALUE_PATTERN.finditer(s):
                extra_evidence.append(m.group(0).strip())

    # Cap human_cause at the first 1-2 sentences (whichever gets us to ~240
    # chars first). The dashboard row "why" cell + the email banner both
    # truncate around 260 chars; honour that here so the renderer doesn't
    # have to redo it.
    human_cause = ""
    for p in human_parts:
        candidate = (human_cause + " " + p).strip() if human_cause else p
        if len(candidate) > 260 and human_cause:
            break
        human_cause = candidate
        if human_cause.count(". ") >= 1 and len(human_cause) > 80:
            break

    # Dedupe evidence (preserve order)
    seen: set[str] = set()
    deduped: list[str] = []
    for e in extra_evidence:
        key = e.strip()
        if key and key not in seen:
            seen.add(key)
            deduped.append(key)
    return human_cause.strip(), deduped


def derive_human_cause(
    human_cause_field: str | None,
    rca: str | None,
    reason: str | None = None,
    fallback: str = "No RCA prose recorded.",
) -> str:
    """Return the plain-English cause string to render in the UI.

    Resolution order:
      1. `human_cause_field` if non-empty — the LLM explicitly provided it.
      2. Split `rca` and use the prose half (legacy rows).
      3. Use `reason` directly if `rca` is empty (legacy fallback path).
      4. `fallback` string as a last resort.

    The returned string is guaranteed formula-free (no PromQL, no
    `metric{...} = value`, no histogram_quantile blocks) under the
    assumption that the LLM-provided human_cause has been validated by
    response_validator.validate_human_cause; legacy splits run through
    `_strip_evidence_fragments` which strips known formula shapes.
    """
    if human_cause_field and human_cause_field.strip():
        return human_cause_field.strip()
    rca_text = (rca or "").strip()
    if rca_text:
        derived, _ = split_human_cause_and_evidence(rca_text)
        if derived:
            return derived
        # If splitting produced nothing usable (all-formula RCA), fall back
        # to the raw RCA truncated — better to give the operator the full
        # blob than empty banner.
        return rca_text[:260]
    reason_text = (reason or "").strip()
    if reason_text:
        return reason_text
    return fallback


__all__ = [
    "split_human_cause_and_evidence",
    "derive_human_cause",
]
