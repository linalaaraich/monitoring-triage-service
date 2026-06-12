"""Exemplar library — pre-LLM injection of canonical "good RCA" reference shapes.

The triage service maintains a curated library of best-practice RCA scenarios
(see app/exemplars/library.yaml and docs/happy-path-scenarios.md). Before
every LLM inference, the prompt builder picks the best-matching exemplar for
the firing alert and injects it into the prompt as a structural reference.
The LLM sees a quality target tailored to THIS alert's archetype.

Why pre-injection (eager) instead of bounded-agency (lazy)?
- The first pass should already be high-quality. Bounded agency is a fallback,
  not a primary path; a model that has the exemplar in front of it produces
  better output on attempt 1 — saving the ~25 s retry latency entirely.
- The exemplar is small (~30 lines per archetype). The cost of always
  including one is dwarfed by the quality lift.
- The library is also exposed via rca-history-mcp's get_exemplar /
  list_exemplars endpoints, so the LLM CAN reach for additional ones during
  bounded-agency retry — but it doesn't have to.

Why a separate library (not in rca_history.db)?
- rca_history is the empirical record. Mixing synthetic exemplars in would
  corrupt the dashboard, the closed-loop feedback (Epic 5 US-5.3), and the
  precision/recall metrics (US-5.7). See decisions-log.html#D17.

Match scoring:
  - alertname regex match  (required, gates the exemplar entirely)
  - service in services    (+0.40 — strong signal)
  - deployment_type match  (+0.30)
  - signal match           (+0.20)
  - severity match         (+0.10)

Highest score wins. Ties are broken by an explicit integer `priority`
field (higher wins), NOT by library order — see finding #4 (2026-06-12):
relying on file position made selection fragile to reordering. Default
priority is 0; archetypes that must win a positional tie carry a higher
priority so reordering the YAML never changes which exemplar is selected.
"""
from __future__ import annotations

import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_LIBRARY_PATH = Path(__file__).parent / "library.yaml"


@lru_cache(maxsize=1)
def _load_library() -> dict[str, Any]:
    """Load the YAML once; memoize. Missing/malformed file returns an empty
    library — exemplar injection silently no-ops in that case."""
    if not _LIBRARY_PATH.exists():
        logger.warning("exemplars/library.yaml not found at %s — exemplar injection disabled", _LIBRARY_PATH)
        return {"exemplars": [], "default": None}
    try:
        with _LIBRARY_PATH.open() as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        logger.error("exemplars/library.yaml is malformed (%s) — exemplar injection disabled", e)
        return {"exemplars": [], "default": None}

    exemplars = data.get("exemplars", []) or []
    for ex in exemplars:
        match = ex.get("match", {}) or {}
        try:
            ex["_alert_re"] = re.compile(match.get("alertname", ".*"))
        except re.error as e:
            logger.warning("invalid regex in exemplar %r: %s — skipping", ex.get("id"), e)
            ex["_alert_re"] = None
        ex["_services"] = set(match.get("services") or [])
        ex["_deployment_types"] = set(match.get("deployment_types") or [])
        ex["_signal"] = match.get("signal")
        ex["_severities"] = set(match.get("severity") or [])
        # Finding #4 (2026-06-12): explicit integer tie-break, independent of
        # YAML order. Higher priority wins when two exemplars score equal.
        try:
            ex["_priority"] = int(ex.get("priority", 0) or 0)
        except (TypeError, ValueError):
            ex["_priority"] = 0
    logger.info("Loaded %d exemplars from %s", len(exemplars), _LIBRARY_PATH)
    return {"exemplars": exemplars, "default": data.get("default")}


def _score_exemplar(
    ex: dict[str, Any],
    alertname: str,
    service: str,
    deployment_type: str,
    signal: str,
    severity: str,
) -> float:
    """Return a relevance score in [0.0, 1.0]. 0.0 means exemplar is not eligible
    (alertname regex didn't match) — the caller skips it. >0.0 means eligible
    and the highest score wins."""
    rx = ex.get("_alert_re")
    if rx is None or not rx.search(alertname):
        return 0.0

    score = 0.10  # base score for an alertname match
    services = ex["_services"]
    if services:
        if service in services or "*" in services:
            score += 0.40
        else:
            # Service set is specified but doesn't include this one.
            # Still eligible (regex matched), but penalised — likely wrong archetype.
            score -= 0.15
    deployment_types = ex["_deployment_types"]
    if deployment_types and deployment_type in deployment_types:
        score += 0.30
    if ex["_signal"] and signal and ex["_signal"] == signal:
        score += 0.20
    severities = ex["_severities"]
    if severities and severity in severities:
        score += 0.10
    return score


def find_for_alert_scored(
    alertname: str,
    service: str = "",
    deployment_type: str = "unknown",
    signal: str = "",
    severity: str = "warning",
) -> tuple[dict[str, Any] | None, float]:
    """Like find_for_alert but also returns the selection score.

    Returns (exemplar, score). The score is 0.0 when the default is
    returned (no exemplar's alertname regex matched). Used by the pipeline
    to persist (exemplar_id, exemplar_score) on each decision — finding #3.

    Tie-break (finding #4): when two exemplars score equal, the one with the
    higher `priority` integer wins. Ties on (score, priority) fall back to the
    exemplar id (lexicographic) purely so selection is fully deterministic and
    independent of YAML file order.
    """
    lib = _load_library()
    exemplars = lib.get("exemplars") or []
    default = lib.get("default")

    best_ex: dict[str, Any] | None = None
    best_key: tuple[float, int, str] | None = None
    for ex in exemplars:
        s = _score_exemplar(ex, alertname, service, deployment_type, signal, severity)
        if s <= 0.0:
            continue  # alertname regex didn't match — not eligible
        # Higher score wins; ties → higher priority; then lower id (stable).
        key = (s, ex.get("_priority", 0), _neg_id(ex.get("id", "")))
        if best_key is None or key > best_key:
            best_key = key
            best_ex = ex

    if best_ex is None:
        return default, 0.0
    return best_ex, float(best_key[0]) if best_key else 0.0


def _neg_id(s: str) -> str:
    """Stable tie-break helper: we want a *lower* id to win the final tie, so
    invert the comparison by returning a string that sorts in reverse. Python
    tuples compare element-wise ascending and we keep `key > best_key`, so to
    make the smaller id win we negate via a reversed-codepoint transform.
    Kept tiny + total-order-preserving (per-char complement)."""
    return "".join(chr(0x10FFFF - ord(c)) for c in s)


def find_for_alert(
    alertname: str,
    service: str = "",
    deployment_type: str = "unknown",
    signal: str = "",
    severity: str = "warning",
) -> dict[str, Any] | None:
    """Return the best-matching exemplar for an alert, or the default if none
    match strongly. Returns None only if the library failed to load.

    All inputs are strings (no app-internal types) so this can be called from
    the prompt builder, the MCP server, and tests without import cycles.
    """
    ex, _score = find_for_alert_scored(
        alertname, service, deployment_type, signal, severity
    )
    return ex


def format_for_prompt(exemplar: dict[str, Any] | None) -> str:
    """Render an exemplar as a prompt section. Empty string if exemplar is None.

    The format is deliberately structural (archetype, decision, RCA, evidence
    shape, actions shape, lesson) so the LLM can use it as a template without
    being tempted to copy facts from it.
    """
    if not exemplar:
        return ""

    archetype = exemplar.get("archetype", "(unnamed archetype)")
    one_line = exemplar.get("one_line", "")
    # 2026-06-02 human-first reason refactor: human_cause is the plain-English
    # banner the email + dashboard render verbatim. Surface it in the exemplar
    # block so the LLM sees the target shape for the field it's expected to fill.
    human_cause = (exemplar.get("human_cause") or "").strip()
    decision = exemplar.get("decision", "")
    confidence_band = exemplar.get("confidence_band", "")
    rca = (exemplar.get("rca") or "").strip()
    evidence_shape = exemplar.get("evidence_shape") or []
    actions_shape = exemplar.get("actions_shape") or []
    lesson = exemplar.get("lesson", "")
    doc_anchor = exemplar.get("doc_anchor", "")
    ex_id = exemplar.get("id", "")

    lines: list[str] = [
        "## Reference exemplar — match this RCA STRUCTURE",
        "",
        "The following exemplar is a curated 'good RCA' for an alert archetype that",
        "matches this firing alert. It is a STRUCTURAL TEMPLATE, not a source of",
        "facts. THIS alert's facts come from the pre-gathered context above —",
        "metrics, logs, traces, Drain3, observed value. Use the exemplar to",
        "calibrate: the level of specificity in the RCA, the shape of evidence to",
        "cite, the kind of state-changing remediation to suggest. If your actual",
        "evidence diverges from the archetype, say so explicitly and reason from",
        "your own evidence.",
        "",
        f"**Archetype:** {archetype}",
    ]
    if decision:
        lines.append(f"**Canonical decision:** {decision}" + (f"  (confidence band {confidence_band})" if confidence_band else ""))
    if one_line:
        lines.append(f"**One-line gist:** {one_line}")
    if human_cause:
        lines.append(f"**Human cause (target shape for the `human_cause` field — plain English, no formulas):** {human_cause}")
    lines.append("")
    if rca:
        lines.append("**RCA shape (paragraph):**")
        lines.append("")
        lines.append(rca)
        lines.append("")
    if evidence_shape:
        lines.append("**Evidence shape (cite analogous things, with YOUR alert's actual values):**")
        for item in evidence_shape:
            lines.append(f"- {item}")
        lines.append("")
    if actions_shape:
        lines.append("**Actions shape (state-changing remediations — adapt to YOUR alert's labels):**")
        for item in actions_shape:
            lines.append(f"- {item}")
        lines.append("")
    elif decision == "DISMISS":
        lines.append("**Actions shape:** empty list `[]` — DISMISS does not emit remediations.")
        lines.append("")
    if lesson:
        lines.append(f"**Lesson:** {lesson}")
        lines.append("")
    if ex_id:
        anchor_suffix = f"#{doc_anchor}" if doc_anchor else ""
        lines.append(
            f"_Source: docs/happy-path-scenarios.md{anchor_suffix} (id: `{ex_id}`). "
            "More archetypes available via rca-history MCP `list_exemplars` / `get_exemplar`._"
        )

    return "\n".join(lines)


def list_all() -> list[dict[str, Any]]:
    """Return all exemplars as plain dicts (for MCP listing). Strips compiled
    regex helpers; keeps schema fields only."""
    lib = _load_library()
    out = []
    for ex in lib.get("exemplars") or []:
        out.append({
            "id": ex.get("id"),
            "archetype": ex.get("archetype"),
            "match": ex.get("match", {}),
            "decision": ex.get("decision"),
            "one_line": ex.get("one_line"),
            "doc_anchor": ex.get("doc_anchor"),
        })
    return out


def get_by_id(exemplar_id: str) -> dict[str, Any] | None:
    """Return the full exemplar by id, with internal helpers stripped."""
    lib = _load_library()
    for ex in lib.get("exemplars") or []:
        if ex.get("id") == exemplar_id:
            return {k: v for k, v in ex.items() if not k.startswith("_")}
    default = lib.get("default")
    if default and default.get("id") == exemplar_id:
        return default
    return None


__all__ = [
    "find_for_alert",
    "find_for_alert_scored",
    "format_for_prompt",
    "list_all",
    "get_by_id",
]
