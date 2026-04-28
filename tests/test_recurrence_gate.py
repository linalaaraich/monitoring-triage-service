"""US-5.8 recurrence gate tests.

Covers annotation parsing, the two gate functions, and the critical-
severity defense-in-depth bypass.
"""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.models import Decision, GrafanaAlert, LLMDecision
from app.recurrence_gate import (
    GateResult,
    RecurrenceConfig,
    parse_recurrence_annotation,
    pre_llm_gate,
    post_llm_gate,
)


# -----------------------------------------------------------------------------
# Annotation parsing
# -----------------------------------------------------------------------------

def test_parse_full_annotation():
    cfg = parse_recurrence_annotation("pre_llm=4,llm_dismiss=2,window=2h")
    assert cfg.opted_in is True
    assert cfg.pre_llm_threshold == 4
    assert cfg.llm_dismiss_threshold == 2
    assert cfg.window_seconds == 7200


def test_parse_partial_annotation_uses_defaults():
    cfg = parse_recurrence_annotation("pre_llm=3")
    assert cfg.opted_in is True
    assert cfg.pre_llm_threshold == 3
    assert cfg.llm_dismiss_threshold == 2  # default
    assert cfg.window_seconds == 7200  # default


def test_parse_window_units():
    assert parse_recurrence_annotation("window=90s").window_seconds == 90
    assert parse_recurrence_annotation("window=30m").window_seconds == 1800
    assert parse_recurrence_annotation("window=4h").window_seconds == 14400
    assert parse_recurrence_annotation("window=1d").window_seconds == 86400


def test_parse_empty_or_none_disables():
    assert parse_recurrence_annotation(None).opted_in is False
    assert parse_recurrence_annotation("").opted_in is False
    assert parse_recurrence_annotation("   ").opted_in is False


def test_parse_malformed_pair_disables():
    """A typo or mangled value disables the gate — never silently misroute."""
    assert parse_recurrence_annotation("pre_llm").opted_in is False
    assert parse_recurrence_annotation("pre_llm=notanumber").opted_in is False
    assert parse_recurrence_annotation("window=2x").opted_in is False  # bad unit


def test_parse_unknown_key_ignored_but_others_kept():
    cfg = parse_recurrence_annotation("pre_llm=4,unknown_key=value,window=2h")
    assert cfg.opted_in is True
    assert cfg.pre_llm_threshold == 4
    assert cfg.window_seconds == 7200


def test_parse_clamps_extreme_values():
    """Negative thresholds → 0; absurd windows clamped to [60s, 86400s]."""
    cfg = parse_recurrence_annotation("pre_llm=-5,llm_dismiss=-1,window=999d")
    assert cfg.pre_llm_threshold == 0
    assert cfg.llm_dismiss_threshold == 0
    assert cfg.window_seconds == 86400  # max clamp


def test_parse_clamps_window_below_minimum():
    cfg = parse_recurrence_annotation("window=10s")
    assert cfg.window_seconds == 60  # min clamp


# -----------------------------------------------------------------------------
# Pre-LLM gate
# -----------------------------------------------------------------------------

def _alert(severity: str = "warning", annotation: str | None = "pre_llm=4,llm_dismiss=2,window=2h",
           fingerprint: str = "fp-abc123", labels_severity: str | None = None) -> GrafanaAlert:
    annotations = {"recurrence_gate": annotation} if annotation else {}
    labels = {"alertname": "MediumCpuUsage", "service": "spring-boot", "severity": severity}
    if labels_severity is not None:
        labels["severity"] = labels_severity
    return GrafanaAlert(
        status="firing",
        labels=labels,
        annotations=annotations,
        startsAt="2026-04-28T12:00:00Z",
        fingerprint=fingerprint,
    )


@pytest.mark.asyncio
async def test_pre_llm_gate_fires_when_count_under_threshold():
    store = AsyncMock()
    store.count_recent_decisions_by_fingerprint = AsyncMock(return_value=2)
    result = await pre_llm_gate(_alert(), store)
    assert result is not None
    assert result.triage_decision == "recurrence_gated_pre_llm"
    assert "fire #3 of 4" in result.reason


@pytest.mark.asyncio
async def test_pre_llm_gate_passes_through_when_count_reached():
    store = AsyncMock()
    store.count_recent_decisions_by_fingerprint = AsyncMock(return_value=4)
    result = await pre_llm_gate(_alert(), store)
    assert result is None  # threshold reached → through to LLM


@pytest.mark.asyncio
async def test_pre_llm_gate_no_opt_in_no_gate():
    store = AsyncMock()
    store.count_recent_decisions_by_fingerprint = AsyncMock(return_value=0)
    result = await pre_llm_gate(_alert(annotation=None), store)
    assert result is None


@pytest.mark.asyncio
async def test_pre_llm_gate_bypasses_critical_severity():
    """Even if a critical-severity alert opts in, the gate must NOT fire."""
    store = AsyncMock()
    store.count_recent_decisions_by_fingerprint = AsyncMock(return_value=0)
    result = await pre_llm_gate(_alert(severity="critical"), store)
    assert result is None


@pytest.mark.asyncio
async def test_pre_llm_gate_checks_label_severity_for_critical():
    """Some rules carry severity in labels.severity — defense-in-depth checks both."""
    store = AsyncMock()
    store.count_recent_decisions_by_fingerprint = AsyncMock(return_value=0)
    a = _alert(severity="warning", labels_severity="critical")
    result = await pre_llm_gate(a, store)
    assert result is None


@pytest.mark.asyncio
async def test_pre_llm_gate_handles_missing_fingerprint():
    store = AsyncMock()
    result = await pre_llm_gate(_alert(fingerprint=""), store)
    assert result is None


# -----------------------------------------------------------------------------
# Post-LLM gate
# -----------------------------------------------------------------------------

def _decision(verdict: Decision = Decision.DISMISS) -> LLMDecision:
    return LLMDecision(
        decision=verdict, severity="warning", confidence=0.8,
        reason="ok", rca="benign explanation",
        suggested_actions=[], evidence=[],
    )


@pytest.mark.asyncio
async def test_post_llm_gate_fires_after_n_dismissals():
    store = AsyncMock()
    store.count_recent_decisions_by_fingerprint = AsyncMock(return_value=2)  # threshold met
    result = await post_llm_gate(_alert(), _decision(), store)
    assert result is not None
    assert result.triage_decision == "recurrence_gated_post_llm_force_escalate"
    assert "2 times" in result.reason


@pytest.mark.asyncio
async def test_post_llm_gate_doesnt_fire_below_threshold():
    store = AsyncMock()
    store.count_recent_decisions_by_fingerprint = AsyncMock(return_value=1)
    result = await post_llm_gate(_alert(), _decision(), store)
    assert result is None


@pytest.mark.asyncio
async def test_post_llm_gate_doesnt_touch_escalate_verdicts():
    """The gate only flips DISMISS → ESCALATE; ESCALATE/INCONCLUSIVE pass through."""
    store = AsyncMock()
    store.count_recent_decisions_by_fingerprint = AsyncMock(return_value=10)  # would fire if applicable
    result = await post_llm_gate(_alert(), _decision(verdict=Decision.ESCALATE), store)
    assert result is None
    result = await post_llm_gate(_alert(), _decision(verdict=Decision.INCONCLUSIVE), store)
    assert result is None


@pytest.mark.asyncio
async def test_post_llm_gate_no_opt_in_no_gate():
    store = AsyncMock()
    store.count_recent_decisions_by_fingerprint = AsyncMock(return_value=10)
    result = await post_llm_gate(_alert(annotation=None), _decision(), store)
    assert result is None


@pytest.mark.asyncio
async def test_post_llm_gate_bypasses_critical_severity():
    store = AsyncMock()
    store.count_recent_decisions_by_fingerprint = AsyncMock(return_value=10)
    result = await post_llm_gate(_alert(severity="critical"), _decision(), store)
    assert result is None
