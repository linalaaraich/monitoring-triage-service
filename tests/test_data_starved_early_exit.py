"""Backend audit 2026-06-04 — issue #2 goal 2 (data-starved early-exit gate).

LLM-pathed decisions averaged ~100-140s to emit "Cannot determine the root
cause / insufficient data" even when context-gather returned NOTHING the model
could ground a cause in — and each one created a noisy `investigate` row the
operator had to triage. When all three MCP pillars come back empty AND there's
no Drain3 anomaly_summary AND no observed value AND no correlation / prior
decision / operator feedback to anchor on, the alert is genuinely data-starved:
calling the LLM (+retry +bounded-agency) just burns two cold inferences to
hedge.

`_context_is_data_starved` + the pipeline gate short-path such an alert BEFORE
the LLM call to a cheap, QUIET `data_starved_suppressed` record: no LLM, no
email, no escalate, recorded as `suppressed` (not a full investigate row).

CONSERVATIVE: any one groundable signal keeps the alert on the full LLM path,
and CRITICAL-severity alerts always bypass the gate. These tests pin the
predicate on every bypass branch + the end-to-end gate behaviour.
"""
from __future__ import annotations

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from app.config import settings
from app.metric_interpreter import interpret as interpret_metric
from app.models import Decision, GatheredContext, GrafanaAlert, LLMDecision
from app.pipeline import (
    TriagePipeline,
    _context_is_data_starved,
    _context_is_mcp_outage,
)
from app.rca_store import RCAStore


@pytest_asyncio.fixture
async def store():
    db_path = os.path.join(tempfile.gettempdir(), "test_data_starved_early_exit.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


def _alert(severity: str = "warning", values: dict | None = None,
           name: str = "SomethingWeird", service: str = "spring-boot") -> GrafanaAlert:
    return GrafanaAlert(
        status="firing",
        labels={"alertname": name, "service": service, "severity": severity,
                "signal": "log"},
        annotations={"summary": "s", "description": "d"},
        startsAt="2026-06-04T10:00:00Z",
        fingerprint="fp-starved",
        values=values or {},
    )


# ── Predicate unit tests ──────────────────────────────────────────────────

def test_predicate_true_when_everything_empty():
    ctx = GatheredContext(sources_available=0)
    assert _context_is_data_starved(
        ctx, _alert(), anomaly_summary="", correlated=None,
        prior_decision=None, corrective_feedback=None, metric_facts=None,
    ) is True


def test_predicate_true_when_reachable_but_empty():
    """BE-B2: the live shape that the OLD gate never caught — all three MCPs
    reachable (sources_available=3, no errors) but every pillar returned an
    empty 200. CONTENT is empty → genuinely data-starved → True."""
    ctx = GatheredContext(sources_available=3, metrics=None, logs=None, traces=None)
    assert _context_is_mcp_outage(ctx) is False
    assert _context_is_data_starved(
        ctx, _alert(), anomaly_summary="", correlated=None,
        prior_decision=None, corrective_feedback=None, metric_facts=None,
    ) is True


def test_predicate_false_on_mcp_outage_all_sources_errored():
    """BE-B2: all MCPs erroring (sources_available=0 WITH recorded errors) is
    an OUTAGE, not data-starvation — the predicate must return False so the
    caller escalates instead of suppressing."""
    ctx = GatheredContext(
        sources_available=0,
        errors=["Prometheus: 503", "Loki: conn refused", "Jaeger: 500"],
    )
    assert _context_is_mcp_outage(ctx) is True
    assert _context_is_data_starved(
        ctx, _alert(), anomaly_summary="", correlated=None,
        prior_decision=None, corrective_feedback=None, metric_facts=None,
    ) is False


def test_predicate_false_when_pillar_has_content():
    ctx = GatheredContext(sources_available=1, metrics={"result": [1]})
    assert _context_is_data_starved(
        ctx, _alert(), anomaly_summary="", correlated=None,
        prior_decision=None, corrective_feedback=None, metric_facts=None,
    ) is False


def test_predicate_false_when_anomaly_summary_present():
    ctx = GatheredContext(sources_available=0)
    assert _context_is_data_starved(
        ctx, _alert(), anomaly_summary="OOM in Employee.save x4",
        correlated=None, prior_decision=None, corrective_feedback=None,
        metric_facts=None,
    ) is False


def test_predicate_false_when_observed_value_present():
    ctx = GatheredContext(sources_available=0)
    alert = _alert(values={"B": 98.4})
    assert _context_is_data_starved(
        ctx, alert, anomaly_summary="", correlated=None,
        prior_decision=None, corrective_feedback=None, metric_facts=None,
    ) is False


def test_predicate_false_when_correlated_present():
    ctx = GatheredContext(sources_available=0)
    assert _context_is_data_starved(
        ctx, _alert(), anomaly_summary="",
        correlated=[{"alert_name": "HighCpu"}],
        prior_decision=None, corrective_feedback=None, metric_facts=None,
    ) is False


def test_predicate_false_when_prior_decision_present():
    ctx = GatheredContext(sources_available=0)
    assert _context_is_data_starved(
        ctx, _alert(), anomaly_summary="", correlated=None,
        prior_decision={"id": "x", "llm_verdict": "escalate"},
        corrective_feedback=None, metric_facts=None,
    ) is False


def test_predicate_false_when_corrective_feedback_present():
    ctx = GatheredContext(sources_available=0)
    assert _context_is_data_starved(
        ctx, _alert(), anomaly_summary="", correlated=None,
        prior_decision=None, corrective_feedback=[{"operator_note": "real"}],
        metric_facts=None,
    ) is False


def test_predicate_false_when_metric_facts_carry_observed_value():
    """An alert whose PromQL+values produce an observed value is groundable
    even if the raw alert.values dict is read indirectly."""
    ctx = GatheredContext(sources_available=0)
    alert = _alert(values={"B": 72.0})
    mf = interpret_metric(alert)
    assert _context_is_data_starved(
        ctx, alert, anomaly_summary="", correlated=None,
        prior_decision=None, corrective_feedback=None, metric_facts=mf,
    ) is False


# ── Pipeline integration ──────────────────────────────────────────────────

def _make_pipeline(store: RCAStore):
    llm = MagicMock()
    llm.investigate = AsyncMock(return_value=(
        LLMDecision(decision=Decision.ESCALATE, severity="warning",
                    confidence=0.85, reason="r", rca="real cause named here",
                    suggested_actions=["kubectl rollout restart deploy/x"],
                    evidence=["e"]),
        10,
    ))
    llm.request_tool_or_decide = AsyncMock(return_value=(None, 0))

    ctx_gatherer = MagicMock()
    # BE-B2: the LIVE empty-but-reachable shape — all three MCPs answered 200
    # with no rows (sources_available=3, no errors, empty content). The OLD
    # gate skipped this case (sources_available>0); the corrected gate fires.
    ctx_gatherer.gather = AsyncMock(return_value=GatheredContext(sources_available=3))

    drain = MagicMock()
    drain.annotate_lines = MagicMock(return_value=([], ""))
    drain.get_stats = MagicMock(return_value={"total_clusters": 0})

    notifier = MagicMock(send_escalation=AsyncMock(), send_timeout_alert=AsyncMock())

    pipeline = TriagePipeline(
        rca_store=store, drain=drain, context_gatherer=ctx_gatherer,
        llm_client=llm, notifier=notifier,
        dedup=MagicMock(check=AsyncMock(return_value=(False, None)),
                        record_first_decision=AsyncMock(), window=300),
    )
    return pipeline, llm, notifier


@pytest.mark.asyncio
async def test_data_starved_alert_quiet_suppressed_no_llm_no_email(store, monkeypatch):
    """Empty context + no observed value → cheap quiet suppressed row, LLM
    never called, no email sent, NOT a full investigate row."""
    monkeypatch.setattr(settings, "data_starved_early_exit_enabled", True)
    pipeline, llm, notifier = _make_pipeline(store)

    await pipeline._process_alert(_alert(severity="warning"), source="grafana")

    llm.investigate.assert_not_called()
    notifier.send_escalation.assert_not_called()
    rows = await store.get_decisions(limit=5)
    assert len(rows) == 1
    row = rows[0]
    assert row["triage_decision"] == "data_starved_suppressed"
    assert row["triage_decision"] != "investigate"
    assert row["action_taken"] == "suppressed"
    assert row["rca_quality"] == "data_starved"
    assert (row.get("llm_verdict") or "") == ""


@pytest.mark.asyncio
async def test_critical_severity_bypasses_gate(store, monkeypatch):
    """A CRITICAL alert with the same thin context ALWAYS gets the full LLM
    investigation + may page — never silently suppressed."""
    monkeypatch.setattr(settings, "data_starved_early_exit_enabled", True)
    pipeline, llm, notifier = _make_pipeline(store)

    await pipeline._process_alert(_alert(severity="critical"), source="grafana")

    llm.investigate.assert_called()
    rows = await store.get_decisions(limit=5)
    assert all(r["triage_decision"] != "data_starved_suppressed" for r in rows)


@pytest.mark.asyncio
async def test_observed_value_keeps_alert_on_llm_path(store, monkeypatch):
    """An alert carrying an observed value is groundable → full LLM path."""
    monkeypatch.setattr(settings, "data_starved_early_exit_enabled", True)
    pipeline, llm, notifier = _make_pipeline(store)

    await pipeline._process_alert(
        _alert(severity="warning", values={"B": 91.2}), source="grafana",
    )

    llm.investigate.assert_called()
    rows = await store.get_decisions(limit=5)
    assert all(r["triage_decision"] != "data_starved_suppressed" for r in rows)


@pytest.mark.asyncio
async def test_anomaly_summary_keeps_alert_on_llm_path(store, monkeypatch):
    """Drain3 anomaly evidence present → never suppressed by this gate."""
    monkeypatch.setattr(settings, "data_starved_early_exit_enabled", True)
    pipeline, llm, notifier = _make_pipeline(store)
    # annotate_lines returns a real anomaly summary this time.
    pipeline.context.gather = AsyncMock(
        return_value=GatheredContext(logs=["ERROR boom"], sources_available=1),
    )
    pipeline.drain.annotate_lines = MagicMock(
        return_value=(["[ANOMALY] ERROR boom"], "1 of 1 lines anomalous: ERROR boom"),
    )

    await pipeline._process_alert(_alert(severity="warning"), source="grafana")

    llm.investigate.assert_called()
    rows = await store.get_decisions(limit=5)
    assert all(r["triage_decision"] != "data_starved_suppressed" for r in rows)


@pytest.mark.asyncio
async def test_gate_disabled_falls_through_to_llm(store, monkeypatch):
    """With the gate disabled the data-starved alert reaches the LLM (the
    anti-hedge retry remains the downstream safety net)."""
    monkeypatch.setattr(settings, "data_starved_early_exit_enabled", False)
    pipeline, llm, notifier = _make_pipeline(store)

    await pipeline._process_alert(_alert(severity="warning"), source="grafana")

    llm.investigate.assert_called()
    rows = await store.get_decisions(limit=5)
    assert all(r["triage_decision"] != "data_starved_suppressed" for r in rows)


@pytest.mark.asyncio
async def test_all_mcps_down_escalates_not_suppressed(store, monkeypatch):
    """BE-B2 — when ALL three MCP pillars error (outage), a non-critical alert
    must FAIL OPEN: escalate + raw-alert email, NEVER silently suppressed as
    data-starved. This is the regression the inverted gate introduced."""
    monkeypatch.setattr(settings, "data_starved_early_exit_enabled", True)
    pipeline, llm, notifier = _make_pipeline(store)
    # Outage shape: no source succeeded, every pillar recorded an error.
    pipeline.context.gather = AsyncMock(return_value=GatheredContext(
        sources_available=0,
        errors=["Prometheus: 503", "Loki: conn refused", "Jaeger: 500"],
    ))

    await pipeline._process_alert(_alert(severity="warning"), source="grafana")

    # Failed open: a human was paged via the raw-alert email, no LLM burned.
    notifier.send_timeout_alert.assert_awaited()
    llm.investigate.assert_not_called()
    rows = await store.get_decisions(limit=5)
    assert len(rows) == 1
    row = rows[0]
    assert row["triage_decision"] == "mcp_outage_escalated"
    assert row["triage_decision"] != "data_starved_suppressed"
    assert row["llm_verdict"] == "escalate"
