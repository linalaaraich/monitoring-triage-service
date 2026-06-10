"""Shelved-in-disguise email gate (2026-05-21 hotfix).

Background: today's 14:55-18:55 UTC audit caught 2/6 operator emails that
were false positives — Drain3AnomalyDetected RCAs where the LLM picked
ESCALATE but self-reported confidence=0.00, quality=needs_review, and
suggested_actions=["Shelved — no correlation found..."]. The Drain3
playbook (llm_client.py:554-556) tells the LLM to pick DISMISS for these
cases, but the model sometimes outputs ESCALATE anyway. The pipeline's
email gate was naive — verdict-only. It now also checks confidence,
quality, and whether all suggested_actions are "shelved".

These tests lock in:
  - the predicate `_is_shelved_in_disguise` correctly identifies the
    shape on all three trigger paths,
  - clean ESCALATE decisions still get through (regression),
  - DISMISS verdicts still suppress (regression).
"""
from __future__ import annotations

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from app.models import Decision, GrafanaAlert, LLMDecision, RCARecord
from app.pipeline import TriagePipeline, _is_shelved_in_disguise
from app.rca_store import RCAStore


def _decision(
    verdict: Decision = Decision.ESCALATE,
    confidence: float = 0.0,
    suggested_actions: list[str] | None = None,
    rca: str = "bingbot is 404-ing on /favicon.ico — benign crawler behaviour",
) -> LLMDecision:
    return LLMDecision(
        decision=verdict,
        severity="warning",
        confidence=confidence,
        reason="reason text",
        rca=rca,
        suggested_actions=suggested_actions if suggested_actions is not None else [],
        evidence=[],
    )


# ---------------------------------------------------------------------------
# Unit tests for the gate predicate
# ---------------------------------------------------------------------------


def test_predicate_escalate_with_low_confidence_is_shelved():
    """The reproducer: ESCALATE verdict at confidence=0.00 → shelved."""
    d = _decision(verdict=Decision.ESCALATE, confidence=0.0)
    assert _is_shelved_in_disguise(d, quality="needs_review") is True


def test_predicate_escalate_with_needs_review_quality_is_shelved():
    """Quality classifier said needs_review → don't trust the verdict."""
    d = _decision(verdict=Decision.ESCALATE, confidence=0.85)
    assert _is_shelved_in_disguise(d, quality="needs_review") is True


def test_predicate_escalate_with_data_starved_quality_is_shelved():
    """data_starved is also a thin-output signal."""
    d = _decision(verdict=Decision.ESCALATE, confidence=0.85)
    assert _is_shelved_in_disguise(d, quality="data_starved") is True


def test_predicate_escalate_with_all_shelved_actions_is_shelved():
    """ALL suggested_actions contain 'shelved' → the LLM explicitly
    shelved the RCA but still emitted ESCALATE."""
    d = _decision(
        verdict=Decision.ESCALATE,
        confidence=0.85,
        suggested_actions=[
            "Shelved — no correlation found, no remediation issued. Awaiting recurrence.",
        ],
    )
    assert _is_shelved_in_disguise(d, quality="actionable") is True


def test_predicate_escalate_with_one_shelved_one_real_action_is_NOT_shelved():
    """Only triggers if ALL actions are shelved — one real action means
    the LLM did emit something operator-actionable."""
    d = _decision(
        verdict=Decision.ESCALATE,
        confidence=0.85,
        suggested_actions=[
            "Shelved pending recurrence.",
            "kubectl rollout restart deploy/spring-boot -n app",
        ],
    )
    assert _is_shelved_in_disguise(d, quality="actionable") is False


def test_predicate_clean_escalate_is_not_shelved():
    """Regression: a normal high-confidence ESCALATE with real actions
    and good quality must still page the operator."""
    d = _decision(
        verdict=Decision.ESCALATE,
        confidence=0.85,
        suggested_actions=["kubectl rollout restart deploy/spring-boot -n app"],
    )
    assert _is_shelved_in_disguise(d, quality="actionable") is False


def test_predicate_dismiss_is_never_shelved():
    """Regression: DISMISS verdict is handled by the existing suppression
    path; the shelved gate must not interfere."""
    d = _decision(verdict=Decision.DISMISS, confidence=0.0)
    assert _is_shelved_in_disguise(d, quality="needs_review") is False
    d2 = _decision(verdict=Decision.DISMISS, confidence=0.85)
    assert _is_shelved_in_disguise(d2, quality="actionable") is False


# ---------------------------------------------------------------------------
# 2026-06-10 stress-test fix: critical/high severity must page even when the
# automated RCA is thin (KubeWorkloadDown reproducer — a real down workload was
# being silently shelved because the LLM had no k8s evidence to name a cause).
# ---------------------------------------------------------------------------


def test_critical_severity_bypasses_shelved_gate_low_confidence():
    """A critical alert at confidence=0.30 (would normally shelve) must still
    page — silence on a critical is worse than a low-confidence email."""
    d = _decision(verdict=Decision.ESCALATE, confidence=0.30)
    assert _is_shelved_in_disguise(d, quality="data_starved", severity="critical") is False


def test_high_severity_bypasses_shelved_gate_data_starved():
    """High severity is also exempt from the anti-noise shelving."""
    d = _decision(verdict=Decision.ESCALATE, confidence=0.0)
    assert _is_shelved_in_disguise(d, quality="needs_review", severity="high") is False


def test_warning_severity_still_shelved_when_thin():
    """Regression: the bypass is severity-scoped — a low-severity thin ESCALATE
    must STILL be shelved (the original anti-noise behaviour is preserved)."""
    d = _decision(verdict=Decision.ESCALATE, confidence=0.30)
    assert _is_shelved_in_disguise(d, quality="data_starved", severity="warning") is True
    # default severity arg also preserves the old behaviour
    assert _is_shelved_in_disguise(d, quality="data_starved") is True


def test_critical_severity_does_not_resurrect_dismiss():
    """The severity bypass only applies to ESCALATE — a DISMISS stays handled
    by the suppression path regardless of severity."""
    d = _decision(verdict=Decision.DISMISS, confidence=0.0)
    assert _is_shelved_in_disguise(d, quality="needs_review", severity="critical") is False


def test_predicate_boundary_exactly_0_40_is_NOT_shelved():
    """Confidence cutoff is strict <0.40 — at 0.40 the LLM is borderline
    but not low-trust enough to override the verdict on confidence alone."""
    d = _decision(
        verdict=Decision.ESCALATE,
        confidence=0.40,
        suggested_actions=["kubectl rollout restart deploy/x -n app"],
    )
    assert _is_shelved_in_disguise(d, quality="actionable") is False


# ---------------------------------------------------------------------------
# Integration tests against the full pipeline
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def fresh_store():
    db_path = os.path.join(tempfile.gettempdir(), "test_shelved_in_disguise.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


def _make_alert(name: str = "Drain3AnomalyDetected", service: str = "spring-boot") -> GrafanaAlert:
    return GrafanaAlert(
        status="firing",
        labels={"alertname": name, "service": service, "severity": "warning", "signal": "log"},
        annotations={"summary": "test", "description": "test desc"},
        startsAt="2026-05-21T16:32:53Z",
        fingerprint=f"shelved-test-{name}-{service}",
    )


def _make_pipeline(store: RCAStore) -> tuple[TriagePipeline, MagicMock]:
    """Build a pipeline with a MagicMock notifier so we can assert on
    send_escalation calls."""
    notifier = MagicMock(
        send_escalation=AsyncMock(),
        send_timeout_alert=AsyncMock(),
    )
    pipeline = TriagePipeline(
        rca_store=store,
        drain=MagicMock(),
        context_gatherer=MagicMock(),
        llm_client=MagicMock(),
        notifier=notifier,
        dedup=MagicMock(
            check=AsyncMock(return_value=(False, None)),
            record_first_decision=AsyncMock(),
        ),
    )
    return pipeline, notifier


async def _run_with_staged_decision(
    pipeline: TriagePipeline,
    alert: GrafanaAlert,
    decision: LLMDecision,
    quality: str,
) -> None:
    """Stub out _investigate_and_act with a version that exercises ONLY
    the persist + email gate using the staged decision + quality. This
    isolates the gate behaviour from the LLM, context-gather, validator,
    retry, override, recurrence, and clamp logic — none of which we're
    testing here."""
    import json as _json
    import time as _time
    from app.metrics import alerts_processed, emails_sent
    from app.pipeline import _is_shelved_in_disguise

    async def _stub_investigate_and_act(alert, source, pipeline_start, env=None):
        elapsed_ms = int((_time.monotonic() - pipeline_start) * 1000)
        is_shelved_in_disguise = _is_shelved_in_disguise(decision, quality)
        record = RCARecord(
            alert_source=source,
            alert_name=alert.alertname,
            alert_fingerprint=alert.fingerprint,
            affected_service=alert.service,
            severity=decision.severity,
            triage_decision="investigate",
            llm_verdict=decision.decision.value.lower(),
            llm_confidence=(
                f"{decision.confidence:.2f}" if decision.confidence is not None else None
            ),
            rca_report=decision.rca,
            llm_reasoning=decision.reason,
            action_taken=(
                "shelved" if is_shelved_in_disguise
                else "emailed" if decision.decision == Decision.ESCALATE
                else "suppressed"
            ),
            investigation_duration_ms=elapsed_ms,
            rca_quality=quality,
            suggested_actions=(
                _json.dumps(decision.suggested_actions) if decision.suggested_actions else None
            ),
        )
        if decision.decision == Decision.ESCALATE and not is_shelved_in_disguise:
            try:
                await pipeline.notifier.send_escalation(
                    alert, decision, record, 0, ctx=None, correlated=[],
                )
                emails_sent.labels(type="escalation").inc()
                alerts_processed.labels(decision="escalate").inc()
            except Exception:
                emails_sent.labels(type="escalation_failed").inc()
                alerts_processed.labels(decision="escalate").inc()
        elif is_shelved_in_disguise:
            alerts_processed.labels(decision="shelved").inc()
        else:
            alerts_processed.labels(decision="dismiss").inc()

        await pipeline.store.save_decision(record)
        if alert.fingerprint:
            await pipeline.dedup.record_first_decision(alert.fingerprint, record.id)

    pipeline._investigate_and_act = _stub_investigate_and_act
    await pipeline._process_alert(alert, source="drain3")


@pytest.mark.asyncio
async def test_case1_escalate_low_conf_needs_review_does_NOT_email(fresh_store):
    """Case 1 from the audit: verdict=ESCALATE + confidence=0.0 +
    quality=needs_review → action_taken=shelved, no email sent."""
    pipeline, notifier = _make_pipeline(fresh_store)
    alert = _make_alert()
    decision = _decision(
        verdict=Decision.ESCALATE,
        confidence=0.0,
        suggested_actions=["Shelved — no correlation found, no remediation issued."],
    )

    await _run_with_staged_decision(pipeline, alert, decision, quality="needs_review")

    notifier.send_escalation.assert_not_called()
    rows = await fresh_store.get_decisions(limit=5)
    assert len(rows) == 1
    assert rows[0]["action_taken"] == "shelved"
    assert rows[0]["llm_verdict"] == "escalate"  # verdict preserved


@pytest.mark.asyncio
async def test_case2_escalate_with_all_shelved_actions_does_NOT_email(fresh_store):
    """Case 2: verdict=ESCALATE + suggested_actions=['Shelved...'] →
    action_taken=shelved even if confidence and quality look OK."""
    pipeline, notifier = _make_pipeline(fresh_store)
    alert = _make_alert(name="Drain3AnomalyDetected_v2")
    decision = _decision(
        verdict=Decision.ESCALATE,
        confidence=0.75,
        suggested_actions=["Shelved pending recurrence — re-evaluate on next fire."],
    )

    await _run_with_staged_decision(pipeline, alert, decision, quality="actionable")

    notifier.send_escalation.assert_not_called()
    rows = await fresh_store.get_decisions(limit=5)
    assert len(rows) == 1
    assert rows[0]["action_taken"] == "shelved"


@pytest.mark.asyncio
async def test_case3_clean_escalate_still_emails_operator(fresh_store):
    """Regression: verdict=ESCALATE + confidence=0.85 + quality=actionable
    + real action → action_taken=emailed, notifier IS called."""
    pipeline, notifier = _make_pipeline(fresh_store)
    alert = _make_alert(name="HighP95Latency", service="spring-boot")
    decision = _decision(
        verdict=Decision.ESCALATE,
        confidence=0.85,
        rca="JVM heap exhausted — GC overhead, full GC every 4s.",
        suggested_actions=["kubectl rollout restart deploy/spring-boot -n app"],
    )

    await _run_with_staged_decision(pipeline, alert, decision, quality="actionable")

    notifier.send_escalation.assert_called_once()
    rows = await fresh_store.get_decisions(limit=5)
    assert len(rows) == 1
    assert rows[0]["action_taken"] == "emailed"


@pytest.mark.asyncio
async def test_case4_dismiss_still_suppresses(fresh_store):
    """Regression: verdict=DISMISS → action_taken=suppressed, no email."""
    pipeline, notifier = _make_pipeline(fresh_store)
    alert = _make_alert(name="LowMemoryWarning")
    decision = _decision(
        verdict=Decision.DISMISS,
        confidence=0.7,
        rca="memory within expected band",
        suggested_actions=[],
    )

    await _run_with_staged_decision(pipeline, alert, decision, quality="actionable")

    notifier.send_escalation.assert_not_called()
    rows = await fresh_store.get_decisions(limit=5)
    assert len(rows) == 1
    assert rows[0]["action_taken"] == "suppressed"
