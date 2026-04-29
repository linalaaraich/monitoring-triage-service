"""US-3.9 (Tier 0) — F-4 clamp strip+populate behavior.

Tests the full clamp logic from app/pipeline.py Step 6d after the
2026-04-29 strip+populate change: when confidence gets clamped to 0.4
(surface-only / data_starved / templated actions), the pipeline ALSO
strips suggested_actions and populates diagnostic_steps with
alert-aware read-only verbs.

Companion file tests/test_confidence_clamp_f4.py covers the legacy
clamp-only behavior (pre-strip, kept for the conf=0.4 invariant).
This file covers the strip+populate addition.
"""
from __future__ import annotations

from app.clamp_actions import diagnostic_steps_for_clamp
from app.models import Decision, GrafanaAlert, LLMDecision
from app.response_validator import validate


def _alert(alertname: str = "HighKongP95Latency", service: str = "kong") -> GrafanaAlert:
    return GrafanaAlert(
        labels={
            "alertname": alertname,
            "service": service,
            "instance": "10.0.1.194:8001",
        },
    )


def _full_clamp(
    decision: LLMDecision,
    alert: GrafanaAlert,
    validation_report,
    quality: str,
    actions_source: str,
) -> bool:
    """Reproduces the full clamp logic from app/pipeline.py Step 6d
    AFTER US-3.9 (clamp + strip + populate diagnostic_steps).

    If this diverges from pipeline.py, update both — they encode the
    same rule. Companion shim _clamp() in test_confidence_clamp_f4.py
    is the legacy clamp-only version kept for the confidence-only
    invariant tests; new tests should use this shim.
    """
    if decision.confidence is None or decision.confidence <= 0.4:
        return False
    surface_only_hit = any(
        "surface-only" in h for h in (validation_report.banned_phrase_hits or [])
    )
    if not (surface_only_hit or quality == "data_starved" or actions_source == "template"):
        return False
    decision.confidence = 0.4
    decision.suggested_actions = []
    decision.diagnostic_steps = diagnostic_steps_for_clamp(
        alert=alert,
        rca=decision.rca or "",
        quality=quality,
        actions_source=actions_source,
    )
    return True


def _decision(
    rca: str = "kong upstream is slow",
    conf: float = 0.85,
    actions: list[str] | None = None,
    evidence: list[str] | None = None,
) -> LLMDecision:
    return LLMDecision(
        decision=Decision.ESCALATE,
        severity="warning",
        confidence=conf,
        reason="ok",
        rca=rca,
        suggested_actions=actions if actions is not None else [
            "kubectl set resources deploy/spring-boot -n app --limits=memory=2Gi --requests=memory=1Gi",
            "kubectl rollout restart deploy/spring-boot -n app",
        ],
        evidence=evidence if evidence is not None else [
            "kong p95 = 8204ms",
            "kong span 3ms vs upstream span 8200ms",
        ],
    )


def test_clamp_strips_templated_actions_and_populates_diagnostic_steps():
    """The 0b215ef3 reproducer: HighKongP95Latency with templated kubectl
    actions at conf=0.85. Post-clamp should have:
    - confidence = 0.40
    - suggested_actions = []
    - diagnostic_steps populated with alert-aware verbs
    - evidence preserved verbatim
    """
    alert = _alert()
    decision = _decision()
    original_evidence = list(decision.evidence)

    report = validate(decision, deployment_type="k8s")
    clamped = _full_clamp(
        decision, alert, report, quality="actionable", actions_source="template",
    )

    assert clamped is True
    assert decision.confidence == 0.4
    assert decision.suggested_actions == []
    assert decision.diagnostic_steps, "diagnostic_steps should be populated"
    # Evidence preserved
    assert decision.evidence == original_evidence
    # First diagnostic step is Jaeger drill on Kong
    assert decision.diagnostic_steps[0].startswith("Open Jaeger")
    # Last is the explicit do-NOT
    assert decision.diagnostic_steps[-1].startswith("Do NOT")


def test_clamp_does_not_strip_when_confidence_already_low():
    """A decision with confidence already ≤ 0.4 should NOT trigger the
    strip path — the LLM was self-aware about its uncertainty, no need
    to second-guess it."""
    alert = _alert()
    decision = _decision(conf=0.3)
    original_actions = list(decision.suggested_actions)

    report = validate(decision, deployment_type="k8s")
    clamped = _full_clamp(
        decision, alert, report, quality="data_starved", actions_source="template",
    )

    assert clamped is False
    assert decision.confidence == 0.3
    assert decision.suggested_actions == original_actions
    assert decision.diagnostic_steps == []


def test_clamp_does_not_strip_clean_actionable_decisions():
    """Clean RCA + LLM-emitted actions + actionable quality → no clamp,
    no strip. The output is trustworthy."""
    alert = _alert(alertname="HighP95Latency", service="spring-boot")
    decision = _decision(
        rca=(
            "spring-boot's JDBC connection pool is exhausted because long-"
            "running queries are blocking new acquisitions; trace 7f3a2c "
            "shows 7800ms wait on `SELECT * FROM inventory WHERE x=?`."
        ),
        conf=0.88,
        actions=["kubectl set env deploy/spring-boot -n app SPRING_DATASOURCE_HIKARI_MAXIMUMPOOLSIZE=40"],
        evidence=["hikari_active=50/50", "trace 7f3a2c db span 7800ms"],
    )

    report = validate(decision, deployment_type="k8s")
    clamped = _full_clamp(
        decision, alert, report, quality="actionable", actions_source="llm",
    )

    assert clamped is False
    assert decision.confidence == 0.88
    assert decision.suggested_actions, "Clean decisions should keep their actions"
    assert decision.diagnostic_steps == []


def test_clamp_strips_on_data_starved_path():
    """Even without templated actions, data_starved triggers the clamp+strip."""
    alert = _alert(alertname="HighP95Latency", service="spring-boot")
    decision = _decision(
        rca="not enough data to determine the cause",
        conf=0.7,
        actions=["kubectl rollout restart deploy/spring-boot -n app"],
    )

    report = validate(decision, deployment_type="k8s")
    clamped = _full_clamp(
        decision, alert, report, quality="data_starved", actions_source="llm",
    )

    assert clamped is True
    assert decision.confidence == 0.4
    assert decision.suggested_actions == []
    # Should have spring-boot-specific pivots
    joined = " ".join(decision.diagnostic_steps)
    assert "hikaricp_connections_active" in joined
    assert "jvm_gc_pause_seconds" in joined


def test_clamp_strips_on_surface_only_validator_hit():
    """A surface-only LEDE that the validator caught also triggers strip."""
    alert = _alert(alertname="HighP95Latency", service="spring-boot")
    decision = _decision(
        rca=(
            "Based on the repeated log entries for actuator health and "
            "prometheus queries, it appears that there is a recurring "
            "issue with the system."
        ),
        conf=0.85,
    )

    report = validate(decision, deployment_type="k8s")
    # Sanity: validator must have caught the surface-only LEDE for this test
    # to be meaningful.
    assert any("surface-only" in h for h in (report.banned_phrase_hits or [])), (
        f"Test setup expects validator to catch surface-only; "
        f"banned_phrase_hits={report.banned_phrase_hits!r}"
    )

    clamped = _full_clamp(
        decision, alert, report, quality="actionable", actions_source="llm",
    )
    assert clamped is True
    assert decision.suggested_actions == []
    assert decision.diagnostic_steps


def test_clamp_preserves_evidence_for_quality_classification():
    """The save_decision path re-classifies rca_quality if not pre-set,
    using suggested_actions + evidence as inputs. Stripping suggested_actions
    while preserving evidence ensures _classify_rca_quality returns
    'actionable' (or 'data_starved' on hedge phrases), NOT 'needs_review'
    (which requires BOTH to be empty)."""
    from app.rca_store import _classify_rca_quality

    alert = _alert()
    decision = _decision(rca="kong upstream is slow", conf=0.85)
    report = validate(decision, deployment_type="k8s")
    _full_clamp(decision, alert, report, quality="actionable", actions_source="template")

    # After strip: suggested_actions empty, evidence preserved.
    # _classify_rca_quality must NOT return 'needs_review' (which requires
    # both empty).
    quality = _classify_rca_quality(
        decision.rca, decision.reason,
        decision.suggested_actions, decision.evidence,
    )
    assert quality != "needs_review", (
        "Stripped+clamped decisions with preserved evidence should NOT classify "
        "as needs_review — that's reserved for empty-both rows."
    )
