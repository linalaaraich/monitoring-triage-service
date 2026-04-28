"""F-4: confidence calibration clamp tests.

Validates that decision.confidence gets clamped to 0.4 at persistence
time when the output looks untrustworthy. The clamp lives at the end of
_investigate_and_act in app/pipeline.py — testing it directly via a unit
shim of that logic so we don't need to spin up the whole pipeline.
"""
from __future__ import annotations

from app.models import Decision, LLMDecision
from app.response_validator import validate


def _clamp(decision: LLMDecision, validation_report, quality: str, actions_source: str) -> bool:
    """Reproduces the clamp logic from app/pipeline.py:Step 6d.

    Tests the policy independently of the rest of the pipeline. If this
    diverges from pipeline.py, update both — they encode the same rule.
    """
    if decision.confidence is None or decision.confidence <= 0.4:
        return False
    surface_only_hit = any(
        "surface-only" in h for h in (validation_report.banned_phrase_hits or [])
    )
    if surface_only_hit or quality == "data_starved" or actions_source == "template":
        decision.confidence = 0.4
        return True
    return False


def _decision(rca: str, conf: float, actions: list[str]) -> LLMDecision:
    return LLMDecision(
        decision=Decision.ESCALATE,
        severity="warning",
        confidence=conf,
        reason="ok",
        rca=rca,
        suggested_actions=actions,
        evidence=["specific=42"],
    )


def test_clamp_fires_when_surface_only_hit():
    # Real production regression: LLM emitted 0.85 conf with surface-only RCA
    bad_rca = (
        "Based on the repeated log entries for actuator health and prometheus "
        "queries, it appears that there is a recurring issue with the system."
    )
    decision = _decision(bad_rca, 0.85, ["kubectl rollout restart deploy/x -n app"])
    report = validate(decision, deployment_type="k8s")
    clamped = _clamp(decision, report, quality="actionable", actions_source="llm")
    assert clamped is True
    assert decision.confidence == 0.4


def test_clamp_fires_when_rca_quality_data_starved():
    decision = _decision("Something happened.", 0.9, ["kubectl rollout restart deploy/x -n app"])
    report = validate(decision, deployment_type="k8s")  # no surface-only hit
    clamped = _clamp(decision, report, quality="data_starved", actions_source="llm")
    assert clamped is True
    assert decision.confidence == 0.4


def test_clamp_fires_when_actions_came_from_template_fallback():
    """LLM emitted no state-changing actions; pipeline used the template.
    That's a sign the LLM struggled — confidence shouldn't be high."""
    decision = _decision(
        "spring-boot is overloaded by a stuck JDBC pool.", 0.92,
        ["kubectl rollout restart deploy/spring-boot -n app"],
    )
    report = validate(decision, deployment_type="k8s")
    clamped = _clamp(decision, report, quality="actionable", actions_source="template")
    assert clamped is True


def test_clamp_does_not_fire_for_clean_rca_with_llm_actions():
    decision = _decision(
        "spring-boot's JDBC connection pool is exhausted because long-running "
        "queries are blocking new acquisitions; trace 7f3a2c shows 7800ms wait.",
        0.88,
        ["kubectl set env deploy/spring-boot -n app SPRING_DATASOURCE_HIKARI_MAXIMUMPOOLSIZE=40"],
    )
    report = validate(decision, deployment_type="k8s")
    clamped = _clamp(decision, report, quality="actionable", actions_source="llm")
    assert clamped is False
    assert decision.confidence == 0.88


def test_clamp_does_nothing_when_confidence_already_low():
    """An LLM that already self-reported low confidence shouldn't get pushed lower."""
    decision = _decision("...", 0.3, [])
    report = validate(decision, deployment_type="k8s")
    clamped = _clamp(decision, report, quality="data_starved", actions_source="template")
    assert clamped is False
    assert decision.confidence == 0.3
