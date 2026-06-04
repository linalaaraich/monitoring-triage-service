"""Tests for the 2026-06-04 parrot-placeholder + human_cause banned-phrase
scan extensions to response_validator.validate().

Background: live-prod RCA rows on 2026-06-03/04 showed the LLM emitting:

  1. Literal placeholder strings as service names (the `{{SERVICE_NAME}}`
     substitution in SYSTEM_PROMPT rule B didn't actually stop the model
     from copying the template literally):
       - "Loki returned 0 lines for service=X"
       - "Loki returned 0 lines for service=Y"
       - "Loki returned 0 lines for service=alert_service"
     These appeared in `rca` AND in `evidence` items.

  2. Hedge phrases like "Insufficient data to determine root cause —
     need additional evidence." stuffed into `human_cause` while the
     `rca` field stayed superficially OK. Because the prior validator
     only scanned rca + reason, these hedges flew under the radar and
     ended up rendered verbatim in the email banner / dashboard "why"
     cell — the operator's first line of sight.

These tests lock in:
  - parrot placeholders in rca/reason/human_cause/evidence are
    flagged as banned-phrase hits and trigger retry
  - banned phrases ("insufficient data", "could not determine",
    "additional investigation needed") in human_cause are flagged
    even when rca/reason are clean
"""
from __future__ import annotations

from app.models import LLMDecision
from app.response_validator import validate


def _decision(
    *,
    rca: str = "JVM heap exhausted — full GC every 4 seconds.",
    reason: str = "ok",
    human_cause: str = "spring-boot pod is OOM-looping every 12 minutes.",
    evidence: list[str] | None = None,
) -> LLMDecision:
    return LLMDecision(
        decision="ESCALATE",
        severity="warning",
        confidence=0.85,
        reason=reason,
        rca=rca,
        human_cause=human_cause,
        suggested_actions=["kubectl rollout restart deploy/spring-boot -n app"],
        evidence=evidence or ["working_set / limit = 0.984"],
    )


# ---------------------------------------------------------------------------
# Parrot-placeholder detection
# ---------------------------------------------------------------------------


def test_parrot_service_equals_X_in_rca_is_flagged():
    """The classic 2026-06-03 prod bug: rca says `service=X`."""
    rca = (
        "The alert fired but Loki returned 0 lines for service=X and "
        "Jaeger showed no relevant spans within the alert window."
    )
    report = validate(_decision(rca=rca), deployment_type="systemd")
    assert any("parrot-placeholder" in h for h in report.banned_phrase_hits), (
        report.banned_phrase_hits
    )
    assert report.should_retry is True


def test_parrot_service_equals_X_in_evidence_is_flagged():
    """The placeholder appears in an evidence item, not the rca prose."""
    evidence = [
        "Loki returned 0 lines for service=X — possible causes: service "
        "not emitting logs, wrong label, shipper down",
        "Jaeger has no relevant spans in the alert time window",
    ]
    report = validate(_decision(evidence=evidence), deployment_type="systemd")
    assert any("parrot-placeholder" in h for h in report.banned_phrase_hits), (
        report.banned_phrase_hits
    )


def test_parrot_service_equals_Y_is_flagged():
    """`service=Y` is the same shape as `service=X`."""
    rca = "Cannot ground a cause; Loki returned 0 lines for service=Y."
    report = validate(_decision(rca=rca), deployment_type="systemd")
    assert any("parrot-placeholder" in h for h in report.banned_phrase_hits), (
        report.banned_phrase_hits
    )


def test_parrot_service_equals_alert_service_is_flagged():
    """`service=alert_service` — the LLM used the field name as the value.
    Observed on 2026-06-03 LokiIngestionRateLow rows id 32171d01, be171098.
    """
    rca = "Loki returned 0 lines for service=alert_service — investigate."
    report = validate(_decision(rca=rca), deployment_type="docker-vm")
    assert any("parrot-placeholder" in h for h in report.banned_phrase_hits), (
        report.banned_phrase_hits
    )


def test_parrot_service_equals_SERVICE_NAME_placeholder_is_flagged():
    """The Jinja-style placeholder leaked through verbatim."""
    rca = "Loki returned 0 lines for service={{SERVICE_NAME}} — investigate."
    report = validate(_decision(rca=rca), deployment_type="docker-vm")
    assert any("parrot-placeholder" in h for h in report.banned_phrase_hits)


def test_parrot_angle_bracket_placeholder_is_flagged():
    """`service=<service>` shape — XML-style placeholder."""
    rca = "Loki returned 0 lines for service=<the affected service>."
    report = validate(_decision(rca=rca), deployment_type="docker-vm")
    assert any("parrot-placeholder" in h for h in report.banned_phrase_hits)


def test_parrot_in_human_cause_is_flagged():
    """The placeholder is in human_cause — the operator's first line of sight.
    Must be caught even when rca is clean.
    """
    hc = "Loki returned 0 lines for service=X — wrong label or shipper down."
    report = validate(_decision(human_cause=hc), deployment_type="systemd")
    assert any("parrot-placeholder" in h for h in report.banned_phrase_hits)


def test_real_service_name_does_not_trigger_parrot():
    """The fix must not false-positive on legitimate `service=<name>` prose.
    `service=k3s-node` / `service=drain3` / `service=loki` are the actual
    service tokens the prompt builder substitutes in — never flag them.
    """
    for svc in ("k3s-node", "drain3", "loki", "spring-boot", "kong"):
        rca = (
            f"k3s on the monitoring VM is saturating its CPU budget; "
            f"Loki returned 0 lines for service={svc} which is expected "
            f"for node-level alerts."
        )
        report = validate(_decision(rca=rca), deployment_type="systemd")
        assert not any(
            "parrot-placeholder" in h for h in report.banned_phrase_hits
        ), f"false positive on legitimate service={svc!r}: {report.banned_phrase_hits!r}"


def test_parrot_service_equals_this_service_fallback_is_flagged():
    """The prompt builder's fallback string `this-service` (when alert.service
    is empty) leaking into the RCA prose."""
    rca = "Loki returned 0 lines for service=this-service — investigate."
    report = validate(_decision(rca=rca), deployment_type="systemd")
    assert any("parrot-placeholder" in h for h in report.banned_phrase_hits)


# ---------------------------------------------------------------------------
# human_cause banned-phrase scan
# ---------------------------------------------------------------------------


def test_insufficient_data_in_human_cause_is_flagged_even_when_rca_clean():
    """The 2026-06-04 prod bug: human_cause carries the hedge, rca looks ok."""
    hc = "Insufficient data to determine root cause — need additional evidence."
    rca = "spring-boot service is showing memory pressure on the JVM heap."  # passes other checks
    report = validate(_decision(rca=rca, human_cause=hc), deployment_type="k8s")
    assert any(
        "insufficient" in h.lower() for h in report.banned_phrase_hits
    ), report.banned_phrase_hits
    assert report.should_retry is True


def test_could_not_determine_in_human_cause_is_flagged():
    """`could not determine` is a hedge — caught everywhere now."""
    hc = "We could not determine the root cause with the available data."
    report = validate(_decision(human_cause=hc), deployment_type="k8s")
    assert any(
        "could not determine" in h.lower() for h in report.banned_phrase_hits
    ), report.banned_phrase_hits


def test_additional_investigation_needed_in_human_cause_is_flagged():
    """`additional investigation needed` is a hedge tail — caught now."""
    hc = "Cause unclear; additional investigation needed."
    report = validate(_decision(human_cause=hc), deployment_type="k8s")
    assert report.should_retry is True


def test_needs_additional_evidence_in_human_cause_is_flagged():
    """Variant — `needs additional evidence`."""
    hc = "The signal is weak; needs additional evidence to call a cause."
    report = validate(_decision(human_cause=hc), deployment_type="k8s")
    assert any(
        "additional evidence" in h.lower() for h in report.banned_phrase_hits
    ), report.banned_phrase_hits


def test_insufficient_signal_in_rca_is_flagged():
    """The 2026-06-04 rca text variant: "insufficient signal" instead of
    "insufficient data" — caught by the widened pattern."""
    rca = (
        "The alert fired but there is insufficient signal in the pre-gathered "
        "context to diagnose a specific issue."
    )
    report = validate(_decision(rca=rca), deployment_type="systemd")
    assert any(
        "insufficient" in h.lower() for h in report.banned_phrase_hits
    ), report.banned_phrase_hits


def test_clean_human_cause_passes():
    """Sanity: a real plain-English human_cause has no false positives."""
    hc = "spring-boot pod is in an OOM-kill loop, restarting every 12 minutes."
    report = validate(_decision(human_cause=hc), deployment_type="k8s")
    assert not any(
        "insufficient" in h.lower() or "parrot" in h.lower()
        for h in report.banned_phrase_hits
    ), report.banned_phrase_hits
