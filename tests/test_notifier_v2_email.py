"""SF-6 (2026-05-23) — v2 email body + subject tests.

Verifies the operator-cognitive-load doctrine (§12.1 in solution-brief)
applied to the escalation email path:
  - Subject is brief: [env] [namespace] [VERDICT] alertPlain, ≤70 chars
  - Body has 4 buttons (dashboard, Grafana, Loki, Rate)
  - SHELVED action_taken overrides ESCALATE verdict in the subject
  - Reason text bolds the affected component inline
  - alertname → plain-English mapping renders ("HighKongP95Latency" →
    "High p95 latency on Kong gateway")
"""
import pytest

from app.models import Decision, GrafanaAlert, LLMDecision, RCARecord
from app.notifier import EmailNotifier


def _record(**kwargs):
    """Minimal RCARecord with sane defaults."""
    base = dict(
        id="ad424303-0553-47e9-9289-bff1108d9baf",
        timestamp="2026-05-23T10:42:11Z",
        alert_source="grafana",
        alert_name="HighKongP95Latency",
        alert_fingerprint="abc123",
        affected_service="kong",
        severity="warning",
        triage_decision="investigate",
        llm_verdict="escalate",
        llm_confidence="0.85",
        rca_report="Kong upstream pool to spring-boot is near saturation.",
        llm_reasoning="upstream saturation",
        action_taken="emailed",
        investigation_duration_ms=25729,
        rca_quality="actionable",
    )
    base.update(kwargs)
    return RCARecord(**base)


def _alert(service="kong", alertname="HighKongP95Latency"):
    return GrafanaAlert(
        status="firing",
        labels={"alertname": alertname, "service": service, "severity": "warning"},
        annotations={"summary": "p95 above threshold"},
        startsAt="2026-05-23T10:42:00Z",
        generatorURL="http://52.202.21.192:3000/alerting/grafana/abc/view",
    )


def _decision(verdict=Decision.ESCALATE, actions=None):
    return LLMDecision(
        decision=verdict,
        severity="warning",
        confidence=0.85,
        reason="Upstream saturation",
        rca="Kong upstream pool to spring-boot is near saturation.",
        anomaly_summary="",
        suggested_actions=actions if actions is not None else [
            "kubectl rollout restart deploy/kong -n app",
        ],
        evidence=["kong_proxy_latency_ms p95 = 4ms"],
    )


# ─── _v2_subject ──────────────────────────────────────────────────────

def test_subject_format_prod_escalate():
    n = EmailNotifier()
    subj = n._v2_subject(_alert(), _decision(), _record())
    assert subj.startswith("[prod] [network] [ESCALATE]")
    assert "High p95 latency on Kong gateway" in subj


def test_subject_under_70_chars():
    n = EmailNotifier()
    subj = n._v2_subject(_alert(), _decision(), _record())
    assert len(subj) <= 70, f"subject too long ({len(subj)}): {subj}"


def test_subject_truncates_long_alertplain():
    """If alertPlain pushes the subject past 70 chars, it gets ellipsised."""
    n = EmailNotifier()
    long_alert = _alert(service="rental-mysql", alertname="OTelCollectorHighSpanDropRate")
    subj = n._v2_subject(long_alert, _decision(), _record(affected_service="rental-mysql"))
    assert len(subj) <= 70


def test_subject_shelved_overrides_escalate():
    """When action_taken=shelved (DA-1 gate), subject says SHELVED not ESCALATE."""
    n = EmailNotifier()
    rec = _record(action_taken="shelved", rca_quality="needs_review", llm_confidence="0.10")
    subj = n._v2_subject(_alert(), _decision(verdict=Decision.ESCALATE), rec)
    assert "[SHELVED]" in subj
    assert "[ESCALATE]" not in subj


def test_subject_env_stg_for_rental_namespace():
    """env_for() heuristic: rental services → stg, others → prod."""
    n = EmailNotifier()
    subj = n._v2_subject(_alert(service="rental-backend"), _decision(),
                          _record(affected_service="rental-backend"))
    assert subj.startswith("[stg] [rental]")


# ─── _build_v2_escalation_body ────────────────────────────────────────

def test_body_contains_four_buttons():
    n = EmailNotifier()
    body = n._build_v2_escalation_body(_alert(), _decision(), _record(), 0, None, [])
    assert "View on dashboard" in body
    assert "Open Grafana" in body
    assert "Open Loki" in body
    assert "Rate this alert" in body


def test_body_dashboard_url_uses_short_id():
    n = EmailNotifier()
    body = n._build_v2_escalation_body(_alert(), _decision(), _record(), 0, None, [])
    # short_id is first 8 chars of the UUID "ad424303-0553-47e9-..."
    assert "/dashboard/alert/ad424303" in body


def test_body_renders_plain_alert_name():
    n = EmailNotifier()
    body = n._build_v2_escalation_body(_alert(), _decision(), _record(), 0, None, [])
    assert "High p95 latency on Kong gateway" in body
    # Raw alertname should NOT appear in the user-facing h1
    # (it's fine for it to appear elsewhere — e.g. footer, hidden fields)


def test_body_includes_first_suggested_action_only():
    """Design shows ONE action inline; rest live on detail page."""
    n = EmailNotifier()
    actions = [
        "kubectl rollout restart deploy/kong -n app",
        "helm rollback kong 7",
        "kubectl scale deploy/spring-boot --replicas=6",
    ]
    body = n._build_v2_escalation_body(_alert(), _decision(actions=actions),
                                         _record(), 0, None, [])
    assert "kubectl rollout restart deploy/kong" in body
    # Second + third actions should NOT be in the email body (one-action-inline rule)
    assert "helm rollback kong 7" not in body
    assert "scale deploy/spring-boot" not in body


def test_body_no_pre_v2_word_salad():
    """The new body should NOT contain pre-v2 verbose elements: top log
    issues digest, diagnostic_steps block, evidence ul, history count."""
    n = EmailNotifier()
    body = n._build_v2_escalation_body(_alert(), _decision(), _record(), 5, None, [])
    # These were big sections in the old _build_escalation_body
    assert "Top log patterns" not in body
    assert "Diagnostic steps" not in body
    assert "Quick links" not in body  # old multi-link list at the bottom


def test_body_bolds_component_in_reason():
    """The 'Why' block should inline-bold the affected component."""
    n = EmailNotifier()
    rec = _record(affected_service="spring-boot")
    body = n._build_v2_escalation_body(
        _alert(service="spring-boot", alertname="HighP95Latency"),
        _decision(),
        rec, 0, None, [],
    )
    # The reason contains "spring-boot" — should be wrapped in a bold mono span
    assert "<strong" in body and "spring-boot</strong>" in body
