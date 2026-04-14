import pytest
from pydantic import ValidationError

from app.models import Decision, GrafanaAlert, GrafanaWebhook, LLMDecision, RCARecord


def test_grafana_alert_properties(sample_alert):
    assert sample_alert.alertname == "HighP95Latency"
    assert sample_alert.instance == "10.0.2.30:8080"
    assert sample_alert.severity == "warning"
    assert sample_alert.service == "app-spring-actuator"


def test_grafana_alert_defaults():
    alert = GrafanaAlert(status="firing", labels={})
    assert alert.alertname == "unknown"
    assert alert.instance == "unknown"
    assert alert.severity == "warning"
    assert alert.service == "unknown"


def test_grafana_webhook_parsing(sample_webhook):
    assert sample_webhook.status == "firing"
    assert len(sample_webhook.alerts) == 1
    assert sample_webhook.alerts[0].alertname == "HighP95Latency"


def test_llm_decision_escalate():
    decision = LLMDecision(
        decision=Decision.ESCALATE,
        severity="critical",
        confidence=0.95,
        reason="High latency detected",
        rca="Database connection pool exhausted",
        suggested_actions=["Restart the service", "Scale DB connections"],
        evidence=["P95 latency at 2500ms", "DB pool at 100%"],
    )
    assert decision.decision == Decision.ESCALATE
    assert decision.confidence == 0.95
    assert len(decision.suggested_actions) == 2


def test_llm_decision_dismiss():
    decision = LLMDecision(
        decision=Decision.DISMISS,
        severity="info",
        reason="Transient spike during deployment",
    )
    assert decision.decision == Decision.DISMISS
    assert decision.confidence == 0.0  # default


def test_llm_decision_inconclusive():
    decision = LLMDecision(
        decision=Decision.INCONCLUSIVE,
        severity="warning",
        confidence=0.3,
        reason="Insufficient data to determine",
    )
    assert decision.decision == Decision.INCONCLUSIVE
    assert decision.confidence == 0.3


def test_llm_decision_invalid_decision():
    with pytest.raises(ValidationError):
        LLMDecision(decision="MAYBE", severity="warning", reason="unsure")


def test_rca_record_defaults():
    record = RCARecord(
        alert_name="HighP95Latency",
        triage_decision="investigate",
        action_taken="emailed",
    )
    assert record.id  # UUID auto-generated
    assert record.timestamp  # datetime auto-generated
    assert record.alert_source == "grafana"
    assert record.investigation_duration_ms == 0
