import pytest

from app.llm_client import LLMClient
from app.models import Decision


@pytest.fixture
def llm():
    return LLMClient()


def test_parse_valid_escalate(llm):
    raw = '{"decision": "ESCALATE", "severity": "critical", "confidence": 0.95, "reason": "DB pool exhausted", "rca": "Connection pool at max capacity", "anomaly_summary": "3 new error patterns", "suggested_actions": ["Restart service"], "evidence": ["P95 at 2500ms"]}'
    result, error = llm._parse_response(raw)
    assert result is not None
    assert result.decision == Decision.ESCALATE
    assert result.severity == "critical"
    assert result.confidence == 0.95
    assert len(result.suggested_actions) == 1


def test_parse_valid_dismiss(llm):
    raw = '{"decision": "DISMISS", "severity": "info", "confidence": 0.8, "reason": "Transient spike", "rca": "Brief spike during deployment", "anomaly_summary": "", "suggested_actions": [], "evidence": []}'
    result, error = llm._parse_response(raw)
    assert result is not None
    assert result.decision == Decision.DISMISS


def test_parse_valid_inconclusive(llm):
    raw = '{"decision": "INCONCLUSIVE", "severity": "warning", "confidence": 0.3, "reason": "Insufficient data", "rca": "Not enough context to determine", "anomaly_summary": "", "suggested_actions": ["Gather more data"], "evidence": []}'
    result, error = llm._parse_response(raw)
    assert result is not None
    assert result.decision == Decision.INCONCLUSIVE
    assert result.confidence == 0.3


def test_parse_markdown_wrapped_json(llm):
    raw = '```json\n{"decision": "ESCALATE", "severity": "warning", "reason": "test", "rca": "test", "anomaly_summary": "", "suggested_actions": [], "evidence": []}\n```'
    result, error = llm._parse_response(raw)
    assert result is not None
    assert result.decision == Decision.ESCALATE


def test_parse_invalid_json_returns_none(llm):
    result, error = llm._parse_response("This is not JSON at all")
    assert result is None
    assert error != ""


def test_parse_invalid_decision_value_returns_none(llm):
    raw = '{"decision": "MAYBE", "severity": "warning", "reason": "unsure"}'
    result, error = llm._parse_response(raw)
    assert result is None
    assert error != ""


def test_parse_empty_string_returns_none(llm):
    result, error = llm._parse_response("")
    assert result is None


def test_parse_partial_json_returns_none(llm):
    raw = '{"decision": "ESCALATE", "severity": "critical"'
    result, error = llm._parse_response(raw)
    assert result is None


def test_parse_maps_root_cause_to_rca(llm):
    raw = '{"decision": "ESCALATE", "severity": "warning", "root_cause": "Memory leak in service", "reason": "OOM imminent", "suggested_actions": [], "evidence": []}'
    result, error = llm._parse_response(raw)
    assert result is not None
    assert result.rca == "Memory leak in service"


def test_parse_maps_recommended_actions(llm):
    raw = '{"decision": "ESCALATE", "severity": "warning", "reason": "test", "rca": "test", "recommended_actions": ["Restart pod"], "evidence": []}'
    result, error = llm._parse_response(raw)
    assert result is not None
    assert result.suggested_actions == ["Restart pod"]


def test_parse_maps_verdict_to_decision(llm):
    raw = '{"verdict": "DISMISS", "severity": "info", "reason": "noise", "rca": "transient", "suggested_actions": [], "evidence": []}'
    result, error = llm._parse_response(raw)
    assert result is not None
    assert result.decision == Decision.DISMISS


def test_parse_default_confidence_is_zero(llm):
    raw = '{"decision": "ESCALATE", "severity": "warning", "reason": "test", "rca": "test", "suggested_actions": [], "evidence": []}'
    result, error = llm._parse_response(raw)
    assert result is not None
    assert result.confidence == 0.0
