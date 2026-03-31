import pytest

from app.llm_client import LLMClient
from app.models import Decision


@pytest.fixture
def llm():
    return LLMClient()


def test_parse_valid_escalate(llm):
    raw = '{"decision": "ESCALATE", "severity": "critical", "reason": "DB pool exhausted", "rca": "Connection pool at max capacity", "anomaly_summary": "3 new error patterns", "suggested_actions": ["Restart service"], "evidence": ["P95 at 2500ms"]}'
    result = llm._parse_response(raw)
    assert result is not None
    assert result.decision == Decision.ESCALATE
    assert result.severity == "critical"
    assert len(result.suggested_actions) == 1


def test_parse_valid_dismiss(llm):
    raw = '{"decision": "DISMISS", "severity": "info", "reason": "Transient spike", "rca": "Brief spike during deployment", "anomaly_summary": "", "suggested_actions": [], "evidence": []}'
    result = llm._parse_response(raw)
    assert result is not None
    assert result.decision == Decision.DISMISS


def test_parse_markdown_wrapped_json(llm):
    raw = '```json\n{"decision": "ESCALATE", "severity": "warning", "reason": "test", "rca": "test", "anomaly_summary": "", "suggested_actions": [], "evidence": []}\n```'
    result = llm._parse_response(raw)
    assert result is not None
    assert result.decision == Decision.ESCALATE


def test_parse_invalid_json_returns_none(llm):
    result = llm._parse_response("This is not JSON at all")
    assert result is None


def test_parse_invalid_decision_value_returns_none(llm):
    raw = '{"decision": "MAYBE", "severity": "warning", "reason": "unsure"}'
    result = llm._parse_response(raw)
    assert result is None


def test_parse_empty_string_returns_none(llm):
    result = llm._parse_response("")
    assert result is None


def test_parse_partial_json_returns_none(llm):
    raw = '{"decision": "ESCALATE", "severity": "critical"'
    result = llm._parse_response(raw)
    assert result is None
