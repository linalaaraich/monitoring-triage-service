"""Phase 6 (2026-06-03) — rca_history.list_feedback bounded-agency tool.

Locks in:
  - tool name registered in _TOOL_SCHEMAS with the correct Pydantic schema
  - parse_tool_request accepts a well-formed list_feedback request
  - parse_tool_request rejects unknown args
  - execute_tool routes the call to the rca-history MCP's /tools/list_feedback
    endpoint (NOT a direct DB read — MCP-only invariant)
  - TOOLS_DESCRIPTION mentions the new tool so the LLM knows it exists
"""
from __future__ import annotations

import httpx
import pytest

from app.bounded_agency import (
    TOOLS_DESCRIPTION,
    RCAHistoryListFeedbackArgs,
    ToolRequest,
    _TOOL_SCHEMAS,
    execute_tool,
    parse_tool_request,
)


class _StubStore:
    """Stub RCA store. The list_feedback path must NEVER reach into this
    object — that would be a direct-DB read bypassing the MCP-only invariant."""

    async def get_decisions(self, *args, **kwargs):
        raise AssertionError("store.get_decisions called — list_feedback must route through MCP")

    async def get_high_value_feedback_for_family(self, *args, **kwargs):
        raise AssertionError(
            "store.get_high_value_feedback_for_family called from bounded-agency "
            "— that's the proactive-injection path, NOT the on-demand tool path"
        )


# ---------------------------------------------------------------------------
# Tool registration + schema
# ---------------------------------------------------------------------------


def test_list_feedback_registered_in_tool_schemas():
    """The tool MUST appear in _TOOL_SCHEMAS or the LLM can't invoke it."""
    assert "rca_history.list_feedback" in _TOOL_SCHEMAS
    assert _TOOL_SCHEMAS["rca_history.list_feedback"] is RCAHistoryListFeedbackArgs


def test_list_feedback_in_tools_description():
    """The LLM-facing description block MUST mention the tool so the model
    knows it exists (otherwise the prompt-text tool advertisement is moot)."""
    assert "rca_history.list_feedback" in TOOLS_DESCRIPTION


def test_list_feedback_args_schema_validates_required_alert_name():
    """alert_name is required, service is optional."""
    # Valid
    args = RCAHistoryListFeedbackArgs(alert_name="HighP95Latency")
    assert args.alert_name == "HighP95Latency"
    assert args.service is None
    assert args.days == 14
    assert args.limit == 5

    # Valid with all fields
    args2 = RCAHistoryListFeedbackArgs(
        alert_name="X", service="spring-boot", days=30, limit=10,
    )
    assert args2.service == "spring-boot"
    assert args2.days == 30

    # Missing required field rejected
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        RCAHistoryListFeedbackArgs(service="spring-boot")


def test_parse_tool_request_accepts_list_feedback():
    raw = {
        "tool_request": {
            "name": "rca_history.list_feedback",
            "args": {"alert_name": "HighP95Latency", "service": "kong", "days": 14, "limit": 5},
        }
    }
    parsed = parse_tool_request(raw)
    assert parsed is not None
    assert parsed.name == "rca_history.list_feedback"
    assert parsed.args["alert_name"] == "HighP95Latency"
    assert parsed.args["service"] == "kong"


def test_parse_tool_request_rejects_missing_alert_name():
    """Missing required alert_name → parse returns None (Pydantic validation fail)."""
    raw = {
        "tool_request": {
            "name": "rca_history.list_feedback",
            "args": {"days": 14},
        }
    }
    assert parse_tool_request(raw) is None


# ---------------------------------------------------------------------------
# Routing — must go through the rca-history MCP, not the store directly
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_tool_routes_list_feedback_through_mcp(monkeypatch):
    """Execute the tool and assert the only network call is to the MCP's
    /tools/list_feedback endpoint with the expected params."""
    captured: dict = {}

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["path"] = request.url.path
        captured["params"] = dict(request.url.params)
        return httpx.Response(
            200,
            json={
                "alert_name": "HighP95Latency",
                "service": "kong",
                "days": 14,
                "count": 1,
                "records": [
                    {
                        "decision_id": "d_abc",
                        "when": "2026-05-30T14:22:00",
                        "feedback_type": "rate",
                        "rating": "no",
                        "verdict_was_right": "no",
                        "action_was_right": None,
                        "actual_cause": "cron blip",
                        "tags": "[]",
                        "notes": None,
                        "alert_name": "HighP95Latency",
                        "service": "kong",
                    }
                ],
            },
        )

    class _MockedAsyncClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(mock_handler)
            super().__init__(*a, **kw)

    import httpx as _httpx
    monkeypatch.setattr(_httpx, "AsyncClient", _MockedAsyncClient)

    request = ToolRequest(
        name="rca_history.list_feedback",
        args={"alert_name": "HighP95Latency", "service": "kong", "days": 14, "limit": 5},
    )
    result = await execute_tool(request, context_gatherer=None, store=_StubStore())

    assert "error" not in result
    assert result["tool"] == "rca_history.list_feedback"
    assert isinstance(result["result"], dict)
    # Response shape: a dict with a `records` list (the LLM iterates this)
    assert "records" in result["result"]
    assert isinstance(result["result"]["records"], list)
    assert result["result"]["records"][0]["decision_id"] == "d_abc"

    # Routed through the MCP, not a direct DB call
    assert captured["path"] == "/tools/list_feedback"
    assert captured["params"]["alert_name"] == "HighP95Latency"
    assert captured["params"]["service"] == "kong"
    assert captured["params"]["days"] == "14"
    assert captured["params"]["limit"] == "5"


@pytest.mark.asyncio
async def test_execute_tool_omits_service_param_when_absent(monkeypatch):
    """service is optional — omit from the MCP call when not supplied."""
    captured: dict = {}

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"count": 0, "records": []})

    class _MockedAsyncClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(mock_handler)
            super().__init__(*a, **kw)

    import httpx as _httpx
    monkeypatch.setattr(_httpx, "AsyncClient", _MockedAsyncClient)

    request = ToolRequest(
        name="rca_history.list_feedback",
        args={"alert_name": "X", "days": 14, "limit": 5, "service": None},
    )
    await execute_tool(request, context_gatherer=None, store=_StubStore())
    # service=None must NOT be forwarded to the MCP — only present-and-truthy
    assert "service" not in captured["params"]
    assert captured["params"]["alert_name"] == "X"
