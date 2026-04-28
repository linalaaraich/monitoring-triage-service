"""Tests for the exemplar tool entries in the bounded-agency whitelist.

These are LLM-callable tools (during the bounded-agency retry) that let the
model fetch additional canonical RCA exemplars when the pre-injected one
isn't a good fit. Implemented as direct in-process calls into the
exemplars module — same pattern as `rca_history.similar`. No HTTP / MCP
roundtrip. The naming mirrors the MCP convention (`rca_history.<tool>`)
because that's how the LLM thinks of them.
"""
from unittest.mock import MagicMock

import pytest

from app.bounded_agency import (
    ToolRequest,
    execute_tool,
    parse_tool_request,
)


def test_list_exemplars_request_parses_with_no_args():
    tr = parse_tool_request({"tool_request": {"name": "rca_history.list_exemplars", "args": {}}})
    assert tr is not None
    assert tr.name == "rca_history.list_exemplars"
    assert tr.args == {}


def test_get_exemplar_request_parses_with_id():
    tr = parse_tool_request({
        "tool_request": {
            "name": "rca_history.get_exemplar",
            "args": {"exemplar_id": "oom-loop"},
        }
    })
    assert tr is not None
    assert tr.name == "rca_history.get_exemplar"
    assert tr.args == {"exemplar_id": "oom-loop"}


def test_get_exemplar_rejects_missing_id():
    """The id arg is required; a request without it must be rejected by
    the Pydantic schema (returns None, not a malformed ToolRequest)."""
    tr = parse_tool_request({
        "tool_request": {"name": "rca_history.get_exemplar", "args": {}}
    })
    assert tr is None


@pytest.mark.asyncio
async def test_execute_list_exemplars_returns_catalogue():
    tr = ToolRequest(name="rca_history.list_exemplars", args={})
    result = await execute_tool(tr, context_gatherer=MagicMock(), store=MagicMock())
    assert "result" in result
    items = result["result"]
    assert isinstance(items, list)
    assert len(items) == 14
    # Each item should have the catalogue shape (id + archetype + gist)
    sample = items[0]
    assert "id" in sample
    assert "archetype" in sample
    assert "one_line" in sample


@pytest.mark.asyncio
async def test_execute_get_exemplar_returns_full_archetype():
    tr = ToolRequest(name="rca_history.get_exemplar", args={"exemplar_id": "network-firewall-attribution"})
    result = await execute_tool(tr, context_gatherer=MagicMock(), store=MagicMock())
    assert "result" in result
    ex = result["result"]
    assert ex["id"] == "network-firewall-attribution"
    assert "rca" in ex
    assert "evidence_shape" in ex
    assert "actions_shape" in ex


@pytest.mark.asyncio
async def test_execute_get_exemplar_unknown_id_returns_error():
    tr = ToolRequest(name="rca_history.get_exemplar", args={"exemplar_id": "no-such-archetype"})
    result = await execute_tool(tr, context_gatherer=MagicMock(), store=MagicMock())
    assert "error" in result
    assert "exemplar_not_found" in result["error"]
