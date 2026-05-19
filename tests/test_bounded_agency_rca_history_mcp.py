"""S3-HF-05 (2026-05-19) regression guard.

Verifies that `rca_history.similar` in `bounded_agency.execute_tool`
routes through the rca-history-MCP `/tools/get_similar_decisions`
endpoint, not a direct in-process `store.get_decisions` call.

If this test ever fails, the MCP-only invariant has regressed on the
bounded-agency retry path. See feedback_mcp_only_data_access.md.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import httpx
import pytest

from app.bounded_agency import ToolRequest, execute_tool
from app.config import settings


class _StubStore:
    """Stub RCA store. If execute_tool reaches into this object for the
    rca_history.similar path, the test fails — that's the bypass we closed."""

    async def get_decisions(self, *args, **kwargs):
        raise AssertionError(
            "store.get_decisions called — bounded_agency reverted to "
            "the pre-S3-HF-05 direct-DB read path"
        )

    async def get_recent_decisions_for_alert(self, *args, **kwargs):
        raise AssertionError(
            "store.get_recent_decisions_for_alert called — bounded_agency "
            "reverted to the pre-S3-HF-05 direct-DB read path"
        )


@pytest.mark.asyncio
async def test_rca_history_similar_routes_through_mcp(monkeypatch):
    """Execute the rca_history.similar tool and assert the only network
    call is to the rca-history-MCP `/tools/get_similar_decisions` endpoint."""
    captured: dict = {}

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["path"] = request.url.path
        captured["host"] = request.url.host
        captured["params"] = dict(request.url.params)
        return httpx.Response(
            200,
            json={
                "alert_name": "HighP95Latency",
                "min_quality": "actionable",
                "count": 1,
                "records": [{"id": "abc", "alert_name": "HighP95Latency", "rca_quality": "actionable"}],
            },
        )

    class _MockedAsyncClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(mock_handler)
            super().__init__(*a, **kw)

    # bounded_agency.execute_tool does `import httpx` lazily inside the
    # function — patch the module-global httpx.AsyncClient so the lazy
    # import resolves to our mocked client.
    import httpx as _httpx
    monkeypatch.setattr(_httpx, "AsyncClient", _MockedAsyncClient)

    request = ToolRequest(
        name="rca_history.similar",
        args={"alert_name": "HighP95Latency", "affected_service": "kong", "days": 7, "limit": 3},
    )
    result = await execute_tool(request, context_gatherer=None, store=_StubStore())

    # The MCP returned a result; the stub's AssertionError never fired.
    assert "error" not in result
    assert result["tool"] == "rca_history.similar"
    assert result["result"]["count"] == 1

    # Confirm the URL path is the MCP tool surface — not /api/v1/anything-direct.
    assert captured["path"] == "/tools/get_similar_decisions"
    # And the params include min_quality (the new quality filter).
    assert captured["params"]["min_quality"] == "actionable"
    assert captured["params"]["alert_name"] == "HighP95Latency"
    assert captured["params"]["affected_service"] == "kong"


@pytest.mark.asyncio
async def test_rca_history_similar_forwards_min_quality_widening(monkeypatch):
    """If the LLM widens to min_quality=data_starved, the MCP call must
    forward that — this is the escape hatch for archetypes with thin
    actionable history."""
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
        name="rca_history.similar",
        args={"alert_name": "HighP95Latency", "min_quality": "data_starved"},
    )
    await execute_tool(request, context_gatherer=None, store=_StubStore())
    assert captured["params"]["min_quality"] == "data_starved"
