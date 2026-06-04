"""Regression guard for the bounded-agency external-MCP route surface.

Deep-test 2026-06-04 finding F-2: `bounded_agency.execute_tool` was calling
the bare routes `/query`, `/query_range`, `/traces`, which 404 on the
deployed MCP image (it serves `/tools/*` only). The on-demand retry-query
path the LLM can request was therefore silently dead. These tests assert
each external-MCP tool routes through the correct `/tools/*` endpoint with
the param names the deployed MCPs expect.

If any of these fail, the bounded-agency retry path has drifted from the
deployed MCP surface again — see context.py for the canonical paths.
"""
from __future__ import annotations

import httpx
import pytest

from app.bounded_agency import ToolRequest, execute_tool


def _patch_client(monkeypatch, handler):
    class _MockedAsyncClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    import httpx as _httpx
    monkeypatch.setattr(_httpx, "AsyncClient", _MockedAsyncClient)


@pytest.mark.asyncio
async def test_prometheus_query_routes_to_tools_query_instant(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"status": "success", "result": []})

    _patch_client(monkeypatch, handler)

    request = ToolRequest(name="prometheus.query", args={"expr": "up{job='spring-boot'}"})
    result = await execute_tool(request, context_gatherer=None, store=None)

    assert "error" not in result
    assert captured["path"] == "/tools/query_instant"
    # schema names the arg `expr`; the MCP expects `promql`.
    assert captured["params"]["promql"] == "up{job='spring-boot'}"
    assert "expr" not in captured["params"]


@pytest.mark.asyncio
async def test_loki_query_range_routes_to_tools_query_logs(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"lines": [], "count": 0})

    _patch_client(monkeypatch, handler)

    request = ToolRequest(
        name="loki.query_range",
        args={"query": '{service_name="spring-boot"} |~ "error"', "lookback_seconds": 600},
    )
    result = await execute_tool(request, context_gatherer=None, store=None)

    assert "error" not in result
    assert captured["path"] == "/tools/query_logs"
    # schema names the arg `query`; the MCP expects `logql`.
    assert captured["params"]["logql"] == '{service_name="spring-boot"} |~ "error"'
    # lookback_seconds (600) → relative start string "10m".
    assert captured["params"]["start"] == "10m"


@pytest.mark.asyncio
async def test_jaeger_get_traces_routes_to_tools_find_traces(monkeypatch):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"traces": [], "count": 0})

    _patch_client(monkeypatch, handler)

    request = ToolRequest(
        name="jaeger.get_traces",
        args={"service": "spring-boot", "operation": "GET /api/employee", "limit": 5},
    )
    result = await execute_tool(request, context_gatherer=None, store=None)

    assert "error" not in result
    assert captured["path"] == "/tools/find_traces"
    assert captured["params"]["service"] == "spring-boot"
    assert captured["params"]["operation"] == "GET /api/employee"
    assert captured["params"]["limit"] == "5"


@pytest.mark.asyncio
async def test_jaeger_get_traces_omits_empty_operation(monkeypatch):
    """find_traces applies `if operation:` server-side; we should not forward
    an empty operation that the LLM left blank."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"traces": [], "count": 0})

    _patch_client(monkeypatch, handler)

    request = ToolRequest(name="jaeger.get_traces", args={"service": "spring-boot"})
    await execute_tool(request, context_gatherer=None, store=None)
    assert "operation" not in captured["params"]
