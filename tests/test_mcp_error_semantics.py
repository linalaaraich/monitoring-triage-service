"""MCP error semantics — distinguish a query fumble (4xx) from a source
outage (5xx / connection error).

misc.md issue 6 / task #3: the triage's MCP call paths previously surfaced a
bad LLM-issued query (4xx) identically to a real source outage (5xx / conn),
so the RCA read "source unavailable" for what was actually an invalid query.
This pins the corrected behaviour in both call paths:

  - app/context.py `_mcp_call` -> raises MCPQueryRejected on 4xx, a generic
    exception on 5xx; gather() labels the prompt section accordingly.
  - app/bounded_agency.py `execute_tool` -> returns error_kind="query_rejected"
    on 4xx vs "source_unavailable" on 5xx/conn; the retry prompt block tells
    the model to FIX its query rather than abandon the source.
"""
from __future__ import annotations

import httpx
import pytest

from app.context import ContextGatherer, MCPQueryRejected, _mcp_error_label
from app.models import GrafanaAlert


def _make_alert(service="spring-boot", starts_at=""):
    return GrafanaAlert(
        status="firing",
        labels={"alertname": "TestAlert", "service": service, "severity": "warning"},
        startsAt=starts_at,
    )


def _gatherer_with_responder(responder):
    """Build a ContextGatherer whose httpx client uses a MockTransport."""
    g = ContextGatherer()
    transport = httpx.MockTransport(responder)
    g._client = httpx.AsyncClient(transport=transport)
    return g


# --- _mcp_call: 4xx vs 5xx -------------------------------------------

@pytest.mark.asyncio
async def test_mcp_call_4xx_raises_query_rejected():
    def responder(request):
        return httpx.Response(400, text="parse error: unexpected token in PromQL")

    g = _gatherer_with_responder(responder)
    try:
        with pytest.raises(MCPQueryRejected) as exc_info:
            await g._mcp_call("prometheus", "http://mcp/tools/query_range", {"promql": "garbage"})
        assert exc_info.value.status == 400
        assert "parse error" in exc_info.value.detail
        assert exc_info.value.server == "prometheus"
    finally:
        await g.close()


@pytest.mark.asyncio
async def test_mcp_call_5xx_raises_generic_not_query_rejected():
    def responder(request):
        return httpx.Response(503, text="upstream down")

    g = _gatherer_with_responder(responder)
    try:
        with pytest.raises(httpx.HTTPStatusError):
            await g._mcp_call("prometheus", "http://mcp/tools/query_range", {"promql": "up"})
        # And specifically NOT the query-rejected type.
        with pytest.raises(Exception) as exc_info:
            await g._mcp_call("prometheus", "http://mcp/tools/query_range", {"promql": "up"})
        assert not isinstance(exc_info.value, MCPQueryRejected)
    finally:
        await g.close()


@pytest.mark.asyncio
async def test_mcp_call_connection_error_is_not_query_rejected():
    def responder(request):
        raise httpx.ConnectError("connection refused", request=request)

    g = _gatherer_with_responder(responder)
    try:
        with pytest.raises(Exception) as exc_info:
            await g._mcp_call("loki", "http://mcp/tools/query_logs", {"logql": "{x=1}"})
        assert not isinstance(exc_info.value, MCPQueryRejected)
    finally:
        await g.close()


# --- _mcp_error_label: distinct prompt text --------------------------

def test_error_label_query_rejected_distinct_from_unavailable():
    rejected = _mcp_error_label("Prometheus", MCPQueryRejected("Prometheus", 422, "bad expr"))
    outage = _mcp_error_label("Prometheus", RuntimeError("connection refused"))
    assert "query rejected" in rejected.lower()
    assert "do not conclude prometheus is down" in rejected.lower()
    assert "unavailable" in outage.lower()
    assert "query rejected" not in outage.lower()


# --- gather(): end-to-end labelling ----------------------------------

@pytest.mark.asyncio
async def test_gather_labels_query_rejected_for_4xx():
    """A 4xx on the Prometheus pillar surfaces as a 'query rejected' context
    error, not 'unavailable' — the LLM must not read a bad query as an outage.
    Loki/Jaeger return empty-ok so only Prometheus errors."""
    def responder(request):
        url = str(request.url)
        if "query_range" in url:  # prometheus
            return httpx.Response(400, text="invalid PromQL")
        return httpx.Response(200, json=[])  # loki + jaeger empty-ok

    g = _gatherer_with_responder(responder)
    try:
        ctx = await g.gather(_make_alert())
        prom_errors = [e for e in ctx.errors if e.startswith("[Prometheus]")]
        assert prom_errors, f"expected a Prometheus error, got {ctx.errors}"
        assert "query rejected" in prom_errors[0].lower()
        assert "unavailable" not in prom_errors[0].lower()
    finally:
        await g.close()


@pytest.mark.asyncio
async def test_gather_labels_unavailable_for_5xx():
    def responder(request):
        url = str(request.url)
        if "query_range" in url:  # prometheus
            return httpx.Response(500, text="boom")
        return httpx.Response(200, json=[])

    g = _gatherer_with_responder(responder)
    try:
        ctx = await g.gather(_make_alert())
        prom_errors = [e for e in ctx.errors if e.startswith("[Prometheus]")]
        assert prom_errors
        assert "unavailable" in prom_errors[0].lower()
        assert "query rejected" not in prom_errors[0].lower()
    finally:
        await g.close()


# --- bounded_agency.execute_tool: 4xx vs 5xx -------------------------

def _patch_client(monkeypatch, handler):
    class _MockedAsyncClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    import httpx as _httpx
    monkeypatch.setattr(_httpx, "AsyncClient", _MockedAsyncClient)


def _loki_request():
    from app.bounded_agency import ToolRequest
    return ToolRequest(
        name="loki.query_range",
        args={"query": '{service_name="spring-boot"}', "lookback_seconds": 600},
    )


@pytest.mark.asyncio
async def test_execute_tool_4xx_returns_query_rejected(monkeypatch):
    from app.bounded_agency import execute_tool

    def handler(request):
        return httpx.Response(400, text="malformed LogQL")

    _patch_client(monkeypatch, handler)
    result = await execute_tool(_loki_request(), context_gatherer=None, store=None)
    assert result.get("error_kind") == "query_rejected"
    assert result.get("upstream_status") == 400
    assert "query_rejected" in result["error"]


@pytest.mark.asyncio
async def test_execute_tool_5xx_returns_source_unavailable(monkeypatch):
    from app.bounded_agency import execute_tool

    def handler(request):
        return httpx.Response(502, text="bad gateway")

    _patch_client(monkeypatch, handler)
    result = await execute_tool(_loki_request(), context_gatherer=None, store=None)
    assert result.get("error_kind") == "source_unavailable"
    assert result.get("upstream_status") == 502


@pytest.mark.asyncio
async def test_execute_tool_connection_error_is_source_unavailable(monkeypatch):
    from app.bounded_agency import execute_tool

    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    _patch_client(monkeypatch, handler)
    result = await execute_tool(_loki_request(), context_gatherer=None, store=None)
    assert result.get("error_kind") == "source_unavailable"


# --- prompt block rendering ------------------------------------------

def test_prompt_block_query_rejected_tells_model_to_fix_query():
    from app.bounded_agency import tool_result_to_prompt_block

    rejected = tool_result_to_prompt_block({
        "tool": "loki.query_logs", "args": {"logql": "bad"},
        "error_kind": "query_rejected", "upstream_status": 400,
        "error": "query_rejected (HTTP 400): malformed LogQL",
    })
    assert "QUERY REJECTED" in rejected
    assert "your query was the problem" in rejected.lower()
    assert "do not conclude the source is down" in rejected.lower()


def test_prompt_block_source_unavailable_distinct():
    from app.bounded_agency import tool_result_to_prompt_block

    outage = tool_result_to_prompt_block({
        "tool": "loki.query_logs", "args": {"logql": "{x=1}"},
        "error_kind": "source_unavailable", "upstream_status": 502,
        "error": "source_unavailable (HTTP 502): bad gateway",
    })
    assert "source was unavailable" in outage.lower()
    assert "QUERY REJECTED" not in outage
