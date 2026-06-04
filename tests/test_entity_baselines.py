"""US-5.1 Phase B + S3-HF-04 — entity_baselines tests.

Uses an httpx mock transport to stub prometheus-mcp responses, so tests
don't depend on a live Prometheus or MCP server. Post-S3-HF-04 the
baseline path goes through prometheus-mcp (`/tools/query_instant?promql=`)
not direct Prometheus (`/api/v1/query?query=`).
"""
from __future__ import annotations

import time

import httpx
import pytest

from app.entity_baselines import clear_cache, get_baseline


class _FakeProm:
    """Minimal prometheus-mcp stub — captures queries, returns canned values.

    Asserts each request hits the MCP `/tools/query_instant?promql=` surface,
    not the legacy direct-Prometheus `/api/v1/query?query=` surface (S3-HF-04)
    nor the bare `/query?expr=` route (which 404s on the deployed MCP image).
    Test failure here means a regression of the MCP-only invariant.
    """

    def __init__(self, by_query: dict[str, float | None]):
        self.by_query = by_query
        self.captured: list[str] = []
        self.captured_paths: list[str] = []

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            params = dict(request.url.params)
            # Deployed MCP /tools/query_instant uses `promql` param and lifts
            # `result` to the top level of the response.
            q = params.get("promql", "")
            self.captured.append(q)
            self.captured_paths.append(request.url.path)
            for needle, val in self.by_query.items():
                if needle in q:
                    if val is None:
                        return httpx.Response(200, json={"status": "success", "result": []})
                    return httpx.Response(200, json={
                        "status": "success",
                        "result_type": "vector",
                        "result": [{"metric": {}, "value": [0, str(val)]}],
                    })
            return httpx.Response(200, json={"status": "success", "result": []})
        return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def _clear_cache_each_test():
    clear_cache()
    yield
    clear_cache()


@pytest.fixture
def fake_prom(monkeypatch):
    fake = _FakeProm({})

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = fake.transport()
            super().__init__(*a, **kw)

    monkeypatch.setattr("app.entity_baselines.httpx.AsyncClient", _PatchedClient)
    return fake


@pytest.mark.asyncio
async def test_baseline_returns_authoritative_facts_when_history_present(fake_prom):
    fake_prom.by_query = {
        "avg_over_time": 850.0,
        "stddev_over_time": 250.0,
        "quantile_over_time(0.5,": 800.0,
        "quantile_over_time(0.95,": 1100.0,
        "count_over_time": 2016,
    }
    facts = await get_baseline("http://prometheus-mcp:8091", "spring-boot", "http_request_duration_p95")
    assert facts.is_authoritative is True
    assert facts.sample_count == 2016
    assert facts.mean == 850.0
    assert facts.stddev == 250.0
    assert facts.p95 == 1100.0


@pytest.mark.asyncio
async def test_baseline_not_authoritative_when_thin_history(fake_prom):
    fake_prom.by_query = {
        "avg_over_time": 800.0,
        "stddev_over_time": 100.0,
        "quantile_over_time(0.5,": 800.0,
        "quantile_over_time(0.95,": 900.0,
        "count_over_time": 30,
    }
    facts = await get_baseline("http://prometheus-mcp:8091", "spring-boot", "http_request_duration_p95")
    assert facts.is_authoritative is False
    assert "No behavioral baseline available" in facts.as_prose_line(8500.0)


@pytest.mark.asyncio
async def test_sigma_above_baseline_computes(fake_prom):
    fake_prom.by_query = {
        "avg_over_time": 850.0,
        "stddev_over_time": 250.0,
        "quantile_over_time(0.5,": 800.0,
        "quantile_over_time(0.95,": 1100.0,
        "count_over_time": 2016,
    }
    facts = await get_baseline("http://prometheus-mcp:8091", "spring-boot", "http_request_duration_p95")
    sigma = facts.sigma_above_baseline(8500.0)
    assert sigma is not None
    assert 30.0 < sigma < 31.0


@pytest.mark.asyncio
async def test_prose_line_renders_above_baseline(fake_prom):
    fake_prom.by_query = {
        "avg_over_time": 850.0, "stddev_over_time": 250.0,
        "quantile_over_time(0.5,": 800.0, "quantile_over_time(0.95,": 1100.0,
        "count_over_time": 2016,
    }
    facts = await get_baseline("http://prometheus-mcp:8091", "spring-boot", "http_request_duration_p95")
    line = facts.as_prose_line(8500.0)
    assert "spring-boot/http_request_duration_p95" in line
    assert "30.6σ above baseline" in line


@pytest.mark.asyncio
async def test_prose_line_handles_zero_stddev(fake_prom):
    fake_prom.by_query = {
        "avg_over_time": 100.0, "stddev_over_time": 0.0,
        "quantile_over_time(0.5,": 100.0, "quantile_over_time(0.95,": 100.0,
        "count_over_time": 2016,
    }
    facts = await get_baseline("http://prometheus-mcp:8091", "kong", "stable_metric")
    assert facts.sigma_above_baseline(110.0) is None
    assert "degenerate" in facts.as_prose_line(110.0)


@pytest.mark.asyncio
async def test_cache_hit_skips_prometheus(fake_prom):
    fake_prom.by_query = {
        "avg_over_time": 850.0, "stddev_over_time": 250.0,
        "quantile_over_time(0.5,": 800.0, "quantile_over_time(0.95,": 1100.0,
        "count_over_time": 2016,
    }
    await get_baseline("http://prometheus-mcp:8091", "spring-boot", "metric_x")
    fake_prom.captured.clear()
    await get_baseline("http://prometheus-mcp:8091", "spring-boot", "metric_x")
    assert fake_prom.captured == []


@pytest.mark.asyncio
async def test_cache_miss_for_different_service(fake_prom):
    fake_prom.by_query = {
        "avg_over_time": 850.0, "stddev_over_time": 250.0,
        "quantile_over_time(0.5,": 800.0, "quantile_over_time(0.95,": 1100.0,
        "count_over_time": 2016,
    }
    await get_baseline("http://prometheus-mcp:8091", "spring-boot", "metric_x")
    fake_prom.captured.clear()
    await get_baseline("http://prometheus-mcp:8091", "kong", "metric_x")
    assert len(fake_prom.captured) == 5


@pytest.mark.asyncio
async def test_cache_expiry(fake_prom, monkeypatch):
    fake_prom.by_query = {
        "avg_over_time": 850.0, "stddev_over_time": 250.0,
        "quantile_over_time(0.5,": 800.0, "quantile_over_time(0.95,": 1100.0,
        "count_over_time": 2016,
    }
    await get_baseline("http://prometheus-mcp:8091", "spring-boot", "metric_x", cache_ttl_seconds=1)
    fake_prom.captured.clear()
    real_monotonic = time.monotonic
    monkeypatch.setattr("app.entity_baselines.time.monotonic", lambda: real_monotonic() + 100)
    await get_baseline("http://prometheus-mcp:8091", "spring-boot", "metric_x", cache_ttl_seconds=1)
    assert len(fake_prom.captured) == 5


@pytest.mark.asyncio
async def test_baseline_routes_through_prometheus_mcp_surface(fake_prom):
    """S3-HF-04 regression guard: every baseline read must hit the MCP
    `/tools/query_instant` surface, never the direct-Prometheus
    `/api/v1/query?query=` surface nor the bare `/query?expr=` route (which
    404s on the deployed MCP image). If this test ever fails, the MCP-only
    invariant has regressed on the baseline path."""
    fake_prom.by_query = {
        "avg_over_time": 850.0, "stddev_over_time": 250.0,
        "quantile_over_time(0.5,": 800.0, "quantile_over_time(0.95,": 1100.0,
        "count_over_time": 2016,
    }
    await get_baseline("http://prometheus-mcp:8091", "spring-boot", "http_request_duration_p95")

    # Five parallel queries — mean, stddev, p50, p95, count.
    assert len(fake_prom.captured) == 5
    # All hits must be the MCP /tools/query_instant endpoint.
    assert all(p == "/tools/query_instant" for p in fake_prom.captured_paths), (
        f"unexpected paths: {fake_prom.captured_paths}"
    )
    # The PromQL expressions themselves are unchanged — only the transport differs.
    assert any("avg_over_time" in q for q in fake_prom.captured)
    assert any("quantile_over_time(0.95," in q for q in fake_prom.captured)


@pytest.mark.asyncio
async def test_baseline_falls_back_gracefully_on_prometheus_error(monkeypatch):
    class _ErrClient:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, *a, **kw):
            raise httpx.ConnectError("prom down")
    monkeypatch.setattr("app.entity_baselines.httpx.AsyncClient", _ErrClient)
    facts = await get_baseline("http://prometheus-mcp:8091", "spring-boot", "metric_x")
    assert facts.sample_count == 0
    assert facts.is_authoritative is False
