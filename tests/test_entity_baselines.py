"""US-5.1 Phase B — entity_baselines tests.

Uses an httpx mock transport to stub Prometheus responses, so tests
don't depend on a live Prometheus.
"""
from __future__ import annotations

import time

import httpx
import pytest

from app.entity_baselines import clear_cache, get_baseline


class _FakeProm:
    """Minimal Prometheus stub — captures queries, returns canned values."""

    def __init__(self, by_query: dict[str, float | None]):
        self.by_query = by_query
        self.captured: list[str] = []

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            params = dict(request.url.params)
            q = params.get("query", "")
            self.captured.append(q)
            for needle, val in self.by_query.items():
                if needle in q:
                    if val is None:
                        return httpx.Response(200, json={"status": "success", "data": {"result": []}})
                    return httpx.Response(200, json={
                        "status": "success",
                        "data": {"result": [{"metric": {}, "value": [0, str(val)]}]},
                    })
            return httpx.Response(200, json={"status": "success", "data": {"result": []}})
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
    facts = await get_baseline("http://prom:9090", "spring-boot", "http_request_duration_p95")
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
    facts = await get_baseline("http://prom:9090", "spring-boot", "http_request_duration_p95")
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
    facts = await get_baseline("http://prom:9090", "spring-boot", "http_request_duration_p95")
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
    facts = await get_baseline("http://prom:9090", "spring-boot", "http_request_duration_p95")
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
    facts = await get_baseline("http://prom:9090", "kong", "stable_metric")
    assert facts.sigma_above_baseline(110.0) is None
    assert "degenerate" in facts.as_prose_line(110.0)


@pytest.mark.asyncio
async def test_cache_hit_skips_prometheus(fake_prom):
    fake_prom.by_query = {
        "avg_over_time": 850.0, "stddev_over_time": 250.0,
        "quantile_over_time(0.5,": 800.0, "quantile_over_time(0.95,": 1100.0,
        "count_over_time": 2016,
    }
    await get_baseline("http://prom:9090", "spring-boot", "metric_x")
    fake_prom.captured.clear()
    await get_baseline("http://prom:9090", "spring-boot", "metric_x")
    assert fake_prom.captured == []


@pytest.mark.asyncio
async def test_cache_miss_for_different_service(fake_prom):
    fake_prom.by_query = {
        "avg_over_time": 850.0, "stddev_over_time": 250.0,
        "quantile_over_time(0.5,": 800.0, "quantile_over_time(0.95,": 1100.0,
        "count_over_time": 2016,
    }
    await get_baseline("http://prom:9090", "spring-boot", "metric_x")
    fake_prom.captured.clear()
    await get_baseline("http://prom:9090", "kong", "metric_x")
    assert len(fake_prom.captured) == 5


@pytest.mark.asyncio
async def test_cache_expiry(fake_prom, monkeypatch):
    fake_prom.by_query = {
        "avg_over_time": 850.0, "stddev_over_time": 250.0,
        "quantile_over_time(0.5,": 800.0, "quantile_over_time(0.95,": 1100.0,
        "count_over_time": 2016,
    }
    await get_baseline("http://prom:9090", "spring-boot", "metric_x", cache_ttl_seconds=1)
    fake_prom.captured.clear()
    real_monotonic = time.monotonic
    monkeypatch.setattr("app.entity_baselines.time.monotonic", lambda: real_monotonic() + 100)
    await get_baseline("http://prom:9090", "spring-boot", "metric_x", cache_ttl_seconds=1)
    assert len(fake_prom.captured) == 5


@pytest.mark.asyncio
async def test_baseline_falls_back_gracefully_on_prometheus_error(monkeypatch):
    class _ErrClient:
        def __init__(self, *a, **kw): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, *a, **kw):
            raise httpx.ConnectError("prom down")
    monkeypatch.setattr("app.entity_baselines.httpx.AsyncClient", _ErrClient)
    facts = await get_baseline("http://prom:9090", "spring-boot", "metric_x")
    assert facts.sample_count == 0
    assert facts.is_authoritative is False
