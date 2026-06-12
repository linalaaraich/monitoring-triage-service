"""S3-HF-07 tests — Tier 1 deep trace gather.

Three concerns:
  1. The gate (_should_fetch_deep_trace) fires for latency alerts with
     long enough traces, skips everything else.
  2. The PII sanitizer (_sanitize_db_statement / _sanitize_deep_trace)
     never leaks literal SQL values or numeric path IDs.
  3. End-to-end: when the gate fires, ContextGatherer.gather() makes the
     extra /tools/get_trace call and stores the sanitized payload on
     ctx.deep_trace.
"""
from __future__ import annotations

import httpx
import pytest

from app.context import (
    ContextGatherer,
    _sanitize_db_statement,
    _sanitize_deep_trace,
)
from app.models import GrafanaAlert


# ----------------------------------------------------------------------
# 1. PII sanitizer — unit tests
# ----------------------------------------------------------------------

def test_db_statement_replaces_single_quoted_literals():
    assert _sanitize_db_statement("WHERE email = 'lina@x.com'") == "WHERE email = ?"


def test_db_statement_replaces_numeric_literals():
    assert _sanitize_db_statement("WHERE id = 12345") == "WHERE id = ?"


def test_db_statement_replaces_compound_literals():
    out = _sanitize_db_statement(
        "SELECT * FROM orders WHERE customer_id = 42 AND status = 'PAID' AND total > 100.50"
    )
    assert "42" not in out
    assert "'PAID'" not in out
    assert "100.50" not in out
    assert out.count("?") == 3


def test_db_statement_preserves_column_names_and_keywords():
    out = _sanitize_db_statement("SELECT id FROM users WHERE active = 1")
    assert "SELECT" in out and "FROM" in out and "WHERE" in out and "users" in out and "active" in out


def test_db_statement_handles_empty_and_none():
    assert _sanitize_db_statement("") == ""
    assert _sanitize_db_statement(None) is None


def test_sanitize_deep_trace_walks_all_spans():
    raw = {
        "trace_id": "abc123",
        "spans": [
            {"operation": "GET /api/orders", "tags": {"db.statement": "WHERE id = 5", "http.target": "/api/orders/9"}},
            {"operation": "child", "tags": {"db.statement": "WHERE email = 'x@y.com'"}},
        ],
    }
    out = _sanitize_deep_trace(raw)
    assert out["spans"][0]["tags"]["db.statement"] == "WHERE id = ?"
    assert out["spans"][0]["tags"]["http.target"] == "/api/orders/:id"
    assert out["spans"][1]["tags"]["db.statement"] == "WHERE email = ?"


def test_sanitize_deep_trace_preserves_structural_fields():
    """span_id, operation, duration_ms, parent_span_id, error must survive
    unchanged — only the *values inside tags* are scrubbed."""
    raw = {
        "spans": [{
            "span_id": "s1", "operation": "OrderService.findRecent",
            "duration_ms": 1840.5, "parent_span_id": "root", "error": True,
            "tags": {"db.statement": "WHERE id = 7"},
        }],
    }
    out = _sanitize_deep_trace(raw)
    span = out["spans"][0]
    assert span["span_id"] == "s1"
    assert span["operation"] == "OrderService.findRecent"
    assert span["duration_ms"] == 1840.5
    assert span["parent_span_id"] == "root"
    assert span["error"] is True


# ----------------------------------------------------------------------
# 2. Gate logic — _should_fetch_deep_trace
# ----------------------------------------------------------------------

def _make_alert(alertname: str) -> GrafanaAlert:
    # alertname / service / severity are derived from labels via @property
    # on the GrafanaAlert model — they're not constructor args.
    return GrafanaAlert(
        status="firing",
        fingerprint="fp",
        annotations={},
        labels={"alertname": alertname, "service": "spring-boot", "severity": "warning"},
        startsAt="2026-05-19T10:00:00Z",
    )


def test_gate_fires_for_high_p95_with_slow_trace():
    g = ContextGatherer()
    traces = [{"trace_id": "t1", "duration_ms": 1840}]
    assert g._should_fetch_deep_trace(_make_alert("HighP95Latency"), traces) is True


def test_gate_fires_for_kong_p95():
    g = ContextGatherer()
    traces = [{"trace_id": "t1", "duration_ms": 2300}]
    assert g._should_fetch_deep_trace(_make_alert("HighKongP95Latency"), traces) is True


def test_gate_skips_for_oom_alert():
    """Memory alerts don't benefit from span-level detail — skip the extra
    MCP call entirely."""
    g = ContextGatherer()
    traces = [{"trace_id": "t1", "duration_ms": 1840}]
    assert g._should_fetch_deep_trace(_make_alert("HighMemoryUsage"), traces) is False


def test_gate_skips_when_no_traces():
    g = ContextGatherer()
    assert g._should_fetch_deep_trace(_make_alert("HighP95Latency"), []) is False


def test_gate_skips_when_traces_too_short():
    """Trivially-fast traces aren't worth the round-trip."""
    g = ContextGatherer()
    traces = [{"trace_id": "t1", "duration_ms": 120}]
    assert g._should_fetch_deep_trace(_make_alert("HighP95Latency"), traces) is False


def test_pick_slowest_returns_max_duration_trace_id():
    g = ContextGatherer()
    traces = [
        {"trace_id": "fast", "duration_ms": 100},
        {"trace_id": "slow", "duration_ms": 2400},
        {"trace_id": "mid",  "duration_ms": 800},
    ]
    assert g._pick_slowest_trace_id(traces) == "slow"


def test_pick_slowest_returns_none_when_no_trace_ids():
    g = ContextGatherer()
    traces = [{"duration_ms": 1840}]  # missing trace_id
    assert g._pick_slowest_trace_id(traces) is None


# ----------------------------------------------------------------------
# 3. End-to-end — gather() makes the extra call when eligible
# ----------------------------------------------------------------------

@pytest.mark.asyncio
async def test_gather_fires_deep_trace_for_latency_alert(monkeypatch):
    """Stub all three pillar MCPs + the deep-trace MCP. Verify gather()
    calls /tools/get_trace exactly once and the sanitized result lands on
    ctx.deep_trace."""
    deep_trace_calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/tools/find_traces":
            return httpx.Response(200, json={
                "traces": [{"trace_id": "abc123", "duration_ms": 1840, "operations": ["GET /api/orders"]}],
                "count": 1,
            })
        if path == "/tools/get_trace":
            deep_trace_calls.append(dict(request.url.params))
            return httpx.Response(200, json={
                "trace_id": "abc123", "span_count": 2,
                "spans": [
                    {"span_id": "root", "operation": "GET /api/orders", "duration_ms": 1840,
                     "tags": {"http.target": "/api/orders/12345"}},
                    {"span_id": "db",   "operation": "SELECT", "duration_ms": 1620, "parent_span_id": "root",
                     "tags": {"db.statement": "SELECT * FROM orders WHERE customer_id = 999"}},
                ],
            })
        # Prometheus / Loki / tools/query_range / loki — return empties.
        return httpx.Response(200, json={"status": "success", "data": {"result": []}})

    class _MockClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    import httpx as _httpx
    monkeypatch.setattr(_httpx, "AsyncClient", _MockClient)

    g = ContextGatherer()
    alert = _make_alert("HighP95Latency")
    ctx = await g.gather(alert)
    await g.close()

    # The deep-trace MCP was called exactly once with the right trace_id.
    assert len(deep_trace_calls) == 1
    assert deep_trace_calls[0]["trace_id"] == "abc123"
    # The result is on ctx.deep_trace, with PII sanitized.
    assert ctx.deep_trace is not None
    spans = ctx.deep_trace["spans"]
    assert spans[1]["tags"]["db.statement"] == "SELECT * FROM orders WHERE customer_id = ?"
    assert spans[0]["tags"]["http.target"] == "/api/orders/:id"


@pytest.mark.asyncio
async def test_gather_skips_deep_trace_for_non_latency_alert(monkeypatch):
    """HighMemoryUsage shouldn't trigger deep trace — no extra call should fire."""
    deep_trace_calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/tools/get_trace":
            deep_trace_calls.append(1)
        return httpx.Response(200, json={"status": "success", "data": {"result": []}, "traces": []})

    class _MockClient(httpx.AsyncClient):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    import httpx as _httpx
    monkeypatch.setattr(_httpx, "AsyncClient", _MockClient)

    g = ContextGatherer()
    alert = _make_alert("HighMemoryUsage")
    ctx = await g.gather(alert)
    await g.close()

    assert deep_trace_calls == []
    assert ctx.deep_trace is None


# ----------------------------------------------------------------------
# 4. Rank-and-slim (2026-06-12) — the slowest DOWNSTREAM span must survive
#    the prompt char cap. Regression for: real frontend traces serialize to
#    ~14K chars in trace-tree order, the 6000-char cap kept only the first
#    ~8 (all frontend/proxy) spans, and the downstream culprit (e.g.
#    product-catalog) was truncated out — model could never name it.
# ----------------------------------------------------------------------
from app.context import _compact_deep_trace, _deep_trace_summary


def _tree_order_trace() -> dict:
    """Mimic a real Jaeger get_trace: root/proxy spans first, the slow
    downstream span buried deep in trace-tree order."""
    spans = [
        {"span_id": "a", "service": "frontend-proxy", "operation": "ingress", "duration_ms": 1320.0, "parent_span_id": None},
        {"span_id": "b", "service": "frontend", "operation": "GET /api/recommendations", "duration_ms": 1300.0, "parent_span_id": "a"},
    ]
    # 10 small frontend spans padding the tree (push downstream span past the cap)
    for i in range(10):
        spans.append({"span_id": f"f{i}", "service": "frontend", "operation": f"step-{i}", "duration_ms": 5.0, "parent_span_id": "b"})
    # the real culprit, deep in tree order
    spans.append({"span_id": "z", "service": "product-catalog", "operation": "GetProduct", "duration_ms": 1030.0, "parent_span_id": "b",
                  "tags": {"rpc.method": "GetProduct", "db.statement": "SELECT * FROM products WHERE id = 7"}})
    return {"trace_id": "t1", "span_count": len(spans), "spans": spans}


def test_compact_sorts_spans_by_duration_desc():
    out = _compact_deep_trace(_tree_order_trace())
    durs = [s["duration_ms"] for s in out["spans"]]
    assert durs == sorted(durs, reverse=True)


def test_compact_keeps_downstream_span_within_cap():
    import json
    out = _compact_deep_trace(_tree_order_trace())
    rendered = json.dumps(out, indent=2)[:6000]
    # The downstream culprit must appear in the first 6000 chars now.
    assert "product-catalog" in rendered
    # And it should be at/near the top (slowest non-root after the root span).
    svcs = [s["service"] for s in out["spans"]]
    assert "product-catalog" in svcs[:3]


def test_compact_trims_to_top_n_and_slims_fields():
    from app.context import _DEEP_TRACE_TOP_SPANS
    out = _compact_deep_trace(_tree_order_trace())
    assert out["spans_shown"] <= _DEEP_TRACE_TOP_SPANS
    # slimmed: only keep-listed fields plus optional tags
    for s in out["spans"]:
        assert set(s.keys()) <= {"service", "operation", "duration_ms", "status_code",
                                 "error", "parent_span_id", "span_id", "tags"}


def test_compact_preserves_descriptive_tags_only():
    out = _compact_deep_trace(_tree_order_trace())
    pc = [s for s in out["spans"] if s["service"] == "product-catalog"][0]
    assert pc["tags"].get("rpc.method") == "GetProduct"
    assert "db.statement" in pc["tags"]


def test_summary_names_slowest_and_downstream():
    # frontend is the alert's own edge tier — the downstream culprit is
    # product-catalog, and the summary must name it explicitly.
    s = _deep_trace_summary(_tree_order_trace(), own_services={"frontend"})
    assert "Slowest span:" in s
    assert "Slowest downstream dependency:" in s
    assert "product-catalog" in s
    assert "%" in s


def test_summary_empty_for_no_spans():
    assert _deep_trace_summary({"spans": []}) == ""
    assert _deep_trace_summary({}) == ""


def test_compact_handles_non_dict():
    assert _compact_deep_trace(None) is None
    assert _compact_deep_trace([]) == []
