"""Sprint 4 §14 W2 Wed — URL filter persistence on /dashboard/v2.

Acceptance from sprint4-status.html row "URL filter persistence + range
filter wire-up":

> Apply 2 filters + range=24h → refresh page → filters survive. Shareable URL.

This test module covers:
  * The parse/validate helper rejects bad input without 500-ing.
  * The store's get_decisions() honors the new filter kwargs (since_hours,
    verdict, severity, alert_name_like).
  * The dashboard_v2 route reads the query string, applies the filters in
    SQL, and reflects the active set in the HTML <select> options.
  * URL persistence — a refresh-with-query keeps the same render.
  * Filters compose (AND-combined).
  * Bad values fall back to default + don't 500.
"""
from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as app_main
from app.main import (
    _V2_FILTER_DEFAULT_RANGE,
    _V2_FILTER_FAMILIES,
    _V2_FILTER_RANGES,
    _parse_v2_filters,
    _render_v2_filter_bar,
)
from app.models import RCARecord
from app.rca_store import RCAStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def filter_store():
    """RCAStore pre-loaded with a mix of verdicts/severities/families and
    timestamps spanning 30 days so the range filter has something to bite."""
    db_path = os.path.join(tempfile.gettempdir(), "test_v2_filters.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()

    now = datetime.now(UTC).replace(tzinfo=None)
    # Recent (within 1h) — should be visible at any range.
    rows = [
        # (id, hours_ago, alert_name, severity, verdict, action)
        ("recent-esc-cpu",   0.2,  "HighCPUUsage",       "critical", "escalate", "emailed"),
        ("recent-esc-mem",   0.5,  "PodHighMemoryUsage", "critical", "escalate", "emailed"),
        ("recent-dis-cpu",   0.8,  "CpuSpike",           "warning",  "dismiss",  "suppressed"),
        # 5h ago — visible at 6h+ ranges.
        ("five-h-esc-lat",   5.0,  "HighP95Latency",     "warning",  "escalate", "emailed"),
        # 10h ago — visible at 24h+ ranges (not 6h).
        ("ten-h-dis-lat",    10.0, "KongLatencyHigh",    "warning",  "dismiss",  "suppressed"),
        # 3d ago — visible at 7d+ ranges (not 24h).
        ("three-d-esc-disk", 72.0, "DiskSpaceLow",       "warning",  "escalate", "emailed"),
        # 12d ago — visible at 15d range (not 7d).
        ("twelve-d-esc-net", 288.0, "NetworkSaturation", "critical", "escalate", "emailed"),
    ]
    for rid, hours_ago, name, sev, verdict, action in rows:
        rec = RCARecord(
            id=rid,
            timestamp=now - timedelta(hours=hours_ago),
            alert_name=name,
            alert_fingerprint=f"fp-{rid}",
            affected_service="spring-boot",
            severity=sev,
            triage_decision="investigate",
            llm_verdict=verdict,
            action_taken=action,
            investigation_duration_ms=1500,
        )
        await s.save_decision(rec)
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest_asyncio.fixture
async def filter_client(filter_store):
    """ASGI client wired to the filter_store fixture."""
    saved = app_main._store
    app_main._store = filter_store
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app_main._store = saved


# ---------------------------------------------------------------------------
# _parse_v2_filters — input validation unit tests
# ---------------------------------------------------------------------------

def test_parse_filters_empty_returns_defaults():
    """No query params → every filter is None, range is the default."""
    f = _parse_v2_filters(None, None, None, None, None)
    assert f["verdict"] is None
    assert f["severity"] is None
    assert f["family"] is None
    assert f["range"] == _V2_FILTER_DEFAULT_RANGE
    assert f["q"] == ""
    assert f["active_count"] == 0
    # The default range resolves to a positive since_hours.
    assert f["since_hours"] == _V2_FILTER_RANGES[_V2_FILTER_DEFAULT_RANGE]


def test_parse_filters_all_set_compose():
    f = _parse_v2_filters("ESCALATE", "Critical", "cpu", "24h", "  search term  ")
    assert f["verdict"] == "escalate"
    assert f["severity"] == "critical"
    assert f["family"] == "cpu"
    assert f["range"] == "24h"
    assert f["since_hours"] == 24.0
    assert f["q"] == "search term"  # stripped
    assert f["active_count"] == 5
    assert f["family_substring"] == _V2_FILTER_FAMILIES["cpu"]


def test_parse_filters_unknown_verdict_falls_back():
    f = _parse_v2_filters("DELETE_ALL_THE_THINGS", None, None, None, None)
    assert f["verdict"] is None
    assert f["active_count"] == 0


def test_parse_filters_unknown_family_falls_back():
    f = _parse_v2_filters(None, None, "DROP TABLE", None, None)
    assert f["family"] is None
    assert f["family_substring"] is None


def test_parse_filters_unknown_range_falls_back_to_default():
    f = _parse_v2_filters(None, None, None, "99y", None)
    assert f["range"] == _V2_FILTER_DEFAULT_RANGE
    assert f["since_hours"] == _V2_FILTER_RANGES[_V2_FILTER_DEFAULT_RANGE]


def test_parse_filters_q_clamped_to_200_chars():
    long_q = "x" * 1000
    f = _parse_v2_filters(None, None, None, None, long_q)
    assert len(f["q"]) == 200


def test_parse_filters_range_default_is_not_counted_active():
    """The default range shouldn't bump active_count — otherwise the
    "active filters" badge would read >=1 even on a clean load."""
    f = _parse_v2_filters(None, None, None, _V2_FILTER_DEFAULT_RANGE, None)
    assert f["active_count"] == 0


def test_parse_filters_range_24h_counts_as_active():
    f = _parse_v2_filters(None, None, None, "24h", None)
    assert f["range"] == "24h"
    assert f["active_count"] == 1


# ---------------------------------------------------------------------------
# Store — get_decisions kwargs unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_store_since_hours_filters_by_hours(filter_store):
    """since_hours=1 → only rows within the last hour come back."""
    rows = await filter_store.get_decisions(limit=100, since_hours=1.0)
    ids = {r["id"] for r in rows}
    assert "recent-esc-cpu" in ids
    assert "recent-esc-mem" in ids
    assert "recent-dis-cpu" in ids
    # 5h-ago must be excluded by a 1h window
    assert "five-h-esc-lat" not in ids


@pytest.mark.asyncio
async def test_store_since_hours_24h(filter_store):
    rows = await filter_store.get_decisions(limit=100, since_hours=24.0)
    ids = {r["id"] for r in rows}
    # 5h and 10h rows should be in
    assert "five-h-esc-lat" in ids
    assert "ten-h-dis-lat" in ids
    # 3d row should not
    assert "three-d-esc-disk" not in ids


@pytest.mark.asyncio
async def test_store_verdict_filter(filter_store):
    rows = await filter_store.get_decisions(limit=100, since_hours=24.0 * 30, verdict="escalate")
    ids = {r["id"] for r in rows}
    assert "recent-esc-cpu" in ids
    assert "recent-esc-mem" in ids
    # Dismiss rows must not appear
    assert "recent-dis-cpu" not in ids
    assert "ten-h-dis-lat" not in ids


@pytest.mark.asyncio
async def test_store_severity_filter(filter_store):
    rows = await filter_store.get_decisions(limit=100, since_hours=24.0 * 30, severity="critical")
    ids = {r["id"] for r in rows}
    assert "recent-esc-cpu" in ids
    assert "recent-esc-mem" in ids
    # Warnings must not appear
    assert "recent-dis-cpu" not in ids
    assert "five-h-esc-lat" not in ids


@pytest.mark.asyncio
async def test_store_alert_name_like_filter(filter_store):
    """LIKE %CPU% catches HighCPUUsage and CpuSpike (case-insensitive)."""
    rows = await filter_store.get_decisions(
        limit=100, since_hours=24.0 * 30, alert_name_like="CPU",
    )
    ids = {r["id"] for r in rows}
    assert "recent-esc-cpu" in ids
    assert "recent-dis-cpu" in ids
    # Latency / memory / disk rows must not appear
    assert "recent-esc-mem" not in ids
    assert "five-h-esc-lat" not in ids


@pytest.mark.asyncio
async def test_store_filters_compose_and(filter_store):
    """verdict=escalate AND severity=critical AND family=CPU → just one row."""
    rows = await filter_store.get_decisions(
        limit=100,
        since_hours=24.0 * 30,
        verdict="escalate",
        severity="critical",
        alert_name_like="CPU",
    )
    ids = {r["id"] for r in rows}
    assert ids == {"recent-esc-cpu"}


@pytest.mark.asyncio
async def test_store_count_decisions_honors_new_filters(filter_store):
    """count_decisions() must apply the same filters as get_decisions()."""
    n_all = await filter_store.count_decisions(since_hours=24.0 * 30)
    n_esc = await filter_store.count_decisions(
        since_hours=24.0 * 30, verdict="escalate",
    )
    assert n_all == 7
    assert n_esc == 5  # 5 escalate rows in the fixture


# ---------------------------------------------------------------------------
# /dashboard/v2 route — integration tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_v2_empty_query_renders_default(filter_client):
    """No query params → 200 + filter bar renders with defaults selected."""
    resp = await filter_client.get("/dashboard/v2")
    assert resp.status_code == 200
    body = resp.text
    # Filter bar present
    assert 'data-v2-filter-bar' in body
    # The default range is the selected one
    assert f'<option value="{_V2_FILTER_DEFAULT_RANGE}" selected>' in body
    # "any" is selected for verdict + severity + family (active count = 0)
    assert body.count('<option value="" selected>') >= 3


@pytest.mark.asyncio
async def test_v2_verdict_filter_restricts_payload(filter_client):
    """?verdict=escalate → the CIRES_ALERTS payload contains only escalate rows."""
    resp = await filter_client.get("/dashboard/v2?verdict=escalate&range=15d")
    assert resp.status_code == 200
    body = resp.text
    # The escalate option is selected in the verdict <select>
    assert '<option value="escalate" selected>' in body
    # The dismiss-only fixture rows must not appear by id in the embedded JSON
    assert "recent-dis-cpu" not in body
    assert "ten-h-dis-lat" not in body
    # An escalate row IS visible
    assert "recent-esc-cpu" in body


@pytest.mark.asyncio
async def test_v2_range_24h_excludes_older_rows(filter_client):
    """?range=24h → the 3d / 12d fixture rows are not in the payload."""
    resp = await filter_client.get("/dashboard/v2?range=24h")
    assert resp.status_code == 200
    body = resp.text
    assert '<option value="24h" selected>' in body
    # Recent / 5h / 10h rows must appear
    assert "recent-esc-cpu" in body
    assert "ten-h-dis-lat" in body
    # 3d / 12d rows must NOT
    assert "three-d-esc-disk" not in body
    assert "twelve-d-esc-net" not in body


@pytest.mark.asyncio
async def test_v2_multiple_filters_compose(filter_client):
    """?verdict=escalate&severity=critical&family=cpu&range=24h → 1 row."""
    resp = await filter_client.get(
        "/dashboard/v2?verdict=escalate&severity=critical&family=cpu&range=24h"
    )
    assert resp.status_code == 200
    body = resp.text
    # Only the matching row is in the payload
    assert "recent-esc-cpu" in body
    assert "recent-esc-mem" not in body  # different family
    assert "recent-dis-cpu" not in body  # different verdict
    assert "five-h-esc-lat" not in body  # different severity + family


@pytest.mark.asyncio
async def test_v2_bad_values_dont_500(filter_client):
    """Crafted URL with junk values → 200, fall back to default render."""
    resp = await filter_client.get(
        "/dashboard/v2?verdict=DROP&severity='OR'1=1&family=../../etc/passwd&range=999d"
    )
    assert resp.status_code == 200
    body = resp.text
    # All filters fell back: "any" selected on the three select boxes
    # and the default range selected.
    assert f'<option value="{_V2_FILTER_DEFAULT_RANGE}" selected>' in body
    # No SQL-injection echo bypassing the escape — the junk strings should
    # NOT round-trip into the verdict/severity <option selected> markers.
    assert '<option value="DROP" selected>' not in body
    assert "OR\"1=1" not in body


@pytest.mark.asyncio
async def test_v2_html_reflects_active_filter_selections(filter_client):
    """The selected <option> markers in the rendered HTML must match the URL."""
    resp = await filter_client.get(
        "/dashboard/v2?verdict=dismiss&severity=warning&family=memory&range=7d"
    )
    body = resp.text
    assert '<option value="dismiss" selected>' in body
    assert '<option value="warning" selected>' in body
    assert '<option value="memory" selected>' in body
    assert '<option value="7d" selected>' in body


@pytest.mark.asyncio
async def test_v2_search_value_round_trips(filter_client):
    """?q=... renders the value back in the search input (XSS-escaped)."""
    resp = await filter_client.get("/dashboard/v2?q=spring-boot")
    body = resp.text
    assert 'value="spring-boot"' in body


@pytest.mark.asyncio
async def test_v2_search_value_escapes_html(filter_client):
    """Crafted search value must be HTML-escaped — no script injection."""
    resp = await filter_client.get(
        "/dashboard/v2?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
    )
    body = resp.text
    # The raw < / > must NOT survive untouched inside the value="..."
    assert 'value="<script>alert(1)</script>"' not in body
    # The escaped form IS expected
    assert "&lt;script&gt;" in body


@pytest.mark.asyncio
async def test_v2_url_persistence_refresh_identical_render(filter_client):
    """Calling the same URL twice must produce a structurally identical
    filter bar — the acceptance criterion's 'refresh page → filters
    survive' check."""
    url = "/dashboard/v2?verdict=escalate&severity=critical&family=cpu&range=24h"
    r1 = await filter_client.get(url)
    r2 = await filter_client.get(url)
    assert r1.status_code == r2.status_code == 200
    # Extract the form bar from each body and compare. They must match
    # (apart from time-varying bits which the filter bar doesn't contain).
    def _bar(body: str) -> str:
        start = body.index('<form class="v2-filter-bar"')
        end = body.index("</form>", start)
        return body[start:end]
    assert _bar(r1.text) == _bar(r2.text)


@pytest.mark.asyncio
async def test_v2_filter_form_uses_method_get(filter_client):
    """The form must use method=get so filters land in the URL — the
    bookmark/share affordance is the whole point of this story."""
    resp = await filter_client.get("/dashboard/v2")
    body = resp.text
    assert 'method="get"' in body
    assert 'action="/dashboard/v2"' in body


@pytest.mark.asyncio
async def test_v2_filter_form_has_clear_affordance(filter_client):
    """The 'clear all' link routes back to the unfiltered page."""
    resp = await filter_client.get("/dashboard/v2?verdict=escalate")
    body = resp.text
    # Anchor that resets to /dashboard/v2 (no query)
    assert 'href="/dashboard/v2"' in body


@pytest.mark.asyncio
async def test_v2_filters_payload_exposed_to_js(filter_client):
    """window.CIRES_FILTERS is the React layer's read of the active set."""
    resp = await filter_client.get("/dashboard/v2?verdict=escalate&range=24h")
    body = resp.text
    assert "window.CIRES_FILTERS" in body
    assert '"verdict": "escalate"' in body
    assert '"range": "24h"' in body


# ---------------------------------------------------------------------------
# _render_v2_filter_bar — direct render-helper smoke
# ---------------------------------------------------------------------------

def test_filter_bar_renders_with_no_active_filters():
    f = _parse_v2_filters(None, None, None, None, None)
    html = _render_v2_filter_bar(f, page=1, size=20)
    assert "<form" in html
    assert 'method="get"' in html
    # "any" option must be selected on each filterable <select>
    assert html.count('<option value="" selected>') >= 3


def test_filter_bar_marks_active_options_selected():
    f = _parse_v2_filters("escalate", "critical", "cpu", "24h", None)
    html = _render_v2_filter_bar(f, page=1, size=20)
    assert '<option value="escalate" selected>' in html
    assert '<option value="critical" selected>' in html
    assert '<option value="cpu" selected>' in html
    assert '<option value="24h" selected>' in html
