"""Phase 3.A.KPI — tests for /dashboard/v2/kpi and app.kpi_queries.

Covers:
  * compute_kpis() returns all 8 expected keys with sensible empty-DB defaults
  * The route 200s with a non-empty body
  * Each KPI label appears in the rendered HTML
  * Numeric KPIs render actual digits (regex \\d+)
  * Empty-DB path: route still 200s, no 500
  * Edge case: 0 emails in 24h displays "0 / day" (not "None")
  * Single-decision case: numbers track the inserted row
"""
from __future__ import annotations

import os
import re
import tempfile
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as app_main
from app.kpi_queries import compute_kpis
from app.models import RCARecord
from app.rca_store import RCAStore


# Six "live" KPI labels that must appear on the rendered page. The 2 static
# KPIs (mcp_invariant, tests_passing) round out the 2x4 grid but the
# acceptance criterion is "6+ real numbers".
LIVE_KPI_TITLES = [
    "Emails sent",
    "False-positive rate",
    "Median latency",
    "Cheap-path absorbed",
    "Archetype coverage",
    "GPU status",
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def empty_store():
    """Fresh RCAStore with no rows — exercises the empty-DB code path."""
    db_path = os.path.join(tempfile.gettempdir(), "test_kpi_empty.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest_asyncio.fixture
async def populated_store():
    """RCAStore pre-loaded with rows that exercise every KPI."""
    db_path = os.path.join(tempfile.gettempdir(), "test_kpi_populated.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()

    now = datetime.now(UTC).replace(tzinfo=None)
    # 3 emailed alerts in the last 24h — covers KPI 1
    for i in range(3):
        rec = RCARecord(
            id=f"emailed-{i}",
            timestamp=now - timedelta(hours=i + 1),
            alert_name="HighP95Latency" if i < 2 else "PodHighMemoryUsage",
            alert_fingerprint=f"fp-emailed-{i}",
            affected_service="spring-boot",
            severity="critical",
            triage_decision="investigate",
            llm_verdict="escalate",
            action_taken="emailed",
            investigation_duration_ms=2000 + i * 500,
        )
        await s.save_decision(rec)

    # 2 cheap-path suppressions in the last 24h — covers KPI 4
    for i, td in enumerate(("suppressed_duplicate", "triage_suppressed")):
        rec = RCARecord(
            id=f"cheap-{i}",
            timestamp=now - timedelta(hours=2),
            alert_name="CPUSpike",
            alert_fingerprint=f"fp-cheap-{i}",
            affected_service="kong",
            severity="warning",
            triage_decision=td,
            action_taken="suppressed",
            investigation_duration_ms=0,
        )
        await s.save_decision(rec)

    # Operator rated one as FP (verdict_was_right='no') and one as good
    # — covers KPI 2 (false-positive rate). Uses the v2 rate path.
    await s.record_v2_feedback(
        feedback_id="fb-fp",
        decision_id="emailed-0",
        rating="no",
        verdict_was_right="no",
        action_was_right="no",
        actual_cause="It was a deploy",
        tags=["unhelpful"],
        notes="false positive",
        rater="lina",
    )
    await s.record_v2_feedback(
        feedback_id="fb-good",
        decision_id="emailed-1",
        rating="yes",
        verdict_was_right="yes",
        action_was_right="yes",
        actual_cause=None,
        tags=[],
        notes="nailed it",
        rater="lina",
    )

    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest_asyncio.fixture
async def kpi_app_client(populated_store):
    """ASGI test client with main._store wired to the populated fixture.

    Lifespan doesn't run under ASGITransport, so we monkey-patch the
    module-level _store reference the route reads from. Restore on exit
    so other tests are not affected.
    """
    saved = app_main._store
    app_main._store = populated_store
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app_main._store = saved


@pytest_asyncio.fixture
async def empty_app_client(empty_store):
    """ASGI test client wired to the empty store — empty-DB regression path."""
    saved = app_main._store
    app_main._store = empty_store
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app_main._store = saved


# ---------------------------------------------------------------------------
# compute_kpis() — kpi_queries module unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_compute_kpis_returns_all_expected_keys(empty_store):
    kpis = await compute_kpis(empty_store)
    expected = {
        "emails_per_day",
        "false_positive_rate",
        "median_latency",
        "cheap_path_pct",
        "archetype_coverage",
        "gpu_util",
        "mcp_invariant",
        "tests_passing",
    }
    assert set(kpis.keys()) == expected
    # Every KPI must carry the label + sub fields the template reads.
    for k, v in kpis.items():
        assert "label" in v, f"KPI {k} missing 'label'"
        assert "sub" in v, f"KPI {k} missing 'sub'"


@pytest.mark.asyncio
async def test_empty_db_emails_per_day_renders_zero_slash_day(empty_store):
    """Edge case from the spec: 0 emails in 24h must render '0 / day', not None."""
    kpis = await compute_kpis(empty_store)
    assert kpis["emails_per_day"]["value"] == 0
    assert kpis["emails_per_day"]["label"] == "0 / day"
    assert "None" not in kpis["emails_per_day"]["label"]
    assert "None" not in kpis["emails_per_day"]["sub"]


@pytest.mark.asyncio
async def test_empty_db_false_positive_rate_renders_na(empty_store):
    """With zero rated alerts, FP rate must render 'n/a' (not div-by-zero)."""
    kpis = await compute_kpis(empty_store)
    assert kpis["false_positive_rate"]["label"] == "n/a"


@pytest.mark.asyncio
async def test_populated_emails_per_day_counts_emailed_rows(populated_store):
    """Three emailed rows in the last 24h → '3 / day'."""
    kpis = await compute_kpis(populated_store)
    assert kpis["emails_per_day"]["value"] == 3
    assert kpis["emails_per_day"]["label"] == "3 / day"


@pytest.mark.asyncio
async def test_populated_false_positive_rate(populated_store):
    """One FP + one good = 50% over a denom of 2 rated alerts."""
    kpis = await compute_kpis(populated_store)
    fp = kpis["false_positive_rate"]
    assert fp["denom"] == 2
    assert fp["value"] == 1
    assert fp["label"].startswith("50")  # 50.0%
    assert "2 operator-rated" in fp["sub"]


@pytest.mark.asyncio
async def test_populated_cheap_path_counts_suppression_decisions(populated_store):
    """3 emailed + 2 cheap-path = 5 total; cheap path 2/5 = 40%."""
    kpis = await compute_kpis(populated_store)
    cp = kpis["cheap_path_pct"]
    assert cp["value"] == 2
    assert cp["denom"] == 5
    # Format is "40%" with no decimals (cards stripped) — assert prefix
    assert cp["label"].startswith("40")


@pytest.mark.asyncio
async def test_populated_archetype_coverage_distinct_alert_names(populated_store):
    """Three distinct alert names: HighP95Latency, PodHighMemoryUsage, CPUSpike."""
    kpis = await compute_kpis(populated_store)
    assert kpis["archetype_coverage"]["value"] == 3
    assert kpis["archetype_coverage"]["label"] == "3"
    # Sub-line lists the top alert names by frequency.
    assert "HighP95Latency" in kpis["archetype_coverage"]["sub"]


@pytest.mark.asyncio
async def test_populated_median_latency_only_counts_investigate_rows(populated_store):
    """Cheap-path suppressions have 0 duration and must be excluded.

    With investigation_duration_ms ∈ {2000, 2500, 3000} the median = 2500 ms
    → renders as '2.5 s'.
    """
    kpis = await compute_kpis(populated_store)
    lat = kpis["median_latency"]
    assert lat["value"] == 2500
    assert lat["label"] == "2.5 s"
    assert "p95" in lat["sub"]


@pytest.mark.asyncio
async def test_gpu_util_unreachable_ollama_returns_na(empty_store):
    """No reachable Ollama → graceful 'n/a' fallback, never 500."""
    kpis = await compute_kpis(empty_store, ollama_url="http://127.0.0.1:1")
    assert kpis["gpu_util"]["label"] == "n/a"


@pytest.mark.asyncio
async def test_gpu_util_no_url_returns_sf12_placeholder(empty_store):
    """No URL → renders the SF-12 wiring hint per spec."""
    kpis = await compute_kpis(empty_store, ollama_url=None)
    assert kpis["gpu_util"]["label"] == "n/a"
    assert "SF-12" in kpis["gpu_util"]["sub"]


@pytest.mark.asyncio
async def test_compute_kpis_none_store_returns_empty_kpis():
    """If the store is None (lifespan-not-run path), KPIs render as zero."""
    kpis = await compute_kpis(None)
    assert kpis["emails_per_day"]["value"] == 0
    assert "0 / day" in kpis["emails_per_day"]["label"]


# ---------------------------------------------------------------------------
# /dashboard/v2/kpi — route integration tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_kpi_route_returns_200_with_body(kpi_app_client):
    resp = await kpi_app_client.get("/dashboard/v2/kpi")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert len(resp.text) > 500


@pytest.mark.asyncio
async def test_kpi_route_renders_all_six_live_kpi_titles(kpi_app_client):
    resp = await kpi_app_client.get("/dashboard/v2/kpi")
    body = resp.text
    for title in LIVE_KPI_TITLES:
        assert title in body, f"KPI title {title!r} missing from rendered page"


@pytest.mark.asyncio
async def test_kpi_route_renders_digits_in_each_card(kpi_app_client):
    """Every card must render at least one digit somewhere — proves the
    KPI values aren't literal placeholders like '—'.
    """
    resp = await kpi_app_client.get("/dashboard/v2/kpi")
    body = resp.text
    # Split the body on the card class so we can assert per-card.
    parts = body.split('class="kpi-card kpi-card--')
    # First element is the prefix before any card; the rest are the cards.
    assert len(parts) >= 7  # 6 live + 2 static = 8 cards, so 9 parts after split
    for i, card_html in enumerate(parts[1:], start=1):
        # Each card needs to contain at least one digit somewhere — either
        # as the big value or in the sub-line.
        assert re.search(r"\d+", card_html), (
            f"Card #{i} has no digits — value rendered as a non-numeric placeholder"
        )


@pytest.mark.asyncio
async def test_kpi_route_has_auto_refresh_meta(kpi_app_client):
    resp = await kpi_app_client.get("/dashboard/v2/kpi")
    body = resp.text
    # 60s refresh — protects SQLite from query churn per spec.
    assert 'http-equiv="refresh"' in body
    assert 'content="60"' in body


@pytest.mark.asyncio
async def test_kpi_route_includes_sidebar_link_back_to_v2(kpi_app_client):
    """Sidebar surfaces a clickable link back to /dashboard/v2."""
    resp = await kpi_app_client.get("/dashboard/v2/kpi")
    assert 'href="/dashboard/v2"' in resp.text


@pytest.mark.asyncio
async def test_kpi_route_empty_db_still_200s(empty_app_client):
    """Regression — empty DB must not 500 the route."""
    resp = await empty_app_client.get("/dashboard/v2/kpi")
    assert resp.status_code == 200
    # And the "0 / day" emails formatting per the spec edge case.
    assert "0 / day" in resp.text
    # And no Python-rendering bleed-through (None, dict reprs, traceback).
    assert "None" not in resp.text
    assert "Traceback" not in resp.text


@pytest.mark.asyncio
async def test_kpi_route_renders_emails_per_day_value_3(kpi_app_client):
    """Smoke test: the populated fixture's '3 / day' must appear in the
    rendered card so we know the live-data pipeline actually drives the
    template, not a hardcoded constant.
    """
    resp = await kpi_app_client.get("/dashboard/v2/kpi")
    assert "3 / day" in resp.text


@pytest.mark.asyncio
async def test_kpi_route_renders_archetype_top_alerts(kpi_app_client):
    """Sub-line under archetype coverage must enumerate top alert names."""
    resp = await kpi_app_client.get("/dashboard/v2/kpi")
    # HighP95Latency appears twice in the populated fixture, so it should
    # rank #1 by frequency in the top-5 list.
    assert "HighP95Latency" in resp.text


@pytest.mark.asyncio
async def test_kpi_route_title_marker(kpi_app_client):
    """The page title and header must announce the KPI surface."""
    resp = await kpi_app_client.get("/dashboard/v2/kpi")
    body = resp.text
    # Page <title>
    assert "KPI" in body
    # Header H1-equivalent
    assert "Platform health" in body
