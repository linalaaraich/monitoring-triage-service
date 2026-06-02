"""Tests for /dashboard/alerts — read-only per-alertname summary.

Covers:
  * RCAStore.get_alert_summary() returns the expected shape on an empty
    store (== []) and on a populated store (per-alertname rollups with
    fires / emails / dominant_verdict / dominant_severity / last_fire /
    email_ratio / was_gated).
  * Route 200s with non-empty HTML on both populated and empty stores.
  * Empty-DB case surfaces the "no alerts seen yet" affordance instead
    of 500ing.
  * Noisy-row highlight class actually applies — rows where the email
    ratio exceeds 0.5 render with class="alerts-row alerts-row--noisy".
  * The explainer block content is present (operator-tuning pointer).
  * Honest annotation reporting — pages with a gate-tripped alert render
    the "annotation not persisted — check Grafana rule" pointer rather
    than fabricating gate parameters that aren't on the row.
"""
from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as app_main
from app.models import RCARecord
from app.rca_store import RCAStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def empty_store():
    """Fresh RCAStore with no rows — exercises the empty-DB code path."""
    db_path = os.path.join(tempfile.gettempdir(), "test_v2_alerts_empty.db")
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
    """RCAStore pre-loaded with a mix of alerts that exercise every column:

      - HighP95Latency: 4 fires, 3 emailed → ratio 0.75, NOISY
      - MediumCpuUsage: 5 fires, 1 emailed, 2 gated → ratio 0.2, GATED
      - QuietAlert:     2 fires, 0 emailed → ratio 0.0, NOT noisy
    """
    db_path = os.path.join(tempfile.gettempdir(), "test_v2_alerts_populated.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()

    now = datetime.now(UTC).replace(tzinfo=None)

    # HighP95Latency — noisy candidate (3 emails / 4 fires = 0.75)
    for i in range(3):
        await s.save_decision(RCARecord(
            id=f"hlp-emailed-{i}",
            timestamp=now - timedelta(hours=i + 1),
            alert_name="HighP95Latency",
            alert_fingerprint=f"fp-hlp-{i}",
            affected_service="spring-boot",
            severity="critical",
            triage_decision="investigate",
            llm_verdict="escalate",
            action_taken="emailed",
        ))
    await s.save_decision(RCARecord(
        id="hlp-suppressed-0",
        timestamp=now - timedelta(hours=4),
        alert_name="HighP95Latency",
        alert_fingerprint="fp-hlp-3",
        affected_service="spring-boot",
        severity="critical",
        triage_decision="suppressed_duplicate",
        llm_verdict=None,
        action_taken="suppressed",
    ))

    # MediumCpuUsage — gated, NOT noisy (1 email / 5 fires = 0.2)
    await s.save_decision(RCARecord(
        id="mcpu-emailed-0",
        timestamp=now - timedelta(hours=2),
        alert_name="MediumCpuUsage",
        alert_fingerprint="fp-mcpu-0",
        affected_service="kong",
        severity="warning",
        triage_decision="investigate",
        llm_verdict="escalate",
        action_taken="emailed",
    ))
    for i in range(2):
        await s.save_decision(RCARecord(
            id=f"mcpu-gated-{i}",
            timestamp=now - timedelta(hours=i + 3),
            alert_name="MediumCpuUsage",
            alert_fingerprint="fp-mcpu-gated",
            affected_service="kong",
            severity="warning",
            triage_decision="recurrence_gated_pre_llm",
            llm_verdict=None,
            action_taken="suppressed",
        ))
    for i in range(2):
        await s.save_decision(RCARecord(
            id=f"mcpu-dismiss-{i}",
            timestamp=now - timedelta(hours=i + 5),
            alert_name="MediumCpuUsage",
            alert_fingerprint=f"fp-mcpu-dismiss-{i}",
            affected_service="kong",
            severity="warning",
            triage_decision="investigate",
            llm_verdict="dismiss",
            action_taken="logged",
        ))

    # QuietAlert — 2 fires, no emails (ratio 0.0)
    for i in range(2):
        await s.save_decision(RCARecord(
            id=f"quiet-{i}",
            timestamp=now - timedelta(hours=i + 1),
            alert_name="QuietAlert",
            alert_fingerprint=f"fp-quiet-{i}",
            affected_service="redis",
            severity="info",
            triage_decision="triage_suppressed",
            llm_verdict="dismiss",
            action_taken="logged",
        ))

    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest_asyncio.fixture
async def alerts_app_client(populated_store):
    """ASGI client wired to the populated store."""
    saved = app_main._store
    app_main._store = populated_store
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app_main._store = saved


@pytest_asyncio.fixture
async def empty_app_client(empty_store):
    """ASGI client wired to the empty store — empty-DB path."""
    saved = app_main._store
    app_main._store = empty_store
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app_main._store = saved


# ---------------------------------------------------------------------------
# get_alert_summary() — store-level shape tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_alert_summary_empty_store_returns_empty_list(empty_store):
    """An empty store must return [] — not None, not raise."""
    rows = await empty_store.get_alert_summary(days=7)
    assert rows == []


@pytest.mark.asyncio
async def test_get_alert_summary_returns_expected_shape(populated_store):
    """Every row must carry the eight documented fields."""
    rows = await populated_store.get_alert_summary(days=7)
    assert len(rows) == 3
    required = {
        "alert_name", "fires", "emails", "dominant_verdict",
        "dominant_severity", "last_fire", "email_ratio", "was_gated",
    }
    for r in rows:
        missing = required - set(r.keys())
        assert not missing, f"row {r.get('alert_name')!r} missing fields: {missing}"


@pytest.mark.asyncio
async def test_get_alert_summary_counts_and_ratios(populated_store):
    """Per-alertname rollup must aggregate fires + emails correctly."""
    rows = await populated_store.get_alert_summary(days=7)
    by_name = {r["alert_name"]: r for r in rows}

    # HighP95Latency: 4 fires, 3 emailed
    hlp = by_name["HighP95Latency"]
    assert hlp["fires"] == 4
    assert hlp["emails"] == 3
    assert hlp["email_ratio"] == pytest.approx(0.75)
    assert hlp["dominant_verdict"] == "escalate"
    assert hlp["dominant_severity"] == "critical"
    assert hlp["was_gated"] is False

    # MediumCpuUsage: 5 fires, 1 emailed, 2 gated, dominant verdict dismiss (2 vs 1 escalate)
    mcpu = by_name["MediumCpuUsage"]
    assert mcpu["fires"] == 5
    assert mcpu["emails"] == 1
    assert mcpu["email_ratio"] == pytest.approx(0.2)
    assert mcpu["was_gated"] is True
    assert mcpu["dominant_verdict"] == "dismiss"
    assert mcpu["dominant_severity"] == "warning"

    # QuietAlert: 2 fires, 0 emails, ratio 0.0
    quiet = by_name["QuietAlert"]
    assert quiet["fires"] == 2
    assert quiet["emails"] == 0
    assert quiet["email_ratio"] == 0.0
    assert quiet["was_gated"] is False


@pytest.mark.asyncio
async def test_get_alert_summary_sorted_by_fires_desc(populated_store):
    """Rows must come back sorted by total fires DESC."""
    rows = await populated_store.get_alert_summary(days=7)
    fires = [r["fires"] for r in rows]
    assert fires == sorted(fires, reverse=True)


@pytest.mark.asyncio
async def test_get_alert_summary_excludes_rows_outside_window(empty_store):
    """A row older than `days` must NOT show up."""
    old_ts = (datetime.now(UTC).replace(tzinfo=None) - timedelta(days=30))
    await empty_store.save_decision(RCARecord(
        id="old-row",
        timestamp=old_ts,
        alert_name="AncientAlert",
        alert_fingerprint="fp-old",
        affected_service="legacy",
        severity="warning",
        triage_decision="investigate",
        llm_verdict="escalate",
        action_taken="emailed",
    ))
    rows = await empty_store.get_alert_summary(days=7)
    assert rows == []


# ---------------------------------------------------------------------------
# /dashboard/alerts — route integration tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_alerts_route_returns_200_with_body(alerts_app_client):
    resp = await alerts_app_client.get("/dashboard/alerts")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert len(resp.text) > 500


@pytest.mark.asyncio
async def test_alerts_route_renders_each_alert_name(alerts_app_client):
    resp = await alerts_app_client.get("/dashboard/alerts")
    body = resp.text
    for name in ("HighP95Latency", "MediumCpuUsage", "QuietAlert"):
        assert name in body, f"alert name {name!r} missing from rendered page"


@pytest.mark.asyncio
async def test_alerts_route_noisy_row_class_applies(alerts_app_client):
    """The row for HighP95Latency (ratio 0.75 > 0.5) must carry the
    --noisy modifier; the QuietAlert row must not.
    """
    resp = await alerts_app_client.get("/dashboard/alerts")
    body = resp.text
    assert "alerts-row--noisy" in body

    # Find the HighP95Latency row and assert it carries the noisy class.
    # Split on </tr> so each chunk is one row + its trailing markup.
    rows = body.split("</tr>")
    hlp_rows = [r for r in rows if "HighP95Latency" in r]
    assert hlp_rows, "HighP95Latency row not found in rendered HTML"
    assert any("alerts-row--noisy" in r for r in hlp_rows), (
        "HighP95Latency (ratio 0.75) should render with alerts-row--noisy"
    )

    # The QuietAlert row (ratio 0.0) must NOT carry the noisy class.
    quiet_rows = [r for r in rows if "QuietAlert" in r]
    assert quiet_rows, "QuietAlert row not found"
    assert not any("alerts-row--noisy" in r for r in quiet_rows), (
        "QuietAlert (ratio 0.0) must not render with alerts-row--noisy"
    )


@pytest.mark.asyncio
async def test_alerts_route_explainer_block_present(alerts_app_client):
    """The explainer block must surface the Ansible tuning pointer."""
    resp = await alerts_app_client.get("/dashboard/alerts")
    body = resp.text
    # Spec: must reference the Ansible template path + the recurrence_gate
    # annotation format + the re-provision command + the db79ee7 reference.
    assert "alertrules.yml.j2" in body
    assert "recurrence_gate" in body
    assert "pre_llm=N,llm_dismiss=M,window=2h" in body
    assert "monitoring.yml --tags monitoring" in body
    assert "db79ee7" in body
    assert "MediumCpuUsage" in body  # referenced in the tuning callout


@pytest.mark.asyncio
async def test_alerts_route_honest_annotation_reporting(alerts_app_client):
    """When a row was gate-tripped, the cell must surface the honest
    'annotation not persisted — check Grafana rule' pointer rather
    than fabricating the gate parameters.
    """
    resp = await alerts_app_client.get("/dashboard/alerts")
    body = resp.text
    # MediumCpuUsage was gated → the page should carry the honest pointer.
    assert "annotation not persisted" in body
    assert "check Grafana rule" in body


@pytest.mark.asyncio
async def test_alerts_route_empty_db_still_200s(empty_app_client):
    """Regression — empty DB must not 500 the route."""
    resp = await empty_app_client.get("/dashboard/alerts")
    assert resp.status_code == 200
    # And the empty-affordance text per the spec.
    assert "no alerts seen yet" in resp.text
    # No bleed-through.
    assert "Traceback" not in resp.text


@pytest.mark.asyncio
async def test_alerts_route_has_auto_refresh_meta(alerts_app_client):
    resp = await alerts_app_client.get("/dashboard/alerts")
    body = resp.text
    assert 'http-equiv="refresh"' in body
    assert 'content="60"' in body


@pytest.mark.asyncio
async def test_alerts_route_sidebar_marks_alerts_active(alerts_app_client):
    """The sidebar's Alerts item must render as the active item on this page."""
    resp = await alerts_app_client.get("/dashboard/alerts")
    body = resp.text
    # Server-rendered sidebar carries the --active modifier on the active item.
    assert 'kpi-sidebar__item--active" href="/dashboard/alerts"' in body


@pytest.mark.asyncio
async def test_alerts_route_renders_email_ratio_pct(alerts_app_client):
    """HighP95Latency at 75% must render its ratio cell."""
    resp = await alerts_app_client.get("/dashboard/alerts")
    assert "75%" in resp.text
