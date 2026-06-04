"""Tests for the Drain3 webhook evidence flow (2026-04-28 fix).

Background: until 2026-04-28 the Drain3 self-fire path threw away the
actual anomalous-line content and new-template strings — the LLM only
ever saw a count, never the substance. Every Drain3 RCA in production
was therefore useless ("an anomaly was detected with a novel log
template, but no specific evidence supports a concrete cause"). The
operator caught this on a real fire 2026-04-28 11:20:56.

These tests lock in the fix at three layers:
  1. drain_analyzer._ingest_batch_sync returns (lines, templates)
  2. drain_analyzer.maybe_fire_alert forwards new_templates into the
     webhook payload (was hardcoded to []).
  3. pipeline.process_drain3_webhook builds a rich description that
     contains both new templates and sample lines, so the LLM prompt's
     Description field actually carries the diagnostic content.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.drain_analyzer import DrainAnalyzer
from app.models import Drain3Webhook, GrafanaAlert


def test_ingest_batch_sync_returns_lines_and_new_templates(tmp_path, monkeypatch):
    """Test that brand-new templates come back as separate from anomalous
    lines. Uses a fresh state dir so other tests don't pollute the
    template tree (Drain3's FilePersistence persists across instances
    pointing at the same path).
    """
    import uuid
    from app.config import settings
    monkeypatch.setattr(settings, "drain3_state_dir", str(tmp_path))
    sentinel = uuid.uuid4().hex[:8]
    da = DrainAnalyzer()
    lines = [
        f"ERROR-{sentinel}-A novel test failure mode at TestService.method-{sentinel}A line one",
        f"ERROR-{sentinel}-B different novel template at OtherService.foo-{sentinel}B line one",
        f"ERROR-{sentinel}-A novel test failure mode at TestService.method-{sentinel}A line two",
    ]
    anomalous, templates = da._ingest_batch_sync(lines)
    # All three are anomalous (fresh state dir → all clusters new)
    assert len(anomalous) == 3
    assert len(templates) >= 1, f"expected ≥1 new template captured, got {templates}"
    assert all(isinstance(t, str) and t for t in templates)


@pytest.mark.asyncio
async def test_maybe_fire_alert_forwards_new_templates_to_webhook(monkeypatch):
    """The webhook payload `new_templates` field must carry the actual
    template strings — was hardcoded to [] until 2026-04-28."""
    da = DrainAnalyzer()
    # Force the alert-rate threshold to trip
    from app.config import settings
    monkeypatch.setattr(settings, "drain3_alert_min_lines", 1)
    monkeypatch.setattr(settings, "drain3_alert_rate_threshold", 0.0)
    monkeypatch.setattr(settings, "drain3_alert_enabled", True)

    captured_payload = {}

    class _FakeResp:
        status_code = 202
        text = ""

    class _FakeClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json):
            captured_payload.update(json)
            return _FakeResp()

    import app.drain_analyzer as da_mod
    monkeypatch.setattr(da_mod.httpx, "AsyncClient", lambda timeout=5.0: _FakeClient())

    await da.maybe_fire_alert(
        batch_total=10,
        anomalous=["line A", "line B"],
        new_templates=["ERROR <*> heap space", "WARN connection pool drained"],
    )
    assert captured_payload["new_templates"] == [
        "ERROR <*> heap space",
        "WARN connection pool drained",
    ]
    assert captured_payload["anomalous_lines"] == ["line A", "line B"]
    assert captured_payload["service"] == "drain3"


@pytest.mark.asyncio
async def test_process_drain3_webhook_builds_rich_description():
    """The synthetic alert's description must contain both new templates
    and verbatim sample lines so the LLM prompt's Description field
    carries the actual diagnostic content."""
    from app.pipeline import TriagePipeline

    # Build a minimal pipeline with mocked dependencies — we only care about
    # the alert that gets passed to _process_alert.
    captured_alerts = []

    async def _capture(alert, source, env=None):
        captured_alerts.append(alert)

    # Bypass __init__: set only what process_drain3_webhook touches
    pipeline = TriagePipeline.__new__(TriagePipeline)
    pipeline._process_alert = _capture

    webhook = Drain3Webhook(
        anomalous_lines=[
            "2026-04-28 11:20:56 ERROR java.lang.OutOfMemoryError: Java heap space",
            "2026-04-28 11:20:57 ERROR Failed to acquire JDBC connection: timeout after 30000ms",
            "2026-04-28 11:20:58 WARN GC overhead limit exceeded",
        ],
        anomaly_rate=0.1282,
        new_templates=[
            "ERROR java.lang.OutOfMemoryError: <*> space",
            "ERROR Failed to acquire JDBC connection: timeout after <*>ms",
        ],
        service="spring-boot",
        timestamp="2026-04-28T11:20:56Z",
    )
    await pipeline.process_drain3_webhook(webhook)

    assert len(captured_alerts) == 1
    alert: GrafanaAlert = captured_alerts[0]
    desc = alert.annotations["description"]

    # Description must contain the actual templates
    assert "ERROR java.lang.OutOfMemoryError" in desc
    assert "Failed to acquire JDBC connection" in desc
    # And sample anomalous lines (verbatim)
    assert "GC overhead limit exceeded" in desc
    # And the rate
    assert "12.82%" in desc
    # And labels carry signal=log so the drain3-novelty exemplar matches well
    assert alert.labels.get("signal") == "log"


@pytest.mark.asyncio
async def test_process_drain3_webhook_handles_empty_templates_gracefully():
    """No new templates this batch is a valid state — anomalies are from
    rare/under-threshold clusters. The description must still carry sample
    lines so the LLM has something to reason about."""
    from app.pipeline import TriagePipeline

    captured_alerts = []
    async def _capture(alert, source, env=None):
        captured_alerts.append(alert)
    pipeline = TriagePipeline.__new__(TriagePipeline)
    pipeline._process_alert = _capture

    webhook = Drain3Webhook(
        anomalous_lines=["WARN slow query took 5234ms"],
        anomaly_rate=0.05,
        new_templates=[],
        service="spring-boot",
        timestamp="2026-04-28T11:20:56Z",
    )
    await pipeline.process_drain3_webhook(webhook)

    desc = captured_alerts[0].annotations["description"]
    assert "slow query took 5234ms" in desc
    assert "No brand-new templates" in desc  # the explanatory note
