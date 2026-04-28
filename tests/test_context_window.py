"""Context window anchoring tests (Option B)."""
import time

import pytest

from app.context import ContextGatherer, _absolute_window, _parse_alert_time
from app.models import GrafanaAlert


def _make_alert(alertname: str = "TestAlert", service: str = "spring-boot", starts_at: str = "") -> GrafanaAlert:
    """Build a minimal GrafanaAlert for context-gather tests.

    Uses service='spring-boot' by default so the jaeger fetch path is
    exercised (the production code short-circuits jaeger for non-traced
    services, which would otherwise hide the third MCP call from these
    tests).
    """
    return GrafanaAlert(
        status="firing",
        labels={"alertname": alertname, "service": service, "severity": "warning"},
        startsAt=starts_at,
    )


def test_parse_iso_z_suffix():
    epoch = _parse_alert_time("2026-04-22T15:46:30Z")
    assert epoch is not None
    assert 1776800000 < epoch < 1777000000


def test_parse_iso_with_offset():
    assert _parse_alert_time("2026-04-22T15:46:30+00:00") is not None
    assert _parse_alert_time("2026-04-22T16:46:30+01:00") is not None


def test_parse_naive_assumed_utc():
    assert _parse_alert_time("2026-04-22T15:46:30") is not None


def test_parse_empty_returns_none():
    assert _parse_alert_time("") is None
    assert _parse_alert_time(None) is None


def test_parse_garbage_returns_none():
    assert _parse_alert_time("not a date") is None
    assert _parse_alert_time("2026-13-45") is None


def test_parse_future_timestamp_rejected():
    """NTP skew / replay with bogus startsAt → fall back to relative."""
    future = time.time() + 3600
    from datetime import datetime, timezone
    assert _parse_alert_time(datetime.fromtimestamp(future, tz=timezone.utc).isoformat()) is None


def test_absolute_window_shape():
    """For a 10-min window: [alert-8min, alert+2min], end clamped to now."""
    alert = time.time() - 600  # alert 10 min ago
    start, end = _absolute_window(alert, window_minutes=10)
    assert abs((alert - start) - 8 * 60) < 1  # 8 min lookback
    assert abs((end - alert) - 2 * 60) < 1    # 2 min lookahead


def test_absolute_window_clamps_end_to_now():
    """If the alert just fired, lookahead clamps to now."""
    alert = time.time() - 30  # 30 seconds ago
    start, end = _absolute_window(alert, window_minutes=10)
    assert end <= time.time() + 1


def test_absolute_window_narrow_input():
    """Edge: window_minutes <= 2 should not produce negative lookback."""
    alert = time.time() - 100
    start, end = _absolute_window(alert, window_minutes=1)
    assert start <= alert
    assert end >= alert or abs(end - alert) < 200  # clamped


@pytest.mark.asyncio
async def test_gather_passes_absolute_window_to_mcp(monkeypatch):
    """End-to-end: a valid startsAt means the MCP calls see epoch
    timestamps, not '15m' / 'now' relative strings.

    Each pillar formats the window slightly differently:
      - Prometheus: float-second strings like '1771234567.890'
      - Loki: nanosecond integer strings like '1771234567890000000'
      - Jaeger: microsecond integer strings like '1771234567890000'
    None of them contain 'm' (the relative-time suffix) when absolute.
    """
    gatherer = ContextGatherer()
    captured = {}

    async def fake_mcp_call(server, url, params):
        captured[server] = params
        if server == "prometheus":
            return ({"query": "up", "values": []}, 5)
        if server == "loki":
            return ([], 5)
        if server == "jaeger":
            return ([], 5)
        return (None, 5)

    monkeypatch.setattr(gatherer, "_mcp_call", fake_mcp_call)

    alert = _make_alert(starts_at="2026-04-22T15:46:30Z")
    await gatherer.gather(alert)

    for server in ("prometheus", "loki", "jaeger"):
        assert server in captured, f"{server} _mcp_call not invoked"
        start = captured[server]["start"]
        end = captured[server]["end"]
        # Absolute strings: digits (with optional '.'), no 'm' suffix and not 'now'
        assert end != "now", f"{server} got relative end, expected absolute"
        assert not start.endswith("m"), f"{server} got relative start ({start!r}), expected absolute"

    await gatherer.close()


@pytest.mark.asyncio
async def test_gather_falls_back_to_relative_without_startsAt(monkeypatch):
    """Empty startsAt → relative 'Xm' / 'now' fallback (backward compat)."""
    gatherer = ContextGatherer()
    captured = {}

    async def fake_mcp_call(server, url, params):
        captured[server] = params
        if server == "prometheus":
            return ({}, 5)
        if server == "loki":
            return ([], 5)
        return ([], 5)

    monkeypatch.setattr(gatherer, "_mcp_call", fake_mcp_call)
    await gatherer.gather(_make_alert(starts_at=""))

    for server in ("prometheus", "loki", "jaeger"):
        assert captured[server]["end"] == "now"
        assert captured[server]["start"].endswith("m")

    await gatherer.close()
