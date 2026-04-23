import asyncio
import logging
import time
from datetime import datetime, timezone

import httpx

from app.config import settings
from app.metrics import triage_mcp_duration_seconds, triage_mcp_requests_total
from app.models import GatheredContext, GrafanaAlert

logger = logging.getLogger(__name__)


def _parse_alert_time(alert_time: str) -> float | None:
    """Parse an ISO 8601 alert startsAt string to epoch seconds (float).

    Returns None if the input is empty, malformed, or in the future. The
    caller should fall back to relative-window behaviour ('Xm' / 'now') so
    that a bad timestamp never blocks context gathering.
    """
    if not alert_time:
        return None
    try:
        # fromisoformat accepts '+00:00' but not the trailing 'Z' until 3.11.
        normalized = alert_time.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        epoch = dt.timestamp()
        # Future timestamps (NTP skew, replay with a bogus startsAt) → fall back.
        if epoch > time.time() + 60:
            return None
        return epoch
    except (ValueError, TypeError):
        return None


def _prom_result_empty(data) -> bool:
    """True if a Prometheus MCP response carries no series.

    The MCP server passes the Prometheus JSON through largely unchanged, so
    a populated response looks like `{"status":"success","data":{"result":[...]}}`
    and an empty one has `result: []`. Be generous about the shape: we've
    also seen the MCP return a raw list or a plain `{"result":[]}` wrapper.
    """
    if not data:
        return True
    if isinstance(data, list):
        return len(data) == 0
    if isinstance(data, dict):
        # {"data": {"result": [...]}} — standard Prom wrapper
        inner = data.get("data", data)
        if isinstance(inner, dict):
            result = inner.get("result")
            if result is None:
                return False  # unknown shape — don't second-guess, treat as non-empty
            return len(result) == 0
    return False


def _absolute_window(alert_epoch: float, window_minutes: int) -> tuple[float, float]:
    """Build an absolute context window anchored on the alert's startsAt.

    Skewed slightly before the alert (metrics + logs from 'a little before')
    but includes a small look-ahead too so fast-moving incidents aren't
    clipped. Both bounds are clamped to <= now (Prometheus/Loki/Jaeger do
    not return future data anyway, but being explicit avoids confusing
    error surfaces from the MCPs).

    For a 10-minute window: [alert_time - 8min, alert_time + 2min],
    clamped to now.
    """
    lookahead_seconds = 2 * 60
    lookbehind_seconds = max(0, (window_minutes - 2) * 60)
    now = time.time()
    start = alert_epoch - lookbehind_seconds
    end = min(alert_epoch + lookahead_seconds, now)
    return start, end


class ContextGatherer:
    def __init__(self):
        self._client = httpx.AsyncClient(timeout=settings.context_timeout)

    async def close(self):
        await self._client.aclose()

    async def gather(
        self, alert: GrafanaAlert
    ) -> GatheredContext:
        """Gather context from all three pillars in parallel.

        If alert.startsAt (Grafana startsAt) parses cleanly, all three pillars
        share an absolute time window anchored on the alert itself. This
        is the correlation guarantee — metrics/logs/traces for the alert's
        timeframe, not for whenever the LLM happens to wake up.

        We pass the full alert down to each pillar fetch so fallback queries
        can key on alert.instance or alert.annotations.expr when service-scoped
        queries return nothing (which is the common case for node-level alerts
        like HighCpuUsage where `service=k3s-node` matches no `job=~".*k3s-node.*"` series).
        """
        start = time.monotonic()
        alert_epoch = _parse_alert_time(alert.startsAt)
        abs_window = (
            _absolute_window(alert_epoch, settings.prometheus_range_minutes)
            if alert_epoch is not None
            else None
        )

        prom_task = self._fetch_prometheus(alert, abs_window)
        loki_task = self._fetch_loki(alert, abs_window)
        jaeger_task = self._fetch_jaeger(alert, abs_window)

        results = await asyncio.gather(
            prom_task, loki_task, jaeger_task, return_exceptions=True
        )

        total_ms = int((time.monotonic() - start) * 1000)

        ctx = GatheredContext(total_ms=total_ms)
        errors = []

        if isinstance(results[0], Exception):
            errors.append(f"[Prometheus] unavailable: {results[0]}")
            ctx.prometheus_ms = settings.context_timeout * 1000
        else:
            ctx.metrics, ctx.prometheus_ms = results[0]
            ctx.sources_available += 1

        if isinstance(results[1], Exception):
            errors.append(f"[Loki] unavailable: {results[1]}")
            ctx.loki_ms = settings.context_timeout * 1000
        else:
            ctx.logs, ctx.loki_ms = results[1]
            ctx.sources_available += 1

        if isinstance(results[2], Exception):
            errors.append(f"[Jaeger] unavailable: {results[2]}")
            ctx.jaeger_ms = settings.context_timeout * 1000
        else:
            ctx.traces, ctx.jaeger_ms = results[2]
            ctx.sources_available += 1

        ctx.errors = errors

        window_desc = (
            f"abs [{abs_window[0]:.0f},{abs_window[1]:.0f}]"
            if abs_window
            else f"rel last {settings.prometheus_range_minutes}m"
        )
        logger.info(
            "Context gathered: prometheus=%dms loki=%dms jaeger=%dms total=%dms sources=%d window=%s",
            ctx.prometheus_ms,
            ctx.loki_ms,
            ctx.jaeger_ms,
            ctx.total_ms,
            ctx.sources_available,
            window_desc,
        )
        return ctx

    async def _fetch_prometheus(
        self, alert: GrafanaAlert, abs_window: tuple[float, float] | None
    ) -> tuple[dict, int]:
        """Query Prometheus with service-scoped PromQL, fall back to:
          1) the rule's own PromQL expression (from annotations.expr) — authoritative,
          2) an instance-scoped query (useful for node-level alerts), if we have one.

        The primary `{job=~".*<service>.*"}` query matches nothing for service
        labels like `k3s-node` or `monitoring` since those aren't job values —
        that's the case that previously produced "insufficient data" RCAs.
        """
        service = alert.service
        primary = {
            "promql": f'{{job=~".*{service}.*"}}',
            "step": "60s",
        }
        if abs_window:
            primary["start"] = f"{abs_window[0]:.3f}"
            primary["end"] = f"{abs_window[1]:.3f}"
        else:
            primary["start"] = f"{settings.prometheus_range_minutes}m"
            primary["end"] = "now"

        data, ms = await self._mcp_call(
            server="prometheus",
            url=f"{settings.prometheus_mcp_url}/tools/query_range",
            params=primary,
        )

        if _prom_result_empty(data):
            # Try the rule's own PromQL first — it's exactly what Grafana
            # evaluated, so we know it returns a value when the alert fires.
            fallback_promql = alert.annotations.get("expr", "").strip()
            if not fallback_promql and alert.instance and alert.instance != "unknown":
                # Instance-scoped fallback for node-level alerts that don't carry
                # an `expr` annotation yet.
                fallback_promql = f'{{instance="{alert.instance}"}}'
            if fallback_promql:
                fb_params = dict(primary, promql=fallback_promql)
                logger.info(
                    "Prometheus primary empty for service=%s — falling back to %r",
                    service, fallback_promql[:80],
                )
                fb_data, fb_ms = await self._mcp_call(
                    server="prometheus",
                    url=f"{settings.prometheus_mcp_url}/tools/query_range",
                    params=fb_params,
                )
                if not _prom_result_empty(fb_data):
                    return fb_data, ms + fb_ms
                # Fallback also empty — return primary (the LLM prompt will
                # note the miss rather than hallucinate).
        return data, ms

    async def _fetch_loki(
        self, alert: GrafanaAlert, abs_window: tuple[float, float] | None
    ) -> tuple[list[str], int]:
        """Query Loki with service-scoped logs, fall back to any-service logs
        in a short window. Node-level alerts (service=k3s-node etc.) have no
        service-scoped log stream so the fallback is the only way to see
        anything useful.
        """
        service = alert.service
        primary = {
            "logql": f'{{service_name="{service}"}}',
            "limit": settings.loki_log_limit,
        }
        if abs_window:
            primary["start"] = str(int(abs_window[0] * 1_000_000_000))
            primary["end"] = str(int(abs_window[1] * 1_000_000_000))
        else:
            primary["start"] = f"{settings.prometheus_range_minutes}m"
            primary["end"] = "now"

        data, ms = await self._mcp_call(
            server="loki",
            url=f"{settings.loki_mcp_url}/tools/query_logs",
            params=primary,
        )
        lines = data if isinstance(data, list) else data.get("lines", [])

        if not lines:
            # Fallback: last 2min of any logs, smaller limit so we don't blow
            # the LLM context. Won't help latency alerts (too noisy) but very
            # useful for node-level alerts + data-sanity when a shipper is down.
            fb_params = dict(primary)
            fb_params["logql"] = '{service_name=~".+"}'
            fb_params["limit"] = min(settings.loki_log_limit, 50)
            logger.info(
                "Loki primary empty for service=%s — falling back to any-service (limit=%d)",
                service, fb_params["limit"],
            )
            fb_data, fb_ms = await self._mcp_call(
                server="loki",
                url=f"{settings.loki_mcp_url}/tools/query_logs",
                params=fb_params,
            )
            fb_lines = fb_data if isinstance(fb_data, list) else fb_data.get("lines", [])
            if fb_lines:
                return fb_lines, ms + fb_ms
        return lines, ms

    async def _fetch_jaeger(
        self, alert: GrafanaAlert, abs_window: tuple[float, float] | None
    ) -> tuple[list[dict], int]:
        """Query Jaeger for traces. For node-level alerts (service=k3s-node,
        monitoring, loki, etc.) there are no traces — skip the call entirely
        to avoid a 500 ms wasted round-trip that always returns empty.
        """
        service = alert.service
        # Services that don't emit traces. Update if new traced services are added.
        TRACED = {"spring-boot", "kong", "otel-collector"}
        if service not in TRACED:
            return [], 0

        params = {
            "service": service,
            "limit": settings.jaeger_trace_limit,
        }
        if abs_window:
            params["start"] = str(int(abs_window[0] * 1_000_000))
            params["end"] = str(int(abs_window[1] * 1_000_000))
        else:
            params["start"] = f"{settings.prometheus_range_minutes}m"
            params["end"] = "now"
        return await self._mcp_call(
            server="jaeger",
            url=f"{settings.jaeger_mcp_url}/tools/find_traces",
            params=params,
        )

    async def _mcp_call(self, server: str, url: str, params: dict) -> tuple:
        """Execute an MCP server HTTP call with metrics instrumentation."""
        start = time.monotonic()
        try:
            resp = await self._client.get(url, params=params)
            resp.raise_for_status()
            ms = int((time.monotonic() - start) * 1000)
            elapsed = (time.monotonic() - start)
            triage_mcp_requests_total.labels(server=server, status="success").inc()
            triage_mcp_duration_seconds.labels(server=server).observe(elapsed)
            return resp.json(), ms
        except Exception as exc:
            elapsed = time.monotonic() - start
            triage_mcp_requests_total.labels(server=server, status="error").inc()
            triage_mcp_duration_seconds.labels(server=server).observe(elapsed)
            raise exc
