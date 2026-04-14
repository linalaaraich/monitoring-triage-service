import asyncio
import logging
import time

import httpx

from app.config import settings
from app.metrics import triage_mcp_duration_seconds, triage_mcp_requests_total
from app.models import GatheredContext

logger = logging.getLogger(__name__)


class ContextGatherer:
    def __init__(self):
        self._client = httpx.AsyncClient(timeout=settings.context_timeout)

    async def close(self):
        await self._client.aclose()

    async def gather(
        self, alert_name: str, service: str, alert_time: str
    ) -> GatheredContext:
        """Gather context from all three pillars in parallel."""
        start = time.monotonic()

        prom_task = self._fetch_prometheus(service)
        loki_task = self._fetch_loki(service)
        jaeger_task = self._fetch_jaeger(service)

        results = await asyncio.gather(
            prom_task, loki_task, jaeger_task, return_exceptions=True
        )

        total_ms = int((time.monotonic() - start) * 1000)

        ctx = GatheredContext(total_ms=total_ms)
        errors = []

        # Prometheus result
        if isinstance(results[0], Exception):
            errors.append(f"[Prometheus] unavailable: {results[0]}")
            ctx.prometheus_ms = settings.context_timeout * 1000
        else:
            ctx.metrics, ctx.prometheus_ms = results[0]
            ctx.sources_available += 1

        # Loki result
        if isinstance(results[1], Exception):
            errors.append(f"[Loki] unavailable: {results[1]}")
            ctx.loki_ms = settings.context_timeout * 1000
        else:
            ctx.logs, ctx.loki_ms = results[1]
            ctx.sources_available += 1

        # Jaeger result
        if isinstance(results[2], Exception):
            errors.append(f"[Jaeger] unavailable: {results[2]}")
            ctx.jaeger_ms = settings.context_timeout * 1000
        else:
            ctx.traces, ctx.jaeger_ms = results[2]
            ctx.sources_available += 1

        ctx.errors = errors

        logger.info(
            "Context gathered: prometheus=%dms loki=%dms jaeger=%dms total=%dms sources=%d",
            ctx.prometheus_ms,
            ctx.loki_ms,
            ctx.jaeger_ms,
            ctx.total_ms,
            ctx.sources_available,
        )
        return ctx

    async def _fetch_prometheus(self, service: str) -> tuple[dict, int]:
        return await self._mcp_call(
            server="prometheus",
            url=f"{settings.prometheus_mcp_url}/tools/query_range",
            params={
                "promql": f'{{job=~".*{service}.*"}}',
                "start": f"{settings.prometheus_range_minutes}m",
                "end": "now",
                "step": "60s",
            },
        )

    async def _fetch_loki(self, service: str) -> tuple[list[str], int]:
        data, ms = await self._mcp_call(
            server="loki",
            url=f"{settings.loki_mcp_url}/tools/query_logs",
            params={
                "logql": f'{{service_name="{service}"}}',
                "start": f"{settings.prometheus_range_minutes}m",
                "end": "now",
                "limit": settings.loki_log_limit,
            },
        )
        lines = data if isinstance(data, list) else data.get("lines", [])
        return lines, ms

    async def _fetch_jaeger(self, service: str) -> tuple[list[dict], int]:
        return await self._mcp_call(
            server="jaeger",
            url=f"{settings.jaeger_mcp_url}/tools/find_traces",
            params={
                "service": service,
                "start": f"{settings.prometheus_range_minutes}m",
                "end": "now",
                "limit": settings.jaeger_trace_limit,
            },
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
