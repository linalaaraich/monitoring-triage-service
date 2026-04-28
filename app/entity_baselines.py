"""US-5.1 Phase B — per-service metric baselines from Prometheus history.

Computes 7-day-rolling behavioral baselines for the metrics that drive
the alerts. Two ways the LLM uses these:

  1. The metric interpreter calls `get_baseline()` for the alerting
     service + metric and renders a "Behavioral baseline" line in the
     prompt: "p95 latency 8487 ms — 4.2σ above spring-boot's 7-day
     baseline (mean=850ms, σ=250ms)".

  2. RCA prose can cite the σ-claim as evidence rather than just
     "above 1000ms threshold" — much more diagnostic.

Cached per (service, metric) to limit Prometheus query cost.

Phase A (per-service Drain3) is in app/drain_analyzer.py. Phase C
wires the baseline into MetricFacts.as_prompt_block via app/metric_interpreter.py.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Data shapes
# -----------------------------------------------------------------------------

@dataclass(frozen=True)
class BaselineFacts:
    """Result of a baseline query.

    sample_count is the unit-of-measurement Prometheus returned. If it's
    < min_samples_for_baseline (default 100, ~7d at 5min resolution),
    callers should NOT cite the baseline as authoritative — render
    `as_prose_line()` returns a fallback string in that case.

    Quantiles are the per-sample distribution: p50/p95 are the median +
    high-tail of the metric's values over the window, NOT instantaneous
    percentiles. mean/stddev are over those same samples.
    """
    service: str
    metric: str
    window_seconds: int
    sample_count: int
    mean: float
    stddev: float
    p50: float
    p95: float
    queried_at: float  # monotonic time

    @property
    def is_authoritative(self) -> bool:
        return self.sample_count >= 100

    def sigma_above_baseline(self, current_value: float) -> Optional[float]:
        """How many σ the current value is above the mean. None if
        stddev=0 (degenerate baseline) or not authoritative."""
        if not self.is_authoritative:
            return None
        if self.stddev <= 0:
            return None
        return (current_value - self.mean) / self.stddev

    def as_prose_line(self, current_value: float) -> str:
        """Render the baseline as a one-line evidence claim. Falls back
        to a graceful "no baseline available" message if not authoritative.
        """
        days = self.window_seconds // 86400
        if not self.is_authoritative:
            return (
                f"No behavioral baseline available for {self.service}/{self.metric} yet "
                f"(only {self.sample_count} samples in {days}d, need ≥100). "
                f"Reason from the alert's threshold and current value alone."
            )
        sigma = self.sigma_above_baseline(current_value)
        if sigma is None:
            return (
                f"{self.service}/{self.metric}: baseline mean={self.mean:.2g}, σ=0 "
                f"(degenerate — metric is constant in the window)."
            )
        direction = "above" if sigma >= 0 else "below"
        return (
            f"{self.service}/{self.metric} {days}-day baseline: "
            f"mean={self.mean:.3g}, σ={self.stddev:.3g}, p95={self.p95:.3g}. "
            f"Current value {current_value:.3g} = {abs(sigma):.1f}σ {direction} baseline."
        )


# -----------------------------------------------------------------------------
# Cache + queries
# -----------------------------------------------------------------------------

_DEFAULT_WINDOW_SECONDS = 7 * 86400  # 7 days
_DEFAULT_CACHE_TTL_SECONDS = 300       # 5 minutes


@dataclass
class _CacheEntry:
    facts: BaselineFacts
    expires_at: float


# Module-global cache. Keyed by (service, metric, window_seconds).
_cache: dict[tuple[str, str, int], _CacheEntry] = {}
_cache_lock: asyncio.Lock | None = None


def _get_lock() -> asyncio.Lock:
    """Lazy-init the lock so the module can be imported without an active loop."""
    global _cache_lock
    if _cache_lock is None:
        _cache_lock = asyncio.Lock()
    return _cache_lock


def clear_cache() -> None:
    """For tests."""
    _cache.clear()


# -----------------------------------------------------------------------------
# Prometheus query
# -----------------------------------------------------------------------------

async def _query_prometheus(
    prometheus_url: str,
    promql: str,
    timeout_s: float = 10.0,
) -> Optional[float]:
    """Run an instant query, return the first sample's value as float, or None.

    Used for scalar quantiles like quantile_over_time. Range queries use a
    different shape — those have their own helper below.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            resp = await client.get(
                f"{prometheus_url.rstrip('/')}/api/v1/query",
                params={"query": promql},
            )
            if resp.status_code != 200:
                logger.warning(
                    "Prometheus query returned %d for %r", resp.status_code, promql[:80]
                )
                return None
            data = resp.json()
            result = data.get("data", {}).get("result", [])
            if not result:
                return None
            value = result[0].get("value", [None, None])[1]
            return float(value) if value is not None else None
    except (httpx.HTTPError, ValueError) as e:
        logger.debug("Prometheus query failed: %s", e)
        return None


async def _query_count(
    prometheus_url: str,
    metric: str,
    window_seconds: int,
    label_filter: str,
    timeout_s: float = 10.0,
) -> int:
    """Count the number of samples in the window — used to decide whether
    the baseline is authoritative."""
    promql = f"count_over_time({metric}{{{label_filter}}}[{window_seconds}s])"
    val = await _query_prometheus(prometheus_url, promql, timeout_s)
    return int(val) if val is not None else 0


async def _compute_baseline(
    prometheus_url: str,
    service: str,
    metric: str,
    window_seconds: int,
    label_key: str = "service",
    timeout_s: float = 10.0,
) -> BaselineFacts:
    """Compute baseline facts via four parallel Prometheus queries.

    The metric template is interpreted as a fully-qualified expression
    that already contains label filters; if `metric` looks like a bare
    name (no braces), we filter by `label_key=service`.
    """
    if "{" in metric:
        # Caller supplied a labeled metric — use as-is for samples,
        # apply quantile_over_time around it.
        sampled = metric
        # Best-effort sample count (may not be accurate for complex exprs)
        count_label = ""
    else:
        sampled = f'{metric}{{{label_key}="{service}"}}'
        count_label = f'{label_key}="{service}"'

    queries = {
        "mean": f"avg_over_time({sampled}[{window_seconds}s])",
        "stddev": f"stddev_over_time({sampled}[{window_seconds}s])",
        "p50": f"quantile_over_time(0.5, {sampled}[{window_seconds}s])",
        "p95": f"quantile_over_time(0.95, {sampled}[{window_seconds}s])",
        "count": f"count_over_time({sampled}[{window_seconds}s])",
    }
    results: dict[str, Optional[float]] = await asyncio.gather(
        *[_query_prometheus(prometheus_url, q, timeout_s) for q in queries.values()],
        return_exceptions=False,
    )
    keys = list(queries.keys())
    by_name = dict(zip(keys, results))

    return BaselineFacts(
        service=service,
        metric=metric,
        window_seconds=window_seconds,
        sample_count=int(by_name.get("count") or 0),
        mean=float(by_name.get("mean") or 0.0),
        stddev=float(by_name.get("stddev") or 0.0),
        p50=float(by_name.get("p50") or 0.0),
        p95=float(by_name.get("p95") or 0.0),
        queried_at=time.monotonic(),
    )


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------

async def get_baseline(
    prometheus_url: str,
    service: str,
    metric: str,
    *,
    window_seconds: int = _DEFAULT_WINDOW_SECONDS,
    cache_ttl_seconds: int = _DEFAULT_CACHE_TTL_SECONDS,
    timeout_s: float = 10.0,
) -> BaselineFacts:
    """Fetch a behavioral baseline for (service, metric) over the window.

    Cached per (service, metric, window) for cache_ttl_seconds. Cache
    miss runs five parallel Prometheus queries (mean, stddev, p50, p95,
    count). The cache exists because Prometheus quantile_over_time over
    a 7-day range is non-trivial (~10080 samples at 1m resolution per
    series); doing it on every alert would saturate Prometheus.

    Returns a BaselineFacts with sample_count ≤ 100 if Prometheus has
    insufficient history — caller renders that case via
    `BaselineFacts.as_prose_line()` which produces a "no baseline yet"
    message.
    """
    key = (service, metric, window_seconds)
    now = time.monotonic()

    async with _get_lock():
        entry = _cache.get(key)
        if entry is not None and entry.expires_at > now:
            return entry.facts

        facts = await _compute_baseline(
            prometheus_url=prometheus_url,
            service=service,
            metric=metric,
            window_seconds=window_seconds,
            timeout_s=timeout_s,
        )
        _cache[key] = _CacheEntry(facts=facts, expires_at=now + cache_ttl_seconds)
        return facts
