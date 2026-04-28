"""Drain3 log-template miner — per-service template trees (US-5.1 Phase A).

Originally a single global TemplateMiner instance. As of US-5.1 Phase A
(2026-04-28 PM), the analyzer keeps a SEPARATE miner per service so
that spring-boot's templates don't blend with kong's, frontend's,
loki's, etc. Per-service state means:

  - Each service has its own cluster id space + template tree
  - A novel template in spring-boot is judged against spring-boot's
    own history, not against the global pool
  - The LLM prompt can cite "this is novel for SERVICE X" precisely

Persistence:
  - Each service writes to {drain3_state_dir}/{service}.bin
  - Pre-Phase-A `drain3_state.bin` is auto-migrated to `_unknown.bin`
    on first start so prior history isn't lost (counts as "_unknown"
    service which is the safe default for old data)

Threading:
  - One global lock guards the dict + per-miner state. Drain3's
    TemplateMiner internals aren't thread-safe; serializing all
    analyze calls is the simplest correct shape. Latency cost is
    bounded — `_ingest_loop` runs sequentially anyway.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import threading
from dataclasses import dataclass, field
from typing import Any

import httpx
from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence
from drain3.template_miner_config import TemplateMinerConfig

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class AnalyzeResult:
    cluster_id: int | None
    template: str
    is_new_pattern: bool
    match_count: int
    service: str = "_unknown"


# Regex matchers for extracting service from a stream's label dict.
# Loki ships with `service_name`, but some pipelines use other labels.
_SERVICE_LABEL_KEYS = ("service_name", "service", "k8s_app", "app_kubernetes_io_name", "app")


def _service_from_stream_labels(labels: dict[str, Any]) -> str:
    """Extract a service name from a Loki stream's label dict. Falls
    back to `_unknown` if no recognised label is present."""
    if not isinstance(labels, dict):
        return "_unknown"
    for key in _SERVICE_LABEL_KEYS:
        v = labels.get(key)
        if v:
            # Sanitize for use as a filename — replace anything that
            # isn't alnum / dash / underscore with underscore.
            sanitized = re.sub(r"[^A-Za-z0-9_-]+", "_", str(v))[:64]
            if sanitized:
                return sanitized
    return "_unknown"


class DrainAnalyzer:
    """Per-service Drain3 template miners with shared lock + file persistence."""

    def __init__(self):
        os.makedirs(settings.drain3_state_dir, exist_ok=True)
        # Find drain3.ini once; reused for every miner we create lazily.
        self._config = TemplateMinerConfig()
        for path in ["drain3.ini", os.path.join(os.path.dirname(__file__), "..", "drain3.ini")]:
            if os.path.exists(path):
                self._config.load(path)
                break

        # Per-service miners + per-service counters. _unknown is the default
        # bucket for anything we can't route by stream labels.
        self._miners: dict[str, TemplateMiner] = {}
        self._lines_per_service: dict[str, int] = {}
        self._anomalies_per_service: dict[str, int] = {}
        self._lock = threading.Lock()

        # Auto-migrate the pre-Phase-A state file. drain3_state.bin (the
        # old single-miner state) gets moved to _unknown.bin so prior
        # cluster history is preserved.
        legacy_path = os.path.join(settings.drain3_state_dir, "drain3_state.bin")
        unknown_path = os.path.join(settings.drain3_state_dir, "_unknown.bin")
        if os.path.exists(legacy_path) and not os.path.exists(unknown_path):
            try:
                shutil.move(legacy_path, unknown_path)
                logger.info("Migrated legacy drain3_state.bin → _unknown.bin")
            except OSError as e:
                logger.warning("Could not migrate legacy state file: %s", e)

        # P1.7 — self-alerting state. After each ingest batch we compare
        # the current batch's anomaly rate against the threshold.
        self._last_alert_ts: float = 0.0
        self._background_task: asyncio.Task | None = None

    # ------------------------------------------------------------------
    # Per-service miner creation
    # ------------------------------------------------------------------

    def _get_or_create_miner(self, service: str) -> TemplateMiner:
        """Lazily create + return the TemplateMiner for the given service.
        MUST be called with self._lock held."""
        miner = self._miners.get(service)
        if miner is not None:
            return miner
        state_path = os.path.join(settings.drain3_state_dir, f"{service}.bin")
        persistence = FilePersistence(state_path)
        miner = TemplateMiner(persistence, config=self._config)
        self._miners[service] = miner
        self._lines_per_service.setdefault(service, 0)
        self._anomalies_per_service.setdefault(service, 0)
        logger.info("Created per-service Drain3 miner for service=%s", service)
        return miner

    # ------------------------------------------------------------------
    # Analyze (per-service)
    # ------------------------------------------------------------------

    def analyze(self, log_line: str, service: str = "_unknown") -> AnalyzeResult:
        """Analyze a single log line against the SPECIFIC service's miner.

        Defaults to `_unknown` if the caller doesn't have a service
        label — that's the safe bucket for cross-service or unlabelled
        traffic.
        """
        with self._lock:
            miner = self._get_or_create_miner(service)
            result = miner.add_log_message(log_line)
            self._lines_per_service[service] = self._lines_per_service.get(service, 0) + 1

            cluster = result.get("cluster_id")
            template = result.get("template_mined", "")
            change_type = result.get("change_type", "none")
            is_new = change_type in ("cluster_created", "cluster_template_changed")

            match_count = 0
            if cluster is not None:
                for c in miner.drain.clusters:
                    if c.cluster_id == cluster:
                        match_count = c.size
                        break

            if is_new or match_count < settings.drain3_anomaly_threshold:
                self._anomalies_per_service[service] = (
                    self._anomalies_per_service.get(service, 0) + 1
                )

            return AnalyzeResult(
                cluster_id=cluster,
                template=template,
                is_new_pattern=is_new,
                match_count=match_count,
                service=service,
            )

    def annotate_lines(self, lines: list[str], service: str = "_unknown") -> tuple[list[str], str]:
        """Annotate log lines with [ANOMALY] or [KNOWN] prefix.

        All lines in this batch are attributed to the same service.
        Used by the per-alert context-gather path where the alert IS
        scoped to a specific service.
        """
        annotated = []
        anomaly_count = 0
        new_patterns = 0
        for line in lines:
            result = self.analyze(line, service=service)
            if result.is_new_pattern or result.match_count < settings.drain3_anomaly_threshold:
                annotated.append(f"[ANOMALY] {line}")
                anomaly_count += 1
                if result.is_new_pattern:
                    new_patterns += 1
            else:
                annotated.append(f"[KNOWN] {line}")
        summary = (
            f"Anomaly Summary: {anomaly_count} of {len(lines)} lines anomalous "
            f"for service={service}. {new_patterns} new patterns detected."
        )
        return annotated, summary

    # ------------------------------------------------------------------
    # Stats — aggregate or per-service
    # ------------------------------------------------------------------

    def get_stats(self, service: str | None = None) -> dict:
        """Return current Drain3 stats. If `service` is given, scope to
        that miner; else aggregate across all services."""
        with self._lock:
            if service is not None:
                miner = self._miners.get(service)
                if miner is None:
                    return {
                        "service": service,
                        "total_clusters": 0,
                        "recent_anomaly_rate": 0,
                        "top_new_patterns": [],
                        "total_lines_processed": 0,
                        "total_anomalies": 0,
                    }
                clusters = list(miner.drain.clusters)
                lines = self._lines_per_service.get(service, 0)
                anomalies = self._anomalies_per_service.get(service, 0)
                return {
                    "service": service,
                    "total_clusters": len(clusters),
                    "recent_anomaly_rate": round(anomalies / max(lines, 1), 4),
                    "top_new_patterns": [
                        c.get_template()
                        for c in sorted(clusters, key=lambda c: c.cluster_id, reverse=True)[:5]
                    ],
                    "total_lines_processed": lines,
                    "total_anomalies": anomalies,
                }

            # Aggregate
            all_clusters: list[Any] = []
            recent_per_service: dict[str, list[str]] = {}
            for svc, miner in self._miners.items():
                svc_clusters = list(miner.drain.clusters)
                all_clusters.extend(svc_clusters)
                recent_per_service[svc] = [
                    c.get_template()
                    for c in sorted(svc_clusters, key=lambda c: c.cluster_id, reverse=True)[:3]
                ]
            total_lines = sum(self._lines_per_service.values())
            total_anomalies = sum(self._anomalies_per_service.values())
            return {
                "total_clusters": len(all_clusters),
                "recent_anomaly_rate": round(total_anomalies / max(total_lines, 1), 4),
                "total_lines_processed": total_lines,
                "total_anomalies": total_anomalies,
                "services": list(self._miners.keys()),
                "per_service_lines": dict(self._lines_per_service),
                "per_service_anomalies": dict(self._anomalies_per_service),
                "top_new_patterns_per_service": recent_per_service,
                "top_new_patterns": [
                    c.get_template()
                    for c in sorted(all_clusters, key=lambda c: c.cluster_id, reverse=True)[:5]
                ],
            }

    # ------------------------------------------------------------------
    # Loki ingest — service-aware
    # ------------------------------------------------------------------

    async def seed_from_loki(self):
        import time as _time
        logger.info("Seeding Drain3 from Loki (per-service)...")
        try:
            start_ns = int((_time.time() - 3600) * 1e9)
            end_ns = int(_time.time() * 1e9)
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{settings.loki_api_url}/loki/api/v1/query_range",
                    params={
                        "query": '{service_name=~".+"}',
                        "limit": 1000,
                        "start": str(start_ns),
                        "end": str(end_ns),
                    },
                )
                if resp.status_code != 200:
                    logger.warning("Loki seed query failed: %d %s", resp.status_code, resp.text[:200])
                    return
                data = resp.json()
                streams_with_lines: list[tuple[str, list[str]]] = []
                for stream in data.get("data", {}).get("result", []):
                    svc = _service_from_stream_labels(stream.get("stream", {}))
                    lines = [line for _ts, line in stream.get("values", [])]
                    if lines:
                        streams_with_lines.append((svc, lines))
                if streams_with_lines:
                    # Run all per-service ingests in one thread call to keep the
                    # event loop responsive.
                    await asyncio.to_thread(self._seed_streams_sync, streams_with_lines)
                total_lines = sum(len(ls) for _, ls in streams_with_lines)
                logger.info(
                    "Drain3 seeded with %d log lines across %d service streams",
                    total_lines, len(streams_with_lines),
                )
        except Exception as e:
            logger.warning("Drain3 Loki seeding failed (non-fatal): %s", e)

    def _seed_streams_sync(self, streams: list[tuple[str, list[str]]]) -> None:
        """Process all streams sync — one helper for both seed + ingest paths."""
        for svc, lines in streams:
            for line in lines:
                try:
                    self.analyze(line, service=svc)
                except Exception as e:
                    logger.debug("Drain3 analyze failed (non-fatal): %s", e)

    async def start_background_ingestion(self):
        self._background_task = asyncio.create_task(self._ingest_loop())

    async def _ingest_loop(self):
        import time as _time
        while True:
            try:
                await asyncio.sleep(settings.drain3_poll_interval)
                start_ns = int((_time.time() - settings.drain3_poll_interval) * 1e9)
                end_ns = int(_time.time() * 1e9)
                async with httpx.AsyncClient(timeout=15) as client:
                    resp = await client.get(
                        f"{settings.loki_api_url}/loki/api/v1/query_range",
                        params={
                            "query": '{service_name=~".+"}',
                            "limit": 200,
                            "start": str(start_ns),
                            "end": str(end_ns),
                        },
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        # Group lines by service so each batch is per-service
                        streams_with_lines: list[tuple[str, list[str]]] = []
                        total_lines = 0
                        for stream in data.get("data", {}).get("result", []):
                            svc = _service_from_stream_labels(stream.get("stream", {}))
                            lines = [line for _ts, line in stream.get("values", [])]
                            if lines:
                                streams_with_lines.append((svc, lines))
                                total_lines += len(lines)
                        if streams_with_lines:
                            anomalous, new_templates = await asyncio.to_thread(
                                self._ingest_batch_sync_streams, streams_with_lines
                            )
                            await self.maybe_fire_alert(
                                batch_total=total_lines,
                                anomalous=anomalous,
                                new_templates=new_templates,
                            )
                    else:
                        logger.debug("Drain3 Loki poll returned %d", resp.status_code)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Drain3 background ingestion error: %s", e)

    def _ingest_batch_sync_streams(
        self, streams: list[tuple[str, list[str]]]
    ) -> tuple[list[str], list[str]]:
        """Per-service version of the batch ingest. Aggregates anomalous
        lines + new templates across all services in this batch."""
        anomalous_lines: list[str] = []
        new_templates_seen: dict[int, str] = {}
        for svc, lines in streams:
            for line in lines:
                try:
                    result = self.analyze(line, service=svc)
                    if result.is_new_pattern or result.match_count < settings.drain3_anomaly_threshold:
                        anomalous_lines.append(line)
                    if result.is_new_pattern and result.cluster_id is not None:
                        # Use (service, cluster_id) as the dedup key so two
                        # different services with the same internal cluster_id
                        # both get captured.
                        new_templates_seen.setdefault(
                            hash((svc, result.cluster_id)), result.template
                        )
                except Exception as e:
                    logger.debug("Drain3 analyze failed for one line (non-fatal): %s", e)
        return anomalous_lines, list(new_templates_seen.values())

    # Backwards-compat shim for any callers still using the flat-list shape.
    def _ingest_batch_sync(self, lines: list[str]) -> tuple[list[str], list[str]]:
        """Flat-list shim. Routes everything to `_unknown`. Tests that
        don't have a service label use this path."""
        return self._ingest_batch_sync_streams([("_unknown", lines)])

    # ------------------------------------------------------------------
    # Self-alerting (unchanged from V1)
    # ------------------------------------------------------------------

    async def maybe_fire_alert(
        self,
        batch_total: int,
        anomalous: list[str],
        new_templates: list[str] | None = None,
    ) -> None:
        if not settings.drain3_alert_enabled:
            return
        if batch_total < settings.drain3_alert_min_lines:
            return
        rate = len(anomalous) / max(batch_total, 1)
        if rate < settings.drain3_alert_rate_threshold:
            return

        import time as _time
        now = _time.monotonic()
        cooldown = settings.drain3_alert_cooldown_seconds
        if self._last_alert_ts and (now - self._last_alert_ts) < cooldown:
            logger.info(
                "Drain3 anomaly rate %.2f crossed threshold but within cooldown (%.0fs remaining)",
                rate, cooldown - (now - self._last_alert_ts),
            )
            return

        from datetime import datetime, timezone
        payload = {
            "anomalous_lines": anomalous[:50],
            "anomaly_rate": round(rate, 4),
            "new_templates": (new_templates or [])[:20],
            "service": "drain3",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(settings.drain3_self_webhook_url, json=payload)
                if resp.status_code in (200, 202):
                    self._last_alert_ts = now
                    logger.warning(
                        "Drain3 self-alert fired: rate=%.2f (%d/%d lines anomalous), webhook=%d",
                        rate, len(anomalous), batch_total, resp.status_code,
                    )
                else:
                    logger.warning(
                        "Drain3 self-alert webhook returned %d — %s",
                        resp.status_code, resp.text[:100],
                    )
        except (httpx.HTTPError, OSError) as e:
            logger.warning("Drain3 self-alert webhook failed: %s", e)
