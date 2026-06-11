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
import json
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
    # BE-B3 — True if this line was dropped by the source-exclusion denylist
    # (observability/infra service). Skipped lines never touch a miner, are
    # never counted, and can never produce a novel-template anomaly.
    excluded: bool = False


@dataclass
class ScopeCounts:
    """Per-scope (one service, or one application) tally for a single batch."""
    lines: int = 0
    anomalous: int = 0
    new_templates: list[str] = field(default_factory=list)
    sample_lines: list[str] = field(default_factory=list)

    @property
    def rate(self) -> float:
        return self.anomalous / self.lines if self.lines else 0.0


@dataclass
class BatchResult:
    """S5-DRN-01 — structured result of ingesting one batch, preserving the
    per-component and per-application breakdown the 3 tiers need."""
    total_lines: int = 0
    total_anomalous: int = 0
    per_service: dict[str, ScopeCounts] = field(default_factory=dict)
    per_app: dict[str, ScopeCounts] = field(default_factory=dict)
    # Which component services rolled up into each app (for double-fire guard).
    app_components: dict[str, set] = field(default_factory=dict)

    @property
    def total_rate(self) -> float:
        return self.total_anomalous / self.total_lines if self.total_lines else 0.0

    def all_anomalous_lines(self) -> list[str]:
        out: list[str] = []
        for sc in self.per_service.values():
            out.extend(sc.sample_lines)
        return out

    def all_new_templates(self) -> list[str]:
        out: list[str] = []
        for sc in self.per_service.values():
            out.extend(sc.new_templates)
        return out


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


# Stream labels that name the application/namespace a component belongs to.
_NAMESPACE_LABEL_KEYS = (
    "k8s_namespace_name", "namespace", "k8s.namespace.name", "exported_namespace",
)


def _app_from_stream_labels(labels: dict[str, Any], service: str) -> str:
    """S5-DRN-01 — resolve the APPLICATION a component (service) belongs to,
    for the application-tier threshold. Priority:
      1. an explicit settings.drain3_app_map[service] override,
      2. the stream's k8s namespace label (so all services in one namespace —
         e.g. the otel-demo astronomy shop — aggregate into one app),
      3. the service name itself (an ungrouped service is its own single-
         component app, so the app tier harmlessly mirrors the component tier).
    """
    mapped = (settings.drain3_app_map or {}).get(service)
    if mapped:
        return re.sub(r"[^A-Za-z0-9_-]+", "_", str(mapped))[:64] or service
    if isinstance(labels, dict):
        for key in _NAMESPACE_LABEL_KEYS:
            v = labels.get(key)
            if v:
                sanitized = re.sub(r"[^A-Za-z0-9_-]+", "_", str(v))[:64]
                if sanitized:
                    return sanitized
    return service


def is_excluded_service(service: str) -> bool:
    """BE-B3 — True if `service` belongs to the observability/infra stack and
    must NOT be fed into the Drain3 miners.

    Matched defensively (the analyzer's ingestion boundary calls this for every
    resolved service before any miner is touched):

      - case-insensitive exact match against settings.drain3_excluded_services
      - container-name forms: a leading `ai-` / `ai-mcp-` prefix is stripped so
        e.g. `ai-mcp-prometheus`, `ai-otel-collector`, `ai-grafana` all match
      - any `*-exporter` (node-exporter, blackbox-exporter, ...) is excluded
      - separators normalised (`_` ↔ `-`) so `kube_system` == `kube-system`

    Pure string logic — no data reads (MCP-only invariant preserved).
    """
    if not service:
        return False

    def _norm(s: str) -> str:
        # Lowercase, unify separators so `otel_collector` == `otel-collector`.
        return re.sub(r"[_\s]+", "-", str(s).strip().lower())

    svc = _norm(service)
    if not svc or svc == "-unknown":
        return False

    # Container-name forms: strip an `ai-mcp-` or `ai-` prefix used by the
    # platform's container names (ai-mcp-prometheus, ai-otel-collector, ...).
    candidates = {svc}
    for prefix in ("ai-mcp-", "ai-"):
        if svc.startswith(prefix):
            candidates.add(svc[len(prefix):])

    # Any exporter is infra noise.
    if any(c.endswith("-exporter") or c == "exporter" for c in candidates):
        return True

    denylist = {_norm(s) for s in settings.drain3_excluded_services}
    return any(c in denylist for c in candidates)


def is_empty_log_body(log_line: str) -> bool:
    """True when a log line carries no minable content and must NOT seed a
    template. Two shapes seen live (2026-06-09 alert-quality audit):

      1. Raw blank lines — `""` / `"\n"` / pure whitespace.
      2. OTel/JSON-wrapped records whose `body` is empty/whitespace, e.g.
         `{"body":"\n","attributes":{...}}`. The surrounding JSON is non-empty
         so a naive `.strip()` misses it; drain3 was mining the *envelope* and
         minting a fresh "novel template" on every batch (the attributes carry
         rotating file names / instance ids).

    Conservative: only fires when the body is provably empty. A JSON object
    WITH a non-empty body, or any non-JSON line with visible text, returns
    False and is mined as before — no reshuffling of existing templates.
    """
    if log_line is None:
        return True
    stripped = log_line.strip()
    if not stripped:
        return True
    # JSON-wrapped record: inspect the `body` field only.
    if stripped[0] == "{" and '"body"' in stripped:
        try:
            obj = json.loads(stripped)
        except (ValueError, TypeError):
            return False
        if isinstance(obj, dict) and "body" in obj:
            body = obj.get("body")
            if body is None:
                return True
            if isinstance(body, str) and not body.strip():
                return True
    return False


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
        # S5-DRN-01 — per-(tier, scope) cooldown timestamps so a component alert
        # for "cart" never blocks a system alert (or an app alert for its app).
        self._tier_alert_ts: dict[tuple[str, str], float] = {}
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

        BE-B3: if `service` is on the observability/infra exclusion denylist
        the line is dropped at this boundary — NO miner is created, NO line is
        counted, NO anomaly can be produced. Returns an `excluded` sentinel so
        callers can tally skipped lines.
        """
        if is_excluded_service(service):
            return AnalyzeResult(
                cluster_id=None,
                template="",
                is_new_pattern=False,
                match_count=0,
                service=service,
                excluded=True,
            )
        # 2026-06-09 (alert-quality audit, RC-1): empty/whitespace bodies (incl.
        # JSON-wrapped `{"body":"\n",...}` records) carry no minable content and
        # were minting a fresh "novel template" every batch. Drop them at the
        # boundary like an excluded service — no miner touched, no anomaly.
        if is_empty_log_body(log_line):
            return AnalyzeResult(
                cluster_id=None,
                template="",
                is_new_pattern=False,
                match_count=0,
                service=service,
                excluded=True,
            )
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

        BE-B3: if `service` is on the observability/infra exclusion denylist
        the whole batch is dropped from the miner (no annotation, no anomaly).
        """
        if is_excluded_service(service):
            logger.debug(
                "Drain3 BE-B3: skipped %d line(s) for excluded service=%s",
                len(lines), service,
            )
            return [], (
                f"Anomaly Summary: service={service} is an excluded "
                f"observability/infra source; {len(lines)} line(s) not ingested."
            )
        annotated = []
        anomaly_count = 0
        new_patterns = 0
        emitted = 0
        for line in lines:
            result = self.analyze(line, service=service)
            # 2026-06-09 (RC-1 follow-up): empty/excluded lines carry no signal —
            # never annotate them [ANOMALY] or count them in the denominator.
            if getattr(result, "excluded", False):
                continue
            emitted += 1
            if result.is_new_pattern or result.match_count < settings.drain3_anomaly_threshold:
                annotated.append(f"[ANOMALY] {line}")
                anomaly_count += 1
                if result.is_new_pattern:
                    new_patterns += 1
            else:
                annotated.append(f"[KNOWN] {line}")
        summary = (
            f"Anomaly Summary: {anomaly_count} of {emitted} lines anomalous "
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
        skipped = 0
        for svc, lines in streams:
            # BE-B3 — drop whole excluded streams up front (cheaper, and avoids
            # a per-line denylist check for the common infra-flood case).
            if is_excluded_service(svc):
                skipped += len(lines)
                continue
            for line in lines:
                try:
                    self.analyze(line, service=svc)
                except Exception as e:
                    logger.debug("Drain3 analyze failed (non-fatal): %s", e)
        if skipped:
            logger.debug("Drain3 BE-B3 seed: skipped %d excluded infra line(s)", skipped)

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
                        # Group lines by (service, application) so each batch
                        # carries the component + app breakdown the 3 tiers need.
                        streams_with_app: list[tuple[str, str, list[str]]] = []
                        for stream in data.get("data", {}).get("result", []):
                            labels = stream.get("stream", {})
                            svc = _service_from_stream_labels(labels)
                            app = _app_from_stream_labels(labels, svc)
                            lines = [line for _ts, line in stream.get("values", [])]
                            if lines:
                                streams_with_app.append((svc, app, lines))
                        if streams_with_app:
                            batch = await asyncio.to_thread(
                                self._ingest_batch_structured, streams_with_app
                            )
                            await self.maybe_fire_alerts(batch)
                    else:
                        logger.debug("Drain3 Loki poll returned %d", resp.status_code)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Drain3 background ingestion error: %s", e)

    def _ingest_batch_structured(
        self, streams: list[tuple[str, str, list[str]]]
    ) -> BatchResult:
        """S5-DRN-01 — ingest a batch of (service, application, lines) and return
        a BatchResult with the per-component AND per-application breakdown the
        three tiers need. BE-B3 exclusion is applied per stream."""
        batch = BatchResult()
        seen_templates: set = set()   # (svc, cluster_id) dedup across the batch
        skipped = 0
        for svc, app, lines in streams:
            # BE-B3 — observability/infra streams never enter the miner.
            if is_excluded_service(svc):
                skipped += len(lines)
                continue
            svc_c = batch.per_service.setdefault(svc, ScopeCounts())
            app_c = batch.per_app.setdefault(app, ScopeCounts())
            batch.app_components.setdefault(app, set()).add(svc)
            for line in lines:
                try:
                    result = self.analyze(line, service=svc)
                    # 2026-06-09 (RC-1 follow-up, general-cycle backend finding):
                    # an empty/excluded line (is_empty_log_body → excluded sentinel)
                    # carries no signal — it must count as NEITHER a line nor an
                    # anomaly. Counting it before this check let `match_count=0 <
                    # threshold` mark it anomalous and inflate anomaly_rate (the
                    # opposite of RC-1's intent). Skip it entirely.
                    if getattr(result, "excluded", False):
                        continue
                    batch.total_lines += 1
                    svc_c.lines += 1
                    app_c.lines += 1
                    if result.is_new_pattern or result.match_count < settings.drain3_anomaly_threshold:
                        batch.total_anomalous += 1
                        svc_c.anomalous += 1
                        app_c.anomalous += 1
                        if len(svc_c.sample_lines) < 50:
                            svc_c.sample_lines.append(line)
                        if len(app_c.sample_lines) < 50:
                            app_c.sample_lines.append(line)
                    if result.is_new_pattern and result.cluster_id is not None:
                        key = (svc, result.cluster_id)
                        if key not in seen_templates:
                            seen_templates.add(key)
                            svc_c.new_templates.append(result.template)
                            app_c.new_templates.append(result.template)
                except Exception as e:
                    logger.debug("Drain3 analyze failed for one line (non-fatal): %s", e)
        if skipped:
            logger.debug("Drain3 BE-B3 ingest: skipped %d excluded infra line(s)", skipped)
        return batch

    def _ingest_batch_sync_streams(
        self, streams: list[tuple[str, list[str]]]
    ) -> tuple[list[str], list[str]]:
        """Back-compat tuple adapter (per-service shape, no app labels). Resolves
        each service's app via the app_map/service fallback, runs the structured
        ingest, and flattens to the legacy (anomalous_lines, new_templates)."""
        with_app = [
            (svc, _app_from_stream_labels({}, svc), lines) for svc, lines in streams
        ]
        batch = self._ingest_batch_structured(with_app)
        return batch.all_anomalous_lines(), batch.all_new_templates()

    # Backwards-compat shim for any callers still using the flat-list shape.
    def _ingest_batch_sync(self, lines: list[str]) -> tuple[list[str], list[str]]:
        """Flat-list shim. Routes everything to `_unknown`. Tests that
        don't have a service label use this path."""
        return self._ingest_batch_sync_streams([("_unknown", lines)])

    # ------------------------------------------------------------------
    # Self-alerting — S5-DRN-01 3-tier (component / application / system)
    # ------------------------------------------------------------------

    async def maybe_fire_alerts(self, batch: BatchResult) -> None:
        """Evaluate all three tiers INDEPENDENTLY for this batch. Each tier fires
        its own scopes (system="all", application=app name, component=service),
        each gated by a per-(tier, scope) cooldown, and capped per tier per batch
        to prevent an incident from spawning an alert storm."""
        if not settings.drain3_alert_enabled:
            return

        # (tier, threshold, min_lines, scope->counts dict)
        tiers = [
            ("system", settings.drain3_alert_rate_threshold,
             settings.drain3_alert_min_lines,
             {"all": ScopeCounts(
                 lines=batch.total_lines, anomalous=batch.total_anomalous,
                 new_templates=batch.all_new_templates()[:20],
                 sample_lines=batch.all_anomalous_lines()[:50])}),
            ("application", settings.drain3_app_rate_threshold,
             settings.drain3_app_min_lines, batch.per_app),
            ("component", settings.drain3_component_rate_threshold,
             settings.drain3_component_min_lines, batch.per_service),
        ]

        for tier, threshold, min_lines, scopes in tiers:
            # Candidate scopes that cross this tier's bar.
            candidates = [
                (scope, c) for scope, c in scopes.items()
                if c.lines >= min_lines and c.rate >= threshold
            ]
            if tier == "application":
                # Skip an app whose only component already qualifies at the
                # component tier AND the app name == that single service — that
                # would be a pure duplicate. Multi-component apps still fire.
                candidates = [
                    (scope, c) for scope, c in candidates
                    if not (len(batch.app_components.get(scope, set())) <= 1
                            and scope in batch.per_service)
                ]
            # Highest-rate scopes first, then apply the per-tier cap.
            candidates.sort(key=lambda sc: sc[1].rate, reverse=True)
            cap = settings.drain3_max_alerts_per_tier_per_batch
            if len(candidates) > cap:
                logger.warning(
                    "Drain3 %s tier: %d scopes crossed threshold; capping to %d "
                    "(suppressed %d this batch)",
                    tier, len(candidates), cap, len(candidates) - cap,
                )
                candidates = candidates[:cap]
            for scope, counts in candidates:
                # Fix C (2026-06-11): name the REAL emitting services so the
                # pipeline can scope the cross-reference to them.
                if tier == "component":
                    emitters = [scope]
                elif tier == "application":
                    members = batch.app_components.get(scope, set())
                    emitters = sorted(
                        members,
                        key=lambda svc: batch.per_service.get(svc, ScopeCounts()).anomalous,
                        reverse=True,
                    )
                else:  # system
                    emitters = [
                        svc for svc, sc in sorted(
                            batch.per_service.items(),
                            key=lambda kv: kv[1].anomalous, reverse=True,
                        ) if sc.anomalous > 0
                    ]
                await self._fire_one(tier, scope, counts, services=emitters)

    async def _fire_one(self, tier: str, scope: str, counts: "ScopeCounts",
                        services: list[str] | None = None) -> None:
        """Fire a single drain3 self-alert for (tier, scope), respecting the
        per-(tier, scope) cooldown."""
        import time as _time
        now = _time.monotonic()
        cooldown = settings.drain3_alert_cooldown_seconds
        last = self._tier_alert_ts.get((tier, scope), 0.0)
        if last and (now - last) < cooldown:
            logger.info(
                "Drain3 %s/%s rate %.2f crossed threshold but within cooldown "
                "(%.0fs remaining)", tier, scope, counts.rate, cooldown - (now - last),
            )
            return
        from datetime import datetime, timezone
        payload = {
            "anomalous_lines": counts.sample_lines[:50],
            "anomaly_rate": round(counts.rate, 4),
            "new_templates": counts.new_templates[:20],
            # `service` carries the scope so the dashboard/dedup key it sensibly:
            # the component name, the app name, or "drain3" for system-wide.
            "service": scope if tier != "system" else "drain3",
            "tier": tier,
            "scope": scope,
            "services": (services or [])[:5],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(settings.drain3_self_webhook_url, json=payload)
                if resp.status_code in (200, 202):
                    self._tier_alert_ts[(tier, scope)] = now
                    logger.warning(
                        "Drain3 %s-tier self-alert fired: scope=%s rate=%.2f "
                        "(%d/%d lines), webhook=%d",
                        tier, scope, counts.rate, counts.anomalous, counts.lines,
                        resp.status_code,
                    )
                else:
                    logger.warning(
                        "Drain3 %s/%s self-alert webhook returned %d — %s",
                        tier, scope, resp.status_code, resp.text[:100],
                    )
        except (httpx.HTTPError, OSError) as e:
            logger.warning("Drain3 %s/%s self-alert webhook failed: %s", tier, scope, e)

    # ------------------------------------------------------------------
    # Self-alerting — legacy single-tier (kept for back-compat / direct callers)
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
