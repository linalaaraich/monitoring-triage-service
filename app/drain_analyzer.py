import asyncio
import logging
import os
import threading
from dataclasses import dataclass

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


class DrainAnalyzer:
    """Drain3 log-template miner with a threading.Lock so sync drain3 calls
    can safely run from a thread pool without corrupting shared state.

    All methods that touch `self._miner` MUST hold `self._lock`. Callers
    from async code should wrap in `asyncio.to_thread(...)` so the event
    loop doesn't block on Drain3's internal work (tokenization, tree walks,
    and the FilePersistence disk writes which can spike to 100s of ms when
    the state file grows large).

    Found the hard way: the background ingest loop used to do 200
    add_log_message calls back-to-back on the event loop, which blocked
    /drain3/stats HTTP handlers for 15+ seconds per poll.
    """

    def __init__(self):
        os.makedirs(settings.drain3_state_dir, exist_ok=True)
        persistence = FilePersistence(
            os.path.join(settings.drain3_state_dir, "drain3_state.bin")
        )
        config = TemplateMinerConfig()
        for path in ["drain3.ini", os.path.join(os.path.dirname(__file__), "..", "drain3.ini")]:
            if os.path.exists(path):
                config.load(path)
                break
        self._miner = TemplateMiner(persistence, config=config)
        self._total_lines = 0
        self._total_anomalies = 0
        self._background_task: asyncio.Task | None = None
        # Guards every read/write of self._miner, _total_lines, _total_anomalies.
        self._lock = threading.Lock()

        # P1.7 — self-alerting state. After each ingest batch we compare
        # the current batch's anomaly rate against the threshold; if
        # crossed + cooldown OK, POST a Drain3Webhook to our own
        # /webhook/drain3 endpoint so anomalies show up as a visible
        # alert source on the dashboard.
        self._last_alert_ts: float = 0.0  # monotonic, 0 = never fired

    def analyze(self, log_line: str) -> AnalyzeResult:
        with self._lock:
            result = self._miner.add_log_message(log_line)
            self._total_lines += 1

            cluster = result.get("cluster_id")
            template = result.get("template_mined", "")
            change_type = result.get("change_type", "none")
            is_new = change_type in ("cluster_created", "cluster_template_changed")

            match_count = 0
            if cluster is not None:
                for c in self._miner.drain.clusters:
                    if c.cluster_id == cluster:
                        match_count = c.size
                        break

            if is_new or match_count < settings.drain3_anomaly_threshold:
                self._total_anomalies += 1

            return AnalyzeResult(
                cluster_id=cluster,
                template=template,
                is_new_pattern=is_new,
                match_count=match_count,
            )

    def annotate_lines(self, lines: list[str]) -> tuple[list[str], str]:
        """Annotate log lines with [ANOMALY] or [KNOWN] prefix.
        Returns (annotated_lines, anomaly_summary)."""
        annotated = []
        anomaly_count = 0
        new_patterns = 0

        for line in lines:
            result = self.analyze(line)  # takes its own lock
            if result.is_new_pattern or result.match_count < settings.drain3_anomaly_threshold:
                annotated.append(f"[ANOMALY] {line}")
                anomaly_count += 1
                if result.is_new_pattern:
                    new_patterns += 1
            else:
                annotated.append(f"[KNOWN] {line}")

        summary = (
            f"Anomaly Summary: {anomaly_count} of {len(lines)} lines anomalous. "
            f"{new_patterns} new patterns detected."
        )
        return annotated, summary

    def get_stats(self) -> dict:
        with self._lock:
            clusters = self._miner.drain.clusters
            total = len(clusters)
            rate = self._total_anomalies / max(self._total_lines, 1)

            recent_new = [
                c.get_template()
                for c in sorted(clusters, key=lambda c: c.cluster_id, reverse=True)[:5]
            ]

            return {
                "total_clusters": total,
                "recent_anomaly_rate": round(rate, 4),
                "top_new_patterns": recent_new,
                "total_lines_processed": self._total_lines,
                "total_anomalies": self._total_anomalies,
            }

    async def seed_from_loki(self):
        """Fetch recent logs from Loki and feed through Drain3 to build baseline.

        Runs on startup before the HTTP server starts serving, so blocking the
        event loop briefly here is OK — no handlers are waiting.
        """
        import time as _time
        logger.info("Seeding Drain3 from Loki...")
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
                lines: list[str] = []
                for stream in data.get("data", {}).get("result", []):
                    for _ts, line in stream.get("values", []):
                        lines.append(line)

                if lines:
                    # Still offload to a thread — 1000 lines * 20ms can run
                    # seconds even at startup, and it lets `await startup` be
                    # non-blocking for the rest of the lifespan setup.
                    await asyncio.to_thread(self._ingest_batch_sync, lines)
                logger.info("Drain3 seeded with %d log lines from Loki", len(lines))
        except Exception as e:
            logger.warning("Drain3 Loki seeding failed (non-fatal): %s", e)

    async def start_background_ingestion(self):
        """Continuously poll Loki for new logs to keep Drain3 templates current."""
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
                        lines: list[str] = []
                        for stream in data.get("data", {}).get("result", []):
                            for _ts, line in stream.get("values", []):
                                lines.append(line)
                        if lines:
                            # Offload the sync drain3 work to a thread so the
                            # event loop stays responsive to /drain3/stats and
                            # other HTTP handlers. Route through analyze() so
                            # anomaly counters actually reflect all observed
                            # traffic, not just alert-time annotate_lines calls.
                            anomalous = await asyncio.to_thread(self._ingest_batch_sync, lines)
                            # P1.7 — if this batch spiked, self-webhook the
                            # triage pipeline so drain3 becomes a visible
                            # alert source on the dashboard.
                            await self.maybe_fire_alert(batch_total=len(lines), anomalous=anomalous)
                    else:
                        logger.debug("Drain3 Loki poll returned %d", resp.status_code)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Drain3 background ingestion error: %s", e)

    def _ingest_batch_sync(self, lines: list[str]) -> list[str]:
        """Process a batch of log lines through analyze() on the calling thread.

        Called from the background ingest loop via asyncio.to_thread. Runs
        analyze() per line (which takes the lock) rather than raw
        add_log_message so _total_anomalies reflects all ingested traffic,
        not just alert-time annotation. This gives the dashboard's Drain3
        panel an accurate anomaly-rate over time instead of stuck at 0.

        Returns the list of anomalous lines seen in THIS batch — the
        caller uses this to decide whether to trigger a self-webhook
        alert (P1.7).
        """
        anomalous_lines: list[str] = []
        for line in lines:
            try:
                result = self.analyze(line)
                if result.is_new_pattern or result.match_count < settings.drain3_anomaly_threshold:
                    anomalous_lines.append(line)
            except Exception as e:
                logger.debug("Drain3 analyze failed for one line (non-fatal): %s", e)
        return anomalous_lines

    async def maybe_fire_alert(self, batch_total: int, anomalous: list[str]) -> None:
        """P1.7: if this batch crossed the alert-rate threshold and we're
        past cooldown, POST a Drain3Webhook to our own /webhook/drain3.

        This is how drain3 shows up as a first-class alert source on the
        dashboard — the endpoint always existed, but nothing was firing
        to it. Called from the ingest loop after each batch.
        """
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

        # Fire self-webhook. Keep the HTTP client short-lived so failures
        # (e.g. triage still starting) don't park a long-running task.
        from datetime import datetime, timezone
        payload = {
            "anomalous_lines": anomalous[:50],   # cap for wire size
            "anomaly_rate": round(rate, 4),
            "new_templates": [],  # Drain3Webhook schema wants this; can be empty
            "service": "drain3",  # routes to the drain3 branch of the triage pipeline
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
        except Exception as e:
            logger.warning("Drain3 self-alert POST failed (non-fatal): %s", e)

    async def stop_background_ingestion(self):
        if self._background_task:
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass

    # --- S3 Snapshot Management ---

    def save_snapshot_to_file(self) -> str:
        """Serialize Drain3 state to a local file. Returns the file path."""
        from datetime import datetime, timezone

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        snapshot_path = os.path.join(settings.drain3_state_dir, f"snapshot_{timestamp}.bin")
        self._miner.save_state("snapshot")
        state_file = os.path.join(settings.drain3_state_dir, "drain3_state.bin")
        if os.path.exists(state_file):
            import shutil
            shutil.copy2(state_file, snapshot_path)
        logger.info("Drain3 snapshot saved to %s", snapshot_path)
        return snapshot_path

    async def upload_snapshot_to_s3(self, bucket: str, prefix: str = "drain3/snapshots"):
        """Upload current Drain3 state to S3 for backup and drift prevention."""
        import boto3
        from datetime import datetime, timezone

        snapshot_path = self.save_snapshot_to_file()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        s3_key = f"{prefix}/{timestamp}.bin"

        try:
            s3 = boto3.client("s3")
            s3.upload_file(snapshot_path, bucket, s3_key)
            logger.info("Drain3 snapshot uploaded to s3://%s/%s", bucket, s3_key)
        except Exception as e:
            logger.error("S3 snapshot upload failed (non-fatal): %s", e)

    async def download_baseline_from_s3(self, bucket: str, prefix: str = "drain3/baselines"):
        """Download the latest known-good baseline from S3 and reinitialize Drain3."""
        import boto3

        try:
            s3 = boto3.client("s3")
            response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix + "/")
            objects = response.get("Contents", [])
            if not objects:
                logger.warning("No baselines found in s3://%s/%s", bucket, prefix)
                return

            latest = sorted(objects, key=lambda o: o["LastModified"], reverse=True)[0]
            s3_key = latest["Key"]
            local_path = os.path.join(settings.drain3_state_dir, "drain3_state.bin")

            s3.download_file(bucket, s3_key, local_path)
            logger.info("Drain3 baseline restored from s3://%s/%s", bucket, s3_key)

            # Reinitialize miner with the downloaded state
            from drain3.file_persistence import FilePersistence
            persistence = FilePersistence(local_path)
            config = TemplateMinerConfig()
            for path in ["drain3.ini", os.path.join(os.path.dirname(__file__), "..", "drain3.ini")]:
                if os.path.exists(path):
                    config.load(path)
                    break
            self._miner = TemplateMiner(persistence, config=config)
            self._total_lines = 0
            self._total_anomalies = 0
        except Exception as e:
            logger.error("S3 baseline download failed (non-fatal): %s", e)

    async def tag_known_good(self, bucket: str):
        """Tag the current state as a known-good baseline in S3."""
        import boto3
        from datetime import datetime, timezone

        snapshot_path = self.save_snapshot_to_file()
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        s3_key = f"drain3/baselines/known-good-{timestamp}.bin"

        try:
            s3 = boto3.client("s3")
            s3.upload_file(snapshot_path, bucket, s3_key)
            logger.info("Drain3 known-good baseline uploaded to s3://%s/%s", bucket, s3_key)
        except Exception as e:
            logger.error("S3 baseline tag failed (non-fatal): %s", e)
