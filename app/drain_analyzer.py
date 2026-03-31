import asyncio
import logging
import os
from dataclasses import dataclass

import httpx
from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence

from app.config import settings

logger = logging.getLogger(__name__)


@dataclass
class AnalyzeResult:
    cluster_id: int | None
    template: str
    is_new_pattern: bool
    match_count: int


class DrainAnalyzer:
    def __init__(self):
        os.makedirs(settings.drain3_state_dir, exist_ok=True)
        persistence = FilePersistence(
            os.path.join(settings.drain3_state_dir, "drain3_state.bin")
        )
        self._miner = TemplateMiner(persistence, config_filename="drain3.ini")
        self._total_lines = 0
        self._total_anomalies = 0
        self._background_task: asyncio.Task | None = None

    def analyze(self, log_line: str) -> AnalyzeResult:
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
            result = self.analyze(line)
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
        """Fetch recent logs from Loki and feed through Drain3 to build baseline."""
        logger.info("Seeding Drain3 from Loki...")
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{settings.loki_api_url}/loki/api/v1/query_range",
                    params={
                        "query": '{service_name=~".+"}',
                        "limit": 1000,
                        "start": "1h",
                    },
                )
                if resp.status_code != 200:
                    logger.warning("Loki seed query failed: %d", resp.status_code)
                    return

                data = resp.json()
                count = 0
                for stream in data.get("data", {}).get("result", []):
                    for _ts, line in stream.get("values", []):
                        self._miner.add_log_message(line)
                        count += 1

                logger.info("Drain3 seeded with %d log lines from Loki", count)
        except Exception as e:
            logger.warning("Drain3 Loki seeding failed (non-fatal): %s", e)

    async def start_background_ingestion(self):
        """Continuously poll Loki for new logs to keep Drain3 templates current."""
        self._background_task = asyncio.create_task(self._ingest_loop())

    async def _ingest_loop(self):
        while True:
            try:
                await asyncio.sleep(settings.drain3_poll_interval)
                async with httpx.AsyncClient(timeout=15) as client:
                    resp = await client.get(
                        f"{settings.loki_api_url}/loki/api/v1/query_range",
                        params={
                            "query": '{service_name=~".+"}',
                            "limit": 200,
                            "start": f"{settings.drain3_poll_interval}s",
                        },
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        for stream in data.get("data", {}).get("result", []):
                            for _ts, line in stream.get("values", []):
                                self._miner.add_log_message(line)
                                self._total_lines += 1
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Drain3 background ingestion error: %s", e)

    async def stop_background_ingestion(self):
        if self._background_task:
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass
