import asyncio
import logging
import time
from datetime import datetime

from app.config import settings
from app.context import ContextGatherer
from app.dedup import DedupManager
from app.drain_analyzer import DrainAnalyzer
from app.llm_client import LLMClient
from app.metrics import (
    alerts_deduplicated,
    alerts_processed,
    drain3_anomalies,
    drain3_clusters,
    drain3_lines_processed,
    emails_sent,
    llm_duration,
    pipeline_duration,
    pipeline_timeouts,
)
from app.models import Decision, Drain3Webhook, GrafanaAlert, GrafanaWebhook, RCARecord
from app.notifier import EmailNotifier
from app.rca_store import RCAStore

logger = logging.getLogger(__name__)


class TriagePipeline:
    def __init__(
        self,
        rca_store: RCAStore,
        drain: DrainAnalyzer,
        context_gatherer: ContextGatherer,
        llm_client: LLMClient,
        notifier: EmailNotifier,
        dedup: DedupManager,
    ):
        self.store = rca_store
        self.drain = drain
        self.context = context_gatherer
        self.llm = llm_client
        self.notifier = notifier
        self.dedup = dedup

    async def process_grafana_webhook(self, webhook: GrafanaWebhook):
        for alert in webhook.alerts:
            try:
                await self._process_alert(alert, source="grafana")
            except Exception as e:
                logger.error("Unhandled error processing alert %s: %s", alert.alertname, e, exc_info=True)

    async def process_drain3_webhook(self, webhook: Drain3Webhook):
        # Create a synthetic alert from Drain3 anomaly data
        alert = GrafanaAlert(
            status="firing",
            labels={
                "alertname": "Drain3AnomalyDetected",
                "service": webhook.service,
                "severity": "warning",
            },
            annotations={
                "summary": f"Drain3 detected {len(webhook.anomalous_lines)} anomalous log lines",
                "description": f"Anomaly rate: {webhook.anomaly_rate:.2%}. New templates: {len(webhook.new_templates)}",
            },
            startsAt=webhook.timestamp or datetime.utcnow().isoformat(),
            fingerprint=f"drain3-{webhook.service}",
        )
        try:
            await self._process_alert(alert, source="drain3")
        except Exception as e:
            logger.error("Unhandled error processing Drain3 alert: %s", e, exc_info=True)

    async def _process_alert(self, alert: GrafanaAlert, source: str):
        pipeline_start = time.monotonic()

        # Step 1: Deduplication
        is_dup = await self.dedup.check(alert.alertname, alert.instance, alert.status)
        if is_dup:
            alerts_deduplicated.inc()
            logger.info("Alert %s deduplicated — skipping", alert.alertname)
            return

        # Step 2: Pipeline with timeout fallback
        try:
            await asyncio.wait_for(
                self._investigate_and_act(alert, source, pipeline_start),
                timeout=settings.pipeline_timeout,
            )
        except asyncio.TimeoutError:
            elapsed_ms = int((time.monotonic() - pipeline_start) * 1000)
            pipeline_timeouts.inc()
            logger.error(
                "Pipeline timeout after %dms for alert %s — sending raw alert",
                elapsed_ms,
                alert.alertname,
            )

            # Send raw alert email as safety fallback
            await self.notifier.send_timeout_alert(alert)
            emails_sent.labels(type="timeout").inc()

            # Record timeout in RCA history
            record = RCARecord(
                alert_source=source,
                alert_name=alert.alertname,
                alert_fingerprint=alert.fingerprint,
                affected_service=alert.service,
                severity=alert.severity,
                triage_decision="timeout_passthrough",
                action_taken="emailed_raw",
                investigation_duration_ms=elapsed_ms,
            )
            await self.store.save_decision(record)

    async def _investigate_and_act(
        self, alert: GrafanaAlert, source: str, pipeline_start: float
    ):
        # Step 3: Gather context from all three pillars
        ctx = await self.context.gather(alert.alertname, alert.service, alert.startsAt)

        # Step 4: Annotate logs with Drain3
        annotated_logs = []
        anomaly_summary = ""
        if ctx.logs:
            annotated_logs, anomaly_summary = self.drain.annotate_lines(ctx.logs)
            ctx.annotated_logs = annotated_logs
            ctx.anomaly_summary = anomaly_summary

            # Update Drain3 metrics
            drain3_lines_processed.inc(len(ctx.logs))
            drain3_anomalies.inc(sum(1 for l in annotated_logs if l.startswith("[ANOMALY]")))
            drain3_clusters.set(self.drain.get_stats()["total_clusters"])

        # Step 5: Check RCA history for prior occurrences
        history = await self.store.get_alert_frequency(alert.alertname)
        history_context = ""
        if history["count"] > 0:
            history_context = (
                f"This alert has fired {history['count']} time(s) in the last "
                f"{history['days']} days. Last seen: {history['last_seen']}."
            )

        # Step 6: Call LLM
        decision, llm_ms = await self.llm.investigate(
            alert, ctx, anomaly_summary, history_context
        )
        llm_duration.observe(llm_ms / 1000)

        elapsed_ms = int((time.monotonic() - pipeline_start) * 1000)
        pipeline_duration.observe(elapsed_ms / 1000)

        logger.info(
            "LLM verdict for %s: %s (confidence implied by reasoning, %dms total)",
            alert.alertname,
            decision.decision.value,
            elapsed_ms,
        )

        # Step 7: Build RCA record
        record = RCARecord(
            alert_source=source,
            alert_name=alert.alertname,
            alert_fingerprint=alert.fingerprint,
            affected_service=alert.service,
            severity=decision.severity,
            triage_decision="investigate",
            llm_verdict=decision.decision.value.lower(),
            llm_confidence=None,
            rca_report=decision.rca,
            llm_reasoning=decision.reason,
            action_taken="emailed" if decision.decision == Decision.ESCALATE else "suppressed",
            investigation_duration_ms=elapsed_ms,
        )

        # Step 8: Act on decision
        if decision.decision == Decision.ESCALATE:
            await self.notifier.send_escalation(alert, decision, record, history["count"])
            emails_sent.labels(type="escalation").inc()
            alerts_processed.labels(decision="escalate").inc()
        else:
            alerts_processed.labels(decision="dismiss").inc()
            logger.info(
                "Alert %s DISMISSED: %s", alert.alertname, decision.reason
            )

        # Step 9: Save to RCA history
        await self.store.save_decision(record)
