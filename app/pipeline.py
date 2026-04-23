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
    alerts_suppressed,
    drain3_anomalies,
    drain3_clusters,
    drain3_lines_processed,
    emails_sent,
    llm_duration,
    pipeline_duration,
    pipeline_timeouts,
    triage_queue_depth,
)
from app.models import Decision, Drain3Webhook, GrafanaAlert, GrafanaWebhook, RCARecord
from app.notifier import EmailNotifier
from app.rca_store import RCAStore, _classify_rca_quality

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

        # Step 1b (AI-04, Layer 2): Pre-LLM suppression.
        # If the same (alert_name, service) was dismissed within the lookback
        # window, dismiss again without paying the Ollama cost. Gates on
        # settings.triage_suppression_enabled so it can be disabled at runtime.
        suppression_reason = await self._check_suppression(alert)
        if suppression_reason is not None:
            elapsed_ms = int((time.monotonic() - pipeline_start) * 1000)
            alerts_suppressed.labels(reason=suppression_reason).inc()
            logger.info(
                "Alert %s SUPPRESSED pre-LLM: %s (%dms)",
                alert.alertname, suppression_reason, elapsed_ms,
            )
            record = RCARecord(
                alert_source=source,
                alert_name=alert.alertname,
                alert_fingerprint=alert.fingerprint,
                affected_service=alert.service,
                severity=alert.severity,
                triage_decision="triage_suppressed",
                llm_verdict=None,
                rca_report=f"Suppressed by Layer 2 triage: {suppression_reason}",
                llm_reasoning=None,
                action_taken="suppressed",
                investigation_duration_ms=elapsed_ms,
            )
            await self.store.save_decision(record)
            return

        # Track queue depth
        triage_queue_depth.inc()
        try:
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
        finally:
            triage_queue_depth.dec()

    async def _check_suppression(self, alert: GrafanaAlert) -> str | None:
        """Return a non-None reason string if this alert should skip LLM.

        Current rule: if we produced a DISMISS (or prior suppression) for the
        same (alert_name, affected_service) within the lookback window, skip
        the Ollama call and replay the suppression. Keeps demo-day CPU budget
        from being spent on noise.
        """
        if not settings.triage_suppression_enabled:
            return None
        recent = await self.store.get_recent_decision_for_alert(
            alert_name=alert.alertname,
            affected_service=alert.service,
            lookback_minutes=settings.triage_history_lookback_minutes,
        )
        if not recent:
            return None
        verdict = (recent.get("llm_verdict") or "").lower()
        triage_decision = (recent.get("triage_decision") or "").lower()
        if verdict == "dismiss":
            return "recent_dismissed_history"
        if triage_decision == "triage_suppressed":
            return "recent_suppressed_history"
        return None

    async def _investigate_and_act(
        self, alert: GrafanaAlert, source: str, pipeline_start: float
    ):
        # Step 3: Gather context from all three pillars
        ctx = await self.context.gather(alert)

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

        # Step 5: Check RCA history for prior occurrences, plus any past
        # decisions that were tagged data_starved. The latter get quoted
        # verbatim back to the LLM so it sees its own past hedges and
        # avoids repeating them in this round's RCA.
        history = await self.store.get_alert_frequency(alert.alertname)
        history_context = ""
        if history["count"] > 0:
            history_context = (
                f"This alert has fired {history['count']} time(s) in the last "
                f"{history['days']} days. Last seen: {history['last_seen']}.\n"
            )
            if history.get("data_starved_count", 0) > 0:
                prior_hedges = await self.store.get_recent_data_starved_rcas(
                    alert_name=alert.alertname,
                    affected_service=alert.service,
                    limit=3,
                )
                if prior_hedges:
                    history_context += (
                        f"\n⚠ {history['data_starved_count']} recent decision(s) for this alert "
                        f"were tagged data_starved — the model hedged with 'insufficient data' "
                        f"or similar rather than naming a cause. Examples to avoid repeating:\n"
                    )
                    for i, h in enumerate(prior_hedges, 1):
                        rca = (h.get("rca_report") or "").replace("\n", " ")[:200]
                        history_context += f"  [{i}] {h['timestamp'][:19]}: \"{rca}\"\n"
                    history_context += (
                        "\nDo not repeat these phrasings. Use the observed metric value "
                        "from the alert above as your primary evidence, and propose a "
                        "specific hypothesis even if the MCP pillars are thin."
                    )

        # Step 6: Call LLM
        decision, llm_ms = await self.llm.investigate(
            alert, ctx, anomaly_summary, history_context
        )
        llm_duration.observe(llm_ms / 1000)

        # Step 6b: If the first-pass RCA looks data-starved, give the LLM ONE
        # more shot with an explicit "you hedged — do better" instruction
        # appended to the history context. Only retry if the gate is on and
        # we haven't already spent too much of the pipeline budget.
        quality = _classify_rca_quality(decision.rca, decision.reason)
        total_so_far = int((time.monotonic() - pipeline_start) * 1000)
        retry_budget_ms = settings.pipeline_timeout * 1000 - total_so_far - 5000  # 5s safety margin
        if (
            quality == "data_starved"
            and settings.triage_data_starved_retry_enabled
            and retry_budget_ms > 10_000
        ):
            logger.warning(
                "First-pass RCA tagged data_starved (verdict=%s) — retrying with anti-hedge prompt",
                decision.decision.value,
            )
            retry_history = history_context + (
                "\n\n⚠ RETRY — your first response just said 'insufficient data' without naming a cause. "
                "Look at the alert's PromQL and observed value above: those ARE data. "
                "Even if the three pillars came back thin, propose a concrete hypothesis (e.g. "
                "'load-test traffic spiked node CPU; CPU-throttling the triage container is the "
                "likely secondary effect') and two specific commands/queries a human can run to confirm. "
                "Do NOT use the phrases 'insufficient data', 'cannot determine', or 'no recent data' in this response."
            )
            retry_decision, retry_ms = await self.llm.investigate(
                alert, ctx, anomaly_summary, retry_history
            )
            llm_duration.observe(retry_ms / 1000)
            llm_ms += retry_ms
            retry_quality = _classify_rca_quality(retry_decision.rca, retry_decision.reason)
            if retry_quality == "actionable":
                logger.info("Retry produced actionable RCA — replacing first-pass verdict")
                decision = retry_decision
                quality = "actionable"
            else:
                logger.info("Retry still data_starved — keeping first-pass verdict, tagging as data_starved")

        elapsed_ms = int((time.monotonic() - pipeline_start) * 1000)
        pipeline_duration.observe(elapsed_ms / 1000)

        logger.info(
            "LLM verdict for %s: %s (quality=%s, %dms total)",
            alert.alertname,
            decision.decision.value,
            quality,
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
            rca_quality=quality,  # pre-computed, saves store from re-running the classifier
        )

        # Step 8: Act on decision. A notifier failure (SMTP hiccup, template
        # rendering bug) must not block Step 9 — otherwise we'd lose the RCA
        # record for an alert the LLM actually finished. Save-first would be
        # cleaner but persisting before emailing breaks ordering guarantees
        # elsewhere; wrap-and-log is the safer change.
        if decision.decision == Decision.ESCALATE:
            try:
                await self.notifier.send_escalation(alert, decision, record, history["count"], ctx=ctx)
                emails_sent.labels(type="escalation").inc()
                alerts_processed.labels(decision="escalate").inc()
            except Exception as notify_exc:
                logger.error(
                    "Escalation email failed for %s (%s) — decision still recorded",
                    alert.alertname, notify_exc, exc_info=True,
                )
                emails_sent.labels(type="escalation_failed").inc()
                alerts_processed.labels(decision="escalate").inc()
        else:
            alerts_processed.labels(decision="dismiss").inc()
            logger.info(
                "Alert %s DISMISSED: %s", alert.alertname, decision.reason
            )

        # Step 9: Save to RCA history (always — even on notifier failure)
        await self.store.save_decision(record)
