import asyncio
import logging
import time
from datetime import UTC, datetime

from app.config import settings
from app.context import ContextGatherer
from app.dedup import DedupManager
from app.drain_analyzer import DrainAnalyzer
from app.llm_client import LLMClient
from app.metrics import (
    override_forced_escalations,
    recurrence_force_escalated,
    recurrence_gated_pre_llm,
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
    triage_bounded_agency_invocations_total,
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
        # Create a synthetic alert from Drain3 anomaly data.
        #
        # 2026-04-28 fix: previously the description was just count-of-lines +
        # rate, with the actual log content thrown away — every Drain3 RCA
        # in production read "an anomaly was detected" with no clue what the
        # anomaly was. We now surface (a) the actual new template strings
        # and (b) a sample of verbatim anomalous lines into the description,
        # which flows directly into the LLM prompt's "Description" field.
        # Capped to fit the prompt budget but rich enough to ground the RCA.
        templates = (webhook.new_templates or [])[:10]
        sample_lines = (webhook.anomalous_lines or [])[:8]
        evidence_parts = [f"Anomaly rate: {webhook.anomaly_rate:.2%} ({len(webhook.anomalous_lines)} lines flagged in batch)."]
        if templates:
            evidence_parts.append("New log templates seen for the first time:")
            for t in templates:
                evidence_parts.append(f"  • {t[:240]}")
        else:
            evidence_parts.append("No brand-new templates this batch — the anomalies are from rare/under-threshold clusters.")
        if sample_lines:
            evidence_parts.append(f"Sample anomalous lines (verbatim, top {len(sample_lines)} of {len(webhook.anomalous_lines)}):")
            for line in sample_lines:
                evidence_parts.append(f"  • {line[:240]}")
        rich_description = "\n".join(evidence_parts)

        alert = GrafanaAlert(
            status="firing",
            labels={
                "alertname": "Drain3AnomalyDetected",
                "service": webhook.service,
                "severity": "warning",
                "signal": "log",
            },
            annotations={
                "summary": f"Drain3 detected {len(webhook.anomalous_lines)} anomalous log lines (rate {webhook.anomaly_rate:.2%})",
                "description": rich_description,
            },
            startsAt=webhook.timestamp or datetime.now(UTC).replace(tzinfo=None).isoformat(),
            fingerprint=f"drain3-{webhook.service}",
        )
        try:
            await self._process_alert(alert, source="drain3")
        except Exception as e:
            logger.error("Unhandled error processing Drain3 alert: %s", e, exc_info=True)

    async def _process_alert(self, alert: GrafanaAlert, source: str):
        pipeline_start = time.monotonic()

        # Step 1: Deduplication (P1.6 — fingerprint-window).
        # On second+ fire of the same fingerprint within the window, persist
        # a short-path `suppressed_duplicate` record linking to the prior
        # RCA instead of silent drop. Operators see the flap as a compact
        # row, not a gap.
        is_dup, prior_decision_id = await self.dedup.check(alert.fingerprint, alert.status)
        if is_dup:
            alerts_deduplicated.inc()
            logger.info(
                "Alert %s deduplicated (fingerprint=%s, prior_rca=%s) — persisting short-path record",
                alert.alertname, alert.fingerprint[:12] if alert.fingerprint else "-",
                prior_decision_id or "pending",
            )
            # Short-path record so the dashboard shows it
            short = RCARecord(
                alert_source=source,
                alert_name=alert.alertname,
                alert_fingerprint=alert.fingerprint,
                affected_service=alert.service,
                severity=alert.severity,
                triage_decision="suppressed_duplicate",
                llm_verdict=None,
                rca_report=(
                    f"Duplicate fire within {self.dedup.window}s dedup window. "
                    f"See prior RCA {prior_decision_id or '(pending)'} for the full analysis."
                ),
                action_taken=(
                    f"see_previous_rca:{prior_decision_id}" if prior_decision_id else "see_previous_rca:pending"
                ),
                investigation_duration_ms=int((time.monotonic() - pipeline_start) * 1000),
                rca_quality="actionable",
            )
            try:
                await self.store.save_decision(short)
            except Exception as exc:
                logger.warning("Failed to persist suppressed_duplicate record: %s", exc)
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

        # Step 1c (US-5.8 recurrence gate, pre-LLM tier).
        # For opted-in alerts (Grafana annotation `recurrence_gate=...`)
        # whose fingerprint has fired N times within the window, persist a
        # cheap row and skip the LLM. Critical-severity alerts bypass even
        # if they accidentally opt in (defense-in-depth in
        # recurrence_gate._is_critical).
        from app.recurrence_gate import pre_llm_gate as _pre_llm_gate
        gate_result = await _pre_llm_gate(alert, self.store)
        if gate_result is not None:
            elapsed_ms = int((time.monotonic() - pipeline_start) * 1000)
            recurrence_gated_pre_llm.inc()
            logger.info(
                "Alert %s gated pre-LLM by recurrence gate (%dms)",
                alert.alertname, elapsed_ms,
            )
            record = RCARecord(
                alert_source=source,
                alert_name=alert.alertname,
                alert_fingerprint=alert.fingerprint,
                affected_service=alert.service,
                severity=alert.severity,
                triage_decision=gate_result.triage_decision,
                llm_verdict=None,
                rca_report=gate_result.reason,
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
            annotated_logs, anomaly_summary = self.drain.annotate_lines(
                ctx.logs, service=alert.service or "_unknown",
            )
            ctx.annotated_logs = annotated_logs
            ctx.anomaly_summary = anomaly_summary

            # Update Drain3 metrics
            drain3_lines_processed.inc(len(ctx.logs))
            drain3_anomalies.inc(sum(1 for l in annotated_logs if l.startswith("[ANOMALY]")))
            drain3_clusters.set(self.drain.get_stats()["total_clusters"])

        # F-1.5 (live-verify follow-up 2026-04-28 PM): for Drain3 self-fires,
        # the alert.annotations["description"] already carries the rich
        # webhook content (templates + sample lines), but the LLM's prompt
        # uses `drain_summary` (which is `ctx.anomaly_summary`) for the
        # primary anomaly evidence. Loki re-query for service=drain3 returns
        # nothing (the lines are emitted from spring-boot stdout), so
        # drain_summary stays empty unless we pull the description in.
        # Override anomaly_summary for this one path.
        if alert.alertname == "Drain3AnomalyDetected" and source == "drain3":
            rich_desc = (alert.annotations or {}).get("description")
            if rich_desc and len(rich_desc) > 30:
                anomaly_summary = rich_desc
                ctx.anomaly_summary = rich_desc
                logger.info(
                    "Drain3 self-fire: overrode anomaly_summary with webhook's rich evidence (%d chars)",
                    len(rich_desc),
                )

        # Step 5: Check RCA history for prior occurrences, plus any past
        # decisions that were tagged data_starved. The latter get quoted
        # verbatim back to the LLM so it sees its own past hedges and
        # avoids repeating them in this round's RCA. Also look for other
        # alerts that fired within ±5 minutes so the LLM (and the email)
        # can reason about cascades — "this CPU alert fired 30s after a
        # latency alert on the same service" is much more actionable than
        # the CPU alert on its own.
        from datetime import datetime as _dt
        try:
            alert_time = _dt.fromisoformat(alert.startsAt.replace("Z", "+00:00"))
            alert_time = alert_time.replace(tzinfo=None)  # match stored isoformat
        except Exception:
            alert_time = _dt.utcnow()
        correlated = await self.store.get_correlated_alerts(
            fingerprint=alert.fingerprint, at=alert_time, window_minutes=5,
        )
        # Correlation is now rendered as a dedicated prompt section by
        # llm_client._build_prompt (P1.4). No duplication in history_context.
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

        # Step 6: Call LLM. Pre-compute metric facts (P1.1 interpreter) so
        # the prompt carries authoritative ground-truth for the observed
        # value, unit, threshold delta, and deployment type. Correlation
        # (P1.4) becomes a first-class prompt section, moved out of
        # history_context.
        from app.metric_interpreter import interpret as interpret_metric
        from app.response_validator import validate as validate_decision
        metric_facts = interpret_metric(alert)

        # US-5.1 Phase C: fetch behavioral baseline if we have a service
        # label and a recognisable metric. Best-effort — if Prometheus is
        # unreachable or history is thin, get_baseline returns a non-
        # authoritative BaselineFacts and as_prose_line falls back gracefully.
        # Skipped for unknown services / boolean alerts where baseline isn't
        # meaningful (e.g. up=0 has no "Xσ above baseline" interpretation).
        if (
            alert.service
            and alert.service != "unknown"
            and metric_facts.unit not in ("boolean", "")
            and alert.annotations.get("expr")
        ):
            try:
                from app.entity_baselines import get_baseline
                # Use the rule's PromQL expression as the baseline metric.
                # The cache key is (service, metric_expr, window) so distinct
                # alerts on the same service produce distinct baselines.
                metric_facts.baseline = await asyncio.wait_for(
                    get_baseline(
                        prometheus_url="http://" + settings.monitoring_vm_ip + ":9090"
                            if hasattr(settings, "monitoring_vm_ip")
                            else "http://prometheus:9090",
                        service=alert.service,
                        metric=alert.annotations["expr"],
                    ),
                    timeout=8.0,
                )
            except (asyncio.TimeoutError, Exception) as exc:
                logger.debug("Baseline fetch failed (non-fatal): %s", exc)
                # metric_facts.baseline remains None; prompt skips the line
        decision, llm_ms = await self.llm.investigate(
            alert, ctx, anomaly_summary, history_context,
            correlated=correlated,
            metric_facts=metric_facts,
        )
        llm_duration.observe(llm_ms / 1000)

        # P1.3 — Response validator. Prunes vague actions + arch-mismatched
        # commands + records banned-phrase hits. The validator MUTATES
        # decision.suggested_actions (drops rejects), so by the time we hit
        # P1.2 template fallback below, kept_actions is the "real" LLM output.
        validation = validate_decision(
            decision,
            deployment_type=metric_facts.deployment_type,
            confidence_floor=0.3,
            alertname=alert.alertname,
        )
        if validation.violations:
            logger.info(
                "Validator found %d violation(s) for %s: %s",
                len(validation.violations),
                alert.alertname,
                "; ".join(validation.violations[:3]),
            )

        # Step 6b: If the first-pass RCA looks data-starved, give the LLM ONE
        # more shot with an explicit "you hedged — do better" instruction
        # appended to the history context. Only retry if the gate is on and
        # we haven't already spent too much of the pipeline budget.
        # P1.2 — if LLM produced no concrete actions, fall back to the
        # deployment-type-branched template. This is the final backstop
        # against bug #7 (empty suggested_actions on nearly every row).
        # Track the fill source so we can measure template-vs-LLM rates
        # in the evaluation dashboard.
        suggested_actions_source = "llm"
        if not decision.suggested_actions:
            from app.action_templates import fill_template
            templated = fill_template(
                alertname=alert.alertname,
                service=alert.service,
                deployment_type=metric_facts.deployment_type,
                labels=alert.labels,
            )
            if templated:
                decision.suggested_actions = templated
                suggested_actions_source = "template"
                logger.info(
                    "Filled empty suggested_actions from template for %s (deployment=%s, %d actions)",
                    alert.alertname, metric_facts.deployment_type, len(templated),
                )

        quality = _classify_rca_quality(decision.rca, decision.reason, decision.suggested_actions, decision.evidence)
        total_so_far = int((time.monotonic() - pipeline_start) * 1000)
        retry_budget_ms = settings.pipeline_timeout * 1000 - total_so_far - 5000  # 5s safety margin
        # Retry triggers (added 2026-04-28 PM after live-verify):
        #   - data_starved (original): rca_quality classifier returned thin
        #   - surface_only_hit: validator caught a surface-only lede / hedge
        #   - hallucination_hit: per-alert blocklist (F-3) caught a wrong-evidence
        # All three signal "this output is not trustworthy"; retry gives the
        # LLM one shot at fixing itself before we persist the row.
        validator_caught_quality_issue = bool(validation.banned_phrase_hits)
        should_retry_for_quality = (
            quality == "data_starved" or validator_caught_quality_issue
        )
        if (
            should_retry_for_quality
            and settings.triage_data_starved_retry_enabled
            and retry_budget_ms > 10_000
        ):
            retry_decision = None
            retry_ms = 0
            used_agency = False

            if settings.triage_bounded_agency_enabled:
                from app.bounded_agency import (
                    parse_tool_request,
                    execute_tool,
                    tool_result_to_prompt_block,
                )
                logger.info(
                    "First-pass data_starved for %s — invoking bounded-agency retry (P1.5)",
                    alert.alertname,
                )
                parsed, agency_ms = await self.llm.request_tool_or_decide(
                    alert, ctx, anomaly_summary, history_context,
                    correlated=correlated, metric_facts=metric_facts,
                )
                llm_ms += agency_ms
                llm_duration.observe(agency_ms / 1000)

                if parsed is not None:
                    tool_req = parse_tool_request(parsed)
                    if tool_req is not None:
                        # Model asked for one tool call — execute + re-prompt.
                        logger.info(
                            "Agency: LLM requested tool %s with args %s",
                            tool_req.name, tool_req.args,
                        )
                        tool_result = await execute_tool(tool_req, self.context_gatherer, self.store)
                        tool_block = tool_result_to_prompt_block(tool_result)
                        retry_decision, rd_ms = await self.llm.investigate(
                            alert, ctx, anomaly_summary, history_context,
                            correlated=correlated, metric_facts=metric_facts,
                            tool_result_block=tool_block,
                        )
                        llm_duration.observe(rd_ms / 1000)
                        llm_ms += rd_ms
                        retry_ms = agency_ms + rd_ms
                        used_agency = True
                        triage_bounded_agency_invocations_total.labels(outcome="tool_called").inc()
                    else:
                        # Model chose to emit a decision directly without a tool — try to parse
                        try:
                            from app.models import LLMDecision as _LLMDecision
                            retry_decision = _LLMDecision(**parsed)
                            retry_ms = agency_ms
                            used_agency = True
                            triage_bounded_agency_invocations_total.labels(outcome="decided_directly").inc()
                        except Exception as e:
                            logger.debug("Agency response couldn't be parsed as LLMDecision: %s", e)
                            triage_bounded_agency_invocations_total.labels(outcome="no_action").inc()
                else:
                    triage_bounded_agency_invocations_total.labels(outcome="no_action").inc()

            # Plain anti-hedge retry as fallback (bounded-agency disabled
            # or produced nothing usable).
            if retry_decision is None:
                logger.info(
                    "Falling back to plain anti-hedge retry for %s (agency_enabled=%s)",
                    alert.alertname, settings.triage_bounded_agency_enabled,
                )
                retry_history = history_context + (
                    "\n\n⚠ RETRY — your first response just said 'insufficient data' without naming a cause. "
                    "Look at the alert's PromQL and observed value above: those ARE data. "
                    "Even if the three pillars came back thin, propose a concrete hypothesis and two specific "
                    "commands/queries a human can run to confirm. Do NOT use the phrases 'insufficient data', "
                    "'cannot determine', or 'no recent data'."
                )
                retry_decision, fallback_ms = await self.llm.investigate(
                    alert, ctx, anomaly_summary, retry_history,
                    correlated=correlated, metric_facts=metric_facts,
                )
                llm_duration.observe(fallback_ms / 1000)
                llm_ms += fallback_ms
                retry_ms = (retry_ms or 0) + fallback_ms

            retry_quality = _classify_rca_quality(
                retry_decision.rca, retry_decision.reason,
                retry_decision.suggested_actions, retry_decision.evidence,
            )
            # Re-run the validator on retry output (added 2026-04-28 PM-late
            # after live-verify saw surface-only ledes in /decisions despite
            # the first-pass validator catching them — the retry was bypassing
            # validation entirely). This also prunes vague / investigation-only
            # / arch-mismatched actions in retry's suggested_actions in-place.
            retry_validation = validate_decision(
                retry_decision,
                deployment_type=metric_facts.deployment_type,
                confidence_floor=0.3,
                alertname=alert.alertname,
            )
            retry_has_surface_only = any(
                p.startswith("surface-only") or p.startswith("hallucination[")
                for p in retry_validation.banned_phrase_hits
            )
            if retry_quality == "actionable" and not retry_has_surface_only:
                logger.info(
                    "Retry produced actionable RCA, validator clean — replacing first-pass (used_agency=%s)",
                    used_agency,
                )
                decision = retry_decision
                quality = "actionable"
            elif retry_quality == "actionable" and retry_has_surface_only:
                logger.info(
                    "Retry actionable BUT validator caught surface-only/hallucination — keeping first-pass (used_agency=%s, retry_violations=%d)",
                    used_agency, len(retry_validation.violations),
                )
            else:
                logger.info(
                    "Retry still data_starved — keeping first-pass verdict (used_agency=%s)",
                    used_agency,
                )

        elapsed_ms = int((time.monotonic() - pipeline_start) * 1000)
        pipeline_duration.observe(elapsed_ms / 1000)

        # Step 6c (US-5.3): closed-loop feedback override gate. If an
        # operator recently flagged a similar alert as a real incident
        # (alertname + service + ±2h time-of-day match, active window not
        # expired), and this LLM verdict is DISMISS, flip to ESCALATE so
        # the human gets to look at it. The original verdict + reason are
        # preserved in the RCA record for transparency; the prose gets a
        # prepended note about the override so the email reader knows why
        # they got paged on what the LLM thought was noise.
        forced_by_override = False
        if decision.decision == Decision.DISMISS:
            try:
                from datetime import datetime as _dt
                active_overrides = await self.store.get_active_overrides_for_alert(
                    alert_name=alert.alertname,
                    affected_service=alert.service,
                    current_time=_dt.utcnow(),
                )
            except Exception as exc:
                logger.warning(
                    "Override lookup failed (non-fatal — continuing with DISMISS): %s", exc
                )
                active_overrides = []
            if active_overrides:
                ov = active_overrides[0]  # most recent override wins
                logger.info(
                    "Override gate: DISMISS for %s/%s flipped to ESCALATE "
                    "(operator note from %s: %r, active until %s)",
                    alert.alertname, alert.service,
                    ov.get("created_at", "?")[:19],
                    (ov.get("operator_note") or "")[:80],
                    ov.get("active_until", "?")[:19],
                )
                override_forced_escalations.inc()
                forced_by_override = True
                # Flip the verdict + record the override context in the prose
                # so the email + dashboard render the reason for the page.
                decision.decision = Decision.ESCALATE
                override_note = (
                    f"⚠ FORCED ESCALATE BY OPERATOR OVERRIDE — the LLM verdict was "
                    f"DISMISS, but on-call recently flagged a similar alert "
                    f"(alertname + service + ±2h time-of-day) as a real incident "
                    f"on {ov.get('created_at','?')[:19]}"
                )
                if ov.get("operator_note"):
                    override_note += f' (note: "{ov["operator_note"]}")'
                override_note += (
                    f". Override active until {ov.get('active_until','?')[:19]}. "
                    f"If this firing is genuinely routine, POST /feedback/confirm "
                    f"on this decision_id to down-weight the override."
                )
                # Prepend to the existing reason+rca so the LLM's diagnosis
                # is preserved for the operator to evaluate.
                decision.reason = override_note + " | LLM said: " + (decision.reason or "")
                decision.rca = override_note + "\n\n" + (decision.rca or "")

        # Step 6c.5 (US-5.8 post-LLM recurrence gate). Runs AFTER the
        # US-5.3 operator override gate (step 6c) so an explicit operator
        # override always takes precedence over the recurrence heuristic.
        # If the LLM has dismissed this fingerprint M times in the window,
        # force-flip to ESCALATE so a human can decide whether the rule is
        # too noisy or whether there's a real signal the LLM is missing.
        if not forced_by_override and decision.decision == Decision.DISMISS:
            from app.recurrence_gate import post_llm_gate as _post_llm_gate
            recurrence_result = await _post_llm_gate(alert, decision, self.store)
            if recurrence_result is not None:
                recurrence_force_escalated.inc()
                logger.info(
                    "Recurrence post-LLM gate flipping DISMISS to ESCALATE for %s/%s",
                    alert.alertname, alert.service,
                )
                decision.decision = Decision.ESCALATE
                gate_note = (
                    f"⚠ FORCED ESCALATE BY RECURRENCE GATE — "
                    f"{recurrence_result.reason}"
                )
                decision.reason = gate_note + " | LLM said: " + (decision.reason or "")
                decision.rca = gate_note + "\n\n" + (decision.rca or "")
                forced_by_override = True  # piggy-back on existing record-tagging logic

        # Step 6d (F-4): confidence calibration tie-in. The LLM's
        # self-reported confidence has no relationship to validator-
        # pass-rate or rca_quality. Live evidence from 2026-04-28: the
        # model emitted conf=0.95 on a textbook surface-only RCA. Clamp
        # confidence ≤ 0.4 when any of these signal that the output is
        # untrustworthy:
        #   - validator caught a surface-only / hedge pattern
        #   - rca_quality classifier returned data_starved
        #   - first-action template fallback fired (LLM emitted no
        #     state-changing action of its own)
        # The operator sees "low confidence + actionable" and knows to
        # scrutinise. Doesn't change the verdict, only the trust signal.
        confidence_clamped = False
        if decision.confidence is not None and decision.confidence > 0.4:
            surface_only_hit = any(
                "surface-only" in h for h in (validation.banned_phrase_hits or [])
            )
            if surface_only_hit or quality == "data_starved" or suggested_actions_source == "template":
                logger.info(
                    "Confidence calibration (F-4): clamping %.2f → 0.4 (surface=%s, q=%s, actions=%s)",
                    decision.confidence, surface_only_hit, quality, suggested_actions_source,
                )
                decision.confidence = 0.4
                confidence_clamped = True

        logger.info(
            "LLM verdict for %s: %s (quality=%s, %dms total%s%s)",
            alert.alertname,
            decision.decision.value,
            quality,
            elapsed_ms,
            ", forced_by_override=true" if forced_by_override else "",
            ", confidence_clamped=true" if confidence_clamped else "",
        )

        # Step 7: Build RCA record. Persist the rich fields (observed value,
        # PromQL, suggested actions, evidence, correlated alerts) so the
        # dashboard can render them without having to re-query Grafana later.
        import json as _json
        from app.llm_client import pick_primary_value
        # Format observed value once, reuse in both email and dashboard.
        # Uses the shared picker so we don't emit the threshold boolean as
        # the "observed value."
        values = alert.values or {}
        observed_str = ""
        if values:
            primary_ref, primary_val = pick_primary_value(values)
            observed_str = f"{primary_val} (refId={primary_ref})"
            rest = [(k, v) for k, v in sorted(values.items()) if k != primary_ref]
            if rest:
                observed_str += " [" + ", ".join(f"{k}={v}" for k, v in rest) + "]"

        record = RCARecord(
            alert_source=source,
            alert_name=alert.alertname,
            alert_fingerprint=alert.fingerprint,
            affected_service=alert.service,
            severity=decision.severity,
            triage_decision="override_forced_escalate" if forced_by_override else "investigate",
            llm_verdict=decision.decision.value.lower(),
            llm_confidence=f"{decision.confidence:.2f}" if decision.confidence is not None else None,
            rca_report=decision.rca,
            llm_reasoning=decision.reason,
            action_taken="emailed" if decision.decision == Decision.ESCALATE else "suppressed",
            investigation_duration_ms=elapsed_ms,
            rca_quality=quality,
            alert_instance=alert.instance,
            alert_component=alert.labels.get("component"),
            alert_signal=alert.labels.get("signal"),
            observed_value=observed_str or None,
            promql_expr=alert.annotations.get("expr") or None,
            suggested_actions=_json.dumps(decision.suggested_actions) if decision.suggested_actions else None,
            evidence=_json.dumps(decision.evidence) if decision.evidence else None,
            anomaly_summary=decision.anomaly_summary or (ctx.anomaly_summary if ctx else None),
            correlated_alerts=_json.dumps(correlated) if correlated else None,
        )

        # Step 8: Act on decision. A notifier failure (SMTP hiccup, template
        # rendering bug) must not block Step 9 — otherwise we'd lose the RCA
        # record for an alert the LLM actually finished. Save-first would be
        # cleaner but persisting before emailing breaks ordering guarantees
        # elsewhere; wrap-and-log is the safer change.
        if decision.decision == Decision.ESCALATE:
            try:
                await self.notifier.send_escalation(
                    alert, decision, record, history["count"], ctx=ctx,
                    correlated=correlated,
                )
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

        # P1.6 — tell dedup which decision_id covers this fingerprint, so
        # subsequent duplicates within the window persist short-path records
        # pointing at this RCA.
        if alert.fingerprint:
            await self.dedup.record_first_decision(alert.fingerprint, record.id)
