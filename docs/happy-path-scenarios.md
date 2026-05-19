# Happy-path scenarios — the triage service working as intended

These **fourteen** scenarios describe the full CIRES triage pipeline running cleanly end-to-end: Grafana fires an alert, the service deduplicates, gathers context from Prometheus / Loki / Jaeger via the MCP servers in parallel, Drain3 annotates the logs, Ollama (`qwen2.5:7b-instruct` on the laptop's GTX 1060) produces a structured RCA, the validator passes it, an email is sent on ESCALATE, and the row lands on the dashboard with all evidence intact. Each scenario lists the alert payload, what each pillar contributed, the LLM's verdict, and the operator-facing artifacts (email + dashboard row + RCA history).

One scenario per archetype in `app/exemplars/library.yaml` (14 total). Scenarios 1–11 cover the original archetypes shipped in Sprint 2; scenarios 12–14 cover the three archetypes added during the 2026-04-28 audit cycle to close coverage gaps (`service-self-p95-saturation`, `critical-resource-saturation`, `otel-collector-degradation`).

## RCA prose quality — telemetry is the means, not the end

The RCA shape every scenario below demonstrates, formalised after operator feedback 2026-04-28:

1. **First sentence names a cause.** Not the symptom, not the metric value, not the PromQL — a specific failing component, link, process, queue, config, or change. "spring-boot is in an OOM-kill loop because the JVM heap defaults to ~25% of the cgroup" is a cause. "p95 latency 8487ms above threshold" is the alert in different words.
2. **Translate raw expressions into plain language.** "p95 latency 8487ms" → "95% of requests took longer than 8.5 seconds — user-visible slowness." The PromQL itself goes in the `evidence` list, not the prose.
3. **Use telemetry to support the named cause, not as the conclusion.** Trace span breakdowns that prove the cause is in the upstream's connection pool. Log templates that show the regression. Metric saw-tooth shapes that prove a leak. The prose says what's broken; the evidence proves it.
4. **Drill past the symptom.** "High latency" is never the answer. "Connection pool saturated because of long-running queries from the new dashboard endpoint" is. Use traces and logs to localize.
5. **Rank suggested actions by reversibility.** Cheap reverts first; infrastructure changes last. State-changing only — investigation belongs in the prose and `evidence`, not in `suggested_actions`.

This philosophy is enforced in three places: `SYSTEM_PROMPT` rules A and J (in `app/llm_client.py`), exemplar `rca` fields (`app/exemplars/library.yaml`) which serve as structural calibration targets, and `app/response_validator.py` which scans for surface-only ledes ("PromQL `<expr>` reported `<value>`...") and surface-only hedges ("indicates that there are X experiencing Y") and rejects them. See decisions-log entry D19.

The deployment topology assumed throughout: k3s cluster (`observability-rca-k3s`, `10.0.1.194`) hosts `spring-boot`, `kong`, `frontend`, `otel-collector`. Monitoring VM (`observability-rca-monitoring`, `10.0.1.68`) hosts Prometheus, Loki, Jaeger, Grafana via docker-compose. Triage service runs on the operator's laptop (Tailscale MagicDNS hostname) with Ollama on the GTX 1060.

---

## Scenario 1 — Spring-Boot OOM kill loop, caught in a single cycle

**Initial state.** The 09:30 deploy of `spring-boot` v1.4.7 introduced a leak in the order-history endpoint: every authenticated request retains a `List<OrderEvent>` reference on the session bean. JVM heap climbs ~40 MB/min. The pod was previously sized at 1 Gi with no `JAVA_TOOL_OPTIONS`, so the JVM defaults to ~256 MB heap and the cgroup OOM-kills the container roughly every 12 minutes.

**Trigger.** At 10:14:22 UTC, Grafana fires `HighMemoryUsage` for `service=spring-boot, instance=10.0.1.194:8080, severity=critical`. The alert's reduce step (refId=B) reports `0.94` (94 % of cgroup limit). The annotation includes the PromQL expression `container_memory_working_set_bytes{pod=~"spring-boot-.*"} / container_spec_memory_limit_bytes`.

**Dedup.** No fingerprint match in the 5-minute window. The pipeline proceeds.

**Context fan-out (parallel, ceiling 8 s).**
- **Prometheus MCP (220 ms).** Returns a 30-min range of `container_memory_working_set_bytes` (saw-tooth: rises from 200 MB → 940 MB → drops to 200 MB, twice), `kube_pod_container_status_restarts_total{pod="spring-boot-7d9...-x4q2k"}` (count 14, +3 in the last 30 min), and `jvm_gc_pause_seconds_sum` (climbing).
- **Loki MCP (310 ms).** Pulls 500 lines from `{service="spring-boot"}`, including 3× `java.lang.OutOfMemoryError: Java heap space`, several `GC overhead limit exceeded`, and the post-restart Spring banner.
- **Jaeger MCP (180 ms).** 100 recent traces; the bottom 25 % show GC-pause-aligned latency tails (single span >2 s on `OrderService.findRecent`).

**Drain3.** Three of the OOM lines collapse into one cluster and the cluster's relative frequency in the last 30 min jumps from 0 to 1.4 % — flagged as a novel high-severity template. `anomaly_summary`: `"3 lines matched cluster #142 'java.lang.OutOfMemoryError: Java heap space' (new since 09:32, 2 fires in last 30 m)"`.

**LLM call.** `qwen2.5:7b-instruct`, temperature 0, structured-output schema enforced. Cold first inference: 41 s. Returns:

```json
{
  "decision": "ESCALATE",
  "severity": "critical",
  "confidence": 0.92,
  "reason": "JVM heap saturating cgroup limit, OOM-kill cycle confirmed.",
  "rca": "spring-boot pod 10.0.1.194:8080 is in an OOM-kill loop. container_memory_working_set_bytes saw-toothed twice in the last 30 min, peaking at 940 MB against a 1 Gi cgroup. Three 'java.lang.OutOfMemoryError: Java heap space' lines fired 12 min apart, matching restart counter increments (+3 in 30 min, total 14). GC pause time grew before each crash. The pattern post-dates the 09:30 deploy of v1.4.7 — the leak is recent.",
  "anomaly_summary": "Drain3 cluster #142 ('java.lang.OutOfMemoryError') is novel since 09:32 and recurring.",
  "suggested_actions": [
    "kubectl set resources deploy/spring-boot -n app --limits=memory=2Gi --requests=memory=1Gi — raise the ceiling out of OOMKill range",
    "kubectl set env deploy/spring-boot -n app JAVA_TOOL_OPTIONS='-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError' — pin heap to 75% of cgroup, exit on OOM so the orchestrator can restart cleanly",
    "kubectl rollout restart deploy/spring-boot -n app — clear the leaked state after the limit change",
    "If the leak persists post-restart: helm rollback spring-boot — revert v1.4.7 while the leak is investigated"
  ],
  "evidence": [
    "container_memory_working_set_bytes peaked at 940/1024 MB (~92%) twice in 30m",
    "kube_pod_container_status_restarts_total = 14 (+3 in last 30m)",
    "3× 'java.lang.OutOfMemoryError: Java heap space' (Drain3 cluster #142, novel since 09:32)",
    "GC pause sum climbing in the 90 s before each OOM",
    "Pattern starts 09:32, post-deploy v1.4.7 at 09:30"
  ]
}
```

**Validator.** Architecture check passes (kubectl is valid for `service_deployment_type[spring-boot]="k8s"`). All four suggested actions are remediations (allowed verbs: `kubectl set`, `kubectl rollout`, `helm rollback`). RCA cites a specific cause and timeline — `_classify_rca_quality` returns `actionable`.

**Email.** `notification_email` receives a single message titled `[CIRES] ESCALATE — HighMemoryUsage on observability-rca-k3s / spring-boot`. Body shows verdict, confidence, RCA paragraph, evidence as bullets, and the four kubectl commands as a copy-pasteable code block. Deep links to the Grafana panel, the Loki query, and the Jaeger trace IDs are included.

**Dashboard.** A row at `/dashboard` appears within 90 s of the alert: `Time (local): 11:14`, `Verdict: ESCALATE`, `Confidence: 0.92`, `Quality: actionable`, `Source: grafana`, `Service: spring-boot`. Expanding the row shows the full RCA, evidence list, suggested actions, the rendered PromQL, and the correlated alerts pane (empty in this case).

**RCA history.** A row is persisted in `/var/lib/triage-service/rca_history.db` with `triage_decision='processed'`, `llm_verdict='ESCALATE'`, `llm_confidence='0.92'`, `rca_quality='actionable'`, `investigation_duration_ms=42730`. The email succeeds; `emails_sent` Prometheus counter increments.

**Why it's a perfect cycle.** Three pillars converged on the same answer (memory metrics, OOM logs, GC-pause-skewed traces); Drain3 added the recency signal; the LLM correlated with the deploy timestamp; every suggested action was a remediation, not a "go look it up." Latency was below the 5-minute pager-friendly bar.

---

## Scenario 2 — Kong p95 latency spike correctly attributed upstream, not to Kong

**Initial state.** Kong is fronting `spring-boot` and `frontend`. A slow `mysql` query plan flip caused `OrderService.search()` to take 3 s instead of 80 ms. From the user's perspective, Kong looks slow; Grafana's `HighKongP95Latency` rule fires. A naive operator paged at this would chase Kong tuning knobs and miss the real cause.

**Trigger.** At 14:02 local, `HighKongP95Latency` fires for `service=kong, severity=warning`. Reduce step reports `2.31` (seconds). Annotation expression: `histogram_quantile(0.95, rate(kong_http_request_duration_ms_bucket[5m]))/1000`.

**Context fan-out.**
- **Prometheus (190 ms).** Kong's own request-handling histogram shows the 95th percentile of `kong_proxy_latency_ms` (Kong's own time) is 4 ms — flat. The total latency `kong_http_request_duration_ms` is 2310 ms. The arithmetic delta is 2306 ms — that's all upstream.
- **Loki (240 ms).** Kong access logs show `upstream_response_time=2.310` repeatedly for path `/api/orders/search`; spring-boot logs show one slow query log per affected request: `Hibernate took 2294 ms for OrderRepository.findRecent`.
- **Jaeger (270 ms).** Top 20 traces by latency: every one has Kong span ~5 ms and spring-boot span 2.2-2.4 s. Inside the spring-boot span, a single MySQL child span dominates (`SELECT ... FROM orders WHERE customer_id = ? AND created_at > ?`).

**Drain3.** No novel cluster, but `OrderRepository.findRecent` slow-query lines are a known cluster whose rate just doubled — annotated in the prompt as a 2× rate change.

**LLM verdict.** ESCALATE, confidence 0.94. RCA names the right service:

> Kong itself is healthy: `kong_proxy_latency_ms` p95 = 4 ms. The 2.31 s p95 is upstream time inside `spring-boot`'s `/api/orders/search` handler, dominated by a single MySQL query (`OrderRepository.findRecent`). Trace evidence consistently shows >95% of total latency in the MySQL span. Probable cause: query plan regression on the `orders` table (no schema change in last 24h, but row count grew past 1 M between 13:00 and 13:55). Recommend EXPLAIN-ing the query and adding a covering index on `(customer_id, created_at)`.

**Suggested actions** (all valid for `service=kong → k8s` but the RCA points the operator to spring-boot/mysql):

1. `kubectl exec -n app deploy/spring-boot -- curl -s localhost:8080/actuator/metrics/hibernate.query.cache.miss-count` — confirm cache miss spike before any rollback.
2. `kubectl exec -n app sts/mysql -- mysql -e "EXPLAIN SELECT ... FROM orders ..."` — confirm plan regression.
3. `kubectl exec -n app sts/mysql -- mysql -e "ALTER TABLE orders ADD INDEX idx_cust_created (customer_id, created_at)"` — add the covering index.
4. `kubectl rollout restart deploy/spring-boot -n app` — bounce after the index ships, clear any stale Hibernate plan cache.

**Why it's a perfect cycle.** Without traces, the LLM might have blamed Kong (it's the alert subject). Trace breakdown made the upstream attribution unambiguous. The validator did not reject the actions despite `service=kong` because they correctly target the upstream service named in the RCA — this is the architecture-aware behavior introduced in P1.9.

---

## Scenario 3 — Synthetic blip dismissed without an email

**Initial state.** Prometheus performs a one-shot scrape of node-exporter on the monitoring VM every 15 s. Network jitter caused two consecutive scrapes to fail at 23:47 and 23:47:15. The third scrape at 23:47:30 succeeded.

**Trigger.** Grafana `TargetDown` fires at 23:47:35 for `instance=10.0.1.68:9100, job=node-exporter, service=monitoring`. By the time the triage webhook is processed (23:47:48), the target is healthy.

**Context fan-out.**
- **Prometheus.** `up{instance="10.0.1.68:9100"}` time series: 1, 1, 1, ..., 0, 0, 1, 1, 1, ... Two consecutive zeros over 30 s, then recovery. No load anomaly, no concurrent failure on the host.
- **Loki.** Default fallback (no service-scoped lines) returns ambient logs. Marked `loki_is_fallback=True` so the LLM treats them as background context, not evidence.
- **Jaeger.** No traces for `monitoring` service (none expected — monitoring stack doesn't emit traces).

**Drain3.** No anomaly. Anomaly summary: `"no novel templates and no rate change in the alert window."`

**LLM verdict.** DISMISS, confidence 0.86.

> The target was unreachable for two consecutive 15-second scrape intervals (23:47:00, 23:47:15) and has been healthy since 23:47:30 — well before triage gathered context. No correlated alerts, no novel log patterns, no host-level metric anomaly. This is consistent with a transient network jitter or scrape collision, not a service outage. No action required.

**Suggested actions.** Empty list — DISMISS path skips the template fallback because the LLM correctly named no remediation.

**Email.** None. The pipeline writes a row to `rca_history` and increments `alerts_processed{decision="DISMISS"}` but does not call the notifier — by design, only ESCALATE fires SMTP.

**Dashboard.** A grey-toned row appears with `Verdict: DISMISS, Confidence: 0.86, Quality: actionable` and the one-paragraph RCA. Operators glancing at the dashboard see the system noticed and intentionally chose not to wake them.

**Why it's a perfect cycle.** The system did not page on noise. The "Insufficient data" failure mode (R4) is avoided because the LLM did name a specific cause — "transient scrape miss" — rather than hedging. The dashboard still records the decision so a reviewer can audit the reasoning later.

---

## Scenario 4 — Cascade incident: 4 alerts collapsed into one coherent kill-chain RCA

**Initial state.** A runaway `loki` retention job leaks compacted-but-unreferenced chunks on the monitoring VM. Disk usage climbs from 62 % to 91 % in 40 minutes. Loki's WAL writes start to lag, Grafana's Loki datasource times out on the live alerting evaluation, the `triage-webhook` Grafana contact point starts seeing `DatasourceNoData` errors.

**Trigger sequence (within a 12-minute window).**
- 03:11:04 — `HighDiskUsage` on `monitoring-vm`, severity warning.
- 03:14:31 — `LokiIngestLag` on `service=loki`, severity warning.
- 03:18:48 — `DatasourceNoData` for two alerting rules backed by the Loki datasource.
- 03:22:09 — `AlertInhibitionTriggered` (Grafana flag indicating self-inhibited rule evaluations).

**Correlation (Epic 5 US-5.2 incident correlator).** Each alert hits the deduplicator with a unique fingerprint, so all four enter the pipeline. The correlator groups them on a 15-minute sliding window, keyed on `instance` host. Instead of four LLM calls, one bundled `Incident` object is sent with all four sub-alerts attached.

**Context fan-out (single fan-out across the bundle).**
- **Prometheus.** Disk used %, disk inode usage, loki ingest rate, loki WAL backlog metric, and a 30-min view of all four alert sources side-by-side.
- **Loki.** 500 lines per alert source; `loki` itself shows `level=error msg="failed to flush chunk"` repeatedly with growing latency.
- **Jaeger.** Empty (none of the involved services are traced).

**Drain3.** Detects the `failed to flush chunk` cluster jumping from baseline 0.1 % to 8 % of recent loki output — a strong rate anomaly, not a novel cluster.

**LLM verdict.** ESCALATE, severity critical, confidence 0.93. The RCA reads as a kill chain, not as four independent observations:

> A single root cause produced four symptoms within 12 minutes. Disk on the monitoring VM filled from 62 % to 91 % between 02:30 and 03:11 (HighDiskUsage at 03:11). Loki's chunk flusher began to fail repeatedly at 03:13 (Drain3 cluster `failed to flush chunk` rate spiked from 0.1 % to 8 %), producing the LokiIngestLag alert at 03:14. With Loki backed up, Grafana's alerting queries against the Loki datasource started timing out at 03:18 (DatasourceNoData on two rules). The aggregate effect tripped the inhibition rule at 03:22. The chain is disk-pressure → loki write failure → grafana evaluation failure → meta-alert. Treat as a single incident, fix at the source.

**Suggested actions** (deployment type `docker-vm` for monitoring services):

1. `ssh deploy@observability-rca-monitoring 'docker exec loki sh -c "rm -rf /loki/compactor/deletion-marker.json"'` — clear stale deletion markers blocking the compactor's exit (cause of the leaked chunks per the loki upstream issue tracker).
2. `ssh deploy@observability-rca-monitoring 'docker compose -f /opt/monitoring/compose.yml restart loki'` — restart loki so the compactor begins anew.
3. `ssh deploy@observability-rca-monitoring 'sudo journalctl --vacuum-size=200M && docker system prune -af --volumes'` — reclaim disk pre-restart; resolves the disk alert in one shot.
4. `If still > 80% after prune: terraform apply -var monitoring_root_volume_gb=120` — expand the EBS volume so this can't recur over the weekend.

**Email.** A single email lands — title prefixed `[CIRES INCIDENT — 4 correlated alerts]`. Body shows the kill-chain RCA paragraph, then a bulleted timeline (one bullet per sub-alert with timestamp), then the four suggested actions, then deep links to each constituent alert. The dashboard row aggregates the four under a single expandable `Incident` cell so the on-call engineer doesn't see four separate noise rows.

**Why it's a perfect cycle.** Four alerts that would otherwise have produced four near-identical RCAs and four pages collapse into one coherent story. The LLM saw the timeline as evidence and explicitly named the chain. The remediation order (disk first, restart second, expand third) reflects irreversibility — cheap reversible actions before infrastructure changes.

---

## Scenario 5 — Drain3 self-fires on a novel post-deploy error template

**Initial state.** A Helm upgrade of `spring-boot` from `v1.4.6` to `v1.4.7` at 14:28 introduced a transaction-ordering bug that surfaces only under concurrent writes. The classic symptom: PostgreSQL throws `ERROR: deadlock detected` on roughly 0.5 % of write requests. No metric alert fires (error rate too low to trip `HighErrorRate`), but the log template is brand-new since the deploy.

**Trigger.** At 14:36, Drain3's background ingestion (polling Loki every 30 s) detects:
- A new template `cluster #211 = "ERROR: deadlock detected; Process <PID> waits for ..."` first seen 14:32, never previously observed.
- 47 occurrences in the last 100 lines from `service=spring-boot` (47 % of the window above the 10 % `drain3_alert_rate_threshold`).

`DrainAnalyzer.maybe_fire_alert()` self-POSTs a `Drain3Webhook` to `http://localhost:8090/webhook/drain3`:

```json
{
  "anomalous_lines": ["ERROR: deadlock detected ...", "..."],
  "anomaly_rate": 0.47,
  "new_templates": ["ERROR: deadlock detected; Process %d waits for %s on relation %d ..."],
  "service": "spring-boot",
  "timestamp": "2026-04-27T14:36:18Z"
}
```

**Pipeline path.** The webhook is converted to a synthetic `GrafanaAlert(alertname='Drain3AnomalyDetected', service='spring-boot', severity='warning')`. Dedup miss. Pipeline proceeds.

**Context fan-out.**
- **Prometheus.** Standard fan-out for spring-boot — request rate flat, error rate up modestly, JVM healthy.
- **Loki.** Confirms 47 % of recent lines are the deadlock template; pulls full multi-line stack traces showing `BasicDataSource.getConnection` and `OrderEventRepository.persistChain`.
- **Jaeger.** Top 50 traces for spring-boot include 12 with error spans tagged `db.error=deadlock`.

**Drain3.** Already fired — its summary is the alert. The pipeline annotates the logs with cluster IDs anyway so the LLM can see which lines are baseline vs novel.

**LLM verdict.** ESCALATE, confidence 0.89.

> A novel error template `ERROR: deadlock detected ...` has been firing in `spring-boot` since 14:32, four minutes after the helm upgrade to v1.4.7 at 14:28. The template never appeared in the previous 14 days of logs (Drain3 cluster #211 is new). 47 of the last 100 log lines match it. Trace evidence confirms 12 affected traces with `db.error=deadlock` on the `OrderEventRepository.persistChain` operation. The strong temporal correlation with the deploy and the previously-unseen template strongly suggest a regression in the upgrade. The error rate is currently below the metric alert threshold, so this would not have been caught without log-template novelty detection.

**Suggested actions.**

1. `helm rollback spring-boot 1 -n app` — revert to v1.4.6, the immediate-prior stable release. Cheap and reversible.
2. `kubectl rollout status deploy/spring-boot -n app` — confirm rollback completes.
3. After confirmed quiet, file a JIRA ticket against the v1.4.7 changelog covering `OrderEventRepository.persistChain` (the trace span where deadlocks land).
4. If the error pattern persists post-rollback: `kubectl exec -n app sts/mysql -- mysql -e "SHOW ENGINE INNODB STATUS"` — capture the deadlock graph for diagnosis.

**Why it's a perfect cycle.** No metric alert was high enough to fire — without Drain3 the issue would have stayed below the radar until customer reports caught it. The LLM correlated the new template's first-seen timestamp (14:32) with the deploy event (14:28) on its own; the prompt only included the deploy as part of the standard service-history context. The result is a precise post-deploy regression call within minutes of the bug being introduced.

---

## Scenario 6 — Bounded-agency retry: from INCONCLUSIVE to ESCALATE in one extra MCP query

**Initial state.** Frontend pods are returning 5xx for ~3 % of requests. The metric alert fires, but the first-pass context bundle is thin: error counter is up, logs from `frontend` show only generic `client closed request`, and Jaeger shows nothing because the front-end isn't traced (the trace context starts at Kong).

**Trigger.** `HighFrontendErrorRate` at 16:48 local, `service=frontend, severity=warning`.

**First LLM pass.**
- Metrics: error rate from 0.4 % → 3.1 %.
- Loki: 200 lines, mostly `client closed request` and access logs — useful but not diagnostic.
- Jaeger: 0 traces (frontend not instrumented for traces directly).
- Drain3: nothing novel.

The LLM returns:

```json
{
  "decision": "INCONCLUSIVE",
  "confidence": 0.42,
  "reason": "Error rate is up but I cannot see what the upstream is doing. I would like one trace query against kong to confirm whether the 5xx originates upstream.",
  "rca": "...",
  "next_query": {
    "tool": "jaeger.traces",
    "args": {"service": "kong", "tag.http.status_code": "503", "limit": 25}
  }
}
```

**Bounded-agency engagement.** `triage_bounded_agency_enabled=True`. The `bounded_agency.py` validator confirms the request matches the whitelist (`jaeger.traces` is allowed, `service` and `tag.*` are allowed args, `limit ≤ 50`). The Jaeger MCP is called once more — 95 ms — and returns 25 traces, of which 23 show `kong → spring-boot` with the spring-boot span returning 503 inside 50 ms (no work done, immediate rejection).

**Second LLM pass.** Same SYSTEM_PROMPT (KV-cache friendly), with the new evidence appended. Returns ESCALATE, confidence 0.84:

> Frontend 5xx is upstream-attributable. Of 25 kong traces in the alert window with `http.status_code=503`, 23 show spring-boot returning 503 inside ~50 ms — too fast to be timeouts. This pattern is consistent with spring-boot rejecting requests at admission, e.g. a saturated thread pool or a circuit-breaker state. Frontend itself is healthy; the user-visible 5xx is the downstream signature.

**Suggested actions.** Target spring-boot, not frontend:

1. `kubectl exec -n app deploy/spring-boot -- curl -s localhost:8080/actuator/metrics/tomcat.threads.busy` — confirm thread pool saturation.
2. `kubectl set env deploy/spring-boot -n app SERVER_TOMCAT_THREADS_MAX=400` — raise from default 200 if confirmed saturated.
3. `kubectl rollout restart deploy/spring-boot -n app` — apply the env change cleanly.

**Why it's a perfect cycle.** The first pass correctly refused to guess. The bounded-agency mechanism added exactly one targeted MCP call — not a free-form agent loop — and that single extra ~100 ms of latency converted an unhelpful INCONCLUSIVE row into a precise upstream RCA. Determinism is preserved: same inputs → same retry → same final answer.

---

## Scenario 7 — Adaptive threshold (US-5.4) keeps the system quiet through a normal Tuesday-morning ramp

**Initial state.** Tuesday 09:00 UTC is the regular weekly traffic peak — internal users sign in for the start of the workday, batch jobs hand off to interactive workloads. Spring-boot CPU climbs from 22 % to 78 % over ~15 minutes. Under the legacy static threshold (`HighCpuUsage > 75 %`) this would page; the operator would acknowledge, look at the dashboard, see the same shape as last Tuesday, and silence — every week. False-positive fatigue.

**The new rule.** Epic 5 US-5.4 rewrote the rule using `stddev_over_time + offset 7d`:

```promql
( avg by (service) (rate(container_cpu_usage_seconds_total{service="spring-boot"}[5m]))
- avg by (service) (rate(container_cpu_usage_seconds_total{service="spring-boot"}[5m] offset 7d)) )
/ stddev_over_time(rate(container_cpu_usage_seconds_total{service="spring-boot"}[5m] offset 7d)[2h:5m])
> 3
```

Translation: alert only when current CPU is more than 3 σ above the same hour last week, measured over a ±2-hour window.

**What happens.** This Tuesday's 78 % is +0.4 σ above last Tuesday's 09:00 average. The rule does not fire. No webhook reaches the triage service. No row is written; no email is sent. The operator's morning is undisturbed.

**Dashboard view.** The Grafana CPU panel shows the spike, but a reference band (also Epic 5) overlays the previous-week's same-hour mean ± 1 σ in muted grey, so the on-call engineer can see at a glance that the current curve is hugging the baseline.

**What the triage service contributes.** Nothing — and that is the point. The Prometheus `triage_alerts_received_total` counter does not increment. The "operate quiet when nothing is wrong" KPI improves; the false-positive rate measured against the labeled corpus (Epic 5 US-5.7) drops.

**Why it's a perfect cycle.** The pipeline is perfectly silent on a non-event. This is what the system *should* do most of the time: the value of an observability stack is measured as much in the alerts it suppresses as in the ones it produces. Pair this scenario with Scenario 1 — when the same metric is genuinely +5 σ above baseline, the rule fires and the LLM produces an ESCALATE. The thresholds adapt; the operator's trust does not erode.

---

## Scenario 8 — Closed-loop feedback (US-5.3): operator override teaches the system

**Background.** `HighKongP95LatencyKong` fires every Saturday between 04:00 and 04:30 because of an internal batch ETL writing through Kong. For three consecutive Saturdays, the LLM correctly DISMISSed the alert: the latency is real, but it's expected, and historical RCAs in the SQLite store (`rca_history`) consistently classify it as routine.

**Week 4 — operator overrides.** This Saturday, the same alert fires. LLM DISMISSes with confidence 0.81 — same RCA shape as the prior weeks. But a customer-facing dashboard shows real user latency at the same time, and the on-call engineer (Lina) inspects, decides this Saturday's spike is real, and POSTs:

```http
POST /feedback/override
{
  "rca_id": "f7e8...c2a1",
  "operator_verdict": "ESCALATE",
  "operator_note": "User-facing latency observed by external monitor — not just ETL noise this time.",
  "operator": "lina@cires.tech"
}
```

The override row is recorded in `rca_history.feedback_overrides`. A new derived metric `triage_feedback_overrides_total{from='DISMISS', to='ESCALATE'}` increments.

**Week 5 — same alert, learned response.** The following Saturday, `HighKongP95LatencyKong` fires again at 04:11. The pre-LLM suppression layer (extended in US-5.3 to consult similarity-weighted recent overrides) finds the previous override on a high-similarity alert (`alertname` match, ±2 h time-of-day match, same service) within the last 30 days. It marks the alert with `force_escalate_reason="recent operator override on similar alert"`.

The pipeline still calls the LLM (the override changes routing, not the RCA). The LLM produces its usual DISMISS RCA with confidence 0.79, but the post-LLM gate sees `force_escalate=True`. The decision flips to ESCALATE; the email subject prefix becomes `[CIRES — operator-policy escalation]` and the email body explicitly explains the override:

> The LLM's verdict was DISMISS (confidence 0.79) — this matches the seasonal Saturday-batch pattern. However, on 2026-04-25 you marked a similar alert as a real incident. To honour that override policy, this alert has been escalated for human review. If this Saturday's batch is genuinely routine again, /feedback/confirm will down-weight the override.

**Why it's a perfect cycle.** The system doesn't just consume LLM verdicts — it learns from operator decisions. The override loop makes the triage service *empirically improve* week over week. The Prometheus counters `triage_precision` and `triage_recall` (Epic 5 US-5.3 + US-5.7) gain new ground-truth labels every time an operator overrides or confirms; the labeled corpus grows; the next prompt iteration can be evaluated against it. The dashboard adds a small "feedback ledger" panel showing override count and how many subsequent similar alerts were re-escalated by policy — a jury-friendly visualisation of the closed loop.

---

## Scenario 9 — App boot failure / CrashLoopBackOff from a bad config map

**Initial state.** A junior engineer ships a ConfigMap edit changing `spring.datasource.url` from `jdbc:mysql://mysql:3306/orders` to `jdbc:mysql://mysql:3306/order` (singular `order`). The 17:42 rollout picks up the change. The new spring-boot pod fails its Liquibase migration at boot because the database doesn't exist, exits non-zero, and Kubernetes restarts it. `BackOff` delays climb: 10 s → 20 s → 40 s → 80 s. The service is fully down for users hitting `/api/orders`.

**Trigger.** At 17:44, two Grafana rules fire within ~30 s of each other:

- `KubePodCrashLooping` for `service=spring-boot, instance=10.0.1.194:8080, severity=critical`. Reduce step (refId=B) reports `5` (5 restarts in last 5 min). PromQL: `rate(kube_pod_container_status_restarts_total{pod=~"spring-boot-.*"}[5m]) * 60 * 5`.
- `TargetDown` for the same pod (Prometheus's scrape never sees it healthy long enough between restarts).

The correlator (Epic 5 US-5.2) groups them as one incident.

**Context fan-out.**
- **Prometheus MCP (210 ms).** Restart counter graph is a pure staircase — +1 every 10–80 s. `kube_pod_status_phase{phase="Running"}` is 0 most of the window; `phase="Waiting"` is 1, with the canonical `reason="CrashLoopBackOff"` label. Memory and CPU are essentially zero — the pod never reaches steady state.
- **Loki MCP (290 ms).** 500 lines, but only the first ~30 lines per restart are spring-boot's own; the rest is k8s control-plane noise. The spring-boot lines all end with: `Liquibase: Migration failed for changeSet ... org.hibernate.exception.SQLGrammarException: Unknown database 'order'` followed by the Spring banner aborting and `APPLICATION FAILED TO START`.
- **Jaeger (180 ms).** 0 traces for spring-boot. Expected — the app never reached the point of accepting requests.

**Drain3.** Two relevant signals:
1. The `Unknown database 'order'` line is a brand-new template since 17:42 (cluster #287, 0 prior occurrences).
2. The `APPLICATION FAILED TO START` line is a known cluster but its rate jumped from 0 to ~2 occurrences/min.

`anomaly_summary`: `"2 templates flagged: cluster #287 'Unknown database 'order'' (NEW since 17:42, 5 fires); cluster #112 'APPLICATION FAILED TO START' (rate +∞%)."`

**LLM verdict.** ESCALATE, severity critical, confidence 0.95.

> PromQL `rate(kube_pod_container_status_restarts_total[5m])*300` returned 5 — the spring-boot pod has restarted 5 times in 5 minutes. Logs show every restart aborts at the Liquibase migration step with `SQLGrammarException: Unknown database 'order'`. The MySQL schema name in this cluster is `orders` (plural), confirmed by the `KubePodCrashLooping` history showing healthy boots on this same pod earlier today. Drain3 cluster #287 (`Unknown database 'order'`) is brand-new since 17:42 and only appears post-deploy — strongly suggesting a bad config change at deploy time, not a database outage. The cluster is in CrashLoopBackOff with exponential backoff already at 80 s; user-facing endpoints are returning 503 from Kong because the upstream is unreachable.

**Suggested actions** (deployment_type k8s):

1. `kubectl rollout undo deploy/spring-boot -n app` — revert the deployment to the prior revision; fastest restore-to-service.
2. After the rollback completes, fix the source of truth: `git revert <commit-sha-of-configmap-change>` in `monitoring-project`, then `ansible-playbook -i inventory/tailnet.yml playbooks/k3s-app.yml` — apply the fix forward via the GitOps path so the next deploy doesn't reintroduce it.
3. As a safety net, add a Liquibase pre-flight check to the Helm chart's `helm.sh/hook: pre-install,pre-upgrade` so the migration runs before traffic is shifted: `helm upgrade spring-boot ./charts/spring-boot --set preflight.enabled=true -n app`.

**Why it's a perfect cycle.** Three converging signals — restart counter staircase, Liquibase failure log, Drain3 novel template post-deploy — make the cause unambiguous. The remediation order respects irreversibility: rollback to restore service first (cheap, reversible), then fix forward through GitOps (auditable), then a structural improvement (preflight hook) so the same class of bug becomes harder to ship. The LLM did not blame "MySQL is down" (it isn't; the database name is just wrong) because the log evidence was specific enough to disambiguate. CrashLoopBackOff is one of the most common production failure modes; getting it right is foundational.

---

## Scenario 10 — AWS security-group change silently blocks Kong → spring-boot

**Initial state.** A Terraform PR was merged at 11:08 that intended to tighten the security group attached to the k3s nodes — restricting SSH ingress to a new bastion CIDR. A typo in the same PR's `aws_security_group_rule` resource accidentally narrowed the *intra-cluster* rule too: instead of `cidr_blocks = [var.vpc_cidr]` (10.0.0.0/16), it was set to `cidr_blocks = [var.bastion_cidr]` (10.0.99.0/28). After `terraform apply`, k3s pods can't reach each other's NodePort/ClusterIP traffic from outside the node — including Kong's upstream calls to the spring-boot ClusterIP. From the user's perspective, every request through Kong returns 502 after a 30 s timeout. Spring-boot itself is healthy: its `/actuator/health` is green, no logs, no traces.

**Trigger.** At 11:14, three alerts fire:

- `HighKongUpstreamErrorRate` (`service=kong, severity=critical`) — 502 rate climbs from 0.1 % to 96 %.
- `HighKongP95Latency` (`service=kong, severity=warning`) — p95 hits 30 s (the upstream timeout).
- `HighFrontendErrorRate` (`service=frontend, severity=warning`) — 503s on frontend, downstream signature.

The correlator groups them on a 15 min window.

**Context fan-out (single bundle).**
- **Prometheus.** Kong's `kong_upstream_target_health` for the spring-boot upstream flipped to `0` (unhealthy) at 11:09. `up{job="spring-boot"}` is `1` (Prometheus scrapes spring-boot from inside the cluster, which still works — same node — so the metric pillar gives a confusing "spring-boot is up" signal). `node_network_transmit_packets_total` on the k3s node shows a 90 % drop in cluster-internal traffic at exactly 11:08:42.
- **Loki.** Kong access logs: every entry shows `upstream_status=- upstream_response_time=30.001 status=502`. Spring-boot logs: silent (no inbound requests reaching it). MySQL logs: silent.
- **Jaeger.** Kong's spans show outbound connection-reset / connect-timeout to the spring-boot ClusterIP. No spring-boot child spans (the connection never lands).

**Drain3.** Kong's `upstream timed out` template's rate explodes — known cluster, rate change from 0.1 % to 89 %. No novel templates.

**LLM verdict.** ESCALATE, severity critical, confidence 0.88.

> PromQL `sum(rate(kong_http_requests_total{status=~"5.."}[5m])) / sum(rate(kong_http_requests_total[5m]))` returned 0.96 (96 % error rate). Kong is the symptom; spring-boot is the apparent target. But spring-boot is reporting healthy: `up{job="spring-boot"}=1` and its access logs show NO inbound requests reaching it during the alert window. Kong's traces consistently show connect-timeout / connect-reset on the upstream connection to the spring-boot ClusterIP, and `kong_upstream_target_health` flipped to 0 at 11:09:02. The pattern is a *network-layer* break, not an application failure. The k3s node's transmit packet rate dropped 90 % at 11:08:42, which is one minute after the Terraform deploy that landed at 11:08 (verified via the `monitoring-project` ansible journal — last `terraform apply` ran at 11:08:31). The most likely cause is the security-group change in that apply narrowing intra-cluster CIDR: Kong on node A can no longer reach the spring-boot ClusterIP fronting a pod on node B (or even on the same node, if the kube-proxy iptables redirect crosses the SG boundary).

**Suggested actions.**

1. `cd /root/provisioning-monitoring-infra && terraform plan -target=module.k3s_security_group` — confirm the diff that's currently applied; the LLM expects to see the intra-cluster rule narrowed.
2. **Restore service immediately** by reverting the Terraform: `terraform apply -refresh-only=false -target=module.k3s_security_group -var bastion_cidr=10.0.0.0/16` (temporarily widens; cheap and reversible) — this restores intra-cluster connectivity in <30 s and the 502s clear immediately.
3. Once service is restored: `git revert <commit-sha>` on the typo'd PR in `provisioning-monitoring-infra`, push, and re-run the apply through the normal CI path. This puts the fix on the audit trail.
4. Add a guard: `terraform validate` plus a custom rule in CI that fails any plan touching `aws_security_group_rule` if it would *narrow* an intra-cluster CIDR. (Implement as an `opa-conftest` policy in the repo's `.github/workflows/terraform.yml`.)

**Why it's a perfect cycle.** This is the scenario where a single-pillar view fails the operator. Metrics alone say "spring-boot is up, kong is throwing 5xx" — naive RCA blames Kong tuning. Logs alone (no spring-boot inbound) point at network. Traces explicitly show connect-timeout. Drain3 contributes nothing here (no novel templates), and that's fine — the LLM correctly weights the trace evidence and the deploy timestamp instead. The deploy correlation (11:08:42 packet drop coincident with 11:08:31 terraform apply) is the keystone — without it, the LLM might still suspect a NetworkPolicy. Suggested action #2 prioritises restore-of-service over root-cause diagnosis, which is correct under outage conditions. This is the kind of RCA that a senior network-aware SRE would write in 20 minutes; the system produces it in ~70 s.

---

## Scenario 11 — TLS certificate near expiry caught before users see a single failure

**Initial state.** The public Grafana endpoint (`grafana.cires.tech`) is fronted by an ALB with a Let's Encrypt certificate auto-renewed by `cert-manager` running in a separate utility k3s namespace. The renewal hook silently failed three days ago because the ACME HTTP-01 challenge path was rerouted by an unrelated ingress edit. The current cert expires at `2026-04-30T08:14:00Z` — three days from now. No traffic has been impacted yet.

**Trigger.** A blackbox-exporter probe is scheduled every 5 minutes and exposes `probe_ssl_earliest_cert_expiry`. The Grafana rule `TLSCertExpiringSoon` fires at 09:30 when the expiry is < 7 days:

```promql
(probe_ssl_earliest_cert_expiry{instance="grafana.cires.tech:443"} - time()) / 86400 < 7
```

Reduce step (refId=B) reports `2.93` (days). Severity: warning — there is no current outage.

**Context fan-out.**
- **Prometheus MCP.** Returns the expiry-days metric (current 2.93, 7 days ago 9.93 — declining linearly because no renewal has happened), `probe_success{instance="grafana.cires.tech:443"}=1` (the endpoint is still serving traffic fine), and the relevant `cert_manager_certificate_ready_status{name="grafana-cires-tech"}` which has been `0` (not ready) for the last 3 days.
- **Loki.** Pulls cert-manager logs. Last successful renewal was 60 days ago. The most recent renewal attempt (3 days ago) has: `Failed to perform self check GET request 'http://grafana.cires.tech/.well-known/acme-challenge/...': 404`.
- **Jaeger.** Empty (cert-manager isn't traced; not expected).

**Drain3.** Cert-manager renewal-failure log template is a novel cluster (`cluster #341`, first seen 3 days ago, recurred 12 times since). `anomaly_summary`: `"cluster #341 ('Failed to perform self check ... 404') is novel since 2026-04-24, 12 recurrences."`

**LLM verdict.** ESCALATE, severity warning (not critical — no current outage), confidence 0.93.

> PromQL `(probe_ssl_earliest_cert_expiry - time()) / 86400` returned 2.93 — the TLS certificate fronting `grafana.cires.tech` expires in 2.9 days. The endpoint itself is serving fine RIGHT NOW (`probe_success=1`), so this is a pre-failure alert: act before users see broken HTTPS. Cert-manager has been failing renewal for 3 days: `cert_manager_certificate_ready_status` has been 0 since 2026-04-24 and Drain3 cluster #341 (`Failed to perform self check ... 404`) is novel since the same date with 12 recurrences. The renewal is failing because cert-manager's HTTP-01 self-check can't reach `/.well-known/acme-challenge/...` — a 404 indicates the challenge path is no longer routed to the cert-manager solver, almost certainly because of an ingress change ~3 days ago.

**Suggested actions.**

1. `kubectl get ingress -A -o yaml | grep -A 20 'grafana.cires.tech'` — *(REJECTED by validator: read-only verb. The validator strips this and the LLM re-emits.)*

(After validator pushback, the corrected list:)

1. `kubectl rollout restart deploy/cert-manager -n cert-manager` — kick a fresh renewal attempt; if the routing has been fixed since the original break, this resolves the renewal in one cycle.
2. `kubectl annotate certificate grafana-cires-tech -n network cert-manager.io/issue-temporary-certificate="true" --overwrite` — attach a temporary self-signed cert so we have headroom if the real renewal needs more than 2.9 days.
3. Restore the ACME challenge path in the ingress: `git revert <commit-sha-of-ingress-edit-2026-04-24>` in `monitoring-project`, then `ansible-playbook -i inventory/tailnet.yml playbooks/k3s-app.yml`. This is the durable fix.
4. After the renewal succeeds (watch `kubectl get certificate -A` for `READY=True`), set up a redundant alert at expiry < 14 days so we have more lead time next time: edit `monitoring-project/roles/grafana/templates/alertrules.yml.j2`, then `ansible-playbook playbooks/grafana.yml`.

**Why it's a perfect cycle.** Pre-failure detection. The system fired an alert *while everything still works*, named the underlying renewal failure (not the surface symptom), correlated cert-manager log novelty with the renewal-status metric, and proposed a restore-pathway that prioritises buying time (temporary cert) before fixing the root cause (ingress revert). The validator caught and rejected the LLM's first instinct to emit a `kubectl get ... | grep` (which is investigation, not remediation), and the regenerated list contains only state-changing commands. This is the playbook for "warning" severity: act now so it never escalates to "critical."

---

## Scenario 12 — Service-self p95 saturation (the slowness is *inside* the service, not upstream)

**Initial state.** Spring-Boot v1.5.0 shipped at 13:40 with a new `/api/dashboard/aggregate` endpoint that scans the in-memory `OrderCache` (a `ConcurrentHashMap<UUID, Order>` of ~120 k entries) under a single `synchronized` block. Under load, the lock becomes the bottleneck; latency manifests entirely inside Spring-Boot's own handler — not in upstream MySQL, not in Kong, not in network. This is the **mirror image of Scenario 2**: same alert shape (p95 spike), opposite attribution.

**Trigger.** At 14:18 local, `HighP95Latency` fires for `service=spring-boot, severity=warning`. Reduce step reports `1.84` (seconds). Annotation expression: `histogram_quantile(0.95, sum by (le)(rate(http_server_requests_seconds_bucket{job="app-spring-actuator"}[5m])))`.

**Why this is *not* an `upstream-latency-attribution` (Scenario 2).** That archetype fires when a downstream service (Kong) reports high p95 driven by an upstream service it calls. Here, spring-boot is reporting its own p95 — there's no "upstream" to attribute to. The archetype matcher correctly picks `service-self-p95-saturation` because the alert is fired *on the service itself*, not on a gateway.

**Context fan-out.**
- **Prometheus MCP (210 ms).** Returns `http_server_requests_seconds_bucket` quantiles (p95 1.8 s, p99 2.4 s — climbing past 14:00), `jvm_gc_pause_seconds_sum` (flat — this is *not* a GC story), `jvm_threads_states_threads{state="blocked"}` jumped from a baseline of 2 to 47 around 14:00 onwards, `process_cpu_usage` at 88 % (a single thread fully consumed; you can see this in the `cpu_usage_idle` pattern), and the entity-baseline (via S3-HF-04 → prometheus-mcp) reports the request-rate is *normal* — this isn't a traffic spike.
- **Loki MCP (180 ms).** No errors, no warnings, no slow-query logs. Just successful 200 responses with longer-than-usual server-times. Critically: **nothing is wrong from the application's own perspective.** Drain3 returns no novel clusters.
- **Jaeger MCP (260 ms).** Top 20 latency traces: every span shows `OrderController.getDashboardAggregate` at 1.6-1.9 s with **no child spans** beyond fast in-memory access. There are no MySQL calls, no HTTP calls, no external dependencies in the slow path. Inside the span, custom tags reveal `lock.wait.ms=1620` on the synchronized block. This is the keystone evidence.

**LLM verdict.** ESCALATE, severity warning, confidence 0.91. The RCA explicitly disconfirms upstream causes:

> Spring-Boot's `/api/dashboard/aggregate` endpoint is saturating its own request handlers because of lock contention on the in-process `OrderCache` synchronized block. Trace evidence shows 1.6-1.9 s spent *inside* the spring-boot span with no child calls — `lock.wait.ms` tags consistently around 1.6 s on the affected traces. JVM thread states confirm this: blocked-thread count jumped from 2 to 47 around 14:00, while GC pause time is flat (this is not a heap/GC story) and request rate is normal (not a load story). The pattern post-dates the 13:40 deploy of v1.5.0, which introduced the new aggregate endpoint. Root cause: the new endpoint takes a coarse-grained `synchronized` lock on the entire OrderCache and serialises all callers. Upstream is fine — Kong p95 is 4 ms, MySQL query time is sub-millisecond and not in the slow span path.

**Suggested actions.**

1. `helm rollback spring-boot --revision <pre-v1.5.0>` — fastest restore-of-service. The endpoint is new; rollback removes the bottleneck immediately.
2. `kubectl scale deploy/spring-boot --replicas=4 -n app` — temporary load-spreading if rollback is blocked (won't fix root cause, but blunts impact).
3. After rollback succeeds and the team plans v1.5.1: redesign the aggregate endpoint to use `ConcurrentHashMap`'s native `reduce` / `forEachEntry` (lock-free) or partition the cache so the synchronized block scopes to a partition rather than the whole map. *(This is a code change; not a `suggested_action` since it's not a runtime verb.)*

**Why it's a perfect cycle.** The exemplar matcher correctly distinguished service-self saturation from upstream attribution — the same alertname (`HighP95Latency`) routes to two different archetypes based on the service it fires *on*. The LLM didn't fall into the trap of "p95 is high, must be the database" — it followed the trace evidence into the spring-boot span and stopped there. The deploy correlation closed the case. The `lock.wait.ms` tag is the kind of evidence only the trace pillar can supply.

---

## Scenario 13 — Critical resource saturation (and *not* an adaptive-threshold noop)

**Initial state.** The monitoring VM (`observability-rca-monitoring`) runs Prometheus / Loki / Jaeger / Grafana in docker-compose alongside an otel-collector. At 03:14 UTC, a Loki ingestion regression (a label-cardinality blowup from a misconfigured service) starts driving Loki's CPU usage off the chart: the monitoring VM's overall CPU climbs from a steady-state of 18 % to 96 % over 8 minutes and stays there.

**Trigger.** `CriticalCpuUsage` fires for `instance=observability-rca-monitoring, service=monitoring, severity=critical`. Reduce step reports `0.96`. Annotation: `1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m]))`.

**Why this is *not* an `adaptive-threshold-noop` (Scenario 7).** Scenario 7 dismisses a `Medium`/`HighCpuUsage` warning because the value is within the historical 7-day envelope — Tuesday-morning-ramp territory. This is **critical** severity, the value is **5× the historical p95 baseline** (typical Tuesday 03:14 sees ~22 % CPU; current 96 % is +28σ above baseline), and the archetype matcher routes `Critical(Cpu|Memory)Usage` to `critical-resource-saturation` regardless of baseline noise — critical is critical.

**Context fan-out.**
- **Prometheus MCP (220 ms).** `node_cpu_seconds_total` flame breakdown shows ~70 % of CPU time on a single process group (`loki` container). `container_cpu_usage_seconds_total{name="loki"}` quintupled vs. 30 min prior. `loki_ingester_chunks_created_total` rate exploded from ~10/s to ~800/s — that's the cardinality blowup tell. Entity baseline (via prometheus-mcp): 7-day p95 for this metric is 22 % CPU; current value is 28σ above. Sample count 10080 — authoritative.
- **Loki MCP (300 ms).** Loki's own logs flooded with `level=warn caller=ingester.go:... msg="streams limit exceeded for user fake" stream={...}` — and the stream label is a UUID. Drain3 catches the novel cluster (`cluster #214 'streams limit exceeded ... stream=<UUID>'`) and reports it as novel since 03:14 with ~12 k recurrences in 8 min.
- **Jaeger MCP.** Not relevant — Loki traffic isn't traced; skipped.

**LLM verdict.** ESCALATE, severity critical, confidence 0.96.

> The monitoring VM is saturated because **Loki is being asked to ingest a stream label of unbounded cardinality** — a new service appears to be tagging log streams with a UUID rather than a stable service identifier. CPU is at 96 % (28σ above the 7-day baseline of 22 %), driven almost entirely by Loki's ingestion path. Loki's own warning logs since 03:14 confirm the cardinality blowup ("streams limit exceeded for user fake", stream labels are UUIDs). This is critical because once Loki starts dropping streams the entire log pillar of the observability stack becomes unreliable — and because *this is the monitoring VM*, a sustained pin at 96 % CPU is one Prometheus-scrape timeout away from cascading into `TargetDown` on every job. **The whole observability surface is at risk if this isn't stopped within minutes.**

**Suggested actions.**

1. `docker compose -f /opt/monitoring/docker-compose.yml restart loki` — clear the ingestion backlog and give the operator a steady-state baseline to inspect from.
2. `ansible-playbook -i inventory/tailnet.yml playbooks/loki.yml --tags=limits-config` — push a hard `max_streams_per_user` cap so this regression can't repeat after restart.
3. Identify the offending producer: query `topk(5, count by (service_name) (rate({}[5m])))` against the running Loki to find which service is generating UUID-keyed streams; then patch that service's logging config or labels.
4. After mitigations land, *raise* the recurrence-gate on `CriticalCpuUsage{instance="observability-rca-monitoring"}` — this is critical-bypass-eligible (see US-5.8); the gate should never have skipped it but the audit shows the metric path was healthy.

**Why it's a perfect cycle.** The system correctly distinguished `critical-resource-saturation` from the adaptive-threshold noop archetype despite the alertnames being adjacent. The baseline σ-claim sharpens the case — "28σ above the 7-day baseline" is much more diagnostic than "above 80 %." The RCA names the second-order risk (cascading `TargetDown` on the whole observability stack) — that's the *severity* lens that an SRE applies to host-level alerts, and the exemplar prose primes the LLM to do the same. Critical severity bypasses the recurrence gate per the US-5.8 design — `triage_recurrence_critical_bypassed_total` increments and the operator sees the bypass surfaced in the dashboard.

---

## Scenario 14 — OTel collector degradation (the observability stack reporting on itself)

**Initial state.** The k3s in-cluster otel-collector deployment received a config change at 11:40 that bumped its memory-limiter to 100 MiB. Under the existing trace-volume baseline (~6 k spans/min), the collector hits its limit and starts shedding spans when its internal queue overflows. There's no app-level failure; the failure is *in the telemetry pipeline itself*.

**Trigger.** At 11:53 local, `OTelCollectorHighSpanDropRate` fires for `service=otel-collector, severity=warning`. Reduce step reports `0.17` (17 % of spans dropped over the 5-min window). Annotation: `rate(otelcol_processor_dropped_spans[5m]) / rate(otelcol_processor_received_spans[5m])`.

**Why this archetype is special.** The system being observed and the system doing the observing partially overlap — when the otel-collector degrades, downstream RCAs **cannot trust trace evidence freshness** during the degradation window. The exemplar prose explicitly instructs the LLM to acknowledge this: *"Span drops mean some traces in the affected window are missing. Don't blame an upstream service for 'no slow spans' if span-drop is non-zero during that window — the absence of evidence is not evidence of absence."*

**Context fan-out.**
- **Prometheus MCP (250 ms).** Returns `otelcol_processor_dropped_spans` rate (climbing since 11:42), `otelcol_processor_queue_size` (pegged at queue max of 1000), `container_memory_working_set_bytes{container="otel-collector"}` (saw-toothing against the new 100 MiB limit), and `kube_pod_container_status_restarts_total{container="otel-collector"}=2` (two restarts since 11:42, matches the memory-limiter ejecting and restarting).
- **Loki MCP (200 ms).** Pulls collector logs. Lots of `info refused_spans_total{reason="memory_limiter_high_threshold"}` followed by `warn dropping data ... queue is full`. Drain3 flags the cluster as novel since 11:42 with the rate climbing in lockstep with the dropped-spans metric.
- **Jaeger MCP (180 ms).** Span count over the affected window is ~5 k where the baseline would be ~6 k — a visible deficit. **The pipeline tags this evidence as `*partial — 17 % of spans dropped during window`** so the LLM doesn't infer health from missing data.
- **Deploy-events MCP (90 ms).** Returns the 11:40 config-map change for `otel-collector` — the memory_limiter setting moved from 256 MiB to 100 MiB.

**LLM verdict.** ESCALATE, severity warning (escalating to critical if cascade signals appear), confidence 0.93.

> The k3s otel-collector is dropping ~17 % of incoming spans because the memory_limiter set in the 11:40 config-map change (from 256 MiB to 100 MiB) is now insufficient under steady-state trace volume. The collector pod has restarted twice since 11:42 (memory_limiter ejects it from the data path; Kubernetes restarts; cycle repeats). `otelcol_processor_queue_size` is pegged at 1000 (queue max). Drain3 confirms the memory_limiter warning log is novel since 11:42. **Downstream RCA quality is degraded during this window: trace-based RCAs for any service from 11:42 onwards may be missing 17 % of their span evidence, so don't trust "no slow spans found" as a positive signal until this resolves.**

**Suggested actions.**

1. `kubectl rollout undo deployment/otel-collector -n observability` — fastest restoration. The config change is the proximate cause; reverting it brings the collector back to its known-good 256 MiB limit.
2. After the rollout-undo, monitor `otelcol_processor_dropped_spans` rate; it should hit zero within one queue-flush cycle (~30 s).
3. If the lower memory limit was intentional (e.g. resource-quota pressure on the k3s node): re-apply with `memory_limiter: 256 MiB` **and** add a `batch` processor with `send_batch_max_size=500` to spread the memory pressure across smaller batches before the limiter sees them.
4. File a recurrence note: the audit cycle should add an alert on `kube_pod_container_status_restarts_total{container="otel-collector"}` (currently uncovered) so the next memory-limiter cycle is caught at the first restart, not the 17 %-drop threshold.

**Why it's a perfect cycle.** The unique value of this archetype is that the RCA **labels the trust degradation of its own pillar** in the same paragraph it names the cause. A naive RCA on a downstream `HighP95Latency` alert during this window might conclude "no slow spans, must not be a real latency issue" — that would be wrong because 17 % of spans are missing. By flagging "trace evidence is degraded during this window," the LLM teaches the operator to weigh downstream evidence appropriately, and the validator's cause-evidence rule doesn't accidentally reject claims that lean on the metric pillar instead. This is the kind of meta-awareness that earns the LLM operator trust on the boring days that determine whether they reach for it on the bad days.

*(Partially forward-looking note: `OTelCollectorHighQueueDepth` and `OTelCollectorHighMemoryUsage` are listed in this archetype's matcher regex but their Grafana rules are not yet provisioned. The exemplar regex stays as written so the archetype matches as those rules land; the audit static-prompt is aware of this.)*

---

## Cross-cutting properties demonstrated by these scenarios

| Property | Scenario(s) |
|---|---|
| Three-pillar context (metrics + logs + traces) all consulted, none redundant | 1, 2, 4, 6, 9, 10, 12 |
| Drain3 contributes a signal the other pillars cannot (novelty, rate change) | 1, 4, 5, 9, 11, 13, 14 |
| Architecture-aware suggestions (k8s vs docker-vm vs systemd) | 1 (k8s), 2 (k8s), 4 (docker-vm), 9 (k8s), 10 (k8s + IaC), 11 (k8s), 12 (k8s), 13 (docker-vm), 14 (k8s) |
| Validator catches and blocks investigation-as-action; only remediation verbs ship | All — explicitly visible in 11 |
| LLM declines to hedge — names a cause or explicitly chooses DISMISS / INCONCLUSIVE | 3, 6 |
| System stays quiet when nothing is wrong (no false-positive page) | 7 |
| Bounded-agency retry resolves first-pass uncertainty without an unbounded agent loop | 6 |
| Incidents collapse multiple alerts into one human-readable kill chain | 4, 9, 10 |
| Operator feedback closes the loop and changes future routing | 8 |
| Pre-failure detection (alert fires before user impact) | 11 |
| Deploy / IaC correlation (RCA names a specific commit or apply event) | 1, 5, 9, 10, 11, 12, 14 |
| Network / firewall / connectivity attribution distinct from app failure | 10 |
| App-boot / config failure (CrashLoopBackOff) handled with rollback-first remediation | 9 |
| **Same alertname routes to two different archetypes based on the service it fires on** | 2 vs 12 (`HighP95Latency` upstream vs self) |
| **Critical severity bypasses recurrence gate** (US-5.8 design) | 13 |
| **Baseline σ-claim from entity-baseline MCP path sharpens severity argument** (S3-HF-04) | 12, 13 |
| **RCA labels degraded trust in its own evidence pillar when telemetry pipeline is affected** | 14 |
| Email + dashboard + RCA history record stay consistent | All |
| Pipeline latency stays under 90 s on warm cache, 60 s on first-inference cold | 1 (42 s), 2, 3 (~15 s), 4 (~60 s for bundle), 5, 6 (+~25 s for retry), 9, 10 (~70 s), 11, 12 (~55 s), 13 (~48 s), 14 (~60 s) |

Each row above corresponds to an acceptance criterion already shipped in Sprint 2 or scoped in Sprint 2 Epic 5 — see `monitoring-docs/sprint2-epic5-ueba.html` for the spec, `monitoring-docs/decisions-log.html` for the rationale on each design call.
