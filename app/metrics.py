from prometheus_client import Counter, Gauge, Histogram, generate_latest

webhooks_received = Counter(
    "triage_webhooks_received_total",
    "Total webhook requests received",
    ["source"],
)

alerts_deduplicated = Counter(
    "triage_alerts_deduplicated_total",
    "Total alerts skipped by deduplication",
)

alerts_suppressed = Counter(
    "triage_alerts_suppressed_total",
    "Total alerts suppressed by Layer 2 pre-LLM triage (no Ollama call)",
    ["reason"],
)

alerts_processed = Counter(
    "triage_alerts_processed_total",
    "Total alerts fully processed through pipeline",
    ["decision"],
)

# US-5.3 closed-loop feedback. Counter increments every time the pre-LLM
# similarity gate flips a DISMISS to an ESCALATE because of an active
# operator override. The Gauges (precision/recall) are computed lazily
# at scrape time — see app/main.py /metrics handler.
override_forced_escalations = Counter(
    "triage_override_forced_escalations_total",
    "DISMISS verdicts flipped to ESCALATE by an active operator override",
)

# US-5.8 recurrence gate.
recurrence_gated_pre_llm = Counter(
    "triage_recurrence_gated_pre_llm_total",
    "Alerts skipped pre-LLM by the recurrence gate (count under threshold).",
)
recurrence_force_escalated = Counter(
    "triage_recurrence_force_escalated_total",
    "DISMISS verdicts flipped to ESCALATE by the post-LLM recurrence gate.",
)
recurrence_critical_bypassed = Counter(
    "triage_recurrence_critical_bypassed_total",
    "Critical-severity alerts that opted into the gate by misconfiguration — gate bypassed defensively.",
)

triage_precision = Gauge(
    "triage_precision",
    "TP / (TP+FP) over the last feedback_metrics_window_days. "
    "TP = ESCALATE confirmed by /feedback/confirm; FP = ESCALATE without "
    "confirm AND without override (i.e., escalations the operator hasn't "
    "labeled). Computed lazily at scrape time.",
)

triage_recall = Gauge(
    "triage_recall",
    "TP / (TP+FN) over the last feedback_metrics_window_days. "
    "FN = DISMISS overridden via /feedback/override. Computed lazily at scrape time.",
)

pipeline_duration = Histogram(
    "triage_pipeline_duration_seconds",
    "Full pipeline duration from webhook to decision",
    buckets=[1, 5, 10, 30, 60, 120, 300],
)

pipeline_timeouts = Counter(
    "triage_pipeline_timeouts_total",
    "Total pipeline timeouts (5-min fallback triggered)",
)

context_duration = Histogram(
    "triage_context_gathering_seconds",
    "Context gathering duration",
    ["source"],
    buckets=[0.5, 1, 2, 4, 8],
)

llm_duration = Histogram(
    "triage_llm_investigation_seconds",
    "LLM investigation duration",
    buckets=[5, 10, 30, 60, 120, 300],
)

emails_sent = Counter(
    "triage_emails_sent_total",
    "Total emails sent",
    ["type"],
)

triage_email_sent_total = Counter(
    "triage_email_sent_total",
    "Total email dispatch attempts by outcome",
    ["status"],
)

drain3_clusters = Gauge(
    # Renamed from "drain3_clusters_total" 2026-04-29 (audit §4 finding):
    # _total suffix is a Prometheus convention for counters. This is a
    # gauge — a snapshot of the current cluster count, which can shrink
    # if templates expire. Old name caused Grafana queries for
    # `drain3_clusters` to silently return empty.
    "drain3_clusters",
    "Total Drain3 log template clusters (current count, not a counter)",
)

triage_validator_retries_total = Counter(
    # S3-HF-03 (Tier 2). Increments every time the response validator
    # catches a hypothesis-menu pattern ("possibly X or Y") or a
    # cause-evidence-mismatch (RCA's first sentence shares no token with
    # the evidence list). Used to monitor false-positive rate after the
    # aggressive default ship; if rate > 5%, dial back via
    # settings.triage_hypothesis_menu_strict=False.
    "triage_validator_retries_total",
    "Validator-triggered retries by reason (hypothesis_menu, cause_evidence_mismatch).",
    ["reason"],
)

triage_bounded_agency_invocations_total = Counter(
    # Counts data-starved retries that triggered the bounded-agency loop in
    # pipeline.py. Outcome values: "tool_called" (LLM asked for one MCP tool
    # and the executor ran it + re-prompted), "decided_directly" (LLM emitted
    # a verdict in the agency pass without a tool call), "no_action" (parse
    # failed or LLM produced nothing — falls through to anti-hedge retry).
    # Wired 2026-04-29 (audit §4 finding: documented at triage-service.html
    # but never registered).
    "triage_bounded_agency_invocations_total",
    "Bounded-agency retries by outcome",
    ["outcome"],
)

drain3_anomalies = Counter(
    "drain3_anomalies_total",
    "Total log lines flagged as anomalous",
)

drain3_lines_processed = Counter(
    "drain3_log_lines_processed_total",
    "Total log lines processed by Drain3",
)

# --- AI-01: Ollama call metrics ---

ollama_request_duration_seconds = Histogram(
    "ollama_request_duration_seconds",
    "Duration of individual Ollama HTTP requests",
    buckets=[1, 5, 10, 30, 60, 120],
)

ollama_requests_total = Counter(
    "ollama_requests_total",
    "Total Ollama requests by outcome",
    ["status"],
)

ollama_circuit_state = Gauge(
    "ollama_circuit_state",
    "Ollama circuit breaker state (0=closed, 1=open, 2=half_open)",
)

# --- AI-03: Enhanced self-observability metrics ---

triage_queue_depth = Gauge(
    "triage_queue_depth",
    "Number of alerts currently being processed in the pipeline",
)

triage_mcp_requests_total = Counter(
    "triage_mcp_requests_total",
    "Total MCP server requests by server and status",
    ["server", "status"],
)

triage_mcp_duration_seconds = Histogram(
    "triage_mcp_duration_seconds",
    "Latency of MCP server calls",
    ["server"],
)

triage_fallback_total = Counter(
    "triage_fallback_total",
    "Total LLM fallback activations by reason",
    ["reason"],
)

triage_llm_token_count = Histogram(
    "triage_llm_token_count",
    "LLM token counts per request, broken down by prompt and completion",
    ["type"],
    buckets=[64, 256, 512, 1024, 2048, 4096, 8192, 16384],
)


def get_metrics() -> bytes:
    return generate_latest()
