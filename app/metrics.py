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

alerts_processed = Counter(
    "triage_alerts_processed_total",
    "Total alerts fully processed through pipeline",
    ["decision"],
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

drain3_clusters = Gauge(
    "drain3_clusters_total",
    "Total Drain3 log template clusters",
)

drain3_anomalies = Counter(
    "drain3_anomalies_total",
    "Total log lines flagged as anomalous",
)

drain3_lines_processed = Counter(
    "drain3_log_lines_processed_total",
    "Total log lines processed by Drain3",
)


def get_metrics() -> bytes:
    return generate_latest()
