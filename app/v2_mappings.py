"""Shared mapping tables for the v2 dashboard + v2 email.

Both `app/main.py` (dashboard render) and `app/notifier.py` (escalation
email) need the same alertname → plain-English / service → env /
service → namespace / service → service-type tables to keep the design's
data contract consistent across surfaces.

Extracted 2026-05-23 from app/main.py while shipping SF-6 (email
overhaul) — keeping these in one place avoids the dashboard saying
"backend" for a service while the email says "infra" for the same one.
"""

# Verdict normalization — dashboard + email both render these.
VERDICT_MAP = {
    "escalate": "ESCALATE",
    "dismiss": "DISMISS",
    "inconclusive": "PENDING",
    "shelved": "SHELVED",  # synthetic — derived from action_taken
}

# Plain-English rendering for the dashboard "Alert" column + email subject.
ALERT_NAME_PLAIN = {
    "HighP95Latency": "High p95 latency",
    "HighKongP95Latency": "High p95 latency on Kong gateway",
    "HighCpuUsage": "High CPU usage",
    "CriticalCpuUsage": "Critical CPU usage",
    "MediumCpuUsage": "Elevated CPU usage",
    "HighMemoryUsage": "High memory usage",
    "CriticalMemoryUsage": "Critical memory usage",
    "MediumMemoryUsage": "Elevated memory usage",
    "PodHighMemoryUsage": "Pod memory pressure",
    "PodHighCpuUsage": "Pod CPU saturation",
    "TargetDown": "Prometheus target down",
    "Drain3AnomalyDetected": "Novel log-template anomaly",
    "HighDiskUsage": "High disk usage",
    "CriticalDiskUsage": "Critical disk usage",
    "DiskFillingUp": "Disk filling up",
    "LokiHighDiskUsage": "Loki disk usage high",
    "LokiCriticalDiskUsage": "Loki disk usage critical",
    "LokiIngestionRateLow": "Loki ingestion rate dropped",
    "LokiDiskFillingUp": "Loki disk filling up",
    "OTelCollectorDown": "OTel collector down",
    "OTelCollectorHighSpanDropRate": "OTel collector dropping spans",
}

SERVICE_TYPE = {
    "spring-boot": "backend",
    "spring-boot-app": "backend",
    "springboot-app": "backend",
    "backend": "backend",
    "rental-backend": "backend",
    "frontend": "frontend",
    "rental-frontend": "frontend",
    "kong": "network",
    "kong-kong-proxy": "network",
    "rental-mysql": "db",
    "mysql": "db",
    "loki": "infra",
    "prometheus": "infra",
    "jaeger": "infra",
    "grafana": "infra",
    "cadvisor": "infra",
    "node-exporter": "infra",
    "monitoring": "infra",
    "otel-collector": "infra",
    "k3s-node": "infra",
    "drain3": "infra",
}

NAMESPACE = {
    "spring-boot": "app",
    "spring-boot-app": "app",
    "springboot-app": "app",
    "frontend": "frontend",
    "kong": "network",
    "kong-kong-proxy": "network",
    "backend": "rental",
    "rental-backend": "rental",
    "rental-frontend": "rental",
    "rental-mysql": "rental",
    "loki": "observability",
    "prometheus": "observability",
    "jaeger": "observability",
    "grafana": "observability",
    "otel-collector": "observability",
    "drain3": "observability",
    "k3s-node": "kube-system",
    "monitoring": "observability",
}


def env_for(service: str, namespace: str | None = None) -> str:
    """Heuristic environment for a service. Phase 1 rule:
    rental-namespace services → "stg"; everything else → "prod".
    Real label-based extraction is SF-1 in Sprint 4.
    """
    if (namespace or "") == "rental" or "rental" in (service or ""):
        return "stg"
    return "prod"


def design_shape_for_alert(alertname: str, service: str, verdict_lower: str,
                            action_taken: str = "") -> dict:
    """Map alert primitives → the env/namespace/serviceType/alertPlain/verdict
    fields the design's dashboard + email both consume. Use from notifier.py
    when there's no full RCARecord row available (live alert path).
    """
    namespace = NAMESPACE.get(service, (service or "")[:20] or "—")
    if action_taken.lower() == "shelved":
        verdict = "SHELVED"
    else:
        verdict = VERDICT_MAP.get((verdict_lower or "").lower(), "PENDING")
    return {
        "env": env_for(service, namespace),
        "namespace": namespace,
        "serviceType": SERVICE_TYPE.get(service, "infra"),
        "component": service or "—",
        "alertName": alertname,
        "alertPlain": ALERT_NAME_PLAIN.get(alertname, alertname),
        "verdict": verdict,
    }
