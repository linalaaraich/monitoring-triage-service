"""Shared mapping tables for the v2 dashboard + v2 email.

Both `app/main.py` (dashboard render) and `app/notifier.py` (escalation
email) need the same alertname -> plain-English / service -> env /
service -> namespace / service -> service-type tables to keep the design's
data contract consistent across surfaces.

Extracted 2026-05-23 from app/main.py while shipping SF-6 (email
overhaul) - keeping these in one place avoids the dashboard saying
"backend" for a service while the email says "infra" for the same one.

2026-06-02: `env_resolver(alert, ...)` consolidates environment
extraction into one precedence-ordered function shared by the pipeline
(persisted RCARecord.env), the dashboard row (`_v2_transform_row`), the
dashboard URL filter, and the email subject/body. See `env_resolver`
docstring for the precedence chain.
"""

from typing import Any

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
    # WS-1 (2026-06-04): operator-facing names for the platform's app tenant.
    # The image is the mukundmadhav employee-CRUD demo (/api/employee). The
    # generic framework tokens (`spring-boot`, `mysql`, `kong`) stay as
    # legacy aliases so historical RCA rows keep resolving; new emissions
    # from the OTel service.name + app.kubernetes.io/name relabel use the
    # `employees-*` tokens.
    "employees-backend":  "backend",
    "employees-db":       "db",
    "employees-gateway":  "network",
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
    # WS-1 (2026-06-04): see SERVICE_TYPE note above.
    "employees-backend":  "app",
    "employees-db":       "app",
    "employees-gateway":  "network",
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


# Recognised env tokens. Anything outside this set falls through to the
# namespace-prefix inference and then to "unknown". Kept short on purpose:
# CIRES today only has prod / stg / dev / preprod / uat / int as real
# tiers; expanding this list silently is how typos get to look like
# legitimate envs in the dashboard.
KNOWN_ENVS = {"prod", "production", "stg", "staging", "preprod", "uat",
              "int", "integration", "dev", "development", "test", "qa",
              "sandbox", "canary"}

# Short-form normalisation so the dashboard / email pill stays compact
# (the design's pill width was sized for 4-char tokens).
_ENV_CANONICAL = {
    "production": "prod",
    "staging":    "stg",
    "development": "dev",
    "integration": "int",
}


def _normalize_env(raw: str) -> str | None:
    """Lower-case + canonical-form the env token. Returns None if the value
    is empty or not in the KNOWN_ENVS allowlist (so we don't leak a typo
    like `prdo` into the dashboard pill)."""
    if not raw:
        return None
    val = raw.strip().lower()
    if val not in KNOWN_ENVS:
        return None
    return _ENV_CANONICAL.get(val, val)


# Namespace-prefix -> env inference. Falls back through the namespace map
# of (service -> logical namespace) when the alert carries no explicit env
# label. The k8s convention CIRES adopts is `<env>-<app>` (e.g.
# `prod-payments`, `stg-checkout`).
_NS_PREFIX_TO_ENV = {
    "prod-":    "prod",
    "stg-":     "stg",
    "staging-": "stg",
    "preprod-": "preprod",
    "uat-":     "uat",
    "int-":     "int",
    "dev-":     "dev",
    "qa-":      "qa",
    "test-":    "test",
}

# Logical-namespace -> env mapping. Aligned with the NAMESPACE table above
# (the values it can produce). The rental* services historically pointed
# at the staging cluster, so the `rental` namespace reads as stg. The
# observability namespace runs in prod (it's the production monitoring
# stack itself); kube-system also reads as prod. Anything we don't
# recognise stays "unknown" so the operator sees the gap.
_LOGICAL_NS_TO_ENV = {
    "rental":        "stg",
    "app":           "prod",
    "frontend":      "prod",
    "network":       "prod",
    "observability": "prod",
    "kube-system":   "prod",
}


def namespace_to_env(namespace: str | None) -> str | None:
    """Infer env from a k8s namespace string. Two rules:

    1. Prefix match: `prod-foo` / `stg-bar` -> prefix env.
    2. Logical-namespace map: `rental` -> stg, `observability` -> prod.

    Returns None when neither rule fires - the caller should fall through
    to the next precedence tier.
    """
    if not namespace:
        return None
    ns = namespace.strip().lower()
    for prefix, env in _NS_PREFIX_TO_ENV.items():
        if ns.startswith(prefix):
            return env
    if ns in _LOGICAL_NS_TO_ENV:
        return _LOGICAL_NS_TO_ENV[ns]
    return None


def env_resolver(
    *,
    labels: dict[str, Any] | None = None,
    annotations: dict[str, Any] | None = None,
    common_labels: dict[str, Any] | None = None,
    group_labels: dict[str, Any] | None = None,
    common_annotations: dict[str, Any] | None = None,
    service: str | None = None,
    namespace: str | None = None,
) -> str:
    """Resolve the environment for an alert via a precedence chain.

    Precedence (first non-empty wins):
      1. Per-alert `labels.env` / `labels.environment` / `labels.deployment_environment`
      2. Alertmanager-style `commonLabels.env` / `commonLabels.environment`
         / `groupLabels.env`
      3. Annotations: `commonAnnotations.env` or `annotations.env`
      4. Inferred from explicit `namespace` (prefix `prod-*` -> prod, or
         logical-namespace map like `rental` -> stg)
      5. Inferred from `labels.namespace` (same rules as 4)
      6. Inferred from `service` token (e.g. `rental-backend` -> stg) via
         the NAMESPACE table joined with `namespace_to_env`
      7. Falls back to "unknown" so the operator sees the gap rather than
         a silent prod default

    Every input is optional; pass whatever the caller has on hand. The
    KNOWN_ENVS allowlist gates raw label values so a typo like `prdo`
    falls through to the next tier instead of becoming the env.
    """
    labels = labels or {}
    annotations = annotations or {}
    common_labels = common_labels or {}
    group_labels = group_labels or {}
    common_annotations = common_annotations or {}

    # Tier 1 + 2 + 3 - explicit labels / annotations
    for source in (labels, common_labels, group_labels, annotations,
                   common_annotations):
        for key in ("env", "environment", "deployment_environment"):
            normalised = _normalize_env(str(source.get(key, "") or ""))
            if normalised:
                return normalised

    # Tier 4 + 5 - namespace-prefix inference
    if not namespace:
        namespace = str(labels.get("namespace", "") or "") or None
    inferred = namespace_to_env(namespace)
    if inferred:
        return inferred

    # Tier 6 - service-token inference via the logical NAMESPACE table
    svc = (service or "").strip().lower()
    if svc:
        logical_ns = NAMESPACE.get(svc)
        inferred = namespace_to_env(logical_ns)
        if inferred:
            return inferred
        # Last-chance heuristic - service names that embed `rental` map to
        # stg (rental-backend, rental-frontend, rental-mysql) even when
        # they're not in the NAMESPACE table.
        if "rental" in svc:
            return "stg"

    # Tier 7 - explicit gap, not a silent prod default
    return "unknown"


def env_for(service: str, namespace: str | None = None) -> str:
    """Backwards-compatible shim. Prefer `env_resolver(...)` for new code.

    Kept so existing callers (and tests written against the pre-2026-06-02
    rule of "rental -> stg, else prod") keep working. New callers should
    pass the full alert context to `env_resolver`.
    """
    env = env_resolver(service=service, namespace=namespace)
    # Preserve the old fallback semantics - the legacy rule defaulted to
    # "prod" for any non-rental service rather than "unknown". Only kick
    # in when the resolver couldn't pick anything else.
    if env == "unknown":
        return "prod"
    return env


def design_shape_for_alert(alertname: str, service: str, verdict_lower: str,
                            action_taken: str = "",
                            labels: dict | None = None,
                            annotations: dict | None = None,
                            common_labels: dict | None = None) -> dict:
    """Map alert primitives -> the env/namespace/serviceType/alertPlain/verdict
    fields the design's dashboard + email both consume. Use from notifier.py
    when there's no full RCARecord row available (live alert path).

    `labels` / `annotations` / `common_labels` are optional - when present,
    env resolution uses the full precedence chain via `env_resolver`. When
    absent (legacy callers), the resolver falls back to service-token
    inference.
    """
    namespace = NAMESPACE.get(service, (service or "")[:20] or "-")
    if action_taken.lower() == "shelved":
        verdict = "SHELVED"
    else:
        verdict = VERDICT_MAP.get((verdict_lower or "").lower(), "PENDING")
    env = env_resolver(
        labels=labels,
        annotations=annotations,
        common_labels=common_labels,
        service=service,
        namespace=namespace,
    )
    return {
        "env": env,
        "namespace": namespace,
        "serviceType": SERVICE_TYPE.get(service, "infra"),
        "component": service or "-",
        "alertName": alertname,
        "alertPlain": ALERT_NAME_PLAIN.get(alertname, alertname),
        "verdict": verdict,
    }
