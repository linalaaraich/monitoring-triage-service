from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Ollama
    ollama_url: str = "http://ollama:11434"
    ollama_model: str = "llama3.1:8b"
    ollama_timeout: int = 300
    ollama_request_timeout: int = 30

    # Circuit breaker
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_cooldown_seconds: int = 60

    # MCP server URLs
    prometheus_mcp_url: str = "http://prometheus-mcp:8091"
    loki_mcp_url: str = "http://loki-mcp:8092"
    jaeger_mcp_url: str = "http://jaeger-mcp:8093"
    drain3_mcp_url: str = "http://drain3-mcp:8094"
    rca_history_mcp_url: str = "http://rca-history-mcp:8095"

    # Loki direct (for Drain3 background ingestion)
    loki_api_url: str = "http://loki:3100"

    # SMTP
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    notification_email: str = ""

    # Context gathering
    context_timeout: int = 8
    # MCP query scope. These are the upper bounds the triage passes to each
    # MCP when gathering context for an alert. Bumped from 15/50/20 on
    # 2026-04-23 after observing that the LLM had to reason from only 50
    # log lines and ~2 traces per alert, which is below the "give it the
    # full picture" bar. Values are high enough to capture cascades but not
    # so high they blow past the Ollama model's context window.
    prometheus_range_minutes: int = 30    # was 15
    loki_log_limit: int = 500             # was 50
    jaeger_trace_limit: int = 100         # was 20

    # Deduplication
    dedup_window_seconds: int = 300

    # Pipeline
    pipeline_timeout: int = 300

    # Layer 2 pre-LLM triage (noise suppression without calling the LLM)
    triage_suppression_enabled: bool = True
    # 2026-05-19 (P2 fix): lowered 15 → 10 after a real-load investigation
    # showed one dismiss was silencing 5+ subsequent fires of the same alert
    # within a 15-minute window. 10 minutes caps the cascade at ~3 fires.
    triage_history_lookback_minutes: int = 10

    # DA-3 — cross-row verdict coherence. When a NON-duplicate fire happens
    # for a fingerprint that had a prior decision within this window, the
    # pipeline fetches that prior decision's cause + RCA and injects it into
    # the LLM prompt with a coherence instruction (reuse the prior cause if
    # the situation is unchanged, frame any genuine change as "changed my
    # mind because…", or say "condition resolved" if the alert is now
    # recovering). Prevents the platform emitting contradictory RCAs on
    # consecutive fires of the same flapping alert. Window is wider than the
    # dedup window (so post-dedup flaps still see the prior verdict) but
    # bounded so a stale week-old cause doesn't leak into a fresh incident.
    da3_verdict_coherence_enabled: bool = True
    da3_verdict_coherence_window_minutes: int = 30

    # SF-5 — sustained-vs-spike verdict modifier. When a fingerprint (or
    # family-scope: cpu/memory/disk/loki-disk/latency-p95 on the same
    # host/service) refires within sf5_transient_spike_window_seconds of a
    # prior decision, classify as transient_spike + shelve without the LLM
    # call. Direct response to the "too many useless emails" feedback
    # (2026-05-31): a 90 s CPU blip that resolves on its own shouldn't page
    # the operator; a sustained 10-min stress still escalates normally.
    # Composes with DA-5 family dedup + reuses DA-3's prior-decision lookup
    # so the MCP-only invariant holds. False-negative bias is intentional —
    # a real sustained breach that accidentally gets shelved just re-fires
    # in 5 min, but a false-positive shelving would hide a real incident.
    sf5_transient_spike_enabled: bool = True
    sf5_transient_spike_window_seconds: int = 120
    # Families that opt into transient-spike classification. Restricted to
    # archetypes where "duration above threshold" is a meaningful signal
    # (CPU/memory/disk utilisation, p95 latency). Binary alerts like
    # TargetDown / DeadMansSwitch are intentionally excluded.
    sf5_transient_spike_families: list[str] = [
        "cpu", "memory", "disk", "loki-disk", "latency-p95",
    ]

    # If the first LLM pass produces a data-starved RCA (hedges like "insufficient
    # data" without naming a cause), retry once with an explicit anti-hedge prompt.
    # Adds up to ~25 s to the pipeline on cold inferences; disable if latency
    # budget is tight or Ollama is on a small GPU.
    triage_data_starved_retry_enabled: bool = True
    # P1.5 — bounded-agency retry. When the first pass is data_starved or
    # INCONCLUSIVE, allow the LLM to request EXACTLY ONE additional
    # whitelisted MCP query, then re-decide with that new evidence. At
    # most one extra call; deterministic given the same inputs; uses
    # existing MCPs — no agent framework. See app/bounded_agency.py.
    triage_bounded_agency_enabled: bool = True

    # S3-HF-03 (Tier 2) — hypothesis-menu validator + cause-evidence rule.
    # When True, response_validator scans for "possibly X or Y" / "may be
    # due to (slow query|pool saturation|GC)" / "could be one of" prose
    # AND flags RCAs whose first-sentence cause shares no non-stopword
    # token with the evidence list. Hits trigger the existing retry path;
    # Tier 0 clamp (S3-HF-01) is the safety net for retries that fail.
    # Ships aggressive — dial back via env if the new
    # triage_validator_retries_total{reason} metric shows >5% FP rate.
    triage_hypothesis_menu_strict: bool = True

    # RCA history
    rca_db_path: str = "/var/lib/triage-service/rca_history.db"

    # Drain3
    drain3_state_dir: str = "/var/lib/triage-service/drain3_state"
    drain3_poll_interval: int = 30
    drain3_anomaly_threshold: int = 5
    # P1.7: drain3 → /webhook/drain3 self-alerting.
    # After each ingest batch, if the anomaly rate in the sliding window is
    # above drain3_alert_rate_threshold AND at least drain3_alert_min_lines
    # have been ingested in that window, self-POST a Drain3Webhook to our
    # own /webhook/drain3 endpoint. This makes drain3 a visible alert source
    # on the dashboard (the endpoint existed; nothing called it before).
    # Cooldown prevents thrash.
    drain3_alert_enabled: bool = True
    drain3_alert_rate_threshold: float = 0.10      # 10% anomalous lines → alert
    drain3_alert_min_lines: int = 100              # minimum sample size per window
    drain3_alert_cooldown_seconds: int = 600       # 10 min between alerts
    drain3_self_webhook_url: str = "http://localhost:8090/webhook/drain3"

    # Public UIs for deep-links in the escalation email + dashboard.
    # Defaults assume the tailnet/MagicDNS layout; override per-deployment
    # via env (GRAFANA_URL, JAEGER_URL, LOKI_URL).
    # 2026-06-04: defaults updated from the old-account IP (52.202.21.192,
    # decommissioned) to the new-account Tailscale MagicDNS hostname. The
    # detail-page CIRES_LINKS (Open Grafana / Loki / Jaeger buttons) read
    # these. Compose env vars (GRAFANA_URL / JAEGER_URL / LOKI_URL) still
    # win when set; these defaults are the fallback for any container or
    # local dev shell that doesn't export them.
    grafana_url: str = "http://observability-rca-newacct-monitoring:3000"
    jaeger_url: str = "http://observability-rca-newacct-monitoring:16686"
    loki_url: str = "http://observability-rca-newacct-monitoring:3100"
    # Public URL of the triage's own /dashboard (used by the v2 escalation
    # email's "View on dashboard" button to deep-link into the alert's
    # detail page). Override per-deploy via TRIAGE_DASHBOARD_URL env.
    triage_dashboard_url: str = "http://observability-gpu-uswest2-newacct:8090"

    # Grafana read API auth, for the startup downtime backfill (see
    # app/startup_backfill.py). Empty defaults disable the backfill.
    grafana_api_user: str = "admin"
    grafana_api_password: str = ""
    # On startup, if (now - max(rca_history.timestamp)) > this threshold,
    # query Grafana's annotation API for fire transitions in the gap and
    # replay each unique (alertname, service) through the pipeline.
    # Default 15 min covers laptop lid-close naps without triggering on
    # every normal restart. Disabled entirely when grafana_api_password="".
    startup_backfill_threshold_minutes: int = 15
    startup_backfill_max_gap_hours: int = 24  # cap to avoid replaying a week

    # US-5.3 closed-loop feedback metrics window (precision + recall).
    # Default 7d matches the alert-frequency lookback so operator habits
    # over one week are the unit of measurement. Used by /metrics handler
    # in app/main.py to compute triage_precision + triage_recall.
    feedback_metrics_window_days: int = 7

    # Service name → deployment type map. Used by:
    #   - metric_interpreter.py to attach deployment_type to MetricFacts
    #   - suggested_actions.yaml template selector
    #   - response_validator.py to reject architecture-mismatched actions
    # Keys are the "service" label on the alert (from the alert rule), values
    # are one of:
    #   k8s         — deployed as a k3s workload; kubectl commands apply
    #   docker-vm   — deployed via docker-compose on a plain VM; ssh + docker
    #                 ps/logs apply, kubectl does NOT
    #   systemd     — host-level daemon (node-exporter via systemd unit);
    #                 systemctl + journalctl apply
    #   external    — third-party SaaS or outside our infra; no actions other
    #                 than "contact vendor" are valid
    # Unknown service labels default to "unknown" which suppresses
    # architecture-specific suggestions (templates emit generic actions only).
    service_deployment_type: dict[str, str] = {
        # k3s workloads (live in the k3s cluster, namespace=app/frontend/network/observability)
        # WS-1 (2026-06-04): operator-facing names for the platform's app
        # tenant. The image is the mukundmadhav employee-CRUD demo
        # (/api/employee). The generic framework tokens stay as aliases
        # below so historical alerts and dashboards keep routing to k8s
        # actions.
        "employees-backend": "k8s",
        "employees-db":      "k8s",
        "employees-gateway": "k8s",
        "spring-boot":   "k8s",
        # spring-boot-app + springboot-app are Grafana / OTel label variants for
        # the same workload; charts/spring-boot/ is the canonical deployment.
        # Kept as aliases so a stray label spelling doesn't fall back to
        # "unknown" (audit I-2, 2026-05-21).
        "spring-boot-app": "k8s",
        "springboot-app": "k8s",
        "kong":          "k8s",
        # otel-collector runs in BOTH k3s (DaemonSet, namespace=observability) AND
        # as a docker container on monitoring-vm. The map can only carry one type
        # per name; "k8s" wins because that's where the alert routing fires from
        # today. Disambiguate via the instance label if a docker-vm-specific
        # otel-collector alert appears.
        "otel-collector": "k8s",
        "frontend":      "k8s",
        # monitoring-vm docker-compose stack
        "prometheus":    "docker-vm",
        "loki":          "docker-vm",
        "jaeger":        "docker-vm",
        "grafana":       "docker-vm",
        "cadvisor":      "docker-vm",
        # node-exporter runs as a docker container on monitoring-vm
        # (prom/node-exporter image), NOT as a systemd unit. Corrected
        # 2026-04-28 audit (I-1).
        "node-exporter": "docker-vm",
        "monitoring":    "docker-vm",  # label used by TargetDown for anything on monitoring-vm
        # Host-level (systemd or equivalent daemons on the k3s node + VMs)
        "k3s-node":      "systemd",
        # car-rental tenant (added 2026-05-19) — second Spring Boot + MySQL
        # workload deployed alongside react-springboot-mysql on the same k3s
        # cluster, namespace=rental. Same archetype coverage as the existing
        # spring-boot service since the stack is structurally identical.
        # Note: alert.service for the rental backend container is "backend"
        # (the container name in the helm chart), not "rental-backend".
        # Charts mirrored 2026-05-20 into
        # monitoring-project/charts/rental-{backend,frontend,db}/
        # — see charts/RENTAL-TENANT.md for the source-of-truth note.
        "backend":       "k8s",
        "rental-backend": "k8s",
        "rental-frontend": "k8s",
        "rental-mysql":  "k8s",
    }

    # IP-to-hostname map for turning raw alert instances like "10.0.1.194:9100"
    # into "observability-rca-k3s / node-exporter" in emails + dashboard.
    # Keys are IPs (no port); values are friendly hostnames. Port→role
    # resolution is a separate map below so we can combine into one display
    # string. Override via INSTANCE_HOSTS env (JSON) when the layout shifts.
    instance_hosts: dict[str, str] = {
        "10.0.1.105": "observability-rca-newacct-monitoring",
        "10.0.1.152": "observability-rca-newacct-k3s",
        "127.0.0.1": "localhost",
    }
    instance_ports: dict[str, str] = {
        "9100": "node-exporter",
        "8080": "spring-boot",
        "8000": "kong",
        "8001": "kong-admin",
        "8081": "cadvisor",
        "3000": "grafana",
        "3100": "loki",
        "9090": "prometheus",
        "16686": "jaeger-ui",
        "8888": "otel-collector",
        "4317": "otel-otlp-grpc",
        "4318": "otel-otlp-http",
        "6443": "k3s-api",
        "8090": "triage-service",
        "8091": "mcp-prometheus",
        "8092": "mcp-loki",
        "8093": "mcp-jaeger",
        "8094": "mcp-drain3",
        "8095": "mcp-rca-history",
        "11434": "ollama",
    }

    model_config = {"env_prefix": "", "case_sensitive": False}


settings = Settings()
