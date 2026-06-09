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
    # DEPRECATED 2026-06-04 (audit issue #4, Lina-approved). Default flipped
    # True → False because SF-5 is STRUCTURALLY UNREACHABLE in production:
    # SF-5's precondition is "a prior fire 0–120s ago" (window below), but
    # that is a STRICT SUBSET of the 300s dedup window (dedup_window_seconds,
    # which runs FIRST in the pipeline and short-circuits). Any prior fire
    # within 120s is also within 300s → caught by dedup → SF-5 never sees it.
    # Confirmed empirically: ZERO `spike_shelved` rows have EVER been written
    # despite SF-5 being enabled since deploy. The canonical noise absorber is
    # the recurrence-gate (US-5.8) + dedup; SF-5 added no coverage. Disabled
    # rather than ripped out (safe deprecation) — the path is gated behind
    # this flag, so the default flip neutralises it while keeping the code +
    # unit tests available should a future redesign (e.g. SF-5 window > dedup
    # window, or real duration data) make a "spike" gate reachable.
    sf5_transient_spike_enabled: bool = False
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

    # S5-DRN-01 (2026-06-04) — 3-TIER HIERARCHICAL anomaly thresholds.
    # A single global per-batch rate (drain3_alert_rate_threshold above, now the
    # SYSTEM tier) misses two real failure shapes: (1) ONE service very weird but
    # globally diluted (40% of cart's lines anomalous, but cart is 10 of 1000
    # batch lines → 1% global → no fire); (2) a whole application quietly weird
    # across its components, none individually crossing the bar. So we evaluate
    # three tiers INDEPENDENTLY each batch, each with its own scope-keyed cooldown:
    #   - COMPONENT: per-service rate (catches one weird service)
    #   - APPLICATION: per-app rate, aggregating a namespace's component services
    #   - SYSTEM: the global rate (unchanged — preserves prior behavior)
    # Hierarchy: broader scope ⇒ LOWER bar (0.25 > 0.15 > 0.10), because broad
    # elevation is much harder to reach by noise than a single-service spike.
    drain3_component_rate_threshold: float = 0.25   # one service this weird → fire
    drain3_component_min_lines: int = 30
    drain3_app_rate_threshold: float = 0.15         # a whole app's components elevated
    drain3_app_min_lines: int = 60
    # System tier reuses drain3_alert_rate_threshold / drain3_alert_min_lines.
    # Optional explicit service→application overrides; when absent, the app is
    # derived from the log stream's k8s namespace label, else the service itself
    # (so an ungrouped service is its own single-component app — harmless).
    drain3_app_map: dict[str, str] = {}
    # Cap fires per tier per batch so an incident can't spawn an alert storm;
    # highest-rate scopes fire first and the suppressed count is logged (never
    # silently dropped).
    drain3_max_alerts_per_tier_per_batch: int = 3
    # Issue #1 (2026-06-04) — drain3 noise-suppression gate. A drain3 self-fire
    # that carries NO new templates AND an anomaly_rate below this floor is a
    # data-starved "cannot determine" self-fire (rare/under-threshold clusters,
    # benign DEBUG jitter). These each used to spawn a full ~100s LLM
    # `investigate` row that resolved to a hedge. When enabled, such a fire is
    # short-pathed to a cheap `drain3_noise_suppressed` record with no LLM call.
    # CONSERVATIVE: only fires with no novel templates qualify — any batch that
    # actually introduces a new template is always investigated.
    drain3_noise_suppress_enabled: bool = True
    drain3_noise_suppress_rate_floor: float = 0.05  # < 5% anomalous AND no new templates

    # BE-B3 (2026-06-04) — drain3 SOURCE-EXCLUSION denylist. The Drain3 template
    # miner must only learn templates for MONITORED APPLICATIONS, never for the
    # observability/infra stack itself (Grafana, Loki, Prometheus, the OTel
    # collector, the MCP bridges, exporters, kube-system, ...). Those internal
    # services emit high-cardinality / rotating content that looks "novel" on
    # essentially every batch, so feeding them into the miner produced a flood of
    # duplicate "Novel log-template anomaly" alerts for infra noise. This denylist
    # is enforced at the analyzer's ingestion boundary (DrainAnalyzer._is_excluded):
    # any line whose resolved service matches is dropped — no miner created, no
    # line counted, no anomaly emitted. Matching is case-insensitive and ALSO
    # catches the `ai-mcp-*` / `ai-*` container-name forms, any `*-exporter`, and
    # namespace-style buckets (kube-system / observability / monitoring).
    # This treats the SOURCE; the dedup fingerprint in app/dedup.py only treated
    # the symptom. NOTE: filtering only what already flows in — no new data reads
    # (MCP-only data-access invariant preserved).
    drain3_excluded_services: list[str] = [
        "grafana",
        "loki",
        "prometheus",
        "promtail",
        "otel-collector",
        "ai-otel-collector",
        "node-exporter",
        "cadvisor",
        "kube-state-metrics",
        # MCP bridges (logical names + ai-mcp-* container forms caught by prefix)
        "mcp-prometheus",
        "mcp-loki",
        "mcp-jaeger",
        "mcp-drain3",
        "mcp-rca-history",
        # namespace-style buckets
        "kube-system",
        "observability",
        "monitoring",
        # 2026-06-09 (alert-quality audit, RC-1) — host/infra streams that were
        # the DOMINANT drain3 noise source: Jaeger's embedded BadgerDB
        # compaction INFO + the OTel collector's batch-processor self-noise all
        # ship under `monitoring-vm` (the obs-backend host) / `jaeger`, neither
        # of which the bare `monitoring`/`observability` buckets matched. The
        # monitored apps run on k3s, never on these hosts, so excluding the
        # whole stream is safe. Also the GPU-host infra streams flagged in the
        # 2026-06-04 handoff ("not blocking" then — now the #1 alert source).
        "monitoring-vm",
        "jaeger",
        "ollama",
        "coredns",
        "host-syslog",
        "syslog",
        "gpu-stack",
        "drain3",
        "dcgm-exporter",
    ]

    # Issue #2 (2026-06-04) — data-starved early-exit gate. When context-gather
    # comes back with NOTHING actionable (all three MCP pillars empty AND no
    # Drain3 anomaly_summary AND no observed value AND no correlated alerts AND
    # no prior decision / operator feedback to anchor on), the LLM has nothing
    # to ground a cause in — it will spend a full ~100s cold inference (+retry +
    # bounded-agency = a second inference) only to hedge "Cannot determine the
    # root cause / insufficient data", and clutter the operator feed with a
    # noisy `investigate` row. This gate short-paths such an alert BEFORE the LLM
    # call to a cheap, QUIET `data_starved_suppressed` record: no LLM, no email,
    # no escalate, recorded as `suppressed` so it does not appear as a full
    # investigate row in the feed. Mirrors the drain3 noise-suppression gate.
    #
    # CONSERVATIVE BY DESIGN — every one of the bypass conditions below keeps an
    # alert on the full LLM path. CRITICAL-severity alerts ALWAYS bypass the
    # gate (a critical alert with thin context still deserves a human-readable
    # investigation + page, not a quiet suppression). A genuinely data-starved
    # NON-critical alert is cheap + quiet here instead of a 100s "cannot
    # determine" page. Disable via DATA_STARVED_EARLY_EXIT_ENABLED=false.
    data_starved_early_exit_enabled: bool = True
    # Severities that ALWAYS bypass the early-exit gate (always get the full
    # LLM investigation even on thin context). Match is case-insensitive.
    data_starved_early_exit_bypass_severities: list[str] = ["critical"]

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
