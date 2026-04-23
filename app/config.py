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
    triage_history_lookback_minutes: int = 15

    # If the first LLM pass produces a data-starved RCA (hedges like "insufficient
    # data" without naming a cause), retry once with an explicit anti-hedge prompt.
    # Adds up to ~25 s to the pipeline on cold inferences; disable if latency
    # budget is tight or Ollama is on a small GPU.
    triage_data_starved_retry_enabled: bool = True

    # RCA history
    rca_db_path: str = "/var/lib/triage-service/rca_history.db"

    # Drain3
    drain3_state_dir: str = "/var/lib/triage-service/drain3_state"
    drain3_poll_interval: int = 30
    drain3_anomaly_threshold: int = 5

    # Public UIs for deep-links in the escalation email + dashboard.
    # Defaults assume the tailnet/MagicDNS layout; override per-deployment
    # via env (GRAFANA_URL, JAEGER_URL, LOKI_URL).
    grafana_url: str = "http://52.202.21.192:3000"
    jaeger_url: str = "http://52.202.21.192:16686"
    loki_url: str = "http://52.202.21.192:3100"

    # IP-to-hostname map for turning raw alert instances like "10.0.1.194:9100"
    # into "observability-rca-k3s / node-exporter" in emails + dashboard.
    # Keys are IPs (no port); values are friendly hostnames. Port→role
    # resolution is a separate map below so we can combine into one display
    # string. Override via INSTANCE_HOSTS env (JSON) when the layout shifts.
    instance_hosts: dict[str, str] = {
        "10.0.1.68": "observability-rca-monitoring",
        "10.0.1.194": "observability-rca-k3s",
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
        "9093": "alertmanager",
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
