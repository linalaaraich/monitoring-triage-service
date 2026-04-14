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
    prometheus_range_minutes: int = 15
    loki_log_limit: int = 50
    jaeger_trace_limit: int = 20

    # Deduplication
    dedup_window_seconds: int = 300

    # Pipeline
    pipeline_timeout: int = 300

    # RCA history
    rca_db_path: str = "/var/lib/triage-service/rca_history.db"

    # Drain3
    drain3_state_dir: str = "/var/lib/triage-service/drain3_state"
    drain3_poll_interval: int = 30
    drain3_anomaly_threshold: int = 5

    # Grafana (for dashboard links in emails)
    grafana_url: str = "http://monitoring-vm:3000"

    model_config = {"env_prefix": "", "case_sensitive": False}


settings = Settings()
