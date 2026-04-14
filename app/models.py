import uuid
from datetime import datetime
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


# --- Grafana Alerting webhook payload ---

class GrafanaAlert(BaseModel):
    status: str  # "firing" or "resolved"
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: str = ""
    endsAt: str = ""
    fingerprint: str = ""
    generatorURL: str = ""
    values: dict = Field(default_factory=dict)

    @property
    def alertname(self) -> str:
        return self.labels.get("alertname", "unknown")

    @property
    def instance(self) -> str:
        return self.labels.get("instance", "unknown")

    @property
    def severity(self) -> str:
        return self.labels.get("severity", "warning")

    @property
    def service(self) -> str:
        return (
            self.labels.get("service", "")
            or self.labels.get("job", "")
            or "unknown"
        )


class GrafanaWebhook(BaseModel):
    receiver: str = ""
    status: str = ""
    alerts: list[GrafanaAlert] = Field(default_factory=list)
    groupLabels: dict[str, str] = Field(default_factory=dict)
    commonLabels: dict[str, str] = Field(default_factory=dict)
    commonAnnotations: dict[str, str] = Field(default_factory=dict)
    externalURL: str = ""


# --- Drain3 anomaly webhook payload ---

class Drain3Webhook(BaseModel):
    anomalous_lines: list[str] = Field(default_factory=list)
    anomaly_rate: float = 0.0
    new_templates: list[str] = Field(default_factory=list)
    service: str = "unknown"
    timestamp: str = ""


# --- LLM decision ---

class Decision(str, Enum):
    ESCALATE = "ESCALATE"
    DISMISS = "DISMISS"
    INCONCLUSIVE = "INCONCLUSIVE"


class LLMDecision(BaseModel):
    decision: Decision
    severity: str = "warning"
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str = ""
    rca: str = ""
    anomaly_summary: str = ""
    suggested_actions: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


# --- Context gathering result ---

class GatheredContext(BaseModel):
    metrics: Optional[dict] = None
    logs: Optional[list[str]] = None
    traces: Optional[list[dict]] = None
    annotated_logs: Optional[list[str]] = None
    anomaly_summary: str = ""
    prometheus_ms: int = 0
    loki_ms: int = 0
    jaeger_ms: int = 0
    total_ms: int = 0
    sources_available: int = 0
    errors: list[str] = Field(default_factory=list)


# --- RCA history record ---

class RCARecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    alert_source: str = "grafana"
    alert_name: str = ""
    alert_fingerprint: str = ""
    affected_service: str = ""
    severity: str = "warning"
    triage_decision: str = ""
    llm_verdict: Optional[str] = None
    llm_confidence: Optional[str] = None
    rca_report: Optional[str] = None
    llm_reasoning: Optional[str] = None
    action_taken: str = ""
    related_alerts: Optional[str] = None  # JSON string
    investigation_duration_ms: int = 0


# --- Health ---

class HealthResponse(BaseModel):
    status: str = "healthy"
    uptime_seconds: float = 0
    version: str = "0.1.0"
