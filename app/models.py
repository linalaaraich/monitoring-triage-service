import uuid
from datetime import datetime
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# --- Grafana Alerting webhook payload ---

class GrafanaAlert(BaseModel):
    """One alert inside a Grafana webhook payload.

    Permissive shape — every field has a safe default so we don't 422 on
    any Grafana variant. The empirically-observed failure mode (debug
    handler 2026-04-27) was a webhook batch where some alerts were
    missing `status` (probably resolved-state edge cases or a Grafana 13
    quirk). Rather than guess at the exact trigger we accept any payload
    and let the pipeline ignore malformed entries downstream.

    `model_config` allows unknown extra fields (Grafana adds new keys
    over time — e.g. `silenceURL`, `dashboardURL`, `panelURL`, `imageURL`,
    `valueString`) so a future Grafana upgrade doesn't break the webhook.
    """
    model_config = ConfigDict(extra="ignore")

    status: str = "firing"  # "firing" or "resolved"; default = the common case
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: str = ""
    endsAt: str = ""
    fingerprint: str = ""
    generatorURL: str = ""
    values: dict = Field(default_factory=dict)
    valueString: str = ""

    @field_validator("values", mode="before")
    @classmethod
    def _coerce_values(cls, v):
        # Grafana sometimes sends `values: null` for resolved alerts
        # or NoData transitions — treat as empty dict.
        return v or {}

    @field_validator("labels", "annotations", mode="before")
    @classmethod
    def _coerce_dict(cls, v):
        return v or {}

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
    # S5-DRN-01 — which hierarchical tier raised this and over what scope.
    # Defaults preserve every existing caller (single system-wide fire).
    tier: str = "system"          # component | application | system
    scope: str = "all"            # service name | app name | "all"
    # Fix C (2026-06-11, fabricated-RCA incident): the REAL services that
    # emitted the flagged lines, dominant first. Lets the pipeline scope the
    # three-pillar cross-reference to a service that actually exists instead
    # of the synthetic "drain3" label (which made every pillar return empty
    # and turned "metrics are silent" into an artifact).
    services: list[str] = Field(default_factory=list)


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
    # human_cause: a SINGLE plain-English sentence stating WHAT went wrong.
    # No PromQL, no `metric{...} = value`, no histogram_quantile blocks. The
    # email's "Why" block, the dashboard row's "reason" cell, and the detail
    # page's Cause H1 ALL render this verbatim — operators must understand
    # the failure at a glance without parsing a metric formula. Technical
    # supporting evidence (PromQL expressions, raw values, log snippets,
    # trace IDs) belongs in the `evidence` list below. Empty string means
    # the LLM didn't emit it (legacy rows, fallback paths); the renderer
    # derives a human-readable lead from `rca`/`reason` in that case via
    # app.prose_helpers.derive_human_cause.
    human_cause: str = ""
    anomaly_summary: str = ""
    suggested_actions: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    # US-3.9 (Tier 0): when the F-4 confidence clamp fires (surface-only,
    # data_starved, or templated actions), the pipeline strips
    # suggested_actions and populates this with alert-aware read-only
    # diagnostic verbs (Jaeger drill, hikari/JVM/Kong PromQL pivots) plus
    # an explicit "do NOT kubectl rollout/scale/set" warning. The
    # operator sees a clear "investigate, don't remediate" path instead
    # of templated remediations that don't follow from a hypothesis-only RCA.
    # LLMs may also emit this directly when they want to ask for investigation
    # rather than commit to remediation — both paths are supported.
    diagnostic_steps: list[str] = Field(default_factory=list)

    # Small 3B-parameter models frequently return `evidence` as a list of
    # dict objects (e.g. {"metric": "...", "value": 4.7}) instead of the
    # list[str] we asked for. That's meaningful structured output; we should
    # accept it, not reject it. Coerce dict items to their JSON string form
    # so downstream rendering (email, RCA store) still works.
    @field_validator("evidence", "suggested_actions", "diagnostic_steps", mode="before")
    @classmethod
    def _coerce_list_items_to_str(cls, v):
        if isinstance(v, list):
            out = []
            for item in v:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, dict):
                    # Best-effort compact dict rendering
                    parts = [f"{k}={item[k]}" for k in item]
                    out.append(" ".join(parts))
                elif item is None:
                    continue
                else:
                    out.append(str(item))
            return out
        return v


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
    # True when the Loki query fell back to any-service lines (not scoped
    # to the alert). Used by the LLM prompt builder to flag the logs section
    # as ambient context — NOT alert-specific evidence — so small models
    # don't misread log-volume as the alert's observed metric.
    loki_is_fallback: bool = False
    # S3-HF-07 (shipped 2026-05-19): Tier 1 deep trace gather. When the
    # alert is latency-flavoured and the standard /tools/find_traces
    # response yields a candidate trace, the pipeline fires a single
    # /tools/get_trace call on the slowest trace and renders the per-span
    # breakdown as `## Trace span breakdown` in the LLM prompt. Lets the
    # LLM say "hikaricp pool exhausted, all spans queued" instead of
    # "upstream is slow" — that's the entire Epic-4 trace-depth theme.
    # None when the alert isn't latency-flavoured, when traces are empty,
    # or when the MCP call failed (non-fatal — first-pass RCA still ships).
    deep_trace: Optional[dict] = None
    deep_trace_ms: int = 0
    # 2026-06-12: one deterministic ranked line naming the slowest span +
    # slowest downstream span (service / op / ms / % of trace). Rendered
    # ABOVE the deep-trace JSON so the LLM can't miss the culprit even if it
    # skims. The JSON is now duration-sorted + slimmed (see _compact_deep_trace)
    # so the slow downstream span survives the prompt char cap.
    deep_trace_summary: str = ""
    # 2026-06-10 (iteration 5): deterministic plain-English interpretation of
    # the kube-state context query (replica counts, non-running pods, recent
    # termination reasons). Rendered ABOVE the raw metrics JSON for Kube*/
    # PodCrashLooping alerts — the 14b doesn't infer "available=0 == down"
    # from raw series (decisions 13b15c81/1b177fa4), so code does.
    kube_workload_summary: Optional[str] = None
    # Fix F (2026-06-11): deterministic plain-English summary of the deploy
    # bridge's /tools/recent_deploys answer for kube-workload + Drain3
    # alerts. Either names a real rollout ("deployment ad rolled 14 min
    # before this alert…") or explicitly rules deploys out ("No deploys of
    # ad in the last 2h — deploy-regression can be RULED OUT."). None when
    # the alert class doesn't qualify or the bridge call failed (non-fatal).
    recent_deploys_summary: Optional[str] = None


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
    # Quality of the RCA text — `actionable` if the LLM named a specific
    # cause / mechanism, `data_starved` if the RCA just says "insufficient
    # data" / "no recent logs" type hedges. Post-hoc classified, fed into
    # future prompts so the LLM sees its past hedges and does better next time.
    rca_quality: Optional[str] = None  # "actionable" | "data_starved" | None (not classified)

    # The alert's full identity at fire time — so the dashboard can show
    # the same rich detail the email does without having to re-query Grafana.
    alert_instance: Optional[str] = None       # raw "10.0.1.194:9100"
    alert_component: Optional[str] = None      # "api" / "gateway" / ...
    alert_signal: Optional[str] = None         # "metric" / "log" / "trace"
    observed_value: Optional[str] = None       # rendered value from alert.values
    promql_expr: Optional[str] = None          # from alert.annotations.expr
    # Environment - resolved at pipeline-write time via
    # app.v2_mappings.env_resolver against the alert's labels +
    # commonLabels + namespace + service token. First-class field so the
    # dashboard / email / filter bar all read one persisted value instead
    # of re-deriving the heuristic per surface. "unknown" is the explicit
    # gap value; "prod"/"stg"/"dev"/"preprod"/"uat"/"int" are live tokens.
    env: Optional[str] = None
    # LLM-produced rich fields that previously only lived in the email.
    suggested_actions: Optional[str] = None    # JSON list of strings
    evidence: Optional[str] = None             # JSON list of strings
    # US-3.9 (Tier 0): read-only diagnostic verbs surfaced when the F-4
    # confidence clamp fires. Stored as JSON list of strings; rendered
    # by the email + dashboard as a separate card from suggested_actions.
    diagnostic_steps: Optional[str] = None     # JSON list of strings
    anomaly_summary: Optional[str] = None      # Drain3 summary the LLM saw
    # Correlated alerts found in the ±5m window. JSON list of the same
    # shape returned by RCAStore.get_correlated_alerts.
    correlated_alerts: Optional[str] = None
    # 2026-06-04 (Stage E follow-up): write-time quarantine flag. Pipeline
    # sets this to 1 BEFORE save_decision() when the final RCA is still
    # data_starved OR carries unresolved banned-phrase / parrot-placeholder
    # validator hits. Operator-facing reads (dashboard, KPI rollups) still
    # show the row; LLM-context lookups (DA-3 prior, similar decisions,
    # high-value feedback) skip it via the COALESCE guards in rca_store.
    # Default 0 means "include in lookups" — same semantics as the ALTER
    # column default in rca_store.init_db.
    excluded_from_lookup: int = 0


# --- Health ---

class HealthResponse(BaseModel):
    status: str = "healthy"
    uptime_seconds: float = 0
    version: str = "0.1.0"


# ----------------------------------------------------------------------------
# US-5.3 closed-loop feedback request/response schemas
# ----------------------------------------------------------------------------

class FeedbackRequest(BaseModel):
    """Body of POST /feedback/override and POST /feedback/confirm.

    decision_id is required and must reference an existing rca_history row.
    operator_note is encouraged but optional (free-form short text). For
    /feedback/override, active_for_days controls how long similar future
    fires force-escalate; defaults to 14 days. For /feedback/confirm the
    field is ignored (confirms are timeless).
    """
    decision_id: str
    operator_note: str | None = None
    active_for_days: int | None = None


class FeedbackResponse(BaseModel):
    id: str
    decision_id: str
    feedback_type: str   # 'override' | 'confirm'
    operator_note: str | None = None
    created_at: str
    active_until: str | None = None
