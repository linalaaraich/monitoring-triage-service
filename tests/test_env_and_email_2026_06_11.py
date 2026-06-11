"""2026-06-11 (Lina pre-demo): infra/demo env tags + light-mode emails.

- env_resolver: the platform's own components must resolve "infra" and the
  otel-demo bed "demo" — never "unknown" (and infra beats the logical-
  namespace guess: k3s-node was reading "prod").
- v2 escalation email must render in LIGHT mode: no dark-palette tokens.
"""
from unittest.mock import MagicMock

from app.models import Decision, GatheredContext, GrafanaAlert, LLMDecision
from app.notifier import EmailNotifier
from app.v2_mappings import env_resolver, is_infra_service


def test_infra_services_resolve_infra():
    for svc in ("k3s-node", "monitoring-vm", "drain3", "ai-mcp-loki",
                "mcp-prometheus", "otel-collector", "dcgm-exporter"):
        assert env_resolver(service=svc) == "infra", svc


def test_otel_demo_namespace_resolves_demo():
    assert env_resolver(namespace="otel-demo") == "demo"
    assert env_resolver(service="image-provider", namespace="otel-demo") == "demo"


def test_workload_envs_unchanged():
    assert env_resolver(service="employees-backend", namespace="app") == "prod"
    assert env_resolver(service="rental-backend") == "stg"
    assert env_resolver(labels={"env": "uat"}) == "uat"
    assert not is_infra_service("employees-backend")


def test_explicit_infra_demo_labels_accepted():
    assert env_resolver(labels={"env": "infra"}) == "infra"
    assert env_resolver(labels={"env": "demo"}) == "demo"


def _render_email():
    alert = GrafanaAlert(
        status="firing",
        labels={"alertname": "KubeWorkloadDown", "severity": "critical",
                "namespace": "otel-demo", "service": "ad"},
        annotations={"summary": "ad down"},
        startsAt="2026-06-11T00:00:00Z", fingerprint="t1",
    )
    decision = LLMDecision(
        decision=Decision.ESCALATE, severity="critical", confidence=0.95,
        reason="zero available replicas", human_cause="ad indisponible",
        rca="x", anomaly_summary="",
        suggested_actions=["kubectl describe"], evidence=["replicas=0"],
    )
    n = EmailNotifier.__new__(EmailNotifier)
    record = MagicMock()
    record.id = "abcdef12-3456"
    record.alert_fingerprint = "t1"
    record.env = "demo"
    return n._build_v2_escalation_body(
        alert, decision, record, history_count=0,
        ctx=GatheredContext(sources_available=3), correlated=None,
    )


def test_v2_email_is_light_mode():
    html = _render_email()
    for dark in ("#0a0b0f", "#0f1117", "#1a1d27", "#15171f", "#0a0c11", "#e4e6ee"):
        assert dark not in html, f"dark token {dark} still in email"
    assert "background:#f4f6fb" in html       # light page
    assert "background:#ffffff" in html        # white card
    assert "color:#0b1b3a" in html             # dark text on light


def test_v2_email_carries_env_pill():
    assert "demo" in _render_email()


# ---------------------------------------------------------------------------
# Display naming convention — [appName]-[tech]-[role] (display level only)
# ---------------------------------------------------------------------------

from app.v2_mappings import display_namespace, display_service


def test_display_service_follows_app_tech_role_convention():
    assert display_service("employees-backend") == "employee-spring-backend"
    assert display_service("spring-boot") == "employee-spring-backend"
    assert display_service("employees-db") == "employee-mysql-db"
    assert display_service("kong") == "employee-kong-gateway"
    assert display_service("rental-backend") == "carRental-spring-backend"
    # non-tenant services pass through unchanged
    assert display_service("ad") == "ad"
    assert display_service("prometheus") == "prometheus"


def test_display_namespace_maps_tenants():
    assert display_namespace("app") == "employee"
    assert display_namespace("rental") == "carRental"
    assert display_namespace("otel-demo") == "otel-demo"
