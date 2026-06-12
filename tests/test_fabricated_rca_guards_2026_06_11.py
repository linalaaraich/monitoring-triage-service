"""2026-06-11 — fabricated drain3 deploy-RCA incident (fix wave A+B+D).

A real Drain3AnomalyDetected fired legitimately, but the RCA copied the
deploy-regression exemplar near-verbatim: unfilled template slots ("N
minutes after the deployment", "cluster #N never observed"), a deploy cause
the platform cannot verify (no deploy data source), ignoring the actual
cause written in the novel line ("Product Catalog Fail Feature Flag
Enabled"). These tests pin the three guards.
"""
from app.exemplars import find_for_alert, format_for_prompt
from app.models import Decision, LLMDecision
from app.response_validator import validate as validate_decision


def _decision(human_cause, rca, evidence=None, actions=None):
    return LLMDecision(
        decision=Decision.ESCALATE, severity="warning", confidence=0.85,
        reason=rca, human_cause=human_cause, rca=rca, anomaly_summary="",
        suggested_actions=actions or ["check the flag"], evidence=evidence or ["novel template observed"],
    )


# --- A. The exemplar no longer pre-decides a deploy story -------------------

def test_drain3_exemplar_is_declaimed():
    ex = find_for_alert("Drain3AnomalyDetected", "product-catalog", "k8s", "log", "warning")
    assert ex["id"] == "drain3-novelty-named-from-line"
    rendered = format_for_prompt(ex)
    low = rendered.lower()
    assert "helm rollback" not in low
    assert "n minutes" not in low
    assert "cluster #n" not in low
    assert "hh:mm" not in low
    # the lesson now forbids what it used to teach
    assert "never assert an external event" in low or "no deploy data source" in low


# --- D1. Template-slot leakage is caught ------------------------------------

def test_validator_catches_template_slot_leakage():
    d = _decision(
        "A new error template appeared.",
        "The novel template appeared N minutes after the deployment and "
        "cluster #N was never observed in the prior 14 days.",
    )
    rep = validate_decision(d, deployment_type="k8s", confidence_floor=0.3,
                            alertname="Drain3AnomalyDetected")
    hits = " ".join(rep.banned_phrase_hits)
    assert "template-slot" in hits


# --- D2. Ungrounded deploy claims are caught --------------------------------

def test_validator_rejects_ungrounded_deploy_claim():
    d = _decision(
        "The most recent deploy of product-catalog introduced a regression.",
        "A recent deploy introduced this novel error template.",
        evidence=["Novel Drain3 template: 'Product Catalog Fail Feature Flag Enabled'"],
    )
    rep = validate_decision(d, deployment_type="k8s", confidence_floor=0.3,
                            alertname="Drain3AnomalyDetected")
    assert "ungrounded-deploy-claim" in rep.banned_phrase_hits


def test_validator_allows_deploy_claim_with_deploy_evidence():
    d = _decision(
        "The latest deploy introduced a regression.",
        "The novel template aligns with the rollout in the logs.",
        evidence=["log line: 'Started deployment product-catalog v2.3 at 10:05'"],
    )
    rep = validate_decision(d, deployment_type="k8s", confidence_floor=0.3,
                            alertname="Drain3AnomalyDetected")
    assert "ungrounded-deploy-claim" not in rep.banned_phrase_hits


def test_validator_clean_decision_unaffected():
    d = _decision(
        "product-catalog is failing because its fail feature flag is enabled.",
        "The novel line 'Product Catalog Fail Feature Flag Enabled' names the cause.",
        evidence=["Novel template: 'Product Catalog Fail Feature Flag Enabled' (11 lines, 5.76%)"],
        actions=["disable the productCatalogFailure flag in flagd"],
    )
    rep = validate_decision(d, deployment_type="k8s", confidence_floor=0.3,
                            alertname="Drain3AnomalyDetected")
    assert "ungrounded-deploy-claim" not in " ".join(rep.banned_phrase_hits)
    assert not any("template-slot" in h for h in rep.banned_phrase_hits)


# --- B. The playbook requires quoting the line ------------------------------

def test_drain3_playbook_requires_quoting_the_line():
    from app.llm_client import LLMClient
    from app.models import GatheredContext, GrafanaAlert
    from unittest.mock import MagicMock
    import asyncio
    client = LLMClient.__new__(LLMClient)
    captured = {}
    async def fake(messages):
        captured["m"] = messages
        return None
    client._call_ollama_with_resilience = fake
    client._circuit = MagicMock()
    alert = GrafanaAlert(status="firing",
        labels={"alertname": "Drain3AnomalyDetected", "severity": "warning", "service": "product-catalog"},
        annotations={"summary": "novel templates"}, startsAt="2026-06-11T00:00:00Z", fingerprint="d1")
    asyncio.get_event_loop().run_until_complete(
        client.investigate(alert, GatheredContext(sources_available=3), "NOVEL: Product Catalog Fail Feature Flag Enabled")
    )
    user = captured["m"][-1]["content"]
    assert "THE CAUSE IS IN THE LINE" in user
    assert "NO deploy data source" in user


# --- C + E (approved follow-up wave) -----------------------------------------

from app.pipeline import _has_corroborating_evidence
from app.models import Drain3Webhook, GatheredContext


def test_drain3_webhook_carries_emitting_services():
    w = Drain3Webhook(anomalous_lines=["x"], services=["product-catalog", "frontend"])
    assert w.services[0] == "product-catalog"


def test_empty_context_has_no_corroborating_evidence():
    assert not _has_corroborating_evidence(GatheredContext(sources_available=3))
    assert not _has_corroborating_evidence(
        GatheredContext(sources_available=3, metrics={"status": "success", "result": []})
    )


def test_any_source_counts_as_corroboration():
    assert _has_corroborating_evidence(GatheredContext(sources_available=3, anomaly_summary="NOVEL: flag enabled"))
    assert _has_corroborating_evidence(GatheredContext(sources_available=3, kube_workload_summary="Deployment x: available=0"))
    assert _has_corroborating_evidence(GatheredContext(sources_available=3, annotated_logs=["[ANOMALY] boom"]))
    assert _has_corroborating_evidence(GatheredContext(sources_available=3, traces=[{"traceID": "t"}]))
    assert _has_corroborating_evidence(GatheredContext(sources_available=3, metrics={"result": [{"metric": {}, "values": [[0, "1"]]}]}))


def test_fire_one_payload_carries_services(monkeypatch):
    """The analyzer names the real emitters, dominant first (system tier)."""
    import asyncio
    from app.drain_analyzer import DrainAnalyzer, BatchResult, ScopeCounts

    da = DrainAnalyzer.__new__(DrainAnalyzer)
    da._tier_alert_ts = {}
    batch = BatchResult(
        total_lines=100, total_anomalous=12,
        per_service={
            "product-catalog": ScopeCounts(lines=40, anomalous=10, new_templates=["t"], sample_lines=["l"]),
            "frontend": ScopeCounts(lines=40, anomalous=2),
            "quiet-svc": ScopeCounts(lines=20, anomalous=0),
        },
    )
    sent = {}

    async def fake_fire_one(tier, scope, counts, services=None):
        sent[(tier, scope)] = services

    da._fire_one = fake_fire_one
    # monkeypatch thresholds so only system tier fires
    from app.config import settings
    monkeypatch.setattr(settings, "drain3_alert_rate_threshold", 0.05)
    monkeypatch.setattr(settings, "drain3_alert_min_lines", 10)
    monkeypatch.setattr(settings, "drain3_app_rate_threshold", 9.0)
    monkeypatch.setattr(settings, "drain3_component_rate_threshold", 9.0)
    asyncio.get_event_loop().run_until_complete(da.maybe_fire_alerts(batch))
    assert sent[("system", "all")] == ["product-catalog", "frontend"]


# --- Prod-mimic battery follow-ups (N1/N2/N4) --------------------------------

def test_humanize_verdict_token():
    from app.main import _humanize_verdict_token
    assert _humanize_verdict_token("see_previous_rca:abc-123") == "recurrence"
    assert _humanize_verdict_token("escalate") == "escalate"
    assert _humanize_verdict_token("triage_suppressed") == "triage suppressed"


def test_actionable_tag_suppressed_on_dismiss():
    from app.main import _v2_transform_row
    from datetime import datetime, timezone
    base = {"id": "a"*32, "alert_name": "TargetDown", "affected_service": "monitoring",
            "timestamp": datetime.now(timezone.utc).isoformat(), "severity": "critical",
            "triage_decision": "investigate", "rca_quality": "actionable",
            "rca_report": "{}", "llm_confidence": "0.4"}
    dismiss = dict(base, llm_verdict="dismiss")
    escal = dict(base, llm_verdict="escalate")
    now = datetime.now(timezone.utc)
    assert "actionable" not in _v2_transform_row(dismiss, now_utc=now)["tags"]
    assert "actionable" in _v2_transform_row(escal, now_utc=now)["tags"]


def test_drain3_alert_carries_namespace_hint():
    import asyncio
    from unittest.mock import AsyncMock, MagicMock, patch
    from app.models import Drain3Webhook
    from app.pipeline import TriagePipeline
    p = TriagePipeline.__new__(TriagePipeline)
    captured = {}

    async def fake_process(alert, source, env=None):
        captured["alert"] = alert

    p._process_alert = fake_process
    p._resolve_env = lambda *a, **k: "prod"
    w = Drain3Webhook(anomalous_lines=["x"], new_templates=["t"], service="spring-boot",
                      tier="component", scope="spring-boot", services=["spring-boot"])
    asyncio.get_event_loop().run_until_complete(p.process_drain3_webhook(w))
    assert captured["alert"].labels.get("namespace") == "app"


# --- X1/X2 follow-ups: demo env tier + investigation-log prompt --------------

def test_demo_services_resolve_demo_env_by_token():
    from app.v2_mappings import env_resolver
    for svc in ("cart", "valkey-cart", "product-catalog", "kafka"):
        assert env_resolver(service=svc) == "demo", svc
    assert env_resolver(service="employees-backend", namespace="app") == "prod"


def test_system_prompt_specifies_investigation_log():
    from app.llm_client import SYSTEM_PROMPT
    assert "INVESTIGATION LOG" in SYSTEM_PROMPT
    assert "numbered steps" in SYSTEM_PROMPT
    assert "Trace span breakdown" in SYSTEM_PROMPT


def test_deep_trace_block_requires_numbered_trace_step(monkeypatch):
    from app.llm_client import LLMClient
    from app.models import GatheredContext
    from unittest.mock import MagicMock
    import asyncio
    client = LLMClient.__new__(LLMClient)
    captured = {}
    async def fake(messages):
        captured["m"] = messages
        return None
    client._call_ollama_with_resilience = fake
    client._circuit = MagicMock()
    from app.models import GrafanaAlert
    alert = GrafanaAlert(status="firing",
        labels={"alertname": "HighDemoFrontendP95Latency", "severity": "warning", "service": "frontend"},
        annotations={"summary": "p95 high"}, startsAt="2026-06-11T23:00:00Z", fingerprint="x2")
    ctx = GatheredContext(sources_available=3, deep_trace={"spans": [{"op": "ad", "ms": 2800}]})
    asyncio.get_event_loop().run_until_complete(client.investigate(alert, ctx, ""))
    user = captured["m"][-1]["content"]
    assert "checked traces in the alert window" in user


# --- 2026-06-12: investigate-traces-always (the a69ac64a guess) ---------------

def test_jaeger_fetched_for_demo_and_app_services_not_just_allowlist():
    """RC-1: the old 3-service allowlist skipped Jaeger for all 22 demo
    services + employees-* — so 'traces absent' was the code, not reality."""
    import asyncio
    from app.context import ContextGatherer
    from app.models import GrafanaAlert
    g = ContextGatherer.__new__(ContextGatherer)
    calls = {}

    async def fake_mcp(server, url, params):
        calls[params.get("service")] = url
        return [], 5

    g._mcp_call = fake_mcp
    for svc in ("frontend", "cart", "product-catalog", "spring-boot"):
        calls.clear()
        a = GrafanaAlert(status="firing", labels={"alertname": "HighDemoFrontendP95Latency",
            "service": svc, "severity": "warning"}, fingerprint="t")
        asyncio.get_event_loop().run_until_complete(g._fetch_jaeger(a, None))
        assert svc in calls or "spring-boot" in calls, f"jaeger NOT queried for {svc}"
    # infra services still skipped
    calls.clear()
    a = GrafanaAlert(status="firing", labels={"alertname": "MediumCpuUsage",
        "service": "k3s-node", "severity": "warning"}, fingerprint="t")
    asyncio.get_event_loop().run_until_complete(g._fetch_jaeger(a, None))
    assert not calls, "jaeger should be skipped for k3s-node"


def test_service_should_have_traces_predicate():
    from app.pipeline import _service_should_have_traces, _is_latency_or_error_alert
    from app.models import GrafanaAlert
    assert _service_should_have_traces("frontend")
    assert _service_should_have_traces("employees-backend")
    assert not _service_should_have_traces("k3s-node")
    assert not _service_should_have_traces("ai-mcp-loki")
    a = GrafanaAlert(status="firing", labels={"alertname": "HighDemoFrontendP95Latency"}, fingerprint="t")
    assert _is_latency_or_error_alert(a)
    b = GrafanaAlert(status="firing", labels={"alertname": "KubeWorkloadDown"}, fingerprint="t")
    assert not _is_latency_or_error_alert(b)
