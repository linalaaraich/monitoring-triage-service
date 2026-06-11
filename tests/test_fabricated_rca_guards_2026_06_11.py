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
