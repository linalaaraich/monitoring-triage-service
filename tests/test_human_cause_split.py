"""Human-first reason refactor (2026-06-02).

Lina's complaint: the dashboard / email "why" cell was rendering the first
sentence of `rca`, which the LLM often filled with `histogram_quantile(...)`
or `container_memory_working_set_bytes / spec_memory_limit_bytes = 0.984`
formula text. Mental load on the operator was high; the operator wants
to read a 1-sentence plain-English cause first, then drill into evidence.

This file locks in:

  - `prose_helpers.split_human_cause_and_evidence` correctly peels PromQL /
    metric-formula fragments out of legacy RCA prose into an evidence list,
    leaving a clean human-readable lead in human_cause.

  - `prose_helpers.derive_human_cause` resolves through the new
    LLM-populated `human_cause` field first, then the legacy split,
    then `reason`, then a fallback string — guaranteed formula-free.

  - `LLMDecision.human_cause` field is exposed and persists in the model.

  - The v2 email banner / v1 email "Cause" line / dashboard transform row
    render `human_cause` (no PromQL) — not the formula-loaded RCA prose.

  - `response_validator.validate` flags a `human_cause` field that
    contains a metric formula so the LLM gets a retry feedback signal.

These tests fail BEFORE the refactor and pass after — they are the contract.
"""
from __future__ import annotations

from app.models import Decision, GrafanaAlert, LLMDecision, RCARecord
from app.notifier import EmailNotifier
from app.prose_helpers import (
    derive_human_cause,
    split_human_cause_and_evidence,
)
from app.response_validator import validate


# ---------------------------------------------------------------------------
# split_human_cause_and_evidence — back-compat parser for legacy rows
# ---------------------------------------------------------------------------

def test_split_extracts_histogram_quantile_promql_into_evidence():
    """The classic bad lede — `histogram_quantile(0.95, sum(rate(...)))` —
    must be pulled out of the human prose into the evidence list."""
    rca = (
        "The PromQL expression `histogram_quantile(0.95, sum(rate(kong_request_latency_ms_bucket[5m])) by (le))` "
        "reported 8487.9 ms above the threshold."
    )
    human, evidence = split_human_cause_and_evidence(rca)
    # The formula must NOT remain in the human cause
    assert "histogram_quantile" not in human, f"formula leaked into human: {human!r}"
    assert "_bucket" not in human
    # And it must be surfaced in the evidence list (so we don't lose info)
    assert any("histogram_quantile" in e for e in evidence), evidence


def test_split_extracts_metric_with_labels_equals_value():
    """`container_memory_working_set_bytes{pod="x"} = 0.984` is a metric
    evaluation, not human prose. It belongs in evidence."""
    rca = (
        "Memory pressure is mounting on the spring-boot pod. "
        'container_memory_working_set_bytes{pod="spring-boot-7d9f"} = 0.984. '
        "Pod restarts soon."
    )
    human, evidence = split_human_cause_and_evidence(rca)
    # Prose around the formula survives
    assert "spring-boot" in human.lower()
    # Metric expression peeled out
    assert "= 0.984" not in human
    assert any("0.984" in e for e in evidence), evidence


def test_split_keeps_pure_prose_in_human_cause():
    """No formulas in the RCA → all prose stays as human_cause; evidence empty."""
    rca = (
        "spring-boot is in an OOM-kill loop because the JVM heap defaults to "
        "25% of the cgroup limit. The pod restarts every 12 minutes."
    )
    human, evidence = split_human_cause_and_evidence(rca)
    assert "OOM-kill loop" in human
    # Either no extra evidence pulled, or only trivial pieces
    assert evidence == [] or all(len(e) < 5 for e in evidence)


def test_split_mixed_prose_and_metric_lead_with_prose():
    """Mixed input where prose CARRIES the cause and a formula is embedded
    for support — prose must lead the human_cause; formula goes to evidence."""
    rca = (
        "The Loki disk on the monitoring VM has filled to 98% of capacity. "
        "node_filesystem_avail_bytes{mountpoint=\"/var/lib/loki\"} = 12000000000. "
        "Ingest will stop in about 7 minutes if no action is taken."
    )
    human, evidence = split_human_cause_and_evidence(rca)
    assert "Loki" in human and "98%" in human
    # The metric expression should NOT be in the human cause
    assert "node_filesystem_avail_bytes" not in human
    # And IS in evidence
    assert any("node_filesystem" in e for e in evidence)


def test_split_empty_input_returns_empty_tuple():
    """Empty RCA → empty human + empty evidence (no crash, no fabricated text)."""
    h, e = split_human_cause_and_evidence("")
    assert h == ""
    assert e == []


def test_split_only_formula_input_returns_no_human_cause():
    """An RCA that is purely a metric expression yields no human prose.
    The renderer must catch this and fall back to a placeholder — that's
    not this helper's job, but the split should be honest about it."""
    rca = (
        "`container_cpu_usage_seconds_total{pod=\"spring-boot-7d9f\"} = 0.95`. "
        "`node_load1 = 4.2`."
    )
    human, evidence = split_human_cause_and_evidence(rca)
    # Either empty or very short — nothing left after stripping formulas
    assert len(human) < 30, f"unexpected prose: {human!r}"
    assert len(evidence) >= 1


# ---------------------------------------------------------------------------
# derive_human_cause — renderer-side lookup helper
# ---------------------------------------------------------------------------

def test_derive_prefers_explicit_human_cause_field():
    """When the LLM populated `human_cause`, that wins over any RCA derivation."""
    out = derive_human_cause(
        "Kong upstream pool to spring-boot is saturated.",
        rca="histogram_quantile(0.95, ...) = 8487 reported above threshold.",
        reason="ignored",
    )
    assert out == "Kong upstream pool to spring-boot is saturated."


def test_derive_falls_back_to_rca_split_when_human_cause_empty():
    """No `human_cause` field but rca has prose + formulas — return the prose."""
    out = derive_human_cause(
        "",
        rca="spring-boot is OOM-looping. container_memory_working_set_bytes{pod=\"x\"} = 0.984.",
    )
    assert "OOM-looping" in out
    assert "container_memory_working_set_bytes" not in out


def test_derive_uses_reason_when_rca_empty():
    """Very old rows with no rca prose at all — fall back to reason."""
    out = derive_human_cause("", rca="", reason="LLM unavailable")
    assert out == "LLM unavailable"


def test_derive_returns_fallback_when_all_inputs_empty():
    out = derive_human_cause("", rca="", reason="", fallback="No RCA prose recorded.")
    assert out == "No RCA prose recorded."


# ---------------------------------------------------------------------------
# LLMDecision model — new field present and accepted
# ---------------------------------------------------------------------------

def test_llm_decision_accepts_human_cause_field():
    d = LLMDecision(
        decision=Decision.ESCALATE,
        severity="warning",
        confidence=0.8,
        human_cause="spring-boot pod is OOM-looping every 12 minutes.",
        reason="OOM loop",
        rca="...",
        suggested_actions=["kubectl rollout restart deploy/spring-boot -n app"],
        evidence=["container_memory_working_set_bytes / limit = 0.984"],
    )
    assert d.human_cause == "spring-boot pod is OOM-looping every 12 minutes."


def test_llm_decision_human_cause_defaults_empty_for_backwards_compat():
    """Legacy callers that don't set human_cause still construct cleanly."""
    d = LLMDecision(
        decision=Decision.ESCALATE,
        severity="warning",
        confidence=0.8,
        reason="OOM loop",
        rca="spring-boot is in an OOM-kill loop.",
    )
    assert d.human_cause == ""


# ---------------------------------------------------------------------------
# Email rendering — v2 banner uses human_cause, evidence rendered below
# ---------------------------------------------------------------------------

def _alert(service="spring-boot", alertname="HighP95Latency"):
    return GrafanaAlert(
        status="firing",
        labels={"alertname": alertname, "service": service, "severity": "warning"},
        annotations={"summary": "p95 above threshold"},
        startsAt="2026-06-02T10:42:00Z",
        generatorURL="http://localhost:3000/alerting/grafana/abc/view",
    )


def _record(rca_envelope: str | None = None):
    return RCARecord(
        id="abcdef12-3456-7890-abcd-ef1234567890",
        alert_source="grafana",
        alert_name="HighP95Latency",
        alert_fingerprint="fp1",
        affected_service="spring-boot",
        severity="warning",
        triage_decision="investigate",
        llm_verdict="escalate",
        llm_confidence="0.82",
        rca_report=rca_envelope,
        llm_reasoning="upstream saturation",
        action_taken="emailed",
        investigation_duration_ms=23000,
        rca_quality="actionable",
    )


def test_v2_email_banner_renders_human_cause_no_promql():
    """The "Why" block in the v2 email must show the plain-English cause,
    not the `histogram_quantile` formula the LLM put in `rca`."""
    n = EmailNotifier()
    decision = LLMDecision(
        decision=Decision.ESCALATE,
        severity="warning",
        confidence=0.82,
        human_cause="spring-boot is queueing requests on its JDBC pool; p95 jumped to 8.5 seconds.",
        reason="JDBC saturation",
        rca=(
            "histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le)) = 8.487. "
            "Pool acquisition is the bottleneck."
        ),
        suggested_actions=["kubectl rollout restart deploy/spring-boot -n app"],
        evidence=[
            "histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le)) = 8.487",
            "hikari_active_connections{pod=\"spring-boot-7d9f\"} = 20",
        ],
    )
    body = n._build_v2_escalation_body(_alert(), decision, _record(), 0, None, [])
    # The banner must contain the human cause
    assert "JDBC pool" in body
    assert "8.5 seconds" in body
    # The banner section ("Why" block) must NOT lead with PromQL
    # Find the Why block and look only at the first 500 chars within it
    why_idx = body.find(">Why<")
    assert why_idx > 0
    why_block = body[why_idx: why_idx + 500]
    assert "histogram_quantile" not in why_block, "PromQL leaked into Why banner"


def test_v2_email_renders_evidence_block_below_banner():
    """Technical evidence must be a SEPARATE section below the human banner,
    not mixed into the Why block. Operators see prose first."""
    n = EmailNotifier()
    decision = LLMDecision(
        decision=Decision.ESCALATE,
        severity="warning",
        confidence=0.82,
        human_cause="spring-boot pool exhausted.",
        rca="...",
        evidence=[
            "histogram_quantile(0.95, ...) = 8487",
            "hikari_active_connections = 20/20",
        ],
        suggested_actions=["kubectl rollout restart deploy/spring-boot -n app"],
    )
    body = n._build_v2_escalation_body(_alert(), decision, _record(), 0, None, [])
    # Both evidence entries appear somewhere in the email
    assert "histogram_quantile" in body
    assert "hikari_active_connections" in body
    # And they appear AFTER the Why banner
    why_pos = body.find(">Why<")
    promql_pos = body.find("histogram_quantile")
    assert why_pos < promql_pos, "evidence appeared before Why block"
    # The Technical evidence section header is present
    assert "Technical evidence" in body


def test_v2_email_falls_back_to_rca_split_for_legacy_decision():
    """A decision with no human_cause field (legacy / fallback path) must
    still produce a clean banner — the formula gets stripped automatically."""
    n = EmailNotifier()
    decision = LLMDecision(
        decision=Decision.ESCALATE,
        severity="warning",
        confidence=0.82,
        # No human_cause provided
        rca=(
            "spring-boot is in an OOM-kill loop. "
            "container_memory_working_set_bytes{pod=\"spring-boot-7d9f\"} = 0.984."
        ),
        suggested_actions=["kubectl rollout restart deploy/spring-boot -n app"],
        evidence=[],
    )
    body = n._build_v2_escalation_body(_alert(), decision, _record(), 0, None, [])
    why_idx = body.find(">Why<")
    why_block = body[why_idx: why_idx + 500]
    # Plain prose is there
    assert "OOM-kill loop" in why_block
    # The metric formula is NOT in the why block
    assert "container_memory_working_set_bytes" not in why_block


# ---------------------------------------------------------------------------
# Dashboard row "reason" cell — _v2_transform_row uses human_cause
# ---------------------------------------------------------------------------

def test_dashboard_v2_row_reason_uses_envelope_human_cause():
    """When rca_report is a JSON envelope with human_cause, the dashboard
    `reason` field must use the human_cause, not the rca prose."""
    import json
    from app.main import _v2_transform_row
    row = {
        "id": "abcdef1234567890",
        "alert_name": "HighP95Latency",
        "alert_fingerprint": "fp1",
        "affected_service": "spring-boot",
        "severity": "warning",
        "llm_verdict": "escalate",
        "llm_confidence": "0.82",
        "rca_report": json.dumps({
            "human_cause": "spring-boot is queueing on JDBC; p95 jumped to 8.5 s.",
            "rca": (
                "histogram_quantile(0.95, sum(rate(...))) = 8487. "
                "Pool acquisition is the bottleneck."
            ),
            "schema": "v2",
        }),
        "llm_reasoning": "saturation",
        "action_taken": "emailed",
        "timestamp": "2026-06-02T10:42:00",
        "triage_decision": "investigate",
        "rca_quality": "actionable",
    }
    out = _v2_transform_row(row)
    assert "JDBC" in out["reason"]
    assert "histogram_quantile" not in out["reason"]


def test_dashboard_v2_row_reason_back_compat_raw_rca():
    """Legacy rows where rca_report is raw text (not a JSON envelope) still
    render — the prose_helpers fallback strips the formulas from the lead."""
    from app.main import _v2_transform_row
    row = {
        "id": "abcdef1234567890",
        "alert_name": "PodHighMemoryUsage",
        "alert_fingerprint": "fp2",
        "affected_service": "spring-boot",
        "severity": "warning",
        "llm_verdict": "escalate",
        "llm_confidence": "0.70",
        "rca_report": (
            "spring-boot pod is at memory ceiling. "
            "container_memory_working_set_bytes{pod=\"spring-boot-7d9f\"} = 0.984. "
            "OOM imminent."
        ),
        "llm_reasoning": "memory pressure",
        "action_taken": "emailed",
        "timestamp": "2026-06-02T10:42:00",
        "triage_decision": "investigate",
        "rca_quality": "actionable",
    }
    out = _v2_transform_row(row)
    assert "memory ceiling" in out["reason"] or "OOM" in out["reason"]
    assert "container_memory_working_set_bytes" not in out["reason"]


# ---------------------------------------------------------------------------
# response_validator — flag formulas in `human_cause`
# ---------------------------------------------------------------------------

def test_validator_flags_human_cause_with_promql():
    """If the LLM puts a PromQL formula in `human_cause`, the validator
    must flag it so the retry path forces the LLM to rewrite as prose."""
    decision = LLMDecision(
        decision=Decision.ESCALATE,
        severity="warning",
        confidence=0.85,
        # BAD: a formula in the operator-facing field
        human_cause="histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le)) = 8.487",
        reason="latency",
        rca="...",
        suggested_actions=["kubectl rollout restart deploy/spring-boot -n app"],
        evidence=["..."],
    )
    report = validate(decision, deployment_type="k8s")
    assert any("human_cause" in v for v in report.violations), report.violations


def test_validator_does_not_flag_clean_human_cause():
    """A plain-English human_cause with no formulas must pass."""
    decision = LLMDecision(
        decision=Decision.ESCALATE,
        severity="warning",
        confidence=0.85,
        human_cause="spring-boot is queueing requests on its JDBC pool; p95 jumped to 8.5 seconds.",
        reason="JDBC saturation",
        rca=(
            "spring-boot's JDBC connection pool is exhausted; the slowest "
            "trace waits 7.8 seconds for a connection. Pool max=20 is the "
            "bottleneck under current load."
        ),
        suggested_actions=["kubectl rollout restart deploy/spring-boot -n app"],
        evidence=["hikari pool active=20/20", "trace 7f3a2c: 7800ms in pool acquisition"],
    )
    report = validate(decision, deployment_type="k8s")
    human_cause_hits = [v for v in report.violations if "human_cause" in v]
    assert human_cause_hits == [], f"clean human_cause was flagged: {human_cause_hits}"
