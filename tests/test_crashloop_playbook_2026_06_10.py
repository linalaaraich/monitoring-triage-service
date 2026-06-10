"""Micro-cycle 2026-06-10 — crash-loop / restart alert investigation guidance.

Decision 29a05711 (PodCrashLooping, accounting, otel-demo): a REAL OOM loop
(420+ restarts at a 120Mi limit, exit 137) produced a hedged RCA — verdict
escalate at confidence 0.30, rca_quality data_starved, "Cannot determine the
root cause … metrics show no significant anomalies, logs are clean". The
breach was nameable the whole time:
kube_pod_container_status_last_terminated_reason{reason="OOMKilled"} and the
restart counter sat in Prometheus (with KSM labels arriving as
exported_namespace/exported_pod/exported_container).

Confirmed root cause: alert-type investigation guidance existed ONLY for
Drain3AnomalyDetected (llm_client._build_prompt, the drain3_playbook_block
gated on `alert.alertname == "Drain3AnomalyDetected"`). Nothing for
crash-loop/restart alerts → bounded-agency never queried the kube
restart/OOM series → "no anomalies" hedge. Timing nuance: the alert fired
AFTER the accounting fix rolled the pod (limit 120Mi→256Mi ~12:41, alert
12:43), so live state looked healthy — the investigation must target the
RECENT termination evidence, not just current health.

Fix under test:
  - llm_client.is_crashloop_alert() — restart-shaped alertname gate
  - llm_client.build_crashloop_playbook() — playbook block: exported_* KSM
    label spelling, last_terminated_reason / restart-increase / memory-limit
    evidence series, a copy-pasteable single combined bounded-agency query,
    OOMKilled-naming verdict path, and a remediated/self-resolved path for
    loops that already ended (never "cannot determine")
  - exemplars/library.yaml oom-crashloop-restart — PodCrashLooping now has a
    matching archetype (the old crashloop-bad-config regex only matched
    KubePodCrashLooping|TargetDown, and its services list penalised
    otel-demo services into the generic default)

These tests pin the PROMPT STRUCTURE; model behaviour is verified by real
induction (image-provider OOM, no synthetic webhooks).
"""
from __future__ import annotations

from app import exemplars as exemplars_lib
from app.llm_client import (
    LLMClient,
    build_crashloop_playbook,
    crashloop_evidence_query,
    is_crashloop_alert,
)
from app.models import GatheredContext, GrafanaAlert


def _crashloop_alert(**label_over) -> GrafanaAlert:
    labels = {
        "alertname": "PodCrashLooping",
        "namespace": "otel-demo",
        "pod": "accounting-7c8d9f6b5-x2x4q",
        "service": "accounting",
        "severity": "warning",
        "signal": "availability",
        "component": "k8s",
    }
    labels.update(label_over)
    return GrafanaAlert(
        status="firing",
        labels=labels,
        annotations={
            "summary": "Pod restarting repeatedly",
            "expr": 'max by (namespace, pod, service) (increase(kube_pod_container_status_restarts_total{exported_namespace!="kube-system"}[1h]))',
        },
        startsAt="2026-06-10T12:43:00Z",
        fingerprint="fp-crashloop-test",
        values={"B": 4.0167},
    )


def _prompt_content(alert: GrafanaAlert) -> str:
    ctx = GatheredContext(annotated_logs=None, sources_available=2)
    msgs = LLMClient()._build_prompt(alert, ctx, "", history_context="")
    return msgs[1]["content"]


# ---------------------------------------------------------------------------
# is_crashloop_alert — the gate
# ---------------------------------------------------------------------------

def test_gate_matches_podcrashlooping():
    assert is_crashloop_alert("PodCrashLooping")


def test_gate_matches_kube_variants_and_restart_shapes():
    for name in (
        "KubePodCrashLooping",
        "CrashLoopBackOff",
        "PodCrashLoopBackOff",
        "KubeWorkloadDown",
        "PodRestartingTooOften",
        "TooManyRestarts",
    ):
        assert is_crashloop_alert(name), name


def test_gate_rejects_non_restart_alerts():
    for name in (
        "Drain3AnomalyDetected",
        "HighCpuUsage",
        "PodHighMemoryUsage",
        "TargetDown",
        "HighP95Latency",
        "HighDemoFrontendP95Latency",
        "",
    ):
        assert not is_crashloop_alert(name), name


def test_gate_handles_none():
    assert not is_crashloop_alert(None)


# ---------------------------------------------------------------------------
# Playbook content — the guidance that was missing for 29a05711
# ---------------------------------------------------------------------------

def test_playbook_injected_into_prompt_for_podcrashlooping():
    content = _prompt_content(_crashloop_alert())
    assert "Crash-loop / restart alert playbook" in content


def test_playbook_absent_for_non_restart_alert():
    alert = _crashloop_alert(alertname="HighCpuUsage")
    content = _prompt_content(alert)
    assert "Crash-loop / restart alert playbook" not in content


def test_drain3_playbook_unaffected():
    """Regression: the drain3 playbook still renders for drain3 alerts and
    the crash-loop block does not leak into it."""
    alert = _crashloop_alert(alertname="Drain3AnomalyDetected")
    content = _prompt_content(alert)
    assert "Drain3 alert playbook" in content
    assert "Crash-loop / restart alert playbook" not in content


def test_playbook_names_the_ksm_exported_labels():
    """The 29a05711 miss: KSM series carry exported_namespace/exported_pod —
    a model querying bare namespace/pod gets nothing and hedges."""
    block = build_crashloop_playbook(_crashloop_alert())
    assert 'exported_namespace="otel-demo"' in block
    assert 'exported_pod=~"accounting.*"' in block
    assert "NOT bare namespace/pod" in block


def test_playbook_directs_at_last_terminated_reason_and_restart_increase():
    block = build_crashloop_playbook(_crashloop_alert())
    assert "kube_pod_container_status_last_terminated_reason" in block
    assert "kube_pod_container_status_restarts_total" in block
    assert "kube_pod_container_resource_limits" in block
    assert "container_memory_working_set_bytes" in block


def test_playbook_carries_the_retrospective_timing_guidance():
    """Accounting fired 2 min AFTER the limit bump rolled the pod — live
    state was healthy. The playbook must say current health != no anomalies
    and direct at RECENT termination evidence."""
    block = build_crashloop_playbook(_crashloop_alert())
    assert "RETROSPECTIVE" in block
    assert "AFTER the loop already ended" in block
    assert "RECENT termination evidence" in block


def test_playbook_oomkilled_naming_template():
    """Verdict path (a): OOMKilled must be NAMED with the memory-limit class
    cause, per the RCA-prose-quality invariant."""
    block = build_crashloop_playbook(_crashloop_alert())
    assert 'reason="OOMKilled"' in block
    assert "OOMKilled — memory limit" in block
    assert "raise the" in block and "memory limit" in block


def test_playbook_remediated_path_for_ended_loops():
    """Verdict path (c): restarts stopped after a fix → say remediated /
    self-resolved, never 'cannot determine'."""
    block = build_crashloop_playbook(_crashloop_alert())
    assert "ALREADY ENDED" in block
    assert "remediated" in block
    assert "never call it 'cannot determine'" in block


def test_playbook_forbids_hedging():
    block = build_crashloop_playbook(_crashloop_alert())
    assert "NEVER answer 'insufficient data' / 'cannot determine'" in block


def test_playbook_embeds_single_combined_agency_query():
    """Bounded agency allows EXACTLY ONE extra MCP call — the playbook must
    hand the model one combined (or-union) query covering all three evidence
    families, verbatim-copyable."""
    block = build_crashloop_playbook(_crashloop_alert())
    combined = crashloop_evidence_query("otel-demo", "accounting")
    assert combined in block
    assert "prometheus.query" in block


def test_combined_query_unions_three_evidence_families():
    q = crashloop_evidence_query("otel-demo", "image-provider")
    assert q.count(" or ") == 2
    assert "kube_pod_container_status_last_terminated_reason" in q
    assert "increase(kube_pod_container_status_restarts_total" in q
    assert 'kube_pod_container_resource_limits{resource="memory"' in q
    assert 'exported_namespace="otel-demo"' in q
    assert 'exported_pod=~"image-provider.*"' in q


def test_playbook_falls_back_to_pod_name_when_service_unknown():
    alert = _crashloop_alert(service="")
    # service falls back to labels.job then "unknown" → pod name is prefix
    block = build_crashloop_playbook(alert)
    assert 'exported_pod=~"accounting-7c8d9f6b5-x2x4q.*"' in block


# ---------------------------------------------------------------------------
# Exemplar matching — PodCrashLooping now has an archetype
# ---------------------------------------------------------------------------

def test_podcrashlooping_matches_oom_crashloop_exemplar():
    ex = exemplars_lib.find_for_alert(
        alertname="PodCrashLooping",
        service="image-provider",
        deployment_type="k8s",
        signal="availability",
        severity="warning",
    )
    assert ex is not None
    assert ex.get("id") == "oom-crashloop-restart"


def test_oom_crashloop_exemplar_carries_termination_reason_evidence():
    ex = exemplars_lib.find_for_alert(
        alertname="PodCrashLooping",
        service="accounting",
        deployment_type="k8s",
        signal="availability",
        severity="warning",
    )
    rendered = exemplars_lib.format_for_prompt(ex)
    assert "last_terminated_reason" in rendered
    assert "OOMKilled" in rendered


def test_targetdown_exemplar_matching_unchanged():
    """The new exemplar must not steal TargetDown alerts (its regex excludes
    TargetDown) — the synthetic-blip / crashloop-bad-config behaviour for
    TargetDown stays as before."""
    ex = exemplars_lib.find_for_alert(
        alertname="TargetDown",
        service="node-exporter",
        deployment_type="k8s",
        signal="metric",
        severity="warning",
    )
    assert ex is not None
    assert ex.get("id") != "oom-crashloop-restart"


def test_kubepodcrashlooping_on_employees_still_gets_bad_config_exemplar():
    """Tie-break regression: for the employees-* services the established
    boot-failure exemplar (earlier in the library) must still win."""
    ex = exemplars_lib.find_for_alert(
        alertname="KubePodCrashLooping",
        service="employees-backend",
        deployment_type="k8s",
        signal="metric",
        severity="warning",
    )
    assert ex is not None
    assert ex.get("id") == "crashloop-bad-config"


# ---------------------------------------------------------------------------
# Iteration 2 (same-day live induction): deterministic agency auto-template.
# The playbook alone failed live — the 14b model never produced a parseable
# tool_request ("LLM JSON parse failed" x3 in the 13:16-13:18 window), so the
# agency pass fell back to the plain anti-hedge retry which has no tool offer
# and no KSM evidence → "Cannot determine" again (image-provider induction).
# Fix: pipeline auto-executes the playbook's combined query for crash-loop
# alerts (via prometheus-mcp — MCP-only invariant intact), no LLM tool-pick.
# ---------------------------------------------------------------------------

import os
import tempfile
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

import app.bounded_agency as bounded_agency_mod
from app.bounded_agency import PrometheusQueryArgs, build_crashloop_tool_request
from app.config import settings
from app.models import Decision, LLMDecision
from app.pipeline import TriagePipeline
from app.rca_store import RCAStore


def test_build_crashloop_tool_request_shape():
    req = build_crashloop_tool_request(_crashloop_alert())
    assert req.name == "prometheus.query"
    expr = req.args["expr"]
    assert expr == crashloop_evidence_query("otel-demo", "accounting")
    # The args must validate against the whitelisted schema (rejects extras).
    PrometheusQueryArgs(**req.args)


def test_build_crashloop_tool_request_missing_namespace_defaults_unknown():
    alert = _crashloop_alert()
    del alert.labels["namespace"]
    req = build_crashloop_tool_request(alert)
    assert 'exported_namespace="unknown"' in req.args["expr"]


@pytest_asyncio.fixture
async def crashloop_store():
    db_path = os.path.join(tempfile.gettempdir(), "test_crashloop_agency.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


def _hedged_decision() -> LLMDecision:
    return LLMDecision(
        decision=Decision.ESCALATE, severity="warning", confidence=0.30,
        reason="No clear cause identified from pre-gathered metrics, logs, or traces.",
        human_cause="Cannot determine the root cause of the alert with current data.",
        rca="Cannot determine the root cause. Metrics show no significant anomalies.",
        suggested_actions=[], evidence=[],
    )


def _named_oom_decision() -> LLMDecision:
    return LLMDecision(
        decision=Decision.ESCALATE, severity="warning", confidence=0.85,
        reason="Kernel OOM-kill loop: memory limit too small for the workload.",
        human_cause="accounting is being OOMKilled - its memory limit is too small for the workload.",
        rca=(
            "accounting's container is in an OOM-kill loop: "
            "kube_pod_container_status_last_terminated_reason has reason=OOMKilled "
            "and the restart counter climbed 4x in the last hour while the working "
            "set hit the memory limit."
        ),
        suggested_actions=[
            "kubectl -n otel-demo set resources deploy/accounting --limits=memory=256Mi — lift the ceiling out of OOMKill range",
        ],
        evidence=["kube_pod_container_status_last_terminated_reason{reason='OOMKilled'} = 1"],
    )


@pytest.mark.asyncio
async def test_crashloop_agency_runs_auto_template_not_llm_tool_pick(
    crashloop_store, monkeypatch,
):
    """End-to-end through _process_alert: a crash-loop alert whose first pass
    is data_starved must (1) NEVER go through request_tool_or_decide (the
    flaky tool-pick), (2) auto-execute the combined KSM query, (3) re-prompt
    with the tool result, and (4) persist the evidence-backed retry."""
    monkeypatch.setattr(settings, "data_starved_early_exit_enabled", False)
    monkeypatch.setattr(settings, "triage_data_starved_retry_enabled", True)
    monkeypatch.setattr(settings, "triage_bounded_agency_enabled", True)

    executed = []

    async def fake_execute_tool(req, context_gatherer, store):
        executed.append(req)
        return {
            "tool": req.name, "args": req.args,
            "result": {"status": "success", "data": [{
                "metric": {
                    "__name__": "kube_pod_container_status_last_terminated_reason",
                    "exported_pod": "accounting-7c8d9f6b5-x2x4q",
                    "reason": "OOMKilled",
                },
                "value": 1,
            }]},
        }

    monkeypatch.setattr(bounded_agency_mod, "execute_tool", fake_execute_tool)

    llm = MagicMock()
    llm.investigate = AsyncMock(side_effect=[
        (_hedged_decision(), 10),       # first pass — hedge
        (_named_oom_decision(), 10),    # evidence-laden retry — named cause
    ])
    llm.request_tool_or_decide = AsyncMock(
        side_effect=AssertionError("crash-loop alerts must not use the LLM tool-pick"),
    )

    pipeline = TriagePipeline(
        rca_store=crashloop_store,
        drain=MagicMock(
            annotate_lines=MagicMock(return_value=([], "")),
            get_stats=MagicMock(return_value={"total_clusters": 0}),
        ),
        context_gatherer=MagicMock(
            gather=AsyncMock(return_value=GatheredContext(sources_available=3)),
        ),
        llm_client=llm,
        notifier=MagicMock(send_escalation=AsyncMock(), send_timeout_alert=AsyncMock()),
        dedup=MagicMock(
            check=AsyncMock(return_value=(False, None)),
            record_first_decision=AsyncMock(), window=300,
        ),
    )

    await pipeline._process_alert(_crashloop_alert(), source="grafana")

    # (1) the flaky tool-pick was bypassed
    llm.request_tool_or_decide.assert_not_called()
    # (2) the combined template query was executed exactly once
    assert len(executed) == 1
    assert executed[0].name == "prometheus.query"
    assert "kube_pod_container_status_last_terminated_reason" in executed[0].args["expr"]
    assert 'exported_namespace="otel-demo"' in executed[0].args["expr"]
    # (3) the retry prompt carried the tool result
    assert llm.investigate.await_count == 2
    retry_kwargs = llm.investigate.await_args_list[1].kwargs
    assert "OOMKilled" in (retry_kwargs.get("tool_result_block") or "")
    # (4) the persisted decision is the evidence-backed retry, not the hedge
    rows = await crashloop_store.get_decisions(limit=3)
    assert len(rows) == 1
    assert "OOM" in (rows[0]["rca_report"] or "")
    assert rows[0]["rca_quality"] == "actionable"


@pytest.mark.asyncio
async def test_non_crashloop_alert_still_uses_llm_tool_pick(
    crashloop_store, monkeypatch,
):
    """Regression: the generic bounded-agency flow (LLM picks the tool) is
    untouched for non-restart alerts."""
    monkeypatch.setattr(settings, "data_starved_early_exit_enabled", False)
    monkeypatch.setattr(settings, "triage_data_starved_retry_enabled", True)
    monkeypatch.setattr(settings, "triage_bounded_agency_enabled", True)

    async def fail_execute_tool(req, context_gatherer, store):
        raise AssertionError("no auto-template for non-crashloop alerts")

    monkeypatch.setattr(bounded_agency_mod, "execute_tool", fail_execute_tool)

    llm = MagicMock()
    llm.investigate = AsyncMock(side_effect=[
        (_hedged_decision(), 10),
        (_named_oom_decision(), 10),
    ])
    # Model declines a tool and decides directly — generic path exercised.
    llm.request_tool_or_decide = AsyncMock(
        return_value=(_named_oom_decision().model_dump(mode="json"), 10),
    )

    pipeline = TriagePipeline(
        rca_store=crashloop_store,
        drain=MagicMock(
            annotate_lines=MagicMock(return_value=([], "")),
            get_stats=MagicMock(return_value={"total_clusters": 0}),
        ),
        context_gatherer=MagicMock(
            gather=AsyncMock(return_value=GatheredContext(sources_available=3)),
        ),
        llm_client=llm,
        notifier=MagicMock(send_escalation=AsyncMock(), send_timeout_alert=AsyncMock()),
        dedup=MagicMock(
            check=AsyncMock(return_value=(False, None)),
            record_first_decision=AsyncMock(), window=300,
        ),
    )

    alert = _crashloop_alert(alertname="HighCpuUsage")
    await pipeline._process_alert(alert, source="grafana")

    llm.request_tool_or_decide.assert_awaited()


# ---------------------------------------------------------------------------
# Iteration 3 — digest_crashloop_evidence (pre-interpreted facts, not raw JSON)
# ---------------------------------------------------------------------------

from app.bounded_agency import digest_crashloop_evidence


def _mcp_result(series):
    return {
        "tool": "prometheus.query",
        "args": {"expr": "…"},
        "result": {"status": "success", "result_type": "vector", "result": series},
    }


def _oom_series():
    # Exactly the live shape replayed at 2026-06-10 14:26:40 for image-provider.
    return [
        {"metric": {"__name__": "kube_pod_container_status_last_terminated_reason",
                    "exported_pod": "image-provider-58fc85685d-49dd4",
                    "reason": "OOMKilled"},
         "value": [1781101600, "1"]},
        {"metric": {"exported_pod": "image-provider-56664c7cd7-btlvf"},
         "value": [1781101600, "7.09"]},
        {"metric": {"exported_pod": "image-provider-579cb4974c-9js6n"},
         "value": [1781101600, "0"]},
        {"metric": {"exported_pod": "image-provider-58fc85685d-49dd4"},
         "value": [1781101600, "15.04"]},
        {"metric": {"__name__": "kube_pod_container_resource_limits",
                    "exported_pod": "image-provider-58fc85685d-49dd4"},
         "value": [1781101600, "4194304"]},
    ]


def test_digest_names_oom_with_limit_and_restarts():
    out = digest_crashloop_evidence(_mcp_result(_oom_series()), "image-provider", "otel-demo")
    assert out is not None
    assert "PRE-INTERPRETED FACTS" in out
    assert "last termination reason = OOMKilled" in out
    assert "restarted 15x" in out
    assert "memory limit = 4 MiB" in out
    assert "READY VERDICT" in out
    assert "OOMKilled" in out and "too small for the workload" in out
    # The trailing-window escape hatch must be present (accounting case).
    assert "ENDED" in out
    # Quiet replacement pods are named so the model doesn't confuse them.
    assert "image-provider-579cb4974c-9js6n" in out


def test_digest_non_oom_reason_still_names_mechanism():
    series = [
        {"metric": {"__name__": "kube_pod_container_status_last_terminated_reason",
                    "exported_pod": "cart-abc", "reason": "Error"},
         "value": [0, "1"]},
        {"metric": {"exported_pod": "cart-abc"}, "value": [0, "6"]},
    ]
    out = digest_crashloop_evidence(_mcp_result(series), "cart", "otel-demo")
    assert out is not None
    assert "'Error'" in out
    assert "Cannot determine" in out or "cannot determine" in out  # the anti-hedge line


def test_digest_empty_result_falls_back_to_none():
    assert digest_crashloop_evidence(_mcp_result([]), "x", "y") is None
    assert digest_crashloop_evidence({"tool": "prometheus.query", "error": "boom"}, "x", "y") is None
    # Limits-only (no reasons, no restarts) is not decisive evidence either.
    series = [{"metric": {"__name__": "kube_pod_container_resource_limits",
                          "exported_pod": "p"}, "value": [0, "1048576"]}]
    assert digest_crashloop_evidence(_mcp_result(series), "x", "y") is None


@pytest.mark.asyncio
async def test_pipeline_injects_digested_block(crashloop_store, monkeypatch):
    """The agency retry prompt must carry the digested facts, not raw JSON."""
    captured = {}

    async def fake_execute_tool(req, ctx, store):
        return _mcp_result(_oom_series())

    monkeypatch.setattr("app.bounded_agency.execute_tool", fake_execute_tool)

    llm = MagicMock()
    llm.close = AsyncMock()

    async def capture_investigate(*args, **kwargs):
        if "tool_result_block" in kwargs and kwargs["tool_result_block"]:
            captured["block"] = kwargs["tool_result_block"]
            return (_named_oom_decision(), 10)
        return (_hedged_decision(), 10)

    llm.investigate = AsyncMock(side_effect=capture_investigate)

    pipeline = TriagePipeline(
        rca_store=crashloop_store,
        drain=MagicMock(
            annotate_lines=MagicMock(return_value=([], "")),
            get_stats=MagicMock(return_value={"total_clusters": 0}),
        ),
        context_gatherer=MagicMock(
            gather=AsyncMock(return_value=GatheredContext(sources_available=3)),
        ),
        llm_client=llm,
        notifier=MagicMock(send_escalation=AsyncMock(), send_timeout_alert=AsyncMock()),
        dedup=MagicMock(
            check=AsyncMock(return_value=(False, None)),
            record_first_decision=AsyncMock(), window=300,
        ),
    )

    alert = _crashloop_alert()
    await pipeline._process_alert(alert, source="grafana")

    assert "block" in captured
    assert "PRE-INTERPRETED FACTS" in captured["block"]
    assert "READY VERDICT" in captured["block"]
