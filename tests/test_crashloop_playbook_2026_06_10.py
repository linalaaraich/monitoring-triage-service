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
