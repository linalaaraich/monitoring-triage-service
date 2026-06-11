"""Fix F (2026-06-11) — deploy-bridge context: grounded deploy claims.

Until today the platform had NO deploy/rollout data source, so a
deploy-as-cause RCA could only ever be fabricated (one shipped on a Drain3
alert; the validator's ungrounded-deploy-claim scan now rejects those). The
6th MCP bridge (deploy-mcp, :8096) derives rollouts from kube-state-metrics
series already in Prometheus. For kube-workload + Drain3 alerts the gatherer
makes ONE extra MCP call to /tools/recent_deploys scoped to the alert's
namespace+service and renders a deterministic plain-English line.

Locks in:
  - _summarize_recent_deploys: rollout named with minutes-before-alert,
    replicaset, prior-RS "rolled from X"; empty list -> explicit RULED OUT
    negative; junk shapes -> None
  - gather() wiring: deploy call fires for kube-workload + Drain3 alerts
    only, goes through settings.deploy_mcp_url (MCP-only invariant), and a
    bridge failure is non-fatal
  - prompt rendering: '### Recent deploys (checked via deploy bridge)' near
    the kube-workload block, above ### Metrics; absent when no summary
"""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from app.context import (
    ContextGatherer,
    _is_deploy_check_alert,
    _parse_alert_time,
    _summarize_recent_deploys,
)
from app.llm_client import LLMClient
from app.models import GatheredContext, GrafanaAlert

ALERT_STARTS_AT = "2026-06-11T12:35:00Z"
ALERT_EPOCH = _parse_alert_time(ALERT_STARTS_AT)


def _alert(alertname="KubeWorkloadDown", service="ad", **label_over) -> GrafanaAlert:
    labels = {
        "alertname": alertname,
        "namespace": "otel-demo",
        "service": service,
        "severity": "critical",
        "signal": "availability",
        "component": "k8s",
    }
    labels.update(label_over)
    return GrafanaAlert(
        status="firing",
        labels=labels,
        annotations={"summary": "workload down"},
        startsAt=ALERT_STARTS_AT,
        fingerprint="fp-deploy-bridge-test",
        values={"B": 0.0},
    )


def _deploy_record(minutes_before_alert=14.0, deployment="ad", replicaset="ad-69f7649c7d"):
    rollout_epoch = ALERT_EPOCH - minutes_before_alert * 60
    from datetime import datetime, timezone

    return {
        "deployment": deployment,
        "namespace": "otel-demo",
        "rollout_time_iso": datetime.fromtimestamp(rollout_epoch, timezone.utc).isoformat(),
        "age_minutes": minutes_before_alert + 5,
        "replicaset": replicaset,
        "prior_replicaset": "ad-d678c8d65",
        "prior_replicaset_age_minutes": 8155.0,
    }


# ---------------------------------------------------------------------------
# _summarize_recent_deploys — the deterministic renderer
# ---------------------------------------------------------------------------

def test_summary_names_rollout_minutes_before_alert_and_prior_rs():
    out = _summarize_recent_deploys([_deploy_record()], "ad", ALERT_EPOCH)
    assert "deployment ad rolled 14 min before this alert" in out
    assert "replicaset ad-69f7649c7d" in out
    assert "replacing ad-d678c8d65" in out
    assert "135.9 h" in out  # prior version's runtime, hours above 2h


def test_summary_empty_list_rules_deploys_out():
    out = _summarize_recent_deploys([], "ad", ALERT_EPOCH)
    assert out == (
        "No deploys of ad in the last 2h — deploy-regression can be "
        "RULED OUT as the cause."
    )


def test_summary_rollout_after_alert_cannot_have_caused_it():
    out = _summarize_recent_deploys([_deploy_record(minutes_before_alert=-9.0)], "ad", ALERT_EPOCH)
    assert "AFTER this alert fired" in out
    assert "cannot have caused it" in out


def test_summary_falls_back_to_age_when_alert_time_unknown():
    out = _summarize_recent_deploys([_deploy_record()], "ad", None)
    assert "rolled 19 min ago" in out


def test_summary_unusable_shapes_return_none():
    assert _summarize_recent_deploys(None, "ad", ALERT_EPOCH) is None
    assert _summarize_recent_deploys({"detail": "boom"}, "ad", ALERT_EPOCH) is None
    assert _summarize_recent_deploys(["junk"], "ad", ALERT_EPOCH) is None


def test_summary_is_deterministic():
    args = ([_deploy_record()], "ad", ALERT_EPOCH)
    assert _summarize_recent_deploys(*args) == _summarize_recent_deploys(*args)


# ---------------------------------------------------------------------------
# gather() wiring — one extra MCP call, through the bridge only
# ---------------------------------------------------------------------------

def _gather_with_fake_mcp(alert, deploy_response=None, deploy_raises=False):
    gatherer = ContextGatherer.__new__(ContextGatherer)
    calls = []

    async def fake_mcp_call(server, url, params):
        calls.append({"server": server, "url": url, "params": params})
        if server == "deploy":
            if deploy_raises:
                raise RuntimeError("bridge down")
            return deploy_response, 7
        if "query_range" in url or "query_logs" in url:
            return {"result": [], "lines": []}, 5
        return [], 5

    gatherer._mcp_call = fake_mcp_call
    ctx = asyncio.new_event_loop().run_until_complete(gatherer.gather(alert))
    return ctx, calls


def test_gather_calls_deploy_bridge_for_kube_workload_alert():
    ctx, calls = _gather_with_fake_mcp(_alert(), deploy_response=[_deploy_record()])
    deploy_calls = [c for c in calls if c["server"] == "deploy"]
    assert len(deploy_calls) == 1
    call = deploy_calls[0]
    # MCP-only invariant: the bridge URL, never Prometheus directly
    assert call["url"].endswith(":8096/tools/recent_deploys")
    assert call["params"] == {"namespace": "otel-demo", "service": "ad", "window": "2h"}
    assert "deployment ad rolled 14 min before this alert" in ctx.recent_deploys_summary


def test_gather_calls_deploy_bridge_for_drain3_alert_and_renders_negative():
    ctx, calls = _gather_with_fake_mcp(
        _alert(alertname="Drain3AnomalyDetected", signal="log"), deploy_response=[]
    )
    assert any(c["server"] == "deploy" for c in calls)
    assert "RULED OUT" in ctx.recent_deploys_summary


def test_gather_skips_deploy_bridge_for_non_qualifying_alert():
    ctx, calls = _gather_with_fake_mcp(
        _alert(alertname="HighCpuUsage", component="host"), deploy_response=[]
    )
    assert not any(c["server"] == "deploy" for c in calls)
    assert ctx.recent_deploys_summary is None


def test_gather_skips_deploy_bridge_for_unknown_service():
    ctx, calls = _gather_with_fake_mcp(_alert(service="unknown"))
    assert not any(c["server"] == "deploy" for c in calls)
    assert ctx.recent_deploys_summary is None


def test_gather_deploy_bridge_failure_is_non_fatal():
    ctx, calls = _gather_with_fake_mcp(_alert(), deploy_raises=True)
    assert ctx.recent_deploys_summary is None
    assert ctx.sources_available == 3  # the three pillars still landed


def test_alert_gate():
    assert _is_deploy_check_alert(_alert())
    assert _is_deploy_check_alert(_alert(alertname="PodCrashLooping"))
    assert _is_deploy_check_alert(_alert(alertname="Drain3AnomalyDetected"))
    assert not _is_deploy_check_alert(_alert(alertname="HighCpuUsage"))


# ---------------------------------------------------------------------------
# prompt rendering
# ---------------------------------------------------------------------------

def test_prompt_renders_recent_deploys_block(monkeypatch):
    client = LLMClient.__new__(LLMClient)
    captured = {}

    async def fake_call(messages):
        captured["messages"] = messages
        return None

    monkeypatch.setattr(client, "_call_ollama_with_resilience", fake_call)
    client._circuit = MagicMock()

    ctx = GatheredContext(
        sources_available=3,
        recent_deploys_summary=(
            "Recent rollout: deployment ad rolled 14 min before this alert "
            "(replicaset ad-69f7649c7d, replacing ad-d678c8d65 which had run 135.9 h)."
        ),
    )
    asyncio.new_event_loop().run_until_complete(client.investigate(_alert(), ctx, ""))
    user = captured["messages"][-1]["content"]
    assert "### Recent deploys (checked via deploy bridge)" in user
    assert "replicaset ad-69f7649c7d" in user
    # near the kube-workload zone: above the raw metrics section
    assert user.index("Recent deploys (checked via deploy bridge)") < user.index("### Metrics")
    assert "cite the replicaset in your evidence" in user


def test_prompt_omits_recent_deploys_block_when_absent():
    msgs = LLMClient()._build_prompt(
        _alert(), GatheredContext(sources_available=3), "", history_context=""
    )
    assert "Recent deploys (checked via deploy bridge)" not in msgs[1]["content"]
