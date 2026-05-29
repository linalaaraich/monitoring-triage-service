"""DA-3 — cross-row verdict coherence (Sprint 4 §14, Jira S4-DA-03).

When a NON-duplicate fire happens for a fingerprint that already had a prior
LLM decision within the coherence window, the pipeline fetches that prior
cause and injects it into the LLM prompt with an explicit coherence rule
(reuse the prior cause if unchanged / "changed my mind because…" if revised
/ "condition resolved" if recovering). This prevents the platform emitting
contradictory RCAs on consecutive fires of the same flapping alert.

These tests lock in:
  - the store lookup (within / outside window / none / synthetic-excluded),
  - the prompt-building helper formatting (build_prior_decision_block),
  - the prompt builder injects the block when a prior decision is supplied
    and omits it otherwise,
  - the config knob (window minutes + enable flag) is respected end-to-end,
  - the pipeline fetches the prior decision and passes it to the LLM, and
    does NOT inject when there's no recent prior / the feature is disabled.

All deterministic — the LLM client is stubbed (no real Ollama / MCP).
"""
from __future__ import annotations

import os
import tempfile
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from app.config import settings
from app.llm_client import LLMClient, build_prior_decision_block
from app.models import Decision, GatheredContext, GrafanaAlert, LLMDecision, RCARecord
from app.pipeline import TriagePipeline
from app.rca_store import RCAStore, _utc_now


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def store():
    db_path = os.path.join(tempfile.gettempdir(), "test_da3_coherence.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


def _make_alert(
    name: str = "HighP95Latency",
    service: str = "spring-boot",
    fingerprint: str = "fp-da3-coherence",
) -> GrafanaAlert:
    return GrafanaAlert(
        status="firing",
        labels={"alertname": name, "service": service, "severity": "warning", "signal": "metric"},
        annotations={"summary": "p95 high", "description": "latency p95 over 1s"},
        startsAt="2026-05-26T10:30:00Z",
        fingerprint=fingerprint,
    )


async def _save_prior(
    store: RCAStore,
    fingerprint: str,
    *,
    minutes_ago: float,
    verdict: str = "escalate",
    rca: str = "JVM heap exhausted — full GC every 4s, working set at 98% of cgroup cap.",
    alert_name: str = "HighP95Latency",
    service: str = "spring-boot",
    llm_verdict_override: str | None = "__unset__",
) -> RCARecord:
    """Persist a prior decision and back-date its timestamp by minutes_ago.

    llm_verdict_override lets a caller force NULL (short-path rows) without
    relying on the `verdict` default.
    """
    rec = RCARecord(
        alert_name=alert_name,
        affected_service=service,
        alert_fingerprint=fingerprint,
        triage_decision="investigate",
        llm_verdict=verdict if llm_verdict_override == "__unset__" else llm_verdict_override,
        rca_report=rca,
        llm_reasoning="prior reasoning",
        action_taken="emailed",
        rca_quality="actionable",
    )
    # Back-date the timestamp so window tests are deterministic.
    rec.timestamp = _utc_now() - timedelta(minutes=minutes_ago)
    await store.save_decision(rec)
    return rec


# ---------------------------------------------------------------------------
# Store lookup — get_recent_decision_for_fingerprint
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_store_returns_prior_within_window(store):
    fp = "fp-within"
    await _save_prior(store, fp, minutes_ago=10)
    prior = await store.get_recent_decision_for_fingerprint(fp, window_minutes=30)
    assert prior is not None
    assert prior["llm_verdict"] == "escalate"
    assert "JVM heap" in prior["rca_report"]


@pytest.mark.asyncio
async def test_store_ignores_prior_outside_window(store):
    fp = "fp-outside"
    # 45 min ago is outside the 30-min window → treated fresh.
    await _save_prior(store, fp, minutes_ago=45)
    prior = await store.get_recent_decision_for_fingerprint(fp, window_minutes=30)
    assert prior is None


@pytest.mark.asyncio
async def test_store_returns_none_when_no_prior(store):
    prior = await store.get_recent_decision_for_fingerprint("fp-never-seen", window_minutes=30)
    assert prior is None


@pytest.mark.asyncio
async def test_store_returns_most_recent_of_several(store):
    fp = "fp-multi"
    await _save_prior(store, fp, minutes_ago=20, verdict="dismiss", rca="older cause")
    await _save_prior(store, fp, minutes_ago=5, verdict="escalate", rca="newer cause is the one")
    prior = await store.get_recent_decision_for_fingerprint(fp, window_minutes=30)
    assert prior is not None
    assert prior["llm_verdict"] == "escalate"
    assert "newer cause" in prior["rca_report"]


@pytest.mark.asyncio
async def test_store_skips_short_path_rows_with_null_verdict(store):
    """Short-path dedup / suppression rows carry llm_verdict NULL — they have
    no cause to be coherent with, so the lookup must skip them."""
    fp = "fp-nullverdict"
    await _save_prior(store, fp, minutes_ago=5, llm_verdict_override=None)
    prior = await store.get_recent_decision_for_fingerprint(fp, window_minutes=30)
    assert prior is None


@pytest.mark.asyncio
async def test_store_excludes_synthetic_fingerprints(store):
    """audit-live-* / chaos-* fires must not seed a coherence anchor."""
    await _save_prior(store, "audit-live-2026-05-26-p95", minutes_ago=5)
    await _save_prior(store, "chaos-run-42", minutes_ago=5)
    assert await store.get_recent_decision_for_fingerprint(
        "audit-live-2026-05-26-p95", window_minutes=30
    ) is None
    assert await store.get_recent_decision_for_fingerprint(
        "chaos-run-42", window_minutes=30
    ) is None


@pytest.mark.asyncio
async def test_store_empty_fingerprint_returns_none(store):
    assert await store.get_recent_decision_for_fingerprint("", window_minutes=30) is None


# ---------------------------------------------------------------------------
# Prompt-building helper — build_prior_decision_block
# ---------------------------------------------------------------------------


def test_block_empty_when_no_prior():
    assert build_prior_decision_block(None) == ""
    assert build_prior_decision_block({}) == ""


def test_block_formats_prior_cause_and_coherence_rule():
    prior = {
        "id": "abc",
        "timestamp": "2026-05-26T10:20:00",
        "llm_verdict": "escalate",
        "rca_report": "JVM heap exhausted — full GC every 4s.",
        "llm_reasoning": "heap",
    }
    block = build_prior_decision_block(prior)
    # Section header + DA-3 marker
    assert "Prior decision on THIS fingerprint" in block
    # Prior verdict surfaced (upper-cased) and timestamp trimmed to 19 chars
    assert "ESCALATE" in block
    assert "2026-05-26T10:20:00" in block
    # The prior cause is quoted back verbatim
    assert "JVM heap exhausted" in block
    # All three coherence branches present
    assert "changed my mind because" in block.lower()
    assert "condition resolved" in block.lower()
    assert "reuse" in block.lower()


def test_block_falls_back_to_reasoning_when_rca_empty():
    prior = {
        "timestamp": "2026-05-26T10:20:00",
        "llm_verdict": "dismiss",
        "rca_report": "",
        "llm_reasoning": "transient blip, recovered on its own",
    }
    block = build_prior_decision_block(prior)
    assert "transient blip" in block


def test_block_truncates_long_prior_cause():
    long_cause = "x" * 2000
    prior = {"timestamp": "2026-05-26T10:20:00", "llm_verdict": "escalate", "rca_report": long_cause}
    block = build_prior_decision_block(prior)
    # Truncated to 600 + ellipsis, not the full 2000 chars
    assert "x" * 600 in block
    assert "x" * 700 not in block
    assert "…" in block


# ---------------------------------------------------------------------------
# Prompt builder integration — _build_prompt injects / omits the block
# ---------------------------------------------------------------------------


def test_prompt_includes_block_when_prior_supplied():
    client = LLMClient()
    try:
        alert = _make_alert()
        ctx = GatheredContext()
        prior = {
            "timestamp": "2026-05-26T10:20:00",
            "llm_verdict": "escalate",
            "rca_report": "JDBC pool exhausted — Hikari at 50/50.",
        }
        messages = client._build_prompt(
            alert, ctx, drain_summary="Drain3: none", history_context="",
            correlated=None, metric_facts=None, prior_decision=prior,
        )
        user_content = messages[-1]["content"]
        assert "Prior decision on THIS fingerprint" in user_content
        assert "JDBC pool exhausted" in user_content
    finally:
        import asyncio
        asyncio.get_event_loop().run_until_complete(client.close())


def test_prompt_omits_block_when_no_prior():
    client = LLMClient()
    try:
        alert = _make_alert()
        ctx = GatheredContext()
        messages = client._build_prompt(
            alert, ctx, drain_summary="Drain3: none", history_context="",
            correlated=None, metric_facts=None, prior_decision=None,
        )
        user_content = messages[-1]["content"]
        assert "Prior decision on THIS fingerprint" not in user_content
    finally:
        import asyncio
        asyncio.get_event_loop().run_until_complete(client.close())


# ---------------------------------------------------------------------------
# Pipeline integration — fetch + inject, with the LLM stubbed
# ---------------------------------------------------------------------------


def _make_pipeline(store: RCAStore) -> tuple[TriagePipeline, MagicMock]:
    """Pipeline with a stub LLM that records the prior_decision it was
    handed and returns a clean actionable ESCALATE so the row persists."""

    async def _fake_investigate(alert, ctx, anomaly_summary, history_context, **kwargs):
        _fake_investigate.calls.append(kwargs.get("prior_decision"))
        decision = LLMDecision(
            decision=Decision.ESCALATE,
            severity="warning",
            confidence=0.85,
            reason="ok",
            rca="JVM heap exhausted — full GC every 4s; reused prior cause.",
            suggested_actions=["kubectl rollout restart deploy/spring-boot -n app"],
            evidence=["JVM heap working set at 98% of cgroup cap", "full GC every 4s"],
        )
        return decision, 10

    _fake_investigate.calls = []

    llm = MagicMock()
    llm.investigate = AsyncMock(side_effect=_fake_investigate)
    # Defensive: if a retry path ever fires, don't blow up on a bare
    # MagicMock await. We assert on the FIRST investigate call's
    # prior_decision regardless.
    llm.request_tool_or_decide = AsyncMock(return_value=(None, 0))

    # Context gatherer returns an empty context (no MCP traffic).
    ctx_gatherer = MagicMock()
    ctx_gatherer.gather = AsyncMock(return_value=GatheredContext())

    drain = MagicMock()
    drain.annotate_lines = MagicMock(return_value=([], ""))
    drain.get_stats = MagicMock(return_value={"total_clusters": 0})

    notifier = MagicMock(send_escalation=AsyncMock(), send_timeout_alert=AsyncMock())

    pipeline = TriagePipeline(
        rca_store=store,
        drain=drain,
        context_gatherer=ctx_gatherer,
        llm_client=llm,
        notifier=notifier,
        dedup=MagicMock(
            check=AsyncMock(return_value=(False, None)),
            record_first_decision=AsyncMock(),
            window=600,
        ),
    )
    return pipeline, llm


@pytest.mark.asyncio
async def test_pipeline_injects_prior_within_window(store, monkeypatch):
    """A prior decision within the window is fetched and handed to the LLM."""
    monkeypatch.setattr(settings, "da3_verdict_coherence_enabled", True)
    monkeypatch.setattr(settings, "da3_verdict_coherence_window_minutes", 30)
    # Disable Layer-2 suppression so the second fire reaches the LLM path
    # (otherwise the prior escalate is fine, but a prior dismiss would suppress).
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)

    fp = "fp-pipeline-within"
    await _save_prior(store, fp, minutes_ago=10, rca="JVM heap exhausted — full GC every 4s.")

    pipeline, llm = _make_pipeline(store)
    alert = _make_alert(fingerprint=fp)
    await pipeline._process_alert(alert, source="grafana")

    passed = llm.investigate.side_effect.calls
    assert passed, "LLM.investigate was never called"
    assert passed[0] is not None, "prior decision should have been injected"
    assert "JVM heap" in passed[0]["rca_report"]


@pytest.mark.asyncio
async def test_pipeline_no_injection_outside_window(store, monkeypatch):
    """A prior decision OUTSIDE the window is treated fresh — no injection."""
    monkeypatch.setattr(settings, "da3_verdict_coherence_enabled", True)
    monkeypatch.setattr(settings, "da3_verdict_coherence_window_minutes", 30)
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)

    fp = "fp-pipeline-outside"
    await _save_prior(store, fp, minutes_ago=90)

    pipeline, llm = _make_pipeline(store)
    alert = _make_alert(fingerprint=fp)
    await pipeline._process_alert(alert, source="grafana")

    passed = llm.investigate.side_effect.calls
    assert passed and passed[0] is None, "stale prior should NOT be injected"


@pytest.mark.asyncio
async def test_pipeline_no_injection_when_no_prior(store, monkeypatch):
    """No prior decision → normal flow, no injection."""
    monkeypatch.setattr(settings, "da3_verdict_coherence_enabled", True)
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)

    pipeline, llm = _make_pipeline(store)
    alert = _make_alert(fingerprint="fp-pipeline-fresh")
    await pipeline._process_alert(alert, source="grafana")

    passed = llm.investigate.side_effect.calls
    assert passed and passed[0] is None


@pytest.mark.asyncio
async def test_pipeline_respects_disable_flag(store, monkeypatch):
    """When the feature flag is off, no lookup / injection even with a
    fresh prior decision in the window."""
    monkeypatch.setattr(settings, "da3_verdict_coherence_enabled", False)
    monkeypatch.setattr(settings, "da3_verdict_coherence_window_minutes", 30)
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)

    fp = "fp-pipeline-disabled"
    await _save_prior(store, fp, minutes_ago=5)

    pipeline, llm = _make_pipeline(store)
    alert = _make_alert(fingerprint=fp)
    await pipeline._process_alert(alert, source="grafana")

    passed = llm.investigate.side_effect.calls
    assert passed and passed[0] is None, "disabled flag must skip injection"


@pytest.mark.asyncio
async def test_pipeline_window_knob_respected(store, monkeypatch):
    """A prior 20 min ago is injected under a 30-min window but NOT under a
    10-min window — confirming the config knob is honored, not hard-coded."""
    monkeypatch.setattr(settings, "da3_verdict_coherence_enabled", True)
    monkeypatch.setattr(settings, "triage_suppression_enabled", False)

    # Distinct fingerprints per sub-run so the row each run PERSISTS (a fresh
    # "now"-stamped decision) doesn't itself become the prior the next lookup
    # finds — we want to probe the back-dated 20-min-ago prior only.
    fp_wide = "fp-pipeline-knob-wide"
    fp_narrow = "fp-pipeline-knob-narrow"
    await _save_prior(store, fp_wide, minutes_ago=20)
    await _save_prior(store, fp_narrow, minutes_ago=20)

    # Wide window (30m) → the 20-min-ago prior is inside → injected
    monkeypatch.setattr(settings, "da3_verdict_coherence_window_minutes", 30)
    pipeline, llm = _make_pipeline(store)
    await pipeline._process_alert(_make_alert(fingerprint=fp_wide), source="grafana")
    assert llm.investigate.side_effect.calls[-1] is not None

    # Narrow window (10m) → the 20-min-ago prior is outside → not injected
    monkeypatch.setattr(settings, "da3_verdict_coherence_window_minutes", 10)
    pipeline2, llm2 = _make_pipeline(store)
    await pipeline2._process_alert(_make_alert(fingerprint=fp_narrow), source="grafana")
    assert llm2.investigate.side_effect.calls[-1] is None
