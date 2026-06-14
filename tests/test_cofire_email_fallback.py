"""Co-fire email-fallback safety (Loop 1 audit, 2026-06-13).

On the co-fire path the sibling suppresses its own email, so the primary's
escalation is the incident's ONLY page. If the rich (v2) body threw — or a
send transiently failed — the page was lost and the pipeline only released
the claim for FUTURE siblings, leaving an already-consolidated sibling
silent. send_escalation now falls back to the plain (v1) body and re-sends,
and only re-raises when sending itself is impossible (SMTP down). These
tests pin both branches.
"""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.models import Decision, GrafanaAlert, LLMDecision, RCARecord
from app.notifier import EmailNotifier


def _alert():
    return GrafanaAlert(
        status="firing",
        labels={"alertname": "KubeWorkloadDown", "service": "ad", "severity": "critical"},
        annotations={"summary": "x", "description": "y"},
        startsAt="2026-06-13T10:00:00Z",
    )


def _decision():
    return LLMDecision(
        decision=Decision.ESCALATE, confidence=0.95, severity="critical",
        rca="ad has 0 ready replicas", reason="pods unschedulable",
        human_cause="The ad workload is down — its pods cannot be scheduled.",
    )


@pytest.mark.asyncio
async def test_rich_body_failure_falls_back_to_plain(monkeypatch):
    n = EmailNotifier()
    sends = []
    monkeypatch.setattr(n, "_send", AsyncMock(side_effect=lambda subj, body: sends.append(body)))
    # rich v2 body throws (unusual payload / rendering bug)
    monkeypatch.setattr(n, "_build_v2_escalation_body",
                        lambda *a, **k: (_ for _ in ()).throw(ValueError("boom")))
    monkeypatch.setattr(n, "_build_escalation_body", lambda *a, **k: "PLAIN_FALLBACK_BODY")
    # must NOT raise — the page goes out via the plain body
    await n.send_escalation(_alert(), _decision(), RCARecord(id="d1"), 0)
    assert sends == ["PLAIN_FALLBACK_BODY"], "fallback page was not sent"


@pytest.mark.asyncio
async def test_transient_send_failure_retried_via_plain(monkeypatch):
    n = EmailNotifier()
    calls = {"n": 0}

    async def flaky_send(subj, body):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("transient SMTP")  # v2 send fails once
        return None  # v1 send succeeds

    monkeypatch.setattr(n, "_send", flaky_send)
    monkeypatch.setattr(n, "_build_escalation_body", lambda *a, **k: "PLAIN")
    # v2 body builds fine; the first _send fails, fallback _send succeeds
    await n.send_escalation(_alert(), _decision(), RCARecord(id="d1"), 0)
    assert calls["n"] == 2, "should retry the send via the plain body"


@pytest.mark.asyncio
async def test_smtp_down_reraises_so_pipeline_releases(monkeypatch):
    n = EmailNotifier()
    monkeypatch.setattr(n, "_send", AsyncMock(side_effect=OSError("SMTP down")))
    monkeypatch.setattr(n, "_build_escalation_body", lambda *a, **k: "PLAIN")
    # both v2 and v1 sends fail → must re-raise so the pipeline can
    # release_primary (the co-fire claim) and let a future fire re-page
    with pytest.raises(OSError):
        await n.send_escalation(_alert(), _decision(), RCARecord(id="d1"), 0)
