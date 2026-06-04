"""Backend audit 2026-06-04 — issue #2 (prompt grounding for verdict accuracy).

The drain3 self-fire RCAs averaged ~100s to emit "Cannot determine the root
cause / insufficient data" while the prompt actually carried ~900 chars of rich
anomaly evidence (the verbatim anomalous lines) in `drain_summary`. Root cause:
the old `_build_prompt` layout rendered the anomaly evidence as a bare
`### {drain_summary}` header placed AFTER an empty `### Logs … [Loki] returned 0
lines` block, so the small model anchored on "0 lines" and hedged.

Fix (llm_client._build_prompt):
  - the anomaly evidence is now a clearly-labelled "PRIMARY log evidence" block
    rendered BEFORE the Loki section,
  - and when that evidence exists, the empty service-scoped Loki re-query is
    reframed as a benign non-signal pointing UP at the primary block — no
    headline "returned 0 lines".

These tests pin the prompt STRUCTURE (we can't unit-test the model's weighting,
but we can guarantee it receives the evidence first + isn't handed a misleading
empty-Loki headline). Real-induction (model behaviour) is verified separately.
"""
from __future__ import annotations

from app.llm_client import LLMClient
from app.models import GatheredContext, GrafanaAlert


def _alert(**over) -> GrafanaAlert:
    base = dict(
        status="firing",
        labels={"alertname": "Drain3AnomalyDetected", "service": "spring-boot",
                "severity": "warning", "signal": "log"},
        annotations={"summary": "Drain3 anomaly", "description": "x" * 50},
        startsAt="2026-06-04T10:00:00Z",
        fingerprint="fp-test",
    )
    base.update(over)
    return GrafanaAlert(**base)


def _user_content(drain_summary: str, ctx: GatheredContext, alert=None) -> str:
    client = LLMClient()
    msgs = client._build_prompt(
        alert or _alert(), ctx, drain_summary, history_context="",
    )
    return msgs[1]["content"]


RICH_ANOMALY = (
    "Anomaly rate: 3.23% (3 lines flagged in batch).\n"
    "Sample anomalous lines (verbatim, top 3 of 3):\n"
    "  • java.lang.OutOfMemoryError: Java heap space at com.cires.Employee.save\n"
    "  • HikariPool-1 - Connection is not available, request timed out after 30000ms\n"
    "  • Async task rejected: pool exhausted"
)


def test_anomaly_evidence_rendered_as_primary_block():
    """A non-empty drain_summary renders the PRIMARY-evidence block with the
    verbatim lines."""
    ctx = GatheredContext(annotated_logs=None, sources_available=1)
    content = _user_content(RICH_ANOMALY, ctx)
    assert "PRIMARY log evidence" in content
    assert "OutOfMemoryError: Java heap space" in content
    assert "reason FROM these" in content


def test_anomaly_block_precedes_loki_section():
    """Grounding fix: the anomaly evidence must appear BEFORE the Logs/Loki
    section so the small model reads the evidence first, not the empty-Loki
    framing."""
    ctx = GatheredContext(annotated_logs=None, sources_available=1)
    content = _user_content(RICH_ANOMALY, ctx)
    assert "PRIMARY log evidence" in content
    assert "### Logs" in content
    assert content.index("PRIMARY log evidence") < content.index("### Logs")


def test_empty_loki_reframed_when_anomaly_evidence_present():
    """When the anomaly evidence exists but the service-scoped Loki re-query is
    empty, the Loki section must NOT lead with a 'returned 0 lines' headline the
    model fixates on — it points up at the primary block and explicitly says
    'not a data gap'."""
    ctx = GatheredContext(annotated_logs=None, sources_available=1)
    content = _user_content(RICH_ANOMALY, ctx)
    # No bald "returned 0 lines" framing in the Loki block for this path.
    loki_section = content.split("### Logs", 1)[1].split("### Traces", 1)[0]
    assert "returned 0 lines" not in loki_section
    assert "NOT a data gap" in loki_section
    assert "PRIMARY log evidence" in loki_section  # points back up


def test_empty_loki_keeps_node_framing_when_no_anomaly_evidence():
    """Regression guard: for a genuine empty-everything alert (no anomaly
    evidence) the original node-level empty-Loki framing is preserved — the fix
    only changes behaviour when primary evidence exists."""
    ctx = GatheredContext(annotated_logs=None, sources_available=0)
    alert = _alert(labels={"alertname": "TargetDown", "service": "k3s-node",
                           "severity": "critical", "signal": "metric"})
    content = _user_content("", ctx, alert=alert)
    assert "PRIMARY log evidence" not in content
    assert "returned 0 lines for service=k3s-node" in content


def test_short_drain_summary_not_promoted():
    """A trivially-short drain_summary (e.g. 'Drain3: none') is not promoted as
    primary evidence — avoids a misleading 'PRIMARY evidence' label over noise."""
    ctx = GatheredContext(annotated_logs=None, sources_available=1)
    content = _user_content("Drain3: none", ctx)
    assert "PRIMARY log evidence" not in content


def test_annotated_logs_still_rendered_in_loki_section():
    """When real service-scoped logs exist they still render in the Logs
    section unchanged (the fix only touches the empty-Loki + anomaly paths)."""
    ctx = GatheredContext(
        annotated_logs=["[ANOMALY] ERROR boom", "INFO ok"],
        loki_is_fallback=False,
        sources_available=1,
    )
    content = _user_content("", ctx)
    loki_section = content.split("### Logs", 1)[1].split("### Traces", 1)[0]
    assert "[ANOMALY] ERROR boom" in loki_section
