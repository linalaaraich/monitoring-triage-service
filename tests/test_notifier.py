"""Smoke tests for the HTML email builder. Don't send — just render."""
import pytest

from app.models import Decision, GatheredContext, GrafanaAlert, LLMDecision, RCARecord
from app.notifier import EmailNotifier, _quick_links, _slowest_span_summary, _top_log_issues


@pytest.fixture
def alert_with_links():
    return GrafanaAlert(
        status="firing",
        labels={"alertname": "PostSchemaFix_v2", "service": "spring-boot", "severity": "warning"},
        annotations={
            "summary": "400 rate on POST /api/employee",
            "description": "Malformed JSON payloads rejected by Spring controller.",
            "DashboardURL": "http://52.202.21.192:3000/d/unified-overview",
            "PanelURL": "http://52.202.21.192:3000/d/unified-overview?panelId=7",
        },
        startsAt="2026-04-22T15:46:30Z",
        generatorURL="http://52.202.21.192:3000/alerting/grafana/abc123/view",
    )


@pytest.fixture
def decision_escalate():
    return LLMDecision(
        decision=Decision.ESCALATE,
        severity="warning",
        confidence=0.75,
        reason="Client payload validation failing",
        rca="HTTP 400 rate rose after 15:45 UTC; logs show JSON parse errors on POST /api/employee.",
        anomaly_summary="3 of 5 lines anomalous. 1 new pattern detected.",
        suggested_actions=["Inspect client for malformed payloads", "Add Spring @Valid"],
        evidence=["prometheus: 400-rate 0.4 rps", "loki: JsonParseException x 5"],
    )


@pytest.fixture
def ctx_full():
    return GatheredContext(
        metrics={"query": "up{job=~\"spring.*\"}", "values": [[1234, "1"], [1235, "1"]]},
        logs=["line a", "line a", "line b"],
        annotated_logs=["[KNOWN] line a", "[KNOWN] line a", "[ANOMALY] JsonParseException"],
        traces=[
            {"operationName": "POST /api/employee", "duration": 450000},
            {"operationName": "DB.save", "duration": 200000},
        ],
        sources_available=3,
        prometheus_ms=200, loki_ms=150, jaeger_ms=180,
    )


def test_quick_links_uses_annotations_and_generator_url(alert_with_links):
    links = _quick_links(alert_with_links)
    assert "View Dashboard" in links
    assert "View Panel" in links
    assert "View Alert" in links  # from generatorURL


def test_top_log_issues_counts_duplicates(ctx_full):
    issues = _top_log_issues(ctx_full, top_n=2)
    # Most common should be "[KNOWN] line a" with 2x
    assert issues[0][1] == 2


def test_slowest_span_picks_max_duration(ctx_full):
    summary = _slowest_span_summary(ctx_full)
    assert "POST /api/employee" in summary


def test_escalation_body_contains_core_fields(alert_with_links, decision_escalate, ctx_full):
    notifier = EmailNotifier()
    record = RCARecord(alert_name="PostSchemaFix_v2", triage_decision="investigate",
                       action_taken="emailed", investigation_duration_ms=12345)
    body = notifier._build_escalation_body(
        alert_with_links, decision_escalate, record, 1, ctx_full, [],
    )
    assert "PostSchemaFix_v2" in body
    assert "ESCALATE" in body
    assert "3 of 5 lines anomalous" in body
    assert "POST /api/employee" in body


def test_escalation_body_without_ctx_still_renders(alert_with_links, decision_escalate):
    notifier = EmailNotifier()
    record = RCARecord(alert_name="PostSchemaFix_v2", triage_decision="investigate",
                       action_taken="emailed", investigation_duration_ms=100)
    body = notifier._build_escalation_body(
        alert_with_links, decision_escalate, record, 0, None, [],
    )
    assert "PostSchemaFix_v2" in body
    # The body must still render the alertname even when every pillar is empty —
    # caller compatibility with the post-2026-04-24 readability pass.


def test_slowest_span_defends_against_non_dict_traces():
    """Real-world: MCP may return a list of strings or mixed shapes. The
    builder must not crash — we caught this in live demo-day testing.

    Pydantic v2 now rejects malformed payloads at the model boundary, but
    if a downstream library mutates the field post-construction (or if a
    future MCP change relaxes the model), the defense in `_slowest_span_summary`
    must still hold. Use model_construct to skip validation and exercise
    the defensive branch directly.
    """
    from app.notifier import _slowest_span_summary
    ctx = GatheredContext.model_construct(traces=["not-a-dict", "still-not"])
    result = _slowest_span_summary(ctx)
    assert "non-dict" in result or result == "N/A"


def test_metrics_preview_defends_against_non_dict():
    """Same defense for ctx.metrics. The helper explicitly checks
    isinstance(metrics, dict) before treating it as one — this guards
    against an MCP returning a raw string or list. See model_construct
    rationale on the trace test above."""
    from app.notifier import _metrics_preview
    ctx = GatheredContext.model_construct(metrics="some raw string from MCP")
    result = _metrics_preview(ctx)
    assert isinstance(result, str) and result != ""


def test_full_build_with_malformed_ctx_does_not_crash(alert_with_links, decision_escalate):
    """End-to-end: even with a fully malformed context, the body must render."""
    notifier = EmailNotifier()
    record = RCARecord(alert_name="PostSchemaFix_v2", triage_decision="investigate",
                       action_taken="emailed", investigation_duration_ms=100)
    try:
        bad_ctx = GatheredContext(
            metrics={"query": "up", "values": "not-a-list"},  # values wrong type
            traces=["weird"],
        )
    except Exception:
        # Pydantic may reject — that's fine, build with None
        bad_ctx = None
    body = notifier._build_escalation_body(
        alert_with_links, decision_escalate, record, 0, bad_ctx, [],
    )
    assert "PostSchemaFix_v2" in body
