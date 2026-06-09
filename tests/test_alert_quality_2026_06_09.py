"""2026-06-09 alert-quality-collapse audit — regression tests for the four
root causes behind the "every alert gives nothing" report:

  RC-1  drain3 ingested observability-infra noise (Jaeger BadgerDB compaction,
        OTel collector self-noise, empty `{"body":"\\n"}` lines) → flood of
        "novel template" hedges. Fix: extend denylist + drop empty bodies.
  RC-3  the rca_quality classifier was called without `human_cause` and its
        hedge patterns omitted "evidence"/"additional investigation", so 62/108
        live hedges were mis-tagged `actionable`. Fix: scan human_cause + reuse
        the validator's authoritative banned-phrase set.
  RC-4  duplicate fires wrote a standalone "See prior RCA <id>" stub row. Fix:
        register a recurrence on the existing incident (no stub row).
"""
import os
import tempfile

import pytest
import pytest_asyncio

from app.drain_analyzer import is_empty_log_body, is_excluded_service
from app.rca_store import RCAStore, _classify_rca_quality
from app.models import RCARecord


# ── RC-1: infra-noise source exclusion ────────────────────────────────────
@pytest.mark.parametrize("svc", [
    "monitoring-vm", "jaeger", "ollama", "coredns", "host-syslog",
    "syslog", "gpu-stack", "drain3", "dcgm-exporter", "Monitoring-VM",
])
def test_rc1_infra_streams_excluded(svc):
    assert is_excluded_service(svc) is True


@pytest.mark.parametrize("svc", [
    "spring-boot", "employees-backend", "frontend", "cart", "payment",
    "product-catalog", "recommendation",
])
def test_rc1_monitored_apps_not_excluded(svc):
    assert is_excluded_service(svc) is False


@pytest.mark.parametrize("line", [
    "", "\n", "   ", "\t\n",
    '{"body":"\\n","attributes":{"log.file.name":"x.log"}}',
    '{"body":"","attributes":{}}',
    '{"body":"   ","attributes":{"k":1}}',
])
def test_rc1_empty_bodies_detected(line):
    assert is_empty_log_body(line) is True


@pytest.mark.parametrize("line", [
    "badger INFO LOG Compact 5->6",
    '{"body":"NullPointerException at line 42","attributes":{}}',
    "real error text",
])
def test_rc1_real_lines_not_empty(line):
    assert is_empty_log_body(line) is False


def test_rc1_analyze_skips_empty_body():
    from app.drain_analyzer import DrainAnalyzer
    da = DrainAnalyzer()
    r = da.analyze('{"body":"\\n","attributes":{}}', service="spring-boot")
    assert r.is_new_pattern is False
    assert r.excluded is True


def test_rc1_empty_bodies_not_counted_anomalous():
    # General-cycle backend finding: empty/excluded lines must count as NEITHER
    # a line NOR an anomaly — else match_count=0 < threshold marks them anomalous
    # and inflates anomaly_rate (opposite of RC-1's intent).
    from app.drain_analyzer import DrainAnalyzer
    da = DrainAnalyzer()
    empties = ['{"body":"\\n"}'] * 5
    batch = da._ingest_batch_structured([("frontend", "frontend", empties)])
    assert batch.total_lines == 0, "empty bodies must not count as lines"
    assert batch.total_anomalous == 0, "empty bodies must not count as anomalies"
    # And a real error line in the same batch IS counted + anomalous (new template).
    mixed = ['{"body":"\\n"}', '{"body":"NullPointerException at Foo.bar line 9"}']
    b2 = da._ingest_batch_structured([("frontend", "frontend", mixed)])
    assert b2.total_lines == 1
    assert b2.total_anomalous == 1


def test_rc1_annotate_lines_skips_empty():
    from app.drain_analyzer import DrainAnalyzer
    da = DrainAnalyzer()
    annotated, summary = da.annotate_lines(
        ['{"body":"\\n"}', "real log line here"], service="cart",
    )
    # Only the real line is annotated; the empty body is dropped, not [ANOMALY].
    assert len(annotated) == 1
    assert "of 1 lines anomalous" in summary


# ── RC-3: honest quality classification ───────────────────────────────────
def test_rc3_hedge_in_human_cause_is_data_starved():
    # The live failure: rca says "insufficient evidence", human_cause says
    # "Insufficient data to determine root cause". Classifier must catch it.
    rca = "The alert fired but there is insufficient evidence in the metrics."
    hc = "Insufficient data to determine root cause — need additional context."
    q = _classify_rca_quality(
        rca, "reasoning", '["do x"]', '["some evidence"]', human_cause=hc,
    )
    assert q == "data_starved"


def test_rc3_additional_investigation_hedge_caught():
    hc = "Additional investigation needed to determine if this is actionable."
    q = _classify_rca_quality(
        "rca text", None, '["a"]', '["e"]', human_cause=hc,
    )
    assert q == "data_starved"


def test_rc3_real_cause_stays_actionable():
    rca = "spring-boot JDBC pool exhausted; p95 latency jumped to 8.5s."
    hc = "spring-boot is queueing requests on its JDBC connection pool."
    q = _classify_rca_quality(
        rca, "pool saturation", '["raise pool size"]', '["p95=8.5s"]',
        human_cause=hc,
    )
    assert q == "actionable"


def test_rc3_classifier_signature_back_compat():
    # Old 4-arg callers (no human_cause) must still work.
    q = _classify_rca_quality("clean cause named", "r", '["a"]', '["e"]')
    assert q == "actionable"


# ── RC-4: recurrence on incident, no see-prior stub ───────────────────────
@pytest_asyncio.fixture
async def store():
    db_path = os.path.join(tempfile.gettempdir(), "test_alertquality_rc4.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    os.unlink(db_path)


@pytest.mark.asyncio
async def test_rc4_record_recurrence_bumps_incident(store):
    # First fire: a real investigate row creates the incident (fire_count=1).
    rec = RCARecord(
        alert_name="TargetDown", alert_fingerprint="fp-abc",
        affected_service="monitoring-vm", severity="warning",
        triage_decision="investigate", llm_verdict="escalate",
        action_taken="emailed",
    )
    await store.save_decision(rec)
    inc = await store.get_incident_by_fingerprint("fp-abc")
    assert inc["fire_count"] == 1

    # Duplicate fire: recurrence bumps fire_count WITHOUT a new feed row.
    before = len(await store.get_decisions(limit=100))
    out = await store.record_recurrence(
        fingerprint="fp-abc", at_iso="2026-06-09T02:00:00",
        severity="warning", alert_name="TargetDown",
        affected_service="monitoring-vm",
    )
    assert out["fire_count"] == 2
    after = len(await store.get_decisions(limit=100))
    assert after == before, "recurrence must NOT create a new rca_history row"


@pytest.mark.asyncio
async def test_rc4_record_recurrence_no_fingerprint_is_noop(store):
    out = await store.record_recurrence(
        fingerprint="", at_iso="2026-06-09T02:00:00",
    )
    assert out is None
