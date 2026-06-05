import os
import tempfile

import pytest

# Override state dir before importing
os.environ["DRAIN3_STATE_DIR"] = os.path.join(tempfile.gettempdir(), "test_drain3_state")

from app.drain_analyzer import DrainAnalyzer


@pytest.fixture()
def drain():
    """Create a fresh DrainAnalyzer with no persisted state for each test.

    We bypass __init__ to skip the FilePersistence setup (no disk writes
    in unit tests). The instance attrs we wire up here mirror what real
    __init__ sets — keep this list in sync with app/drain_analyzer.py.
    Updated 2026-04-28 PM for US-5.1 Phase A (per-service miners).
    """
    import shutil
    import threading
    from drain3.template_miner_config import TemplateMinerConfig
    from app.config import settings as _settings
    # Wipe any state from previous tests so each starts fresh (per-service
    # state files persist across tests since they're on disk; reset
    # explicitly to make is_new_pattern assertions deterministic).
    state_dir = _settings.drain3_state_dir
    if os.path.exists(state_dir):
        shutil.rmtree(state_dir)
    os.makedirs(state_dir, exist_ok=True)
    analyzer = DrainAnalyzer.__new__(DrainAnalyzer)
    analyzer._config = TemplateMinerConfig()
    analyzer._miners = {}
    analyzer._lines_per_service = {}
    analyzer._anomalies_per_service = {}
    analyzer._background_task = None
    analyzer._lock = threading.Lock()
    analyzer._last_alert_ts = 0.0
    analyzer._tier_alert_ts = {}
    return analyzer


def test_analyze_new_pattern(drain):
    result = drain.analyze("ERROR 2026-04-05 Connection refused to database at 10.0.2.50:3306")
    assert result.is_new_pattern is True
    assert result.template != ""


def test_analyze_known_pattern(drain):
    line = "INFO 2026-04-05 Request completed successfully in 150ms"
    # Feed same pattern multiple times
    for _ in range(10):
        drain.analyze(line)
    result = drain.analyze(line)
    assert result.match_count >= 10


def test_annotate_lines(drain):
    # Seed with known patterns
    for _ in range(10):
        drain.analyze("INFO Heartbeat check passed")

    lines = [
        "INFO Heartbeat check passed",
        "CRITICAL NullPointerException in PaymentService.processOrder()",
    ]
    annotated, summary = drain.annotate_lines(lines)

    assert len(annotated) == 2
    assert annotated[0].startswith("[KNOWN]") or annotated[0].startswith("[ANOMALY]")
    assert annotated[1].startswith("[ANOMALY]")
    assert "Anomaly Summary:" in summary


def test_get_stats(drain):
    drain.analyze("INFO Server started on port 8080")
    drain.analyze("ERROR Connection timeout after 30s")

    stats = drain.get_stats()
    assert stats["total_clusters"] >= 1
    assert stats["total_lines_processed"] >= 2
    assert "recent_anomaly_rate" in stats
    assert isinstance(stats["top_new_patterns"], list)


def test_annotate_empty_lines(drain):
    annotated, summary = drain.annotate_lines([])
    assert annotated == []
    assert "0 of 0" in summary


# -----------------------------------------------------------------------------
# US-5.1 Phase A — per-service template isolation
# -----------------------------------------------------------------------------

def test_per_service_isolation(drain):
    """Same line analyzed against two different services produces two
    distinct miners — neither is aware of the other's clusters."""
    line = "ERROR JDBC pool exhausted at OrderService.findByDate"
    r1 = drain.analyze(line, service="spring-boot")
    r2 = drain.analyze(line, service="kong")
    assert r1.service == "spring-boot"
    assert r2.service == "kong"
    # Both should be new patterns within their own service tree
    assert r1.is_new_pattern is True
    assert r2.is_new_pattern is True
    # Counts are tracked per-service
    spring_stats = drain.get_stats(service="spring-boot")
    kong_stats = drain.get_stats(service="kong")
    assert spring_stats["total_lines_processed"] == 1
    assert kong_stats["total_lines_processed"] == 1


def test_default_service_is_unknown(drain):
    """Lines with no service argument route to the _unknown bucket."""
    drain.analyze("ERROR something")
    assert "_unknown" in drain.get_stats()["services"]


def test_aggregate_stats_combines_services(drain):
    drain.analyze("ERROR A", service="svc-a")
    drain.analyze("WARN B different template", service="svc-b")
    drain.analyze("DEBUG C yet another", service="svc-c")
    agg = drain.get_stats()
    assert agg["total_lines_processed"] == 3
    assert set(agg["services"]) == {"svc-a", "svc-b", "svc-c"}
    assert agg["total_clusters"] >= 3
    assert "top_new_patterns_per_service" in agg


def test_get_stats_for_unknown_service_returns_empty():
    """Asking for a service that has no miner returns a zeros dict
    rather than crashing."""
    import threading
    from drain3.template_miner_config import TemplateMinerConfig
    from app.drain_analyzer import DrainAnalyzer
    da = DrainAnalyzer.__new__(DrainAnalyzer)
    da._config = TemplateMinerConfig()
    da._miners = {}
    da._lines_per_service = {}
    da._anomalies_per_service = {}
    da._background_task = None
    da._lock = threading.Lock()
    da._last_alert_ts = 0.0
    stats = da.get_stats(service="never-seen")
    assert stats["total_clusters"] == 0
    assert stats["total_lines_processed"] == 0


def test_service_label_extraction():
    """The Loki-stream-label parser pulls service_name first, falls back
    through other recognised keys, returns _unknown if nothing matches."""
    from app.drain_analyzer import _service_from_stream_labels
    assert _service_from_stream_labels({"service_name": "spring-boot"}) == "spring-boot"
    assert _service_from_stream_labels({"k8s_app": "kong"}) == "kong"
    assert _service_from_stream_labels({}) == "_unknown"
    assert _service_from_stream_labels({"unrelated": "x"}) == "_unknown"
    # Sanitization
    assert _service_from_stream_labels({"service_name": "weird/name@v2"}) == "weird_name_v2"


# -----------------------------------------------------------------------------
# BE-B3 — source-exclusion of the observability/infra stack's OWN logs
# -----------------------------------------------------------------------------

def test_is_excluded_service_matches_infra():
    """The denylist matcher catches infra services defensively: exact names,
    case-insensitive, ai-/ai-mcp- container prefixes, *-exporter, separator
    normalisation, and namespace buckets."""
    from app.drain_analyzer import is_excluded_service
    # Exact denylist members
    for svc in ("grafana", "loki", "prometheus", "promtail", "otel-collector",
                "ai-otel-collector", "cadvisor", "kube-state-metrics",
                "mcp-prometheus", "mcp-loki", "mcp-jaeger", "mcp-drain3",
                "mcp-rca-history", "kube-system", "observability", "monitoring"):
        assert is_excluded_service(svc) is True, svc
    # Case-insensitive
    assert is_excluded_service("Grafana") is True
    assert is_excluded_service("LOKI") is True
    # ai-mcp-* / ai-* container-name forms
    assert is_excluded_service("ai-mcp-prometheus") is True
    assert is_excluded_service("ai-grafana") is True
    assert is_excluded_service("ai-otel-collector") is True
    # any *-exporter
    assert is_excluded_service("node-exporter") is True
    assert is_excluded_service("blackbox-exporter") is True
    # separator normalisation (_ vs -)
    assert is_excluded_service("otel_collector") is True
    assert is_excluded_service("kube_system") is True


def test_is_excluded_service_allows_real_apps():
    """Monitored application services are NOT excluded."""
    from app.drain_analyzer import is_excluded_service
    for svc in ("spring-boot", "employee-api", "kong", "frontend",
                "payment-service", "_unknown", ""):
        assert is_excluded_service(svc) is False, svc


def test_excluded_service_line_is_skipped_no_miner_no_anomaly(drain):
    """(a) A grafana/loki/prometheus/mcp-* line is skipped: no miner is
    created, the line is not counted, and it can never be an anomaly."""
    for svc in ("grafana", "loki", "prometheus", "ai-mcp-prometheus",
                "mcp-loki", "node-exporter"):
        # A line that WOULD be novel for a real service
        result = drain.analyze(
            "ERROR rotating token 9f3a-2b1c-novel-content connection churn",
            service=svc,
        )
        assert result.excluded is True
        assert result.is_new_pattern is False
        assert result.cluster_id is None
        # No miner created for the excluded service
        assert svc not in drain._miners
        # Not counted
        assert svc not in drain._lines_per_service
    # annotate_lines on an excluded service drops the whole batch
    annotated, summary = drain.annotate_lines(
        ["ERROR a", "ERROR b novel"], service="grafana"
    )
    assert annotated == []
    assert "excluded" in summary.lower()
    assert "grafana" not in drain._miners
    # Aggregate stats see nothing from infra
    assert drain.get_stats()["total_lines_processed"] == 0


def test_real_app_service_still_produces_novel_anomaly(drain):
    """(b) A real app service line is still ingested and CAN produce a
    novel-template anomaly."""
    result = drain.analyze(
        "CRITICAL NullPointerException in PaymentService.processOrder()",
        service="spring-boot",
    )
    assert result.excluded is False
    assert result.is_new_pattern is True
    assert "spring-boot" in drain._miners
    assert drain._lines_per_service["spring-boot"] == 1
    # And via the batch path
    anomalous, new_templates = drain._ingest_batch_sync_streams(
        [("employee-api", ["FATAL OutOfMemoryError in EmployeeController.list()"])]
    )
    assert len(anomalous) == 1
    assert len(new_templates) == 1
    assert "employee-api" in drain._miners


def test_mixed_batch_ingests_apps_skips_infra(drain):
    """A batch mixing infra + app streams ingests only the app stream."""
    anomalous, new_templates = drain._ingest_batch_sync_streams([
        ("grafana", ["INFO infra noise rotating-id-aaa", "INFO infra noise rotating-id-bbb"]),
        ("loki", ["WARN compactor churn xyz"]),
        ("spring-boot", ["ERROR brand new app failure template here"]),
    ])
    # Only the spring-boot line could be anomalous
    assert len(new_templates) == 1
    assert "grafana" not in drain._miners
    assert "loki" not in drain._miners
    assert "spring-boot" in drain._miners
