import os
import tempfile

import pytest

# Override state dir before importing
os.environ["DRAIN3_STATE_DIR"] = os.path.join(tempfile.gettempdir(), "test_drain3_state")

from app.drain_analyzer import DrainAnalyzer


@pytest.fixture()
def drain():
    """Create a fresh DrainAnalyzer with no persisted state for each test."""
    from drain3 import TemplateMiner
    from drain3.template_miner_config import TemplateMinerConfig
    analyzer = DrainAnalyzer.__new__(DrainAnalyzer)
    config = TemplateMinerConfig()
    analyzer._miner = TemplateMiner(config=config)
    analyzer._total_lines = 0
    analyzer._total_anomalies = 0
    analyzer._background_task = None
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
