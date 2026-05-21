"""Regression test for the dashboard search blob.

The dashboard filter (applyFilter() JS in main.py) matches user input against
the ``data-search`` attribute on each summary row. The blob must include
every field an operator might naturally paste in — most importantly the
decision UUID, the local-time timestamp string rendered in the table,
and the alert fingerprint. Lina filed this as a demo blocker on
2026-05-21 after searching the UUID of a specific PodHighMemoryUsage RCA
and getting an empty result.

The construction lives in :func:`app.main._build_dashboard_search_blob`
specifically so it can be tested without spinning up the HTTP app or
hitting an event loop.
"""

from app.main import _build_dashboard_search_blob, _to_local_time


SAMPLE_ROW = {
    "id": "0de9801c-fbc2-4280-9a92-5e07d1555da9",
    "timestamp": "2026-05-20T19:44:06.620389",
    "alert_name": "PodHighMemoryUsage",
    "alert_fingerprint": "05fe26bd47255550",
    "alert_source": "grafana",
    "affected_service": "spring-boot",
    "severity": "critical",
    "triage_decision": "investigate",
    "llm_verdict": "escalate",
    "rca_quality": "actionable",
    "action_taken": "emailed",
    "alert_instance": "10.42.0.17:8080",
    "alert_component": "api",
    "rca_report": "JDBC pool saturation on spring-boot — Hikari timeouts visible in logs.",
    "llm_reasoning": "Suggested checking the connection pool size.",
    "investigation_duration_ms": 1_453_786,
}


def _blob():
    local_ts = _to_local_time(SAMPLE_ROW["timestamp"])
    return _build_dashboard_search_blob(SAMPLE_ROW, local_ts)


def test_search_blob_contains_decision_id():
    """The original repro: pasting the UUID returned 0 hits."""
    assert "0de9801c-fbc2-4280-9a92-5e07d1555da9" in _blob()


def test_search_blob_contains_local_timestamp():
    """Operator copy-pastes the visible 'YYYY-MM-DD HH:MM:SS' cell from the
    table. The cell renders in Africa/Casablanca; the search blob must
    include the same string."""
    local_ts = _to_local_time(SAMPLE_ROW["timestamp"])
    assert local_ts in _blob()
    # 2026-05-20T19:44:06 UTC → 20:44:06 Casablanca (UTC+1, no DST in WAT)
    assert "2026-05-20 20:44:06" == local_ts


def test_search_blob_contains_raw_iso_timestamp():
    """Engineers paste raw ISO timestamps from logs / Grafana / API."""
    assert "2026-05-20t19:44:06" in _blob()


def test_search_blob_contains_alert_fingerprint():
    assert "05fe26bd47255550" in _blob()


def test_search_blob_contains_visible_columns():
    blob = _blob()
    # Every cell visible in the row's columns.
    assert "podhighmemoryusage" in blob  # alert_name
    assert "spring-boot" in blob          # affected_service
    assert "grafana" in blob              # alert_source
    assert "critical" in blob             # severity
    assert "escalate" in blob             # llm_verdict
    assert "emailed" in blob              # action_taken


def test_search_blob_contains_decision_state():
    blob = _blob()
    # State fields an operator might filter on but that aren't separate
    # columns in the table (triage_decision is visible only via the
    # verdict-pill helper; rca_quality is the quality-pill).
    assert "investigate" in blob          # triage_decision
    assert "actionable" in blob           # rca_quality


def test_search_blob_contains_alert_identity():
    blob = _blob()
    assert "10.42.0.17" in blob           # alert_instance (raw IP:port)
    assert ":8080" in blob                # port survives the join
    assert "api" in blob                  # alert_component


def test_search_blob_contains_rca_prose():
    blob = _blob()
    assert "jdbc pool" in blob            # rca_report fragment
    assert "hikari" in blob               # case-folded
    assert "connection pool" in blob      # llm_reasoning fragment


def test_search_blob_lowercased():
    """Filter compares lowercased query against the blob — blob must be
    lowercased too, otherwise mixed-case fingerprints / IDs would miss."""
    blob = _blob()
    # No uppercase letters anywhere.
    assert blob == blob.lower()


def test_search_blob_handles_missing_fields():
    """A minimal row with only required fields should produce a blob
    without raising — every .get() call has a default."""
    minimal = {"id": "abc", "timestamp": "2026-05-21T10:00:00"}
    blob = _build_dashboard_search_blob(minimal, _to_local_time(minimal["timestamp"]))
    assert "abc" in blob
    # No KeyError / AttributeError.
