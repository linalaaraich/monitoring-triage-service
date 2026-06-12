"""Detail-page CIRES_LINKS contextual deep-link routing.

Validates that `_build_cires_links` picks the right provisioned dashboard for
each alert family and that the Loki / Jaeger URLs carry a service-name
filter so the operator lands on a prefiltered view (not the bare root).

Dashboard UIDs are the ones provisioned by
monitoring-project/roles/grafana/files/dashboards/*.json:

    unified-overview          (Unified Observability Overview)
    tracing-overview          (Distributed Tracing Overview)
    otel-collector-health     (OTel Collector Health)
"""
import json
import urllib.parse as _u

from app.main import _build_cires_links


def _decode_loki_left(url: str) -> dict:
    """Pull the `left=` JSON payload back out of a Loki Explore URL."""
    parsed = _u.urlparse(url)
    qs = _u.parse_qs(parsed.query)
    return json.loads(qs["left"][0])


# -------------------------------------------------------------------------
# Grafana — dashboard-routing table
# -------------------------------------------------------------------------

def test_cpu_alert_routes_to_unified_overview():
    g = _build_cires_links({
        "alertName": "CriticalCpuUsage",
        "component": "node-exporter",
    })["grafana"]
    assert "/d/unified-overview/" in g
    assert "var-service=node-exporter" in g


def test_memory_alert_routes_to_unified_overview():
    g = _build_cires_links({
        "alertName": "PodHighMemoryUsage",
        "component": "spring-boot",
    })["grafana"]
    assert "/d/unified-overview/" in g


def test_disk_alert_routes_to_unified_overview():
    g = _build_cires_links({
        "alertName": "DiskSpaceLow",
        "component": "node-exporter",
    })["grafana"]
    assert "/d/unified-overview/" in g


def test_p95_latency_routes_to_tracing_overview():
    g = _build_cires_links({
        "alertName": "HighP95Latency",
        "component": "spring-boot",
    })["grafana"]
    assert "/d/tracing-overview/" in g
    assert "var-service=employees-backend" in g  # 2026-06-12: tracing dashboard uses canonical trace name


def test_kong_latency_routes_to_tracing_overview():
    g = _build_cires_links({
        "alertName": "HighKongP95Latency",
        "component": "kong",
    })["grafana"]
    assert "/d/tracing-overview/" in g


def test_drain3_routes_to_otel_collector_health():
    g = _build_cires_links({
        "alertName": "Drain3AnomalyDetected",
        "component": "otel-collector",
    })["grafana"]
    assert "/d/otel-collector-health/" in g


def test_unknown_alert_falls_back_to_grafana_root():
    """No dashboard guess beats the Grafana root for things we cannot route."""
    g = _build_cires_links({
        "alertName": "SomeFutureAlertName",
        "component": "",
    })["grafana"]
    # Bare root — no /d/ path component.
    assert "/d/" not in g


# -------------------------------------------------------------------------
# Loki — Explore deep link must carry the service-name filter
# -------------------------------------------------------------------------

def test_loki_explore_url_carries_service_filter():
    url = _build_cires_links({
        "alertName": "Drain3AnomalyDetected",
        "component": "spring-boot",
    })["loki"]
    assert "/explore?" in url
    left = _decode_loki_left(url)
    assert left["datasource"] == "loki"
    assert left["queries"][0]["expr"] == '{service_name="spring-boot"}'


def test_loki_explore_range_is_one_hour():
    url = _build_cires_links({
        "alertName": "Drain3AnomalyDetected",
        "component": "kong",
    })["loki"]
    left = _decode_loki_left(url)
    assert left["range"] == {"from": "now-1h", "to": "now"}


def test_loki_link_is_hosted_on_grafana_origin():
    """Loki has no web UI - /explore is a Grafana page. The Open Loki
    button must point at the Grafana origin (with the loki datasource
    preselected), NOT at the Loki HTTP API port 3100 where /explore
    would 404."""
    from app.config import settings
    url = _build_cires_links({
        "alertName": "Drain3AnomalyDetected",
        "component": "spring-boot",
    })["loki"]
    grafana_origin = settings.grafana_url.rstrip("/")
    assert url.startswith(grafana_origin + "/explore"), (
        f"Loki link must live on the Grafana origin (got {url!r})"
    )


# -------------------------------------------------------------------------
# Jaeger — /search deep link must carry the service param
# -------------------------------------------------------------------------

def test_jaeger_search_url_carries_service_and_lookback():
    url = _build_cires_links({
        "alertName": "HighP95Latency",
        "component": "spring-boot",
    })["jaeger"]
    parsed = _u.urlparse(url)
    qs = _u.parse_qs(parsed.query)
    assert parsed.path == "/search"
    assert qs.get("service") == ["employees-backend"]  # 2026-06-12: Jaeger indexes spring-boot app as employees-backend
    assert qs.get("lookback") == ["1h"]


def test_jaeger_falls_back_to_root_when_no_service():
    url = _build_cires_links({"alertName": "TargetDown", "component": ""})["jaeger"]
    # When service is empty there is nothing to prefilter on; the root is OK.
    assert "/search?" not in url
