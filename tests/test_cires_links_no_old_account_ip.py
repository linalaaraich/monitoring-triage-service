"""Regression — detail-page CIRES_LINKS must NEVER point at the old AWS account.

Lina 2026-06-04: "Grafana and other extra links do not work, fix that have
them point to the exact needed page." Root cause was app/config.py defaults
hardcoded `52.202.21.192` (decommissioned old-account monitoring VM) and the
triage-service compose env only set LOKI_API_URL (Drain3 ingestion), NOT
LOKI_URL (the UI-facing field).

These tests are a guard rail so the IP can never sneak back in via either
the config defaults or the link builder. If a future deploy needs to talk to
a different host, the env var override (GRAFANA_URL / LOKI_URL / JAEGER_URL)
is the only correct path — the old-account IP literal is forever banned.
"""
from app.config import settings
from app.main import (
    _build_cires_links,
    _grafana_deep_link_for_alert,
    _jaeger_deep_link_for_alert,
    _loki_deep_link_for_alert,
)

OLD_ACCOUNT_IP = "52.202.21.192"


def _all_url_fields_clean(values) -> None:
    for v in values:
        assert OLD_ACCOUNT_IP not in (v or ""), (
            f"old-account IP {OLD_ACCOUNT_IP} leaked into URL: {v}"
        )


def test_config_defaults_do_not_contain_old_account_ip():
    """The Settings defaults must not embed the dead IP."""
    _all_url_fields_clean([
        settings.grafana_url,
        settings.loki_url,
        settings.jaeger_url,
    ])


def test_build_cires_links_clean_for_cpu_alert():
    links = _build_cires_links({
        "alertName": "CriticalCpuUsage",
        "component": "node-exporter",
    })
    _all_url_fields_clean(links.values())


def test_build_cires_links_clean_for_latency_alert():
    links = _build_cires_links({
        "alertName": "HighP95Latency",
        "component": "spring-boot",
    })
    _all_url_fields_clean(links.values())


def test_build_cires_links_clean_for_drain3_alert():
    links = _build_cires_links({
        "alertName": "Drain3AnomalyDetected",
        "component": "otel-collector",
    })
    _all_url_fields_clean(links.values())


def test_build_cires_links_clean_when_service_missing():
    """Even with no service we must not emit the old IP."""
    links = _build_cires_links({"alertName": "TargetDown", "component": ""})
    _all_url_fields_clean(links.values())


def test_individual_link_helpers_clean():
    _all_url_fields_clean([
        _grafana_deep_link_for_alert("CriticalCpuUsage", "node-exporter"),
        _loki_deep_link_for_alert("spring-boot"),
        _jaeger_deep_link_for_alert("spring-boot"),
    ])
