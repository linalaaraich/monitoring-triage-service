"""Tests for the exemplar library + matcher.

Library lives in app/exemplars/library.yaml; loader in app/exemplars/__init__.py.
The library is used by the prompt builder (llm_client._build_prompt) to
inject a structural reference RCA before every LLM inference.
"""
from app import exemplars as ex


def test_oom_loop_matches_high_memory_on_spring_boot():
    m = ex.find_for_alert(
        alertname="HighMemoryUsage",
        service="spring-boot",
        deployment_type="k8s",
        signal="metric",
        severity="critical",
    )
    assert m is not None
    assert m["id"] == "oom-loop"


def test_kong_p95_attribution_archetype():
    m = ex.find_for_alert(
        alertname="HighKongP95Latency",
        service="kong",
        deployment_type="k8s",
        signal="metric",
        severity="warning",
    )
    assert m is not None
    assert m["id"] == "upstream-latency-attribution"


def test_target_down_routes_to_dismiss_for_docker_vm():
    """TargetDown on a docker-vm monitoring service is the synthetic-blip
    archetype (likely transient probe miss), not the crashloop archetype."""
    m = ex.find_for_alert(
        alertname="TargetDown",
        service="monitoring",
        deployment_type="docker-vm",
        signal="metric",
    )
    assert m is not None
    assert m["id"] == "synthetic-blip-dismiss"


def test_target_down_routes_to_crashloop_for_k8s_app():
    """Same alertname (TargetDown), different service+deployment — should
    pick the CrashLoopBackOff archetype because the deployment_type and
    service set match more strongly."""
    m = ex.find_for_alert(
        alertname="TargetDown",
        service="spring-boot",
        deployment_type="k8s",
        signal="metric",
    )
    assert m is not None
    assert m["id"] == "crashloop-bad-config"


def test_kube_pod_crashlooping_routes_to_crashloop():
    m = ex.find_for_alert(
        alertname="KubePodCrashLooping",
        service="spring-boot",
        deployment_type="k8s",
    )
    assert m is not None
    assert m["id"] == "crashloop-bad-config"


def test_drain3_anomaly_routes_to_drain3_archetype():
    m = ex.find_for_alert(
        alertname="Drain3AnomalyDetected",
        service="spring-boot",
        signal="log",
    )
    assert m is not None
    assert m["id"] == "drain3-novelty-named-from-line"  # renamed 2026-06-11 (de-claimed)


def test_tls_expiry_archetype():
    m = ex.find_for_alert(
        alertname="TLSCertExpiringSoon",
        service="grafana",
        signal="metric",
        severity="warning",
    )
    assert m is not None
    assert m["id"] == "tls-cert-expiry-pre-failure"


def test_unknown_alert_falls_back_to_default():
    m = ex.find_for_alert(
        alertname="SomeAlertNeverSeen",
        service="foo",
        deployment_type="k8s",
    )
    assert m is not None
    # Should be the generic-sre-shape default, not closed-loop-feedback-override
    # (the latter is gated on a sentinel regex so it never auto-matches).
    assert m["id"] == "generic-sre-shape"


def test_closed_loop_exemplar_does_not_auto_match():
    """The closed-loop-feedback-override archetype only fires when the
    pipeline detects a recent operator override on a similar alert. It
    must NOT auto-match by alertname for arbitrary alerts."""
    m = ex.find_for_alert(alertname="HighCpuUsage", service="kong")
    assert m is None or m["id"] != "closed-loop-feedback-override"

    # But explicit fetch by id should still work
    m = ex.get_by_id("closed-loop-feedback-override")
    assert m is not None
    assert m["id"] == "closed-loop-feedback-override"


def test_format_for_prompt_includes_required_sections():
    m = ex.find_for_alert(
        alertname="HighMemoryUsage",
        service="spring-boot",
        deployment_type="k8s",
        signal="metric",
        severity="critical",
    )
    rendered = ex.format_for_prompt(m)
    assert "## Reference exemplar" in rendered
    assert "**Archetype:**" in rendered
    assert "**RCA shape" in rendered
    assert "**Evidence shape" in rendered
    assert "**Actions shape" in rendered
    assert "docs/happy-path-scenarios.md" in rendered  # source pointer
    assert "oom-loop" in rendered  # the id


def test_format_for_prompt_handles_dismiss_with_empty_actions():
    """DISMISS archetypes (synthetic-blip, adaptive-threshold) have empty
    actions_shape. The renderer should produce a section explaining this,
    not silently drop it."""
    m = ex.find_for_alert(
        alertname="TargetDown",
        service="monitoring",
        deployment_type="docker-vm",
        signal="metric",
    )
    rendered = ex.format_for_prompt(m)
    assert m["id"] == "synthetic-blip-dismiss"
    assert "**Actions shape:**" in rendered
    assert "DISMISS does not emit remediations" in rendered


def test_list_all_returns_all_exemplars():
    items = ex.list_all()
    assert len(items) == 15  # +oom-crashloop-restart (2026-06-10)
    ids = {item["id"] for item in items}
    assert "oom-crashloop-restart" in ids
    assert "oom-loop" in ids
    assert "upstream-latency-attribution" in ids
    assert "tls-cert-expiry-pre-failure" in ids
    assert "network-firewall-attribution" in ids
    assert "crashloop-bad-config" in ids


def test_get_by_id_returns_exemplar():
    m = ex.get_by_id("network-firewall-attribution")
    assert m is not None
    assert m["archetype"].startswith("Connectivity break")
    # Internal helper keys should be stripped
    assert "_alert_re" not in m
    assert "_services" not in m


def test_get_by_id_unknown_returns_none():
    assert ex.get_by_id("does-not-exist") is None


def test_format_for_prompt_none_returns_empty():
    assert ex.format_for_prompt(None) == ""
