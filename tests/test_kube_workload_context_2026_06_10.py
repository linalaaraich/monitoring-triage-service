"""2026-06-10 stress-test fix — Kube workload alerts gather k8s-state evidence.

Stress test induced a real KubeWorkloadDown / KubeWorkloadReplicasDeficit (ad
deployment scaled to an unschedulable nodeSelector). The pipeline's default
service-scoped Prometheus query (`{job=~".*ad.*"}`) matched no series, so the
LLM saw an empty context, hedged "cannot determine", and the shelved-in-disguise
gate suppressed the email — a genuinely-down critical workload never paged.

These tests pin the routing fix: Kube workload alerts query kube-state-metrics
(replica counts, pod phase, last-terminated reason) instead.
"""

from app.context import _is_kube_workload_alert, _kube_state_promql


class _Alert:
    def __init__(self, name):
        self.alertname = name


def test_kube_workload_alerts_are_detected():
    for name in (
        "KubeWorkloadDown",
        "KubeWorkloadReplicasDeficit",
        "KubeContainerRestarting",
        "PodCrashLooping",
        "PodHighMemoryUsage",
    ):
        assert _is_kube_workload_alert(_Alert(name)) is True, name


def test_non_kube_alerts_are_not_detected():
    for name in ("MediumCpuUsage", "HighCpuUsage", "TargetDown", "Drain3AnomalyDetected"):
        assert _is_kube_workload_alert(_Alert(name)) is False, name


def test_kube_state_promql_includes_deployment_replica_series():
    q = _kube_state_promql("ad", "otel-demo")
    assert 'kube_deployment_spec_replicas{deployment="ad"}' in q
    assert 'kube_deployment_status_replicas_available{deployment="ad"}' in q
    assert 'kube_deployment_status_replicas_unavailable{deployment="ad"}' in q


def test_kube_state_promql_scopes_pod_phase_to_namespace():
    q = _kube_state_promql("ad", "otel-demo")
    assert 'exported_namespace="otel-demo"' in q
    assert "kube_pod_status_phase" in q
    assert "kube_pod_container_status_last_terminated_reason" in q


def test_kube_state_promql_omits_namespace_clauses_when_unknown():
    """No namespace → still query the deployment counts, just skip pod-phase."""
    q = _kube_state_promql("ad", "unknown")
    assert "kube_deployment_spec_replicas" in q
    assert "kube_pod_status_phase" not in q
    q2 = _kube_state_promql("ad", "")
    assert "kube_pod_status_phase" not in q2
