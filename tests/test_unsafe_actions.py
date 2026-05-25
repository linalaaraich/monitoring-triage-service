"""Tests for DA-2 — clamp-independent unsafe-action stripping.

The strip fires when `rca_quality=actionable` AND the RCA prose names
no specific cause-of-cause. Triggered by the 2026-05-21 §7c.4 audit
finding: `systemctl restart k3s-node.service` shipped for
CriticalCpuUsage even though the RCA only said "CPU usage is critically
high on the node" — high confidence + actionable quality + no named
cause-of-cause is the exact gap this gate closes.
"""
from app.unsafe_actions import (
    UNSAFE_ACTION_PATTERNS,
    has_named_cause,
    strip_unsafe_actions,
)


# --- has_named_cause -------------------------------------------------

def test_has_named_cause_picks_up_slow_query():
    assert has_named_cause("Latency spike caused by a slow query on the orders table.") is True


def test_has_named_cause_picks_up_gc_pause():
    assert has_named_cause("Heap pressure triggered repeated GC pauses, blocking request threads.") is True


def test_has_named_cause_picks_up_connection_pool_exhaustion():
    assert has_named_cause("Hikari connection pool exhaustion under load — pool saturated at max=20.") is True


def test_has_named_cause_picks_up_deploy_correlation():
    assert has_named_cause("Latency regression introduced by the 14:32 UTC deploy of v2.3.1.") is True


def test_has_named_cause_picks_up_causal_phrase():
    """Generic 'because', 'caused by', 'due to' are recognised — these
    are the linguistic shape of a cause-of-cause claim even when no
    specific subsystem is named."""
    assert has_named_cause("Memory pressure because a background worker leaked references.") is True
    assert has_named_cause("Errors due to upstream timeout from the payment API.") is True


def test_has_named_cause_rejects_symptom_restatement():
    """The audit-surfaced failure mode: RCA just restates the alert."""
    assert has_named_cause("CPU usage is critically high on the node.") is False
    assert has_named_cause("Memory utilisation has exceeded 95%.") is False
    assert has_named_cause("The service is experiencing elevated p95 latency.") is False


def test_has_named_cause_handles_empty_input():
    assert has_named_cause("") is False
    assert has_named_cause(None) is False  # type: ignore[arg-type]


# --- strip_unsafe_actions --------------------------------------------

CAUSE_FREE_RCA = "CPU usage is critically high on the node."
GROUNDED_RCA = "CPU saturation due to a runaway thread in the JVM (GC overhead)."


def test_strip_unsafe_actions_removes_systemctl_when_no_cause():
    """The exact §7c.4 audit case."""
    kept, stripped = strip_unsafe_actions(
        ["systemctl restart k3s-node.service"], CAUSE_FREE_RCA,
    )
    assert kept == []
    assert stripped == ["systemctl restart k3s-node.service"]


def test_strip_unsafe_actions_keeps_systemctl_when_cause_named():
    """Same destructive action survives if the RCA grounds it."""
    kept, stripped = strip_unsafe_actions(
        ["systemctl restart k3s-node.service"], GROUNDED_RCA,
    )
    assert kept == ["systemctl restart k3s-node.service"]
    assert stripped == []


def test_strip_unsafe_actions_removes_kubectl_rollout_when_no_cause():
    kept, stripped = strip_unsafe_actions(
        ["kubectl rollout restart deploy/spring-boot -n app"], CAUSE_FREE_RCA,
    )
    assert kept == []
    assert "kubectl rollout restart" in stripped[0]


def test_strip_unsafe_actions_removes_ssh_when_no_cause():
    kept, stripped = strip_unsafe_actions(
        ["ssh node-30 'top -bn1 | head'"], CAUSE_FREE_RCA,
    )
    assert kept == []
    assert stripped[0].startswith("ssh ")


def test_strip_unsafe_actions_removes_reboot_when_no_cause():
    kept, stripped = strip_unsafe_actions(
        ["reboot the worker node"], CAUSE_FREE_RCA,
    )
    assert kept == []
    assert stripped == ["reboot the worker node"]


def test_strip_unsafe_actions_removes_docker_restart_when_no_cause():
    kept, stripped = strip_unsafe_actions(
        ["docker restart kong-proxy"], CAUSE_FREE_RCA,
    )
    assert kept == []
    assert "docker restart" in stripped[0]


def test_strip_unsafe_actions_keeps_safe_actions_when_no_cause():
    """Read-only / informational actions survive even with no named cause."""
    kept, stripped = strip_unsafe_actions(
        [
            "Open Jaeger and inspect the slowest trace for service=`kong`",
            "Run PromQL `rate(http_requests_total[5m])` to check load",
            "Review the Grafana dashboard for the affected service",
        ],
        CAUSE_FREE_RCA,
    )
    assert len(kept) == 3
    assert stripped == []


def test_strip_unsafe_actions_partial_strip_mixed_list():
    """Mixed list: safe actions stay, unsafe ones leave."""
    kept, stripped = strip_unsafe_actions(
        [
            "Open Jaeger for service=spring-boot",
            "systemctl restart k3s-node.service",
            "Check PromQL for jvm_gc_pause_seconds",
            "kubectl rollout restart deploy/api",
        ],
        CAUSE_FREE_RCA,
    )
    assert len(kept) == 2
    assert len(stripped) == 2
    assert all("systemctl" in s or "kubectl" in s for s in stripped)


def test_strip_unsafe_actions_empty_input_is_noop():
    kept, stripped = strip_unsafe_actions([], CAUSE_FREE_RCA)
    assert kept == []
    assert stripped == []
    kept, stripped = strip_unsafe_actions(None, CAUSE_FREE_RCA)
    assert kept == []
    assert stripped == []


def test_unsafe_action_patterns_compile_correctly():
    """Sanity check: every pattern should compile and match its
    intended verb head. Guards against future copy-paste edits that
    break a regex."""
    samples = {
        "systemctl restart foo": True,
        "kubectl rollout restart deploy/foo": True,
        "ssh node-1 'uptime'": True,
        "reboot": True,
        "docker restart container": True,
        "service nginx restart": True,
        "Check the Grafana dashboard": False,
        "Open Jaeger and inspect": False,
        "Run PromQL query": False,
    }
    for action, should_match in samples.items():
        matched = any(p.search(action) for p in UNSAFE_ACTION_PATTERNS)
        assert matched is should_match, (
            f"Pattern mismatch for {action!r}: expected {should_match}, got {matched}"
        )
