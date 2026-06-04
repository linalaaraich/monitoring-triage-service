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
    """A causal connective grounds the cause ONLY when it introduces a
    concrete subject ('because a background worker ...', 'due to upstream
    timeout ...'). The connective alone is not enough (see the bare-connective
    tests below)."""
    assert has_named_cause("Memory pressure because a background worker leaked references.") is True
    assert has_named_cause("Errors due to upstream timeout from the payment API.") is True


# --- DA-2 bare-connective false-allow fix (2026-06-04) ---------------

def test_has_named_cause_rejects_bare_because():
    """A bare 'because of load' / 'due to something' names no concrete
    subject — it must NOT count as a named cause (false-allow fix)."""
    assert has_named_cause("CPU is high, possibly because of load.") is False
    assert has_named_cause("Elevated latency, could be due to something.") is False
    assert has_named_cause("May be caused by high traffic.") is False
    assert has_named_cause("Errors due to issues on the node.") is False


def test_has_named_cause_rejects_hedged_connective_with_subject():
    """Even with a concrete-looking subject, a hedge prefix ('possibly due
    to X') is a hypothesis, not a named root cause."""
    assert has_named_cause("Latency, possibly due to a slow database somewhere.") is False
    assert has_named_cause("Could be because the cache is cold.") is False


def test_has_named_cause_keeps_grounded_connective():
    """A non-hedged connective + concrete subject still grounds."""
    assert has_named_cause("Failure because the connection pool was exhausted.") is True
    assert has_named_cause("Outage caused by a kernel panic on the host.") is True


def test_strip_unsafe_actions_clamps_on_bare_because():
    """The core fix: a bare-'because' RCA with no concrete subject must NOT
    shield a destructive action from the DA-2 clamp."""
    bare_rca = "CPU usage is critically high, possibly because of load."
    kept, stripped = strip_unsafe_actions(
        ["systemctl restart k3s-node.service"], bare_rca,
    )
    assert kept == []
    assert stripped == ["systemctl restart k3s-node.service"]


def test_strip_unsafe_actions_keeps_on_grounded_because():
    """Contrast: a connective that DOES name a concrete subject grounds the
    cause and the action survives."""
    grounded = "High CPU because the JDBC connection pool was exhausted."
    kept, stripped = strip_unsafe_actions(
        ["systemctl restart k3s-node.service"], grounded,
    )
    assert kept == ["systemctl restart k3s-node.service"]
    assert stripped == []


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
