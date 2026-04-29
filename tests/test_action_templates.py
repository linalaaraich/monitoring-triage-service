"""US-3.10 — Defensive tests for the suggested_actions.yaml template lookup.

Background: the 2026-04-29 HighKongP95Latency 0b215ef3 incident emailed
`kubectl set resources --limits=memory=2Gi --requests=memory=1Gi` for a
Kong p95 latency alert. Initial diagnosis suspected a wrong-archetype
template lookup — i.e., HighKongP95Latency falling through to the
HighMemoryUsage OOMKill template (suggested_actions.yaml lines 67-68).

Investigation 2026-04-29 confirmed the template lookup is FINE:
  - HighKongP95Latency rule at suggested_actions.yaml line 133 returns
    Kong-targeting actions (kong-kong deployment, scale, KONG_PROXY_*
    env tweaks).
  - HighMemoryUsage OOMKill template at line 64-77 only matches
    ^(High|Medium|Critical)MemoryUsage$ — HighKongP95Latency does NOT
    match this regex.
  - The bad actions in 0b215ef3 came from the LLM directly, not from
    template fill (decision.suggested_actions was non-empty, so
    fill_template never fired).

These tests are defensive: they pin the template lookup so future YAML
edits can't silently introduce the wrong-archetype keying that the
plan agent initially suspected. The actual Tier 0 fix for LLM-side bad
actions lives in US-3.9 (the F-4 clamp strips them).
"""
from __future__ import annotations

from app.action_templates import fill_template


def test_high_kong_p95_latency_returns_kong_targeted_actions():
    """Defensive: HighKongP95Latency must NOT match the OOMKill template."""
    actions = fill_template(
        alertname="HighKongP95Latency",
        service="kong",
        deployment_type="k8s",
        labels={"instance": "10.0.1.194:8001"},
    )
    assert actions, "HighKongP95Latency should match a template rule"
    joined = " ".join(actions)

    # Must target Kong, not spring-boot.
    assert "kong-kong" in joined, (
        f"Expected kong-kong in HighKongP95Latency actions, got: {actions}"
    )
    # Must NOT emit unconditional memory-tuning OOMKill remediation.
    # (The text 'memory=2Gi --requests=memory=1Gi' is the exact
    # signature of the bad 0b215ef3 action.)
    assert "memory=2Gi --requests=memory=1Gi" not in joined, (
        f"OOMKill template signature leaked into Kong actions: {actions}"
    )


def test_high_memory_usage_returns_oomkill_template():
    """Confirm the OOMKill template (lines 67-68) fires for its actual alertname."""
    actions = fill_template(
        alertname="HighMemoryUsage",
        service="spring-boot",
        deployment_type="k8s",
        labels={"instance": "10.0.1.50:8080"},
    )
    joined = " ".join(actions)
    # The exact signature from the YAML
    assert "memory=2Gi" in joined
    assert "rollout restart deploy/spring-boot" in joined


def test_high_p95_latency_first_action_is_not_unconditional_memory_bump():
    """HighP95Latency template line 129 starts with rollout restart (connection
    pool play), not memory bump. The memory bump (line 131) is the third
    action and conditioned on 'If Java GC pauses are visible in traces'."""
    actions = fill_template(
        alertname="HighP95Latency",
        service="spring-boot",
        deployment_type="k8s",
        labels={"instance": "10.0.1.50:8080"},
    )
    assert actions, "HighP95Latency should match a template rule"
    # First action should be rollout restart, not memory tuning.
    assert "rollout restart deploy/spring-boot" in actions[0], (
        f"First HighP95Latency action should be rollout restart "
        f"(connection-pool play), got: {actions[0]!r}"
    )
    # Memory bump action, if present, must be conditional ('If ... GC pauses')
    memory_actions = [a for a in actions if "memory=2Gi" in a]
    for ma in memory_actions:
        assert ma.startswith("If "), (
            f"Memory bump action should be conditional, got unconditional: {ma!r}"
        )


def test_oomkill_template_does_not_match_kong_or_latency_alertnames():
    """Regex-level guard: the ^(High|Medium|Critical)MemoryUsage$ rule must
    not accidentally match latency alertnames. This test pins the regex
    boundary so future YAML edits widening the pattern get caught."""
    for bad_match_alertname in (
        "HighKongP95Latency",
        "HighP95Latency",
        "HighMemoryUsageButNotReally",   # leading prefix only
        "MyHighMemoryUsage",              # not anchored at start
    ):
        # Force the alert to a deployment_type the OOMKill rule branches on,
        # so if the regex DID accidentally match we'd see kubectl emissions.
        actions = fill_template(
            alertname=bad_match_alertname,
            service="spring-boot",
            deployment_type="k8s",
            labels={"instance": "10.0.1.50:8080"},
        )
        joined = " ".join(actions)
        # The OOMKill signature is unique to lines 67-68.
        assert "memory=2Gi --requests=memory=1Gi" not in joined, (
            f"OOMKill template wrongly matched alertname={bad_match_alertname!r}: "
            f"{actions}"
        )


def test_high_kong_p95_does_not_target_spring_boot_in_template():
    """The bad 0b215ef3 action was 'kubectl set resources deploy/spring-boot
    -n app --limits=memory=2Gi --requests=memory=1Gi'. Confirm the template
    lookup never produces this exact string for HighKongP95Latency, even
    when service label is misleadingly set to spring-boot (defense in depth)."""
    for service_label in ("kong", "spring-boot", "kong-gateway", "unknown"):
        actions = fill_template(
            alertname="HighKongP95Latency",
            service=service_label,
            deployment_type="k8s",
            labels={"instance": "10.0.1.194:8001"},
        )
        joined = " ".join(actions)
        # The exact bad string from the 0b215ef3 incident
        bad_signature = "deploy/spring-boot -n app --limits=memory=2Gi --requests=memory=1Gi"
        assert bad_signature not in joined, (
            f"Template returned the 0b215ef3 bad action for service={service_label!r}: "
            f"{actions}"
        )
