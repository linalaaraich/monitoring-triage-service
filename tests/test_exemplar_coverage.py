"""Finding #1b (2026-06-12) — exemplar coverage guard against rule drift.

Every LIVE Grafana alert rule (and the synthetic alertnames the pipeline
emits) must EITHER be covered by at least one non-default exemplar archetype,
OR be listed in the INTENTIONAL_DEFAULT allowlist below. The test FAILS if a
new rule is added in monitoring-project without an archetype or an explicit
waiver — so "this rule falls to the generic default" becomes a conscious
choice, recorded here, not silent drift.

"Covered" = at least one non-default exemplar's alertname regex matches the
rule title. We test regex ELIGIBILITY (not full scored selection) because the
score also depends on the runtime service/signal of a specific fire, whereas
the question this guard answers — "does the library even know about this rule
shape?" — is a property of the alertname alone. The closed-loop sentinel
(^__pipeline_explicit__$) is excluded: it is fetched by id, never auto-matched.

Source of rule titles: the rendered alertrules.yml.j2 in monitoring-project
(grep the `title:` lines). When that repo isn't checked out (e.g. an isolated
CI runner), we fall back to a frozen snapshot of the titles so the guard still
runs — and a separate test asserts the snapshot matches the live file when the
live file IS present, catching snapshot staleness.
"""
import re
from pathlib import Path

import pytest

from app import exemplars as ex

# ---------------------------------------------------------------------------
# Where the live rules live, and a frozen snapshot fallback.
# ---------------------------------------------------------------------------
_ALERTRULES = Path("/root/monitoring-project/roles/grafana/templates/alertrules.yml.j2")

# Frozen snapshot of the live rule titles (2026-06-12). Used when the
# monitoring-project repo is not available in the test environment.
_SNAPSHOT_RULE_TITLES = [
    "HighP95Latency", "HighKongP95Latency", "HighDemoFrontendP95Latency",
    "OTelCollectorHighSpanDropRate", "OTelCollectorDown",
    "HighDiskUsage", "CriticalDiskUsage",
    "HighCpuUsage", "CriticalCpuUsage",
    "HighMemoryUsage", "CriticalMemoryUsage",
    "MediumCpuUsage", "MediumMemoryUsage",
    "TargetDown", "DiskFillingUp",
    "KubeWorkloadDown", "KubeWorkloadReplicasDeficit",
    "PodCrashLooping", "PodHighMemoryUsage", "PodHighCpuUsage",
    "LokiHighDiskUsage", "LokiCriticalDiskUsage",
    "LokiIngestionRateLow", "LokiDiskFillingUp",
]

# Synthetic alertnames the pipeline itself emits — NOT Grafana rules, so they
# never appear in alertrules.yml.j2, but they DO flow through find_for_alert.
_SYNTHETIC_ALERTNAMES = [
    "Drain3AnomalyDetected",   # drain3 worker self-fires via /webhook/drain3
    "PodCrashLooping",         # also a Grafana rule; listed for completeness
]

# Rules that intentionally fall to the generic-sre-shape default. A genuinely
# generic rule is a CONSCIOUS choice recorded here, not silent drift. Adding a
# rule to this set must come with a rationale comment.
INTENTIONAL_DEFAULT = {
    # 2026-06-12: the High/Medium CPU family was briefly waived here when the
    # stale adaptive-threshold-noop archetype was deleted — then immediately
    # given a proper `warning-resource-saturation` archetype (finding #1: don't
    # leave common rules on the generic default). No standing waivers: every
    # live rule now maps to a real archetype. Add an entry here ONLY with a
    # written rationale if a genuinely-generic rule appears.
}

_TITLE_RE = re.compile(r"^\s*title:\s*(\S+)\s*$")


def _live_rule_titles() -> list[str] | None:
    # The live alertrules template lives in a SIBLING repo (monitoring-project)
    # that isn't checked out in CI (which only has the triage repo) — and may
    # be present-but-unreadable. Any access problem → fall back to the snapshot
    # below, so the coverage test runs everywhere; it reads the live file only
    # when it's actually available (local dev).
    try:
        if not _ALERTRULES.exists():
            return None
        text = _ALERTRULES.read_text()
    except (OSError, PermissionError):
        return None
    titles = []
    for line in text.splitlines():
        m = _TITLE_RE.match(line)
        if m:
            titles.append(m.group(1))
    return titles or None


def _rule_titles() -> list[str]:
    return _live_rule_titles() or list(_SNAPSHOT_RULE_TITLES)


def _non_default_exemplar_matches(alertname: str) -> list[str]:
    """Return the ids of non-default exemplars whose alertname regex matches
    `alertname`. The closed-loop sentinel is excluded (fetched by id only)."""
    lib = ex._load_library()
    hits = []
    for e in lib.get("exemplars") or []:
        if e.get("id") == "closed-loop-feedback-override":
            continue
        rx = e.get("_alert_re")
        if rx is not None and rx.search(alertname):
            hits.append(e["id"])
    return hits


def test_every_live_rule_has_archetype_or_explicit_waiver():
    rules = sorted(set(_rule_titles()) | set(_SYNTHETIC_ALERTNAMES))
    uncovered = []
    for rule in rules:
        if _non_default_exemplar_matches(rule):
            continue
        if rule in INTENTIONAL_DEFAULT:
            continue
        uncovered.append(rule)
    assert not uncovered, (
        "These alert rules match NO archetype and are not in "
        "INTENTIONAL_DEFAULT — add an exemplar or an explicit waiver "
        f"(with rationale): {uncovered}"
    )


def test_intentional_default_entries_really_fall_to_default():
    """A waiver is only meaningful if the rule genuinely has no archetype.
    If someone later ADDS an archetype covering a waived rule, the waiver is
    stale and should be removed — flag it."""
    stale = [
        rule for rule in INTENTIONAL_DEFAULT
        if _non_default_exemplar_matches(rule)
    ]
    assert not stale, (
        "These rules are in INTENTIONAL_DEFAULT but NOW match an archetype — "
        f"remove the stale waiver: {stale}"
    )


def test_new_flagship_archetypes_cover_their_rules():
    """Finding #1a regression lock: the workload-down family and the
    demo-frontend latency rule must select their NEW archetype."""
    assert "workload-replica-deficit" in _non_default_exemplar_matches("KubeWorkloadDown")
    assert "workload-replica-deficit" in _non_default_exemplar_matches("KubeWorkloadReplicasDeficit")
    assert "demo-frontend-downstream-latency" in _non_default_exemplar_matches("HighDemoFrontendP95Latency")


@pytest.mark.skipif(not _ALERTRULES.exists(), reason="monitoring-project not checked out")
def test_snapshot_matches_live_rules():
    """When the live file IS present, the frozen snapshot must match it — so a
    new rule in monitoring-project can't pass the coverage guard merely because
    the snapshot is stale."""
    live = set(_live_rule_titles() or [])
    snap = set(_SNAPSHOT_RULE_TITLES)
    missing_from_snapshot = live - snap
    removed_from_live = snap - live
    assert not missing_from_snapshot and not removed_from_live, (
        f"Snapshot drift — update _SNAPSHOT_RULE_TITLES. "
        f"New live rules: {sorted(missing_from_snapshot)}; "
        f"removed: {sorted(removed_from_live)}"
    )
