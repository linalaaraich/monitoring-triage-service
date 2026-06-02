"""End-to-end coverage for the first-class environment field.

Shipped 2026-06-02 to replace the per-surface `env = stg if "rental" in svc
else prod` heuristic with a precedence-ordered resolver plus a persisted
rca_history.env column. The resolver is documented in
app.v2_mappings.env_resolver; this module exercises every tier of the
chain plus the wire-through to:

  - RCARecord.env (Pydantic model)
  - rca_history.env (SQLite column + backfill helper)
  - get_decisions(env=...) (SQL filter)
  - /dashboard?env=... URL filter (parse + select narrowing)
  - notifier._v2_subject (subject line carries env even when alert.labels
    has no env key - falls back via service-token inference)
"""
from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as app_main
from app.main import _parse_v2_filters, _V2_FILTER_ENVS
from app.models import Decision, GrafanaAlert, LLMDecision, RCARecord
from app.notifier import EmailNotifier
from app.rca_store import RCAStore
from app.v2_mappings import (
    KNOWN_ENVS,
    env_resolver,
    namespace_to_env,
)


# ---------------------------------------------------------------------------
# env_resolver - precedence chain unit tests
# ---------------------------------------------------------------------------


def test_env_resolver_per_alert_label_wins():
    """Tier 1: alert.labels.env is the highest precedence."""
    env = env_resolver(
        labels={"env": "PROD"},
        common_labels={"env": "stg"},
        service="rental-backend",
    )
    assert env == "prod"


def test_env_resolver_alternate_label_keys():
    """`environment` and `deployment_environment` are accepted alongside `env`."""
    assert env_resolver(labels={"environment": "staging"}) == "stg"
    assert env_resolver(labels={"deployment_environment": "prod"}) == "prod"


def test_env_resolver_common_labels_tier():
    """Tier 2: when per-alert labels miss, commonLabels feeds the resolver."""
    env = env_resolver(common_labels={"env": "preprod"}, service="kong")
    assert env == "preprod"


def test_env_resolver_group_labels_tier():
    """Tier 2b: groupLabels.env counts when no other label has it."""
    env = env_resolver(group_labels={"env": "uat"})
    assert env == "uat"


def test_env_resolver_annotations_tier():
    """Tier 3: annotations.env is the last label-based source before
    namespace inference."""
    env = env_resolver(annotations={"env": "dev"})
    assert env == "dev"


def test_env_resolver_namespace_prefix_inference():
    """Tier 4: `prod-foo` namespace -> prod, `stg-bar` -> stg."""
    assert env_resolver(namespace="prod-payments") == "prod"
    assert env_resolver(namespace="stg-checkout") == "stg"
    assert env_resolver(namespace="dev-frontend") == "dev"


def test_env_resolver_namespace_label_inference():
    """Tier 5: `labels.namespace` is consulted when no explicit namespace
    is passed."""
    env = env_resolver(labels={"namespace": "prod-api"})
    assert env == "prod"


def test_env_resolver_logical_namespace_to_env():
    """The logical-namespace map (rental -> stg, observability -> prod)
    handles non-prefixed namespaces."""
    assert env_resolver(namespace="rental") == "stg"
    assert env_resolver(namespace="observability") == "prod"
    assert env_resolver(namespace="kube-system") == "prod"


def test_env_resolver_service_token_inference():
    """Tier 6: service token alone (no labels, no namespace) routes through
    the NAMESPACE table + logical-ns map."""
    assert env_resolver(service="rental-backend") == "stg"
    assert env_resolver(service="kong") == "prod"  # NAMESPACE[kong]=network -> prod
    assert env_resolver(service="prometheus") == "prod"


def test_env_resolver_unknown_falls_back_to_unknown():
    """Tier 7: nothing matches -> "unknown" explicitly, NOT a silent prod default."""
    assert env_resolver(service="totally-novel-service") == "unknown"
    assert env_resolver() == "unknown"


def test_env_resolver_rejects_typos():
    """Allowlist gate - `prdo` falls through to the next tier instead of
    becoming an env value."""
    env = env_resolver(labels={"env": "prdo"}, service="rental-backend")
    # Falls through tier 1 (prdo not in KNOWN_ENVS), lands in tier 6 (rental -> stg)
    assert env == "stg"


def test_env_resolver_canonicalises_long_form():
    """`production` -> `prod`, `staging` -> `stg` for compact pill rendering."""
    assert env_resolver(labels={"env": "production"}) == "prod"
    assert env_resolver(labels={"env": "Staging"}) == "stg"


def test_env_resolver_empty_string_label_ignored():
    """A label set to "" should not block fall-through to the next tier."""
    env = env_resolver(labels={"env": ""}, service="rental-mysql")
    assert env == "stg"


def test_namespace_to_env_returns_none_for_unknown():
    """Standalone helper returns None when it can't infer - the caller
    chains to the next tier."""
    assert namespace_to_env("zzz-not-a-ns") is None
    assert namespace_to_env("") is None
    assert namespace_to_env(None) is None


def test_known_envs_includes_expected_tokens():
    """Allowlist regression - the six tiers CIRES uses today must stay in."""
    for token in ("prod", "stg", "dev", "preprod", "uat", "int"):
        assert token in KNOWN_ENVS


# ---------------------------------------------------------------------------
# RCARecord + rca_history persistence
# ---------------------------------------------------------------------------


def test_rcarecord_has_env_field():
    """The Pydantic model accepts env and exposes it as an attribute."""
    rec = RCARecord(
        alert_name="HighCpuUsage",
        affected_service="kong",
        triage_decision="investigate",
        action_taken="emailed",
        env="prod",
    )
    assert rec.env == "prod"


def test_rcarecord_env_defaults_none():
    """Backward-compat: env is optional - legacy callers continue to work."""
    rec = RCARecord(
        alert_name="HighCpuUsage",
        affected_service="kong",
        triage_decision="investigate",
        action_taken="emailed",
    )
    assert rec.env is None


@pytest_asyncio.fixture
async def env_store():
    db_path = os.path.join(tempfile.gettempdir(), "test_env_resolver.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.mark.asyncio
async def test_save_decision_populates_env_when_missing(env_store):
    """save_decision auto-fills env via env_resolver(service=...) when
    the caller didn't set it."""
    rec = RCARecord(
        id="auto-env-1",
        timestamp=datetime.now(UTC).replace(tzinfo=None),
        alert_name="HighCpuUsage",
        affected_service="rental-backend",
        severity="warning",
        triage_decision="investigate",
        llm_verdict="dismiss",
        action_taken="suppressed",
    )
    await env_store.save_decision(rec)
    # The record object now carries the resolved env
    assert rec.env == "stg"
    # And the DB row was persisted with it
    rows = await env_store.get_decisions(limit=10, since_hours=1)
    saved = next(r for r in rows if r["id"] == "auto-env-1")
    assert saved["env"] == "stg"


@pytest.mark.asyncio
async def test_save_decision_preserves_explicit_env(env_store):
    """Producer-provided env wins over the auto-derivation."""
    rec = RCARecord(
        id="explicit-env-1",
        timestamp=datetime.now(UTC).replace(tzinfo=None),
        alert_name="HighCpuUsage",
        affected_service="rental-backend",  # would auto-derive to stg
        severity="warning",
        triage_decision="investigate",
        llm_verdict="dismiss",
        action_taken="suppressed",
        env="preprod",
    )
    await env_store.save_decision(rec)
    rows = await env_store.get_decisions(limit=10, since_hours=1)
    saved = next(r for r in rows if r["id"] == "explicit-env-1")
    assert saved["env"] == "preprod"


@pytest.mark.asyncio
async def test_backfill_env_populates_null_rows(env_store):
    """One-off SQL UPDATE for pre-migration rows: env IS NULL becomes the
    service-inferred env."""
    # Persist a row with explicit env=None by going under save_decision's
    # auto-derivation: we use a raw INSERT to simulate a pre-migration row.
    now = datetime.now(UTC).replace(tzinfo=None).isoformat()
    await env_store._db.execute(
        """INSERT INTO rca_history (id, timestamp, alert_source, alert_name,
            affected_service, triage_decision, action_taken)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        ("legacy-1", now, "grafana", "HighCpuUsage", "rental-backend",
         "investigate", "suppressed"),
    )
    await env_store._db.execute(
        """INSERT INTO rca_history (id, timestamp, alert_source, alert_name,
            affected_service, triage_decision, action_taken)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        ("legacy-2", now, "grafana", "HighCpuUsage", "kong",
         "investigate", "suppressed"),
    )
    await env_store._db.commit()
    # Sanity: env is NULL on both rows
    cur = await env_store._db.execute(
        "SELECT COUNT(*) AS n FROM rca_history WHERE env IS NULL"
    )
    pre = await cur.fetchone()
    assert pre["n"] == 2

    updated = await env_store.backfill_env_from_service()
    assert updated == 2

    rows = await env_store.get_decisions(limit=10, since_hours=1)
    by_id = {r["id"]: r for r in rows}
    assert by_id["legacy-1"]["env"] == "stg"
    assert by_id["legacy-2"]["env"] == "prod"


@pytest.mark.asyncio
async def test_backfill_env_is_idempotent(env_store):
    """Second run on the same DB updates 0 rows (only touches NULL/empty)."""
    rec = RCARecord(
        id="idem-1",
        timestamp=datetime.now(UTC).replace(tzinfo=None),
        alert_name="HighCpuUsage",
        affected_service="rental-backend",
        severity="warning",
        triage_decision="investigate",
        llm_verdict="dismiss",
        action_taken="suppressed",
    )
    await env_store.save_decision(rec)
    # First call - row already has env, so 0 updates
    first = await env_store.backfill_env_from_service()
    assert first == 0


# ---------------------------------------------------------------------------
# get_decisions / count_decisions env filter
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def mixed_env_store():
    """Three rows, one per env."""
    db_path = os.path.join(tempfile.gettempdir(), "test_env_filter.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    now = datetime.now(UTC).replace(tzinfo=None)
    rows = [
        ("prod-row",    "kong",           "prod"),
        ("stg-row",     "rental-backend", "stg"),
        ("unknown-row", "novel-service",  "unknown"),
    ]
    for rid, svc, env in rows:
        rec = RCARecord(
            id=rid,
            timestamp=now - timedelta(minutes=1),
            alert_name="HighCpuUsage",
            affected_service=svc,
            severity="warning",
            triage_decision="investigate",
            llm_verdict="escalate",
            action_taken="emailed",
            env=env,
        )
        await s.save_decision(rec)
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.mark.asyncio
async def test_get_decisions_env_filter_narrows(mixed_env_store):
    """env="prod" returns only the prod row."""
    rows = await mixed_env_store.get_decisions(limit=10, since_hours=1, env="prod")
    ids = {r["id"] for r in rows}
    assert ids == {"prod-row"}


@pytest.mark.asyncio
async def test_count_decisions_env_filter(mixed_env_store):
    """count_decisions honours env=... so the dashboard footer matches."""
    n_prod = await mixed_env_store.count_decisions(since_hours=1, env="prod")
    n_stg = await mixed_env_store.count_decisions(since_hours=1, env="stg")
    n_all = await mixed_env_store.count_decisions(since_hours=1)
    assert n_prod == 1
    assert n_stg == 1
    assert n_all == 3


# ---------------------------------------------------------------------------
# /dashboard URL filter
# ---------------------------------------------------------------------------


def test_parse_v2_filters_accepts_env():
    f = _parse_v2_filters(None, None, None, None, None, "prod")
    assert f["env"] == "prod"
    assert f["active_count"] == 1


def test_parse_v2_filters_env_unknown_falls_back():
    """Allowlist gate - bad env value silently drops to None."""
    f = _parse_v2_filters(None, None, None, None, None, "DROP_TABLE")
    assert f["env"] is None
    assert f["active_count"] == 0


def test_parse_v2_filters_env_allowlist_has_unknown():
    """The "unknown" token is filterable so operators can audit the gap."""
    assert "unknown" in _V2_FILTER_ENVS
    f = _parse_v2_filters(None, None, None, None, None, "unknown")
    assert f["env"] == "unknown"


@pytest_asyncio.fixture
async def env_dashboard_client(mixed_env_store):
    saved = app_main._store
    app_main._store = mixed_env_store
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app_main._store = saved


@pytest.mark.asyncio
async def test_dashboard_env_filter_narrows(env_dashboard_client):
    """?env=prod returns only the prod-row decision in the embedded payload."""
    resp = await env_dashboard_client.get("/dashboard?env=prod&range=15d")
    assert resp.status_code == 200
    body = resp.text
    assert "prod-row" in body
    assert "stg-row" not in body
    assert "unknown-row" not in body
    # The Env <select> has prod marked selected
    assert '<option value="prod" selected>' in body


@pytest.mark.asyncio
async def test_dashboard_env_dropdown_present(env_dashboard_client):
    """The Env filter dropdown is rendered in the filter bar."""
    resp = await env_dashboard_client.get("/dashboard")
    assert resp.status_code == 200
    body = resp.text
    assert 'name="env"' in body
    # All canonical env tokens appear as <option> values in the dropdown
    for token in ("prod", "stg", "dev", "unknown"):
        assert f'value="{token}"' in body


# ---------------------------------------------------------------------------
# Email subject - env appears even when alert.labels has no env key
# ---------------------------------------------------------------------------


def _make_alert(service="kong"):
    return GrafanaAlert(
        status="firing",
        labels={"alertname": "HighCpuUsage", "service": service,
                "severity": "warning"},
        annotations={"summary": "cpu high"},
        startsAt="2026-06-02T10:00:00Z",
    )


def _make_decision():
    return LLMDecision(
        decision=Decision.ESCALATE, severity="warning", confidence=0.85,
        reason="cpu", rca="cpu saturation",
    )


def _make_record(env=None, service="kong"):
    return RCARecord(
        id="env-subject-test-aaaaaaaaaaaa",
        timestamp=datetime.now(UTC).replace(tzinfo=None),
        alert_name="HighCpuUsage",
        affected_service=service,
        severity="warning",
        triage_decision="investigate",
        llm_verdict="escalate",
        llm_confidence="0.85",
        action_taken="emailed",
        env=env,
    )


def test_subject_contains_env_when_label_missing():
    """The 2026-06-02 fallback path - alert.labels has no env, resolver
    walks down to service inference, subject still carries [prod]."""
    n = EmailNotifier()
    subj = n._v2_subject(_make_alert(service="kong"), _make_decision(),
                         _make_record(env=None, service="kong"))
    assert "[prod]" in subj


def test_subject_uses_persisted_env_over_re_derivation():
    """When RCARecord.env is set, the subject uses it verbatim - so
    pipeline-resolved env always matches what the dashboard shows."""
    n = EmailNotifier()
    # Service token would resolve to prod via NAMESPACE[kong]=network, but
    # the persisted env says preprod - subject must honour the persisted value.
    subj = n._v2_subject(_make_alert(service="kong"), _make_decision(),
                         _make_record(env="preprod", service="kong"))
    assert "[preprod]" in subj
    assert "[prod]" not in subj


def test_subject_env_from_label_when_present():
    """Tier 1 wins - alert.labels.env beats service inference."""
    n = EmailNotifier()
    alert = _make_alert(service="kong")
    alert.labels["env"] = "uat"
    subj = n._v2_subject(alert, _make_decision(), _make_record(env=None))
    assert "[uat]" in subj
