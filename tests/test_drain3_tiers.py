"""S5-DRN-01 — 3-tier hierarchical Drain3 thresholds (component/application/system).

Firing logic is tested by constructing BatchResult objects directly so the
per-scope counts are deterministic (no dependence on the miner's novelty
heuristics); the structured-ingest breakdown and the app resolver are tested
against real input.
"""
import os
import tempfile
import threading

import pytest

os.environ.setdefault("DRAIN3_STATE_DIR", os.path.join(tempfile.gettempdir(), "test_drain3_tiers"))

import app.drain_analyzer as da_mod
from app.drain_analyzer import (
    DrainAnalyzer, BatchResult, ScopeCounts, _app_from_stream_labels,
)
from app.config import settings


# --------------------------------------------------------------------------
# App-grouping resolver
# --------------------------------------------------------------------------

def test_app_resolver_prefers_explicit_map(monkeypatch):
    monkeypatch.setattr(settings, "drain3_app_map", {"cart": "shop"})
    assert _app_from_stream_labels({"k8s_namespace_name": "otel-demo"}, "cart") == "shop"


def test_app_resolver_uses_namespace_label(monkeypatch):
    monkeypatch.setattr(settings, "drain3_app_map", {})
    assert _app_from_stream_labels({"k8s_namespace_name": "otel-demo"}, "cart") == "otel-demo"
    assert _app_from_stream_labels({"namespace": "team-a"}, "svc") == "team-a"


def test_app_resolver_falls_back_to_service(monkeypatch):
    monkeypatch.setattr(settings, "drain3_app_map", {})
    # No namespace label → the service is its own single-component app.
    assert _app_from_stream_labels({}, "lonely-svc") == "lonely-svc"


# --------------------------------------------------------------------------
# Structured ingest breakdown
# --------------------------------------------------------------------------

@pytest.fixture()
def analyzer():
    import shutil
    from drain3.template_miner_config import TemplateMinerConfig
    state_dir = settings.drain3_state_dir
    if os.path.exists(state_dir):
        shutil.rmtree(state_dir)
    os.makedirs(state_dir, exist_ok=True)
    a = DrainAnalyzer.__new__(DrainAnalyzer)
    a._config = TemplateMinerConfig()
    a._miners = {}
    a._lines_per_service = {}
    a._anomalies_per_service = {}
    a._background_task = None
    a._lock = threading.Lock()
    a._last_alert_ts = 0.0
    a._tier_alert_ts = {}
    return a


def test_structured_ingest_tracks_service_and_app(analyzer):
    # Two services in one app (namespace), all lines novel → all anomalous.
    batch = analyzer._ingest_batch_structured([
        ("cart", "otel-demo", ["err cart alpha", "err cart beta"]),
        ("checkout", "otel-demo", ["err checkout gamma"]),
    ])
    assert batch.total_lines == 3
    assert batch.total_anomalous == 3
    assert batch.per_service["cart"].lines == 2
    assert batch.per_service["checkout"].lines == 1
    # Both components roll up into the one app.
    assert batch.per_app["otel-demo"].lines == 3
    assert batch.app_components["otel-demo"] == {"cart", "checkout"}


def test_structured_ingest_skips_infra(analyzer):
    batch = analyzer._ingest_batch_structured([
        ("grafana", "observability", ["infra noise a", "infra noise b"]),
        ("cart", "otel-demo", ["real app error"]),
    ])
    assert "grafana" not in batch.per_service
    assert batch.per_service["cart"].lines == 1
    assert batch.total_lines == 1


# --------------------------------------------------------------------------
# 3-tier firing
# --------------------------------------------------------------------------

class _Resp:
    status_code = 202
    text = ""


def _mock_webhook(monkeypatch):
    """Patch httpx so every self-alert POST is captured; returns the list."""
    captured: list[dict] = []

    class _Client:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def post(self, url, json):
            captured.append(dict(json))
            return _Resp()

    monkeypatch.setattr(da_mod.httpx, "AsyncClient", lambda timeout=5.0: _Client())
    return captured


def _set_thresholds(monkeypatch, comp=0.5, comp_min=10, app=0.3, app_min=10, sys=0.2, sys_min=10):
    monkeypatch.setattr(settings, "drain3_alert_enabled", True)
    monkeypatch.setattr(settings, "drain3_component_rate_threshold", comp)
    monkeypatch.setattr(settings, "drain3_component_min_lines", comp_min)
    monkeypatch.setattr(settings, "drain3_app_rate_threshold", app)
    monkeypatch.setattr(settings, "drain3_app_min_lines", app_min)
    monkeypatch.setattr(settings, "drain3_alert_rate_threshold", sys)
    monkeypatch.setattr(settings, "drain3_alert_min_lines", sys_min)
    monkeypatch.setattr(settings, "drain3_alert_cooldown_seconds", 600)
    monkeypatch.setattr(settings, "drain3_max_alerts_per_tier_per_batch", 3)


@pytest.mark.asyncio
async def test_component_tier_fires_when_one_service_weird(analyzer, monkeypatch):
    _set_thresholds(monkeypatch)
    captured = _mock_webhook(monkeypatch)
    batch = BatchResult(
        total_lines=1000, total_anomalous=60,   # 6% global → below system 20%
        per_service={
            "cart": ScopeCounts(lines=20, anomalous=15),       # 75% ≥ 50% → fire
            "frontend": ScopeCounts(lines=980, anomalous=45),  # 4.6% → no
        },
        per_app={"shop": ScopeCounts(lines=1000, anomalous=60)},  # 6% → no
        app_components={"shop": {"cart", "frontend"}},
    )
    await analyzer.maybe_fire_alerts(batch)
    assert len(captured) == 1
    assert captured[0]["tier"] == "component"
    assert captured[0]["scope"] == "cart"


@pytest.mark.asyncio
async def test_application_tier_fires_on_whole_app_drift(analyzer, monkeypatch):
    _set_thresholds(monkeypatch)
    captured = _mock_webhook(monkeypatch)
    batch = BatchResult(
        total_lines=1000, total_anomalous=38,   # 3.8% → below system
        per_service={
            "a": ScopeCounts(lines=50, anomalous=20),   # 40% < 50% component
            "b": ScopeCounts(lines=50, anomalous=18),   # 36% < 50% component
            "c": ScopeCounts(lines=900, anomalous=0),
        },
        per_app={
            "shop": ScopeCounts(lines=100, anomalous=38),   # 38% ≥ 30% → fire
            "other": ScopeCounts(lines=900, anomalous=0),
        },
        app_components={"shop": {"a", "b"}, "other": {"c"}},
    )
    await analyzer.maybe_fire_alerts(batch)
    fires = {(c["tier"], c["scope"]) for c in captured}
    assert ("application", "shop") in fires
    assert not any(c["tier"] == "component" for c in captured)
    assert not any(c["tier"] == "system" for c in captured)


@pytest.mark.asyncio
async def test_system_tier_fires_on_broad_elevation(analyzer, monkeypatch):
    # Raise component/app bars so only the system aggregate trips.
    _set_thresholds(monkeypatch, comp=0.6, app=0.5, sys=0.2)
    captured = _mock_webhook(monkeypatch)
    per_service = {f"s{i}": ScopeCounts(lines=200, anomalous=60) for i in range(5)}  # 30% each
    per_app = {f"s{i}": ScopeCounts(lines=200, anomalous=60) for i in range(5)}      # own app
    batch = BatchResult(
        total_lines=1000, total_anomalous=300,   # 30% ≥ 20% → system fires
        per_service=per_service, per_app=per_app,
        app_components={f"s{i}": {f"s{i}"} for i in range(5)},
    )
    await analyzer.maybe_fire_alerts(batch)
    tiers = {c["tier"] for c in captured}
    assert "system" in tiers
    assert "component" not in tiers and "application" not in tiers
    sys_fire = next(c for c in captured if c["tier"] == "system")
    assert sys_fire["scope"] == "all"
    assert sys_fire["service"] == "drain3"


@pytest.mark.asyncio
async def test_cooldown_is_per_tier_scope(analyzer, monkeypatch):
    _set_thresholds(monkeypatch)
    captured = _mock_webhook(monkeypatch)
    # cart is on cooldown; system "all" is not — system must still fire.
    import time as _t
    analyzer._tier_alert_ts[("component", "cart")] = _t.monotonic()
    batch = BatchResult(
        total_lines=100, total_anomalous=40,   # 40% ≥ 20% system → fire
        per_service={"cart": ScopeCounts(lines=100, anomalous=40)},  # 40%<50% comp anyway
        per_app={"cart": ScopeCounts(lines=100, anomalous=40)},
        app_components={"cart": {"cart"}},
    )
    await analyzer.maybe_fire_alerts(batch)
    assert any(c["tier"] == "system" for c in captured)
    assert not any(c["tier"] == "component" and c["scope"] == "cart" for c in captured)


@pytest.mark.asyncio
async def test_component_tier_cap(analyzer, monkeypatch):
    _set_thresholds(monkeypatch)   # cap = 3
    captured = _mock_webhook(monkeypatch)
    per_service = {f"svc{i}": ScopeCounts(lines=20, anomalous=18) for i in range(5)}  # all 90%
    per_app = {f"svc{i}": ScopeCounts(lines=20, anomalous=18) for i in range(5)}
    batch = BatchResult(
        total_lines=100, total_anomalous=90,
        per_service=per_service, per_app=per_app,
        app_components={f"svc{i}": {f"svc{i}"} for i in range(5)},
    )
    await analyzer.maybe_fire_alerts(batch)
    comp_fires = [c for c in captured if c["tier"] == "component"]
    assert len(comp_fires) == 3   # capped from 5


@pytest.mark.asyncio
async def test_payload_carries_tier_and_scope(analyzer, monkeypatch):
    _set_thresholds(monkeypatch)
    captured = _mock_webhook(monkeypatch)
    batch = BatchResult(
        total_lines=50, total_anomalous=40,
        per_service={"cart": ScopeCounts(lines=50, anomalous=40, new_templates=["T1"], sample_lines=["L1"])},
        per_app={"cart": ScopeCounts(lines=50, anomalous=40)},
        app_components={"cart": {"cart"}},
    )
    await analyzer.maybe_fire_alerts(batch)
    comp = next(c for c in captured if c["tier"] == "component")
    assert comp["scope"] == "cart"
    assert comp["service"] == "cart"
    assert comp["new_templates"] == ["T1"]
    assert comp["anomaly_rate"] == 0.8
