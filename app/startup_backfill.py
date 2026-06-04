"""Startup downtime backfill.

If the triage service was down while Grafana kept firing alerts, those
alerts are lost — Grafana's webhook contact point retries a couple times
then gives up. Without a durable queue somewhere, the record of "this
rule fired at 02:37 UTC" lives only in Grafana's own annotation store.

This module runs ONCE on startup. It:

  1. reads max(timestamp) from the RCA history DB → "last_seen"
  2. computes gap = now - last_seen
  3. if gap is short (< threshold) or absurdly long (> max_gap), skip
  4. otherwise pulls Grafana's /api/annotations for the gap window,
     filters to state=Alerting transitions on real rules (i.e. not
     synthetic Verify* / HourlyDemo* rehearsals), dedupes by
     (alertname, service), and posts each back through the normal
     /webhook/grafana endpoint — so the regular pipeline (dedup,
     suppression, context, LLM, notify, persist) handles them.

The pipeline path is the same as live traffic, which means:
  - the LLM does the RCA (no bypass)
  - the email goes out with proper RCA context
  - the dashboard gets a row per unique alert
  - replay_source='backfill_<iso>' label lets us trace these rows

Disabled entirely when grafana_api_password is empty. That makes the
default deploy no-op safe — you have to opt in by setting the env.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

# Alert name patterns to skip on backfill. These are hand-fired rehearsal
# webhooks or rogue cron synthetic tests — they shouldn't eat LLM cycles
# during a catch-up sweep.
_SYNTHETIC_NAME = re.compile(
    r"^(HourlyDemoTest|VerifyPersist|VerifyNewBuild|LaptopSmoke)",
    re.IGNORECASE,
)


def _parse_label_dict(text: str) -> dict[str, str]:
    """Pull the {k=v, k=v} labels dict out of a Grafana annotation `text` field."""
    match = re.search(r"\{([^}]*)\}", text or "")
    if not match:
        return {}
    labels: dict[str, str] = {}
    for pair in match.group(1).split(","):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        labels[k.strip()] = v.strip()
    return labels


async def _fetch_annotations(
    client: httpx.AsyncClient, from_ms: int, to_ms: int
) -> list[dict[str, Any]]:
    r = await client.get(
        f"{settings.grafana_url}/api/annotations",
        params={"type": "alert", "from": from_ms, "to": to_ms, "limit": 500},
        timeout=10.0,
    )
    r.raise_for_status()
    return r.json()


async def _fetch_rule_expr(client: httpx.AsyncClient, alertname: str) -> str | None:
    """Look up the PromQL expression for a rule by title. Returns None if
    rule doesn't exist or has no Prometheus query step."""
    try:
        r = await client.get(
            f"{settings.grafana_url}/api/v1/provisioning/alert-rules",
            timeout=10.0,
        )
        r.raise_for_status()
        for rule in r.json():
            if rule.get("title") == alertname:
                for step in rule.get("data", []):
                    if step.get("datasource_uid") == "prometheus" or step.get("datasourceUid") == "prometheus":
                        return step.get("model", {}).get("expr")
                # Fallback: annotation `expr`
                return (rule.get("annotations") or {}).get("expr")
    except Exception as exc:
        logger.warning("Rule lookup failed for %s: %s", alertname, exc)
    return None


async def _fetch_metric_value(client: httpx.AsyncClient, expr: str) -> float | None:
    """Prometheus instant query; returns the first series' sample value, or None."""
    try:
        r = await client.get(
            f"{settings.grafana_url}/api/datasources/proxy/uid/prometheus/api/v1/query",
            params={"query": expr},
            timeout=5.0,
        )
        r.raise_for_status()
        data = r.json()
        result = data.get("data", {}).get("result") or []
        if result:
            return float(result[0]["value"][1])
    except Exception:
        # Metric query failures are non-fatal — webhook still gets enqueued
        # with an empty values dict, the LLM just has less to cite.
        pass
    return None


async def _post_webhook(
    client: httpx.AsyncClient, self_url: str, payload: dict[str, Any]
) -> bool:
    try:
        r = await client.post(self_url, json=payload, timeout=10.0)
        return r.status_code == 202
    except Exception as exc:
        logger.warning("Self-webhook POST failed: %s", exc)
        return False


async def run_startup_backfill(
    last_seen_iso: str | None,
    self_webhook_url: str = "http://localhost:8090/webhook/grafana",
) -> int:
    """Entry point. Returns number of backfill webhooks enqueued."""
    if not settings.grafana_api_password:
        logger.info("Backfill disabled (grafana_api_password not set)")
        return 0

    now = datetime.now(timezone.utc)
    if last_seen_iso:
        try:
            last_seen = datetime.fromisoformat(last_seen_iso.replace("Z", "+00:00"))
            if last_seen.tzinfo is None:
                last_seen = last_seen.replace(tzinfo=timezone.utc)
        except Exception:
            logger.warning("Could not parse last_seen=%s — skipping backfill", last_seen_iso)
            return 0
    else:
        # No prior history means brand-new DB. Don't backfill — there's no
        # sensible "downtime" to attribute.
        logger.info("No prior RCA history — skipping backfill")
        return 0

    gap = now - last_seen
    threshold = timedelta(minutes=settings.startup_backfill_threshold_minutes)
    max_gap = timedelta(hours=settings.startup_backfill_max_gap_hours)

    if gap < threshold:
        logger.info("Downtime gap %s below threshold %s — no backfill needed", gap, threshold)
        return 0

    window_start = max(last_seen, now - max_gap)
    logger.info(
        "Detected downtime: last RCA at %s, now %s (gap %s). Backfilling from %s.",
        last_seen.isoformat(), now.isoformat(), gap, window_start.isoformat(),
    )

    # Basic auth header for Grafana API. The password is a secret — we never
    # log it; only the username appears in logs.
    auth = base64.b64encode(
        f"{settings.grafana_api_user}:{settings.grafana_api_password}".encode()
    ).decode()
    headers = {"Authorization": f"Basic {auth}"}

    from_ms = int(window_start.timestamp() * 1000)
    to_ms = int(now.timestamp() * 1000)

    enqueued = 0
    async with httpx.AsyncClient(headers=headers) as client:
        try:
            annotations = await _fetch_annotations(client, from_ms, to_ms)
        except Exception as exc:
            logger.error("Backfill: could not fetch annotations: %s", exc)
            return 0

        logger.info("Backfill: %d annotations in window", len(annotations))

        # Keep only Alerting transitions on real rule names.
        fires = [
            a for a in annotations
            if a.get("newState") == "Alerting"
            and not _SYNTHETIC_NAME.match(a.get("alertName", ""))
        ]

        # Dedupe by (alertname, service) — one RCA per unique family.
        uniq: dict[tuple[str, str], dict[str, Any]] = {}
        for a in fires:
            labels = _parse_label_dict(a.get("text", ""))
            name = a["alertName"]
            service = labels.get("service") or labels.get("job") or "unknown"
            key = (name, service)
            if key not in uniq or a["time"] > uniq[key]["time"]:
                a["parsed_labels"] = labels
                a["service"] = service
                uniq[key] = a

        logger.info(
            "Backfill: %d raw fires -> %d unique (alertname, service) to replay",
            len(fires), len(uniq),
        )

        # Batch self-webhook posts. Sequential is fine — the pipeline
        # dedups against recent decisions anyway, and we don't want to
        # hammer Ollama with parallel requests at startup.
        backfill_tag = f"backfill_{now.strftime('%Y-%m-%dT%H:%MZ')}"
        for (name, service), a in sorted(uniq.items()):
            labels = dict(a.get("parsed_labels") or {})
            labels["alertname"] = name
            labels.setdefault("service", service)
            labels["replay_source"] = backfill_tag

            expr = await _fetch_rule_expr(client, name)
            value = await _fetch_metric_value(client, expr) if expr else None

            # Values dict: A=query, B=reduce, C=threshold. We only know one
            # number; put it at B since that's the canonical reduce slot.
            values = {"B": value} if value is not None else {}

            annotations_map: dict[str, str] = {
                "summary": f"{name} fired during triage downtime ({a['time']})",
                "description": (
                    f"Replay from startup backfill — this alert fired at "
                    f"{datetime.fromtimestamp(a['time']/1000, timezone.utc).isoformat()} "
                    f"while the triage service was down."
                ),
            }
            if expr:
                annotations_map["expr"] = expr

            fired_iso = datetime.fromtimestamp(a["time"] / 1000, timezone.utc).isoformat()
            webhook = {
                "receiver": "triage-webhook",
                "status": "firing",
                "alerts": [{
                    "status": "firing",
                    "labels": labels,
                    "annotations": annotations_map,
                    "startsAt": fired_iso,
                    "endsAt": "",
                    "fingerprint": f"backfill_{name}_{service}_{int(a['time'])}",
                    "generatorURL": f"{settings.grafana_url}/alerting/list",
                    "values": values,
                }],
                "groupLabels": {"alertname": name},
                "commonLabels": labels,
                "commonAnnotations": annotations_map,
                "externalURL": settings.grafana_url,
            }

            ok = await _post_webhook(client, self_webhook_url, webhook)
            if ok:
                enqueued += 1
            logger.info(
                "Backfill replay: %s/%s fired_at=%s value=%s -> enqueued=%s",
                name, service, fired_iso, value, ok,
            )

    logger.info("Backfill complete: %d alerts re-enqueued", enqueued)
    return enqueued


async def backfill_rca_quality(store) -> dict[str, int]:
    """One-shot, idempotent recompute of rca_quality for ALL existing
    rca_history rows.

    WHY: the live recompute (pipeline.py Issue #3) is forward-only — it only
    ever sets rca_quality at persist time. Rows written before that gate
    landed (or by code paths that set a stale snapshot) still carry a
    stale / never-computed rca_quality. Those poison the "actionable %" KPI
    and the hedge/feedback loop. This sweep brings the whole table in line
    with the SAME classifier the live pipeline uses.

    REUSES app.rca_store._classify_rca_quality verbatim (the canonical rule —
    no duplicated logic) over the SAME four input columns the pipeline feeds
    it: rca_report, llm_reasoning, suggested_actions, evidence.

    IDEMPOTENT + SAFE TO RE-RUN:
      - recomputes every row, but only UPDATEs rows whose recomputed value
        actually differs from the stored one (already-correct rows untouched)
      - touches ONLY the rca_quality column. The excluded_from_lookup
        quarantine flag and every other column (action_taken, triage_decision,
        the data_starved / mcp-outage-escalated rows' other fields, ...) are
        left exactly as they are. We re-tag quality; we do not re-quarantine,
        re-escalate, or re-route anything.

    Returns a small dict of counters for logging / assertions:
      {"scanned": N, "changed": M, "unchanged": N-M}.

    Does NOT run automatically — invoke deliberately (see module docstring on
    schedule path; this is intentionally NOT wired into schedule_on_startup so
    it can never fire against live without an explicit call).
    """
    # Local import to avoid any import cycle at module load and to make the
    # canonical-rule reuse explicit.
    from app.rca_store import _classify_rca_quality

    db = store._db
    cursor = await db.execute(
        "SELECT id, rca_report, llm_reasoning, suggested_actions, evidence, "
        "rca_quality FROM rca_history"
    )
    rows = await cursor.fetchall()

    scanned = 0
    changed = 0
    to_update: list[tuple[str, str]] = []
    for row in rows:
        scanned += 1
        recomputed = _classify_rca_quality(
            row["rca_report"],
            row["llm_reasoning"],
            row["suggested_actions"],
            row["evidence"],
        )
        if recomputed != (row["rca_quality"] or None):
            to_update.append((recomputed, row["id"]))

    for new_quality, row_id in to_update:
        await db.execute(
            "UPDATE rca_history SET rca_quality = ? WHERE id = ?",
            (new_quality, row_id),
        )
        changed += 1

    if changed:
        await db.commit()

    result = {"scanned": scanned, "changed": changed, "unchanged": scanned - changed}
    logger.info(
        "rca_quality backfill: scanned=%d changed=%d unchanged=%d",
        result["scanned"], result["changed"], result["unchanged"],
    )
    return result


def schedule_on_startup(app, store) -> None:
    """Register the backfill to run once, after the app finishes its other
    startup tasks. Non-blocking — if the backfill errors the service still
    comes up. Call from app.main's startup hook.
    """
    @app.on_event("startup")
    async def _kickoff():
        # Give the rest of the startup sequence (MCP clients, drain3, etc) a
        # head start before hitting Grafana. Avoids a thundering-herd of
        # connect attempts during cold boot.
        await asyncio.sleep(5)
        try:
            cursor = await store._db.execute(
                "SELECT MAX(timestamp) AS ts FROM rca_history"
            )
            row = await cursor.fetchone()
            last_seen = row["ts"] if row else None
        except Exception as exc:
            logger.warning("Could not read last RCA timestamp: %s", exc)
            last_seen = None

        try:
            count = await run_startup_backfill(last_seen)
            if count:
                logger.warning(
                    "Startup backfill replayed %d alerts. Check /decisions for new 'backfill_*' rows.",
                    count,
                )
        except Exception as exc:
            logger.error("Startup backfill raised: %s", exc, exc_info=True)
