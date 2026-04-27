import html as _html
import logging
import re as _re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from zoneinfo import ZoneInfo


# All DB timestamps are stored in UTC (datetime.utcnow().isoformat()). The
# operator audience is in Casablanca — render times in GMT+1 so people
# reading the dashboard at 14:00 local don't mentally subtract an hour
# from every row. Label timestamps with "Casablanca" to keep it obvious
# which zone is in view.
_LOCAL_TZ = ZoneInfo("Africa/Casablanca")


def _to_local_time(iso_utc_str: str | None, with_zone_label: bool = False) -> str:
    """Parse an ISO UTC timestamp string and render it in Africa/Casablanca.

    Accepts:
      - "2026-04-24T10:35:21.982747" (no tz — assume UTC, as saved by utcnow())
      - "2026-04-24T10:35:21+00:00"  (tz-aware UTC)
      - "" / None                    — returns ""

    Returns "YYYY-MM-DD HH:MM:SS" (and " Casablanca" if with_zone_label=True).
    Falls back to the raw input on parse failure — don't crash the dashboard
    over a malformed timestamp.
    """
    if not iso_utc_str:
        return ""
    s = iso_utc_str.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return iso_utc_str  # graceful fallback
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local = dt.astimezone(_LOCAL_TZ)
    base = local.strftime("%Y-%m-%d %H:%M:%S")
    return f"{base} Casablanca" if with_zone_label else base

from fastapi import BackgroundTasks, FastAPI, Query
from fastapi.responses import HTMLResponse, Response

from app.config import settings
from app.context import ContextGatherer
from app.dedup import DedupManager
from app.drain_analyzer import DrainAnalyzer
from app.llm_client import LLMClient
from app.metrics import get_metrics, webhooks_received
from app.models import Drain3Webhook, GrafanaWebhook, HealthResponse
from app.notifier import EmailNotifier
from app.pipeline import TriagePipeline
from app.rca_store import RCAStore

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger(__name__)

# Globals initialized at startup
_start_time: float = 0
_pipeline: TriagePipeline | None = None
_store: RCAStore | None = None
_drain: DrainAnalyzer | None = None
_context_gatherer: ContextGatherer | None = None
_llm_client: LLMClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _start_time, _pipeline, _store, _drain, _context_gatherer, _llm_client
    _start_time = time.monotonic()

    # Initialize components
    _store = RCAStore(settings.rca_db_path)
    await _store.init_db()

    _drain = DrainAnalyzer()
    await _drain.seed_from_loki()
    await _drain.start_background_ingestion()

    _context_gatherer = ContextGatherer()
    _llm_client = LLMClient()
    notifier = EmailNotifier()
    dedup = DedupManager(window_seconds=settings.dedup_window_seconds)

    _pipeline = TriagePipeline(
        rca_store=_store,
        drain=_drain,
        context_gatherer=_context_gatherer,
        llm_client=_llm_client,
        notifier=notifier,
        dedup=dedup,
    )

    logger.info("Triage service started — listening on :8090")

    # Startup downtime backfill: if the service was down while Grafana fired
    # alerts, pull those from Grafana's annotation API and re-enqueue them
    # through the normal pipeline. Kicked off as a fire-and-forget task so
    # it never blocks service readiness — if Grafana is slow, /health still
    # responds within the k8s readiness probe window.
    import asyncio as _asyncio
    from app.startup_backfill import run_startup_backfill

    async def _backfill_after_startup():
        # Small delay so the event loop is fully warm and the MCP clients
        # are done their first health pings. Avoids a cold-boot stampede.
        await _asyncio.sleep(5)
        try:
            cur = await _store._db.execute(
                "SELECT MAX(timestamp) AS ts FROM rca_history"
            )
            row = await cur.fetchone()
            last_seen = row["ts"] if row and "ts" in row.keys() else None
        except Exception as exc:
            logger.warning("Could not read max(timestamp) for backfill: %s", exc)
            last_seen = None
        try:
            n = await run_startup_backfill(last_seen)
            if n:
                logger.warning(
                    "Startup backfill replayed %d alerts — check /decisions for backfill_* rows.",
                    n,
                )
        except Exception as exc:
            logger.error("Startup backfill failed: %s", exc, exc_info=True)

    _asyncio.create_task(_backfill_after_startup())

    yield

    # Shutdown
    await _drain.stop_background_ingestion()
    await _context_gatherer.close()
    await _llm_client.close()
    await _store.close()
    logger.info("Triage service stopped")


app = FastAPI(
    title="CIRES Triage Service",
    version="0.1.0",
    lifespan=lifespan,
)


# --- Webhook endpoints ---


@app.post("/webhook/grafana", status_code=202)
async def webhook_grafana(payload: GrafanaWebhook, background_tasks: BackgroundTasks):
    webhooks_received.labels(source="grafana").inc()
    logger.info(
        "Received Grafana webhook: status=%s alerts=%d",
        payload.status,
        len(payload.alerts),
    )
    background_tasks.add_task(_pipeline.process_grafana_webhook, payload)
    return {"status": "accepted"}


@app.post("/webhook/drain3", status_code=202)
async def webhook_drain3(payload: Drain3Webhook, background_tasks: BackgroundTasks):
    webhooks_received.labels(source="drain3").inc()
    logger.info(
        "Received Drain3 webhook: anomalous_lines=%d anomaly_rate=%.4f",
        len(payload.anomalous_lines),
        payload.anomaly_rate,
    )
    background_tasks.add_task(_pipeline.process_drain3_webhook, payload)
    return {"status": "accepted"}


# --- Query endpoints ---


@app.get("/health")
async def health() -> HealthResponse:
    uptime = time.monotonic() - _start_time
    return HealthResponse(uptime_seconds=round(uptime, 1))


@app.get("/decisions")
async def decisions(
    limit: int = Query(50, ge=1, le=500),
    alert_name: str | None = Query(None),
):
    return await _store.get_decisions(limit=limit, alert_name=alert_name)


@app.get("/drain3/stats")
async def drain3_stats():
    # get_stats holds a threading.Lock and iterates all drain3 clusters.
    # Run it in a thread so we don't block the event loop behind any
    # in-flight ingest batches (which also hold the same lock).
    import asyncio as _asyncio
    return await _asyncio.to_thread(_drain.get_stats)


_DASHBOARD_CSS = """
  :root {
    --bg: #f6f7f3;
    --card: #ffffff;
    --card-alt: #fbfcf8;
    --ink: #1f2a23;
    --ink-soft: #3f4a42;
    --muted: #6b7a6f;
    --rule: rgba(30, 55, 40, .10);
    --rule-hi: rgba(30, 55, 40, .22);
    --sage: #5d8c6b;
    --sage-strong: #3e7d4d;
    --sage-soft: #eef6ee;
    --ok: #3e7d4d;
    --warn: #a1642b;
    --warn-soft: #f6efe3;
    --danger: #a1393a;
    --danger-soft: #f6ebe6;
    --info: #4a7393;
    --info-soft: #eaf0f5;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", Arial, sans-serif;
    background: var(--bg);
    color: var(--ink);
    line-height: 1.5;
    padding: 28px 32px 56px;
    -webkit-font-smoothing: antialiased;
  }
  .container { max-width: 1280px; margin: 0 auto; }

  .header { margin-bottom: 22px; }
  .header .eyebrow { font-size: 11px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; color: var(--muted); margin-bottom: 6px; }
  .header h1 {
    font-size: 26px; font-weight: 700; letter-spacing: -.3px; color: var(--ink);
  }
  .header h1 .accent { color: var(--sage-strong); }
  .header .subtitle { margin-top: 4px; color: var(--muted); font-size: 13px; }

  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .stat {
    background: var(--card);
    border: 1px solid var(--rule);
    padding: 14px 18px;
    border-radius: 12px;
    display: flex; flex-direction: column; gap: 4px;
    transition: border-color .15s;
  }
  .stat:hover { border-color: var(--rule-hi); }
  .stat .num { font-size: 26px; font-weight: 700; letter-spacing: -.3px; line-height: 1.2; color: var(--ink); }
  .stat .lbl { color: var(--muted); font-size: 11px; font-weight: 600; letter-spacing: .4px; text-transform: uppercase; }
  .stat.t-total { border-left: 3px solid var(--sage); }
  .stat.t-esc { border-left: 3px solid var(--danger); }
  .stat.t-esc .num { color: var(--danger); }
  .stat.t-dismiss { border-left: 3px solid var(--ok); }
  .stat.t-dismiss .num { color: var(--ok); }
  .stat.t-timeout { border-left: 3px solid var(--warn); }
  .stat.t-timeout .num { color: var(--warn); }
  .stat.t-suppress { border-left: 3px solid var(--info); }
  .stat.t-suppress .num { color: var(--info); }

  .toolbar { display: flex; gap: 12px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }
  .toolbar input[type=text] {
    background: var(--card); border: 1px solid var(--rule); color: var(--ink);
    padding: 9px 14px; border-radius: 8px; font-size: 13px; min-width: 280px;
    font-family: inherit; transition: border-color .15s, box-shadow .15s;
  }
  .toolbar input[type=text]:focus {
    outline: none; border-color: var(--sage); box-shadow: 0 0 0 3px rgba(93,140,107,.15);
  }
  .toolbar input[type=text]::placeholder { color: var(--muted); }
  .toolbar .hint { font-size: 12px; color: var(--muted); }
  .toolbar .spacer { flex: 1; }
  .toolbar label.refresh {
    font-size: 12px; color: var(--muted);
    display: flex; align-items: center; gap: 6px; cursor: pointer; user-select: none;
  }
  .toolbar input[type=checkbox] { accent-color: var(--sage); }
  .refresh-state { font-size: 11px; color: var(--warn); font-style: italic; margin-left: 6px; }
  .toolbar .explainer-link {
    font-size: 12px; color: var(--sage-strong); text-decoration: none;
    border-bottom: 1px dotted var(--sage); padding-bottom: 1px;
  }
  .toolbar .explainer-link:hover { color: var(--ink); border-bottom-color: var(--ink); }
  .raw-code {
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 10.5px; color: var(--muted); margin-left: 4px;
  }

  .table-card {
    background: var(--card); border: 1px solid var(--rule); border-radius: 12px;
    overflow: hidden;
  }
  table { border-collapse: collapse; width: 100%; }
  thead th {
    background: var(--sage-soft); color: var(--ink-soft);
    font-weight: 700; font-size: 10.5px; letter-spacing: .8px;
    text-transform: uppercase; text-align: left;
    padding: 11px 14px; border-bottom: 1px solid var(--rule);
    position: sticky; top: 0; z-index: 1;
  }
  tbody tr.summary { cursor: pointer; transition: background .12s; }
  tbody tr.summary td {
    padding: 11px 14px; font-size: 13px; border-bottom: 1px solid var(--rule);
    vertical-align: middle; color: var(--ink-soft);
  }
  tbody tr.summary td:nth-child(3) { color: var(--ink); font-weight: 500; }
  tbody tr.summary:hover { background: var(--card-alt); }
  tbody tr.summary.open { background: var(--sage-soft); }
  tbody tr.summary.open td { border-bottom-color: transparent; }

  td.chev { width: 28px; text-align: center; }
  .chev-icon {
    display: inline-block; width: 0; height: 0;
    border-left: 5px solid var(--muted);
    border-top: 4px solid transparent;
    border-bottom: 4px solid transparent;
    transition: transform .15s;
  }
  tbody tr.summary.open .chev-icon { transform: rotate(90deg); border-left-color: var(--sage-strong); }

  td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; white-space: nowrap; }

  .tag {
    display: inline-block; padding: 2px 8px; border-radius: 10px;
    font-size: 10.5px; font-weight: 700; border: 1px solid; letter-spacing: .3px;
  }
  .tag-grafana { color: var(--warn); border-color: rgba(161,100,43,.35); background: var(--warn-soft); }
  .tag-drain3 { color: var(--info); border-color: rgba(74,115,147,.35); background: var(--info-soft); }
  .tag-default { color: var(--muted); border-color: var(--rule); background: var(--bg); }

  .sev { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .5px; }
  .sev-critical { color: var(--danger); }
  .sev-warning { color: var(--warn); }
  .sev-info, .sev-low { color: var(--muted); }

  .pill {
    display: inline-block; padding: 3px 10px; border-radius: 999px;
    font-size: 11px; font-weight: 700; letter-spacing: .4px; text-transform: uppercase;
  }
  .pill-escalate { background: var(--danger-soft); color: var(--danger); border: 1px solid rgba(161,57,58,.30); }
  .pill-dismiss  { background: var(--sage-soft); color: var(--sage-strong); border: 1px solid rgba(62,125,77,.32); }
  .pill-inconclusive { background: var(--warn-soft); color: var(--warn); border: 1px solid rgba(161,100,43,.30); }
  .pill-none { background: var(--bg); color: var(--muted); border: 1px solid var(--rule); }

  /* Quality pill — indicates whether the RCA text actually named a cause
     or just hedged with "insufficient data". data_starved rows are what
     future LLM prompts cite as "don't repeat this". */
  .quality {
    display: inline-block; padding: 2px 8px; border-radius: 10px;
    font-size: 10px; font-weight: 700; letter-spacing: .4px;
    text-transform: uppercase; margin-left: 6px; vertical-align: middle;
  }
  .quality-actionable { background: transparent; color: var(--muted); border: 1px solid var(--rule); }
  .quality-data_starved {
    background: var(--warn-soft); color: var(--warn);
    border: 1px solid rgba(161,100,43,.35);
  }
  .quality-data_starved::before { content: "⚠ "; }

  .action { font-size: 12px; color: var(--ink-soft); }
  .action-emailed { color: var(--danger); }
  .action-emailed_raw { color: var(--warn); }
  .action-suppressed { color: var(--ok); }

  tbody tr.detail { display: none; }
  tbody tr.detail.open { display: table-row; }
  tbody tr.detail > td { padding: 0; background: var(--card-alt); border-bottom: 1px solid var(--rule); }

  .panel {
    padding: 20px 24px 22px;
    border-left: 3px solid var(--sage);
    background: linear-gradient(90deg, var(--sage-soft), var(--card-alt) 70%);
  }
  .panel .meta-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 14px 24px; margin-bottom: 18px;
  }
  .panel .m { display: flex; flex-direction: column; gap: 3px; }
  .panel .m .lbl {
    font-size: 10px; font-weight: 700; letter-spacing: 1px;
    text-transform: uppercase; color: var(--muted);
  }
  .panel .m .val {
    font-size: 12.5px; color: var(--ink); font-weight: 500;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    word-break: break-all;
  }
  .panel .m .val.normal {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    font-weight: 500;
  }

  .section { margin-top: 16px; }
  .section h3 {
    font-size: 13px; font-weight: 700; color: var(--ink);
    margin-bottom: 8px; letter-spacing: .2px;
  }
  .section .body {
    background: var(--card); border: 1px solid var(--rule); border-radius: 8px;
    padding: 14px 16px; color: var(--ink-soft); font-size: 13.5px; line-height: 1.65;
    white-space: pre-wrap; word-break: break-word;
  }
  .section .body.empty { color: var(--muted); font-style: italic; }

  tbody tr.empty td {
    text-align: center; color: var(--muted); padding: 36px 14px;
    font-style: italic; font-size: 13px;
  }

  .drain-card {
    background: var(--card);
    border: 1px solid var(--rule);
    border-left: 3px solid var(--info);
    border-radius: 12px;
    padding: 16px 20px 18px;
    margin-bottom: 20px;
  }
  .drain-card .drain-header {
    display: flex; align-items: baseline; gap: 12px;
    margin-bottom: 14px;
  }
  .drain-card .drain-header .eyebrow {
    font-size: 10.5px; font-weight: 700; letter-spacing: 1.5px;
    text-transform: uppercase; color: var(--muted);
  }
  .drain-card .drain-header h2 {
    font-size: 15px; font-weight: 700; color: var(--ink);
    letter-spacing: -.2px;
  }
  .drain-card .drain-header .anomaly-rate {
    margin-left: auto;
    font-size: 12px; color: var(--muted);
  }
  .drain-card .drain-header .anomaly-rate strong { color: var(--info); font-weight: 700; }
  .drain-tiles {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px; margin-bottom: 14px;
  }
  .drain-tile {
    display: flex; flex-direction: column; gap: 3px;
    padding: 10px 14px;
    background: var(--card-alt);
    border: 1px solid var(--rule);
    border-radius: 8px;
  }
  .drain-tile .num { font-size: 20px; font-weight: 700; color: var(--ink); letter-spacing: -.2px; }
  .drain-tile .lbl {
    font-size: 10.5px; font-weight: 600; letter-spacing: .4px;
    text-transform: uppercase; color: var(--muted);
  }
  .drain-patterns { margin-top: 4px; }
  .drain-patterns summary {
    cursor: pointer; user-select: none; list-style: none;
    font-size: 10.5px; font-weight: 700; letter-spacing: 1px;
    text-transform: uppercase; color: var(--muted);
    padding: 4px 0; display: inline-flex; align-items: center; gap: 6px;
  }
  .drain-patterns summary::-webkit-details-marker { display: none; }
  .drain-patterns summary::before {
    content: ""; display: inline-block; width: 0; height: 0;
    border-left: 4px solid var(--muted);
    border-top: 3px solid transparent; border-bottom: 3px solid transparent;
    transition: transform .15s;
  }
  .drain-patterns[open] summary::before { transform: rotate(90deg); }
  .drain-patterns summary:hover { color: var(--ink); }
  .drain-patterns ol {
    padding-left: 22px; margin-top: 6px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px; color: var(--ink-soft);
  }
  .drain-patterns ol li { padding: 2px 0; word-break: break-word; }
  .drain-patterns .none {
    color: var(--muted); font-style: italic; font-size: 12px; margin-top: 6px;
  }

  /* Deep-link chips on decision row: tiny Grafana/Loki/Jaeger shortcuts */
  .deep-chip {
    display: inline-block; padding: 2px 8px; border-radius: 6px;
    font-size: 10px; font-weight: 700; letter-spacing: .3px; text-transform: uppercase;
    border: 1px solid var(--rule); color: var(--muted); text-decoration: none;
    margin-left: 4px; transition: border-color .12s, color .12s;
  }
  .deep-chip:hover { border-color: var(--sage-strong); color: var(--sage-strong); }
  .deep-chip.dc-grafana { color: var(--warn); border-color: rgba(161,100,43,.25); }
  .deep-chip.dc-grafana:hover { background: var(--warn-soft); }
  .deep-chip.dc-loki { color: var(--info); border-color: rgba(74,115,147,.25); }
  .deep-chip.dc-loki:hover { background: var(--info-soft); }
  .deep-chip.dc-jaeger { color: var(--sage-strong); border-color: rgba(62,125,77,.25); }
  .deep-chip.dc-jaeger:hover { background: var(--sage-soft); }

  /* Detail-panel richer layout — sub-cards for observed value, actions,
     evidence, correlated alerts, deep links. Matches email parity so the
     UI is the "go deep" destination. */
  .obs-card {
    background: var(--card); border: 1px solid var(--rule);
    border-left: 4px solid var(--info);
    border-radius: 10px; padding: 14px 18px; margin-bottom: 14px;
  }
  .obs-card .obs-row { display: flex; gap: 14px; align-items: baseline; margin-bottom: 6px; }
  .obs-card .lbl { font-size: 10.5px; font-weight: 700; letter-spacing: 1px;
    text-transform: uppercase; color: var(--muted); min-width: 140px; }
  .obs-card .val { font-size: 20px; font-weight: 700; color: var(--ink); }
  .obs-card .expr {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px; color: var(--ink-soft); word-break: break-all;
    background: var(--card-alt); padding: 6px 10px; border-radius: 6px; flex: 1;
  }

  .panel-list {
    list-style: none; padding: 0; margin: 0;
    background: var(--card); border: 1px solid var(--rule); border-radius: 8px;
    overflow: hidden;
  }
  .panel-list li {
    padding: 9px 14px; border-bottom: 1px solid var(--rule);
    font-size: 13px; color: var(--ink-soft); word-break: break-word;
  }
  .panel-list li:last-child { border-bottom: none; }
  .panel-list li .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px;
  }

  .correlated-table { width: 100%; border-collapse: collapse; font-size: 12px; background: var(--card); border: 1px solid var(--rule); border-radius: 8px; overflow: hidden; }
  .correlated-table th, .correlated-table td { padding: 7px 12px; text-align: left; border-bottom: 1px solid var(--rule); }
  .correlated-table th { background: var(--sage-soft); font-weight: 700; font-size: 10.5px; letter-spacing: .5px; text-transform: uppercase; color: var(--muted); }
  .correlated-table tr:last-child td { border-bottom: none; }
  .correlated-table td.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; color: var(--muted); }

  .panel-links { display: flex; gap: 8px; flex-wrap: wrap; }
  .panel-link {
    display: inline-block; padding: 6px 12px; border-radius: 6px;
    font-size: 12px; font-weight: 600;
    background: var(--card); border: 1px solid var(--rule); color: var(--ink-soft);
    text-decoration: none; transition: border-color .15s, color .15s;
  }
  .panel-link:hover { border-color: var(--sage-strong); color: var(--sage-strong); }

  /* Placeholder for sections where the LLM emitted nothing — still render
     the section so the UI is consistent + the absence is visible. */
  .panel-empty {
    background: var(--card-alt); border: 1px dashed var(--rule);
    border-radius: 8px; padding: 12px 16px;
    color: var(--muted); font-size: 12.5px; font-style: italic;
    line-height: 1.6;
  }

  /* Copyable PromQL / LogQL rows — since Grafana 13 deep-link format is
     brittle across versions, we hand the user the query as text. */
  .query-row {
    display: flex; gap: 12px; align-items: center;
    margin-bottom: 8px; flex-wrap: wrap;
  }
  .query-lbl {
    font-size: 10.5px; font-weight: 700; letter-spacing: .8px;
    text-transform: uppercase; color: var(--muted);
    min-width: 120px;
  }
  .query-code {
    flex: 1; padding: 8px 12px; border-radius: 6px;
    background: var(--card-alt); border: 1px solid var(--rule);
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px; color: var(--ink-soft);
    word-break: break-all;
    user-select: all; /* triple-click to select all for copying */
  }

  @media (max-width: 700px) {
    body { padding: 18px; }
    .toolbar input[type=text] { min-width: 0; width: 100%; }
    thead th:nth-child(4), tbody td:nth-child(4),
    thead th:nth-child(5), tbody td:nth-child(5) { display: none; }
  }
"""

_DASHBOARD_JS = """
  function toggleDetail(id) {
    var sRow = document.querySelector('tr.summary[data-id="' + id + '"]');
    var dRow = document.getElementById('detail-' + id);
    if (!sRow || !dRow) return;
    sRow.classList.toggle('open');
    dRow.classList.toggle('open');
    // Pause auto-refresh while ANY row is expanded — reloading the page
    // while someone is reading the RCA would be infuriating. Resume once
    // all rows are closed.
    syncRefreshWithPanels();
  }
  function syncRefreshWithPanels() {
    var anyOpen = document.querySelector('tr.summary.open') !== null;
    var cb = document.getElementById('refresh');
    var label = document.getElementById('refresh-state');
    if (anyOpen) {
      // Pause without flipping the checkbox — user stays in "auto-refresh on"
      // mode but the timer is dormant until the panel closes.
      if (window._refreshTimer) { clearInterval(window._refreshTimer); window._refreshTimer = null; }
      if (label) label.textContent = '(paused — a row is open)';
    } else {
      if (cb && cb.checked && !window._refreshTimer) {
        window._refreshTimer = setInterval(function() { window.location.reload(); }, 30000);
      }
      if (label) label.textContent = '';
    }
  }
  function applyFilter() {
    var q = document.getElementById('filter').value.trim().toLowerCase();
    var rows = document.querySelectorAll('tbody tr.summary');
    var shown = 0;
    rows.forEach(function(r) {
      var hay = r.getAttribute('data-search') || '';
      var match = q === '' || hay.indexOf(q) !== -1;
      var id = r.getAttribute('data-id');
      var dRow = document.getElementById('detail-' + id);
      r.style.display = match ? '' : 'none';
      if (dRow && !match && dRow.classList.contains('open')) {
        // collapse detail if its summary is filtered out
        r.classList.remove('open');
        dRow.classList.remove('open');
      }
      if (dRow && !match) dRow.style.display = 'none';
      else if (dRow) dRow.style.display = '';
      if (match) shown++;
    });
    var c = document.getElementById('match-count');
    if (c) c.textContent = shown + ' shown';
  }
  function toggleRefresh() {
    var cb = document.getElementById('refresh');
    if (cb.checked) {
      // Only start the timer if no detail panel is open; syncRefreshWithPanels
      // will start it once everything closes.
      syncRefreshWithPanels();
    } else {
      if (window._refreshTimer) { clearInterval(window._refreshTimer); window._refreshTimer = null; }
      var label = document.getElementById('refresh-state');
      if (label) label.textContent = '';
    }
  }
  document.addEventListener('DOMContentLoaded', function() {
    var f = document.getElementById('filter');
    if (f) f.addEventListener('input', applyFilter);
    applyFilter();
    // Auto-refresh is on by default; honour the checkbox's initial state.
    toggleRefresh();
  });
"""


def _fmt_duration_ms(ms: int | None) -> str:
    """Render an ms duration as 'Xm Ys' / 'Xs' / 'Xms' depending on scale.

    Anything under 1s stays in ms (sub-second resolution matters for MCP latency);
    anything between 1s and 60s shows '12.3 s' with one decimal; anything over a
    minute rolls up to 'N min M s' (whole seconds), dropping the trailing ' 0 s'
    when the total happens to land on a whole-minute mark.
    """
    if ms is None or ms < 0:
        return "—"
    if ms < 1000:
        return f"{ms} ms"
    total_s = ms / 1000
    if total_s < 60:
        return f"{total_s:.1f} s"
    m = int(total_s // 60)
    s = int(round(total_s - m * 60))
    if s == 60:
        m += 1
        s = 0
    return f"{m} min {s} s" if s else f"{m} min"


def _quality_pill(quality: str | None) -> str:
    """Render the rca_quality post-hoc tag as a small pill next to the verdict.

    Engineer-readable labels: actionable→"fits", data_starved→"thin",
    needs_review→"review". Hover tooltip carries the full meaning so the
    operator can disambiguate without leaving the dashboard.
    """
    if not quality:
        return ""
    label_map = {
        "actionable":   ("fits",    "Concrete RCA + ≥1 valid suggested_action — operator has a clear next step"),
        "data_starved": ("thin",    "RCA hedged or evidence empty — model didn't have enough signal to commit"),
        "needs_review": ("review",  "Confidence below the floor (0.30) OR validator flagged the row — surface to a human"),
    }
    short, tip = label_map.get(quality, (quality.replace("_", " "), quality))
    cls = "quality-actionable" if quality == "actionable" else "quality-data_starved"
    return f'<span class="quality {cls}" title="{_html.escape(tip)}">{_html.escape(short)}</span>'


def _humanize_action(action: str | None) -> tuple[str, str]:
    """Map the internal action_taken enum to a (label, tooltip) pair.

    The codes (emailed / emailed_raw / suppressed / drop_alert) are
    pipeline-internal; engineers reading the dashboard for the first
    time shouldn't have to grep the source to understand them.
    """
    a = (action or "").lower()
    if a == "emailed":
        return "Notified", "Triage emailed the on-call (LLM produced a verdict)"
    if a == "emailed_raw":
        return "Notified (no LLM)", "LLM unavailable or timed out — raw alert forwarded for human review"
    if a == "suppressed":
        return "Suppressed", "Pre-LLM suppression — duplicate fingerprint inside the dedup window, or recent dismissed history"
    if a == "drop_alert":
        return "Dropped", "Below severity threshold or matched a quiet-hours rule"
    if not action or action == "—":
        return "—", "No action recorded"
    return action, action


def _humanize_triage_path(triage_decision: str | None) -> tuple[str, str]:
    """Translate triage_decision enum values to human labels."""
    t = (triage_decision or "").lower()
    if t == "investigate":
        return "Investigated", "Pipeline ran the full LLM investigation"
    if t == "triage_suppressed":
        return "Deduped", "Same alert fingerprint already seen inside the dedup window — short-path"
    if t == "dismiss":
        return "Dismissed", "Verdict was DISMISS — alert judged not actionable"
    if t == "dismiss_shelved":
        return "Shelved", "Drain3 anomaly with no correlation found — awaiting recurrence (≥3 fires in 7d → escalate)"
    if t == "escalate":
        return "Escalated", "Verdict was ESCALATE — alert raised to operator"
    if t == "timeout_passthrough":
        return "Timed out", "Pipeline exceeded its budget — raw alert was forwarded with no LLM verdict"
    if not triage_decision or triage_decision == "—":
        return "—", "No triage path recorded"
    return triage_decision, triage_decision


# Match 10-digit Unix timestamps the LLM sometimes embeds in prose.
# (10-digit covers 2001–2286 in seconds; we render as Casablanca local time.)
_UNIX_TS_PATTERN = _re.compile(r"\b(1[5-9][0-9]{8}|2[0-9]{9})\b")


def _humanize_unix_timestamps(text: str) -> str:
    """Replace any 10-digit Unix timestamp in the text with `<unix> (<local>)`.

    The LLM occasionally writes "...observed at 1776985940" instead of a
    human time. We post-process the rendered text so engineers don't have
    to mentally convert. Casablanca local zone matches the rest of the UI.
    """
    if not text:
        return text
    try:
        from zoneinfo import ZoneInfo
    except ImportError:
        return text
    tz = ZoneInfo("Africa/Casablanca")
    def _sub(m):
        try:
            ts = int(m.group(1))
            from datetime import datetime
            local = datetime.fromtimestamp(ts, tz=tz)
            return f"{m.group(1)} ({local.strftime('%Y-%m-%d %H:%M')})"
        except (ValueError, OverflowError):
            return m.group(0)
    return _UNIX_TS_PATTERN.sub(_sub, text)


def _deep_chips(service: str | None, alert_name: str | None) -> str:
    """Small shortcut chip in the decision row.

    Only the Grafana alerting list chip is reliable today. Both the Loki
    Explore URL (Grafana 13 format changed) and the Jaeger v2 search URL
    have been emitting 404s on this deploy. Rather than ship broken chips
    we show the LogQL/PromQL as copyable text in the detail panel below.
    """
    return (
        f'<a href="{settings.grafana_url}/alerting/list" class="deep-chip dc-grafana" '
        f'target="_blank" rel="noopener" title="Open Grafana alerting" '
        f'onclick="event.stopPropagation()">Grafana</a>'
    )


def _verdict_pill(verdict: str | None, action: str | None) -> str:
    v = (verdict or '').lower()
    if v == 'escalate':
        return '<span class="pill pill-escalate">escalate</span>'
    if v == 'dismiss':
        return '<span class="pill pill-dismiss">dismiss</span>'
    if v == 'inconclusive':
        return '<span class="pill pill-inconclusive">inconclusive</span>'
    if action == 'emailed_raw':
        return '<span class="pill pill-inconclusive">timeout</span>'
    return '<span class="pill pill-none">—</span>'


def _source_tag(source: str) -> str:
    s = (source or '').lower()
    cls = 'tag-grafana' if s == 'grafana' else 'tag-drain3' if s == 'drain3' else 'tag-default'
    return f'<span class="tag {cls}">{_html.escape(source or "—")}</span>'


def _render_drain3_panel(stats: dict) -> str:
    """Surface DrainAnalyzer.get_stats() as a sage-styled card on /dashboard.

    Tiles: templates learned, lines processed, anomalies flagged. Header carries
    the current anomaly rate; bottom lists the five most recent templates so
    operators can see at a glance what Drain3 is actually pattern-matching.
    """
    total_clusters = int(stats.get('total_clusters') or 0)
    lines = int(stats.get('total_lines_processed') or 0)
    anomalies = int(stats.get('total_anomalies') or 0)
    rate_raw = float(stats.get('recent_anomaly_rate') or 0.0)
    rate_pct = f"{rate_raw * 100:.2f}%"
    patterns = stats.get('top_new_patterns') or []

    if patterns:
        pattern_html = '<ol>' + ''.join(
            f'<li>{_html.escape(str(p))}</li>' for p in patterns[:5]
        ) + '</ol>'
    else:
        pattern_html = '<div class="none">No templates learned yet — waiting on log ingestion.</div>'

    return (
        '<div class="drain-card">'
        '  <div class="drain-header">'
        '    <div class="eyebrow">Log template analysis</div>'
        '    <h2>Drain3 state</h2>'
        f'    <div class="anomaly-rate">Anomaly rate <strong>{rate_pct}</strong></div>'
        '  </div>'
        '  <div class="drain-tiles">'
        f'    <div class="drain-tile"><div class="num">{total_clusters}</div><div class="lbl">Templates learned</div></div>'
        f'    <div class="drain-tile"><div class="num">{lines:,}</div><div class="lbl">Lines processed</div></div>'
        f'    <div class="drain-tile"><div class="num">{anomalies:,}</div><div class="lbl">Anomalies flagged</div></div>'
        '  </div>'
        '  <details class="drain-patterns">'
        '    <summary>Show most recent templates</summary>'
        f'    {pattern_html}'
        '  </details>'
        '</div>'
    )


def _instance_display_ui(instance: str | None) -> str:
    """Same logic as notifier._instance_display but lives in main.py to avoid
    a cross-module import for the dashboard path. Turns '10.0.1.194:9100' into
    '10.0.1.194:9100 (observability-rca-k3s · node-exporter)'.
    """
    if not instance or instance == "unknown":
        return "—"
    host, _, port = instance.partition(":")
    friendly = []
    if host in settings.instance_hosts:
        friendly.append(settings.instance_hosts[host])
    if port in settings.instance_ports:
        friendly.append(settings.instance_ports[port])
    if friendly:
        return f"{instance} ({' · '.join(friendly)})"
    return instance


def _render_detail_panel(r: dict) -> str:
    """Rich expandable panel — richer than the email, by design. The UI is
    the "go deep" destination, the email is the at-a-glance summary.
    """
    import json as _json
    import urllib.parse as _urllib

    did = _html.escape(r.get('id') or '')
    ts_full = _html.escape(_to_local_time(r.get('timestamp'), with_zone_label=True))
    fingerprint = _html.escape(r.get('alert_fingerprint') or '—')
    triage_path_label, triage_path_tip = _humanize_triage_path(r.get('triage_decision'))
    triage = (
        f'<span title="{_html.escape(triage_path_tip)}">{_html.escape(triage_path_label)}'
        f'<span class="raw-code"> · {_html.escape(r.get("triage_decision") or "—")}</span></span>'
    )
    confidence = _html.escape(str(r.get('llm_confidence') or '—'))
    action_label, action_tip = _humanize_action(r.get('action_taken'))
    action = (
        f'<span title="{_html.escape(action_tip)}">{_html.escape(action_label)}'
        f'<span class="raw-code"> · {_html.escape(r.get("action_taken") or "—")}</span></span>'
    )
    duration = int(r.get('investigation_duration_ms') or 0)
    service = r.get('affected_service') or ''
    quality = r.get('rca_quality') or '—'

    # Meta-grid (top) — identity + core LLM facts.
    meta_html = (
        '<div class="meta-grid">'
        f'  <div class="m"><div class="lbl">Timestamp (local)</div><div class="val">{ts_full}</div></div>'
        f'  <div class="m"><div class="lbl">Decision ID</div><div class="val">{did}</div></div>'
        f'  <div class="m"><div class="lbl">Alert fingerprint</div><div class="val">{fingerprint}</div></div>'
        f'  <div class="m"><div class="lbl">Service</div><div class="val normal">{_html.escape(service)}</div></div>'
        f'  <div class="m"><div class="lbl">Component / signal</div><div class="val normal">{_html.escape((r.get("alert_component") or "—"))} · {_html.escape(r.get("alert_signal") or "—")}</div></div>'
        f'  <div class="m"><div class="lbl">Instance</div><div class="val normal">{_html.escape(_instance_display_ui(r.get("alert_instance")))}</div></div>'
        f'  <div class="m"><div class="lbl">Triage path</div><div class="val normal">{triage}</div></div>'
        f'  <div class="m"><div class="lbl">LLM confidence / quality</div><div class="val normal">{confidence} · {_html.escape(quality).replace("_"," ")}</div></div>'
        f'  <div class="m"><div class="lbl">Action</div><div class="val normal">{action} · {_fmt_duration_ms(duration)}</div></div>'
        '</div>'
    )

    # Observed value + PromQL — the lede. Mirrors the email's lede card.
    observed = r.get('observed_value')
    promql = r.get('promql_expr')
    if observed or promql:
        obs_html = (
            '<div class="obs-card">'
            f'  <div class="obs-row"><div class="lbl">Observed value</div><div class="val">{_html.escape(observed or "—")}</div></div>'
            f'  <div class="obs-row"><div class="lbl">PromQL</div><div class="expr">{_html.escape(promql or "—")}</div></div>'
            '</div>'
        )
    else:
        obs_html = ''

    # RCA + reasoning. Post-process to humanize 10-digit Unix timestamps the
    # LLM occasionally embeds in prose ("observed at 1776985940") so engineers
    # don't have to mentally convert.
    rca = _humanize_unix_timestamps(_html.escape(r.get('rca_report') or ''))
    reasoning = _humanize_unix_timestamps(_html.escape(r.get('llm_reasoning') or ''))
    rca_text = rca or '<em>(no RCA report captured — decision took the suppress or timeout path)</em>'
    reasoning_text = reasoning or '<em>(no reasoning captured)</em>'

    # Suggested actions — always render the section so the user sees what's
    # there (or not). An empty list means the LLM emitted nothing, which is
    # itself useful signal ("model didn't have anything concrete to propose").
    try:
        actions = _json.loads(r['suggested_actions']) if r.get('suggested_actions') else []
    except (ValueError, TypeError):
        actions = []
    if actions:
        items = ''.join(f'<li>{_html.escape(str(a))}</li>' for a in actions)
        actions_inner = f'<ul class="panel-list">{items}</ul>'
    else:
        actions_inner = (
            '<div class="panel-empty">No concrete actions proposed by the model for this alert. '
            'Either the RCA was confident enough that no follow-up is needed, or the model '
            'did not have enough context to suggest specific commands.</div>'
        )
    actions_html = f'<div class="section"><h3>Suggested actions</h3>{actions_inner}</div>'

    # Evidence — same always-render pattern.
    try:
        evidence = _json.loads(r['evidence']) if r.get('evidence') else []
    except (ValueError, TypeError):
        evidence = []
    if evidence:
        items = ''.join(f'<li>{_html.escape(str(e))}</li>' for e in evidence)
        evidence_inner = f'<ul class="panel-list">{items}</ul>'
    else:
        evidence_inner = (
            '<div class="panel-empty">No evidence items emitted. '
            'Check the Root-cause analysis above — the model may have reasoned from the '
            'observed value alone.</div>'
        )
    evidence_html = f'<div class="section"><h3>Evidence cited</h3>{evidence_inner}</div>'

    # Queries block — LogQL that would filter logs for this service,
    # presented as copyable text since Grafana 13 deep-link format is
    # brittle across versions. The user copies and pastes into Explore.
    queries_html = ''
    if service and service != "unknown":
        logql = f'{{service_name="{_html.escape(service)}"}}'
        queries_html = (
            '<div class="section">'
            '<h3>Queries you can paste into Grafana Explore</h3>'
            '<div class="query-row"><span class="query-lbl">LogQL (Loki)</span>'
            f'<code class="query-code">{logql}</code></div>'
        )
        if r.get('promql_expr'):
            queries_html += (
                '<div class="query-row"><span class="query-lbl">PromQL (rule)</span>'
                f'<code class="query-code">{_html.escape(r["promql_expr"])}</code></div>'
            )
        queries_html += '</div>'

    # Anomaly summary (if the LLM or Drain3 noted one).
    anomaly = r.get('anomaly_summary')
    anomaly_html = ''
    if anomaly:
        anomaly_html = (
            '<div class="section"><h3>Drain3 anomaly summary</h3>'
            f'<div class="body">{_html.escape(anomaly)}</div></div>'
        )

    # Correlated alerts (within ±5 min of this one).
    correlated_html = ''
    try:
        correlated = _json.loads(r['correlated_alerts']) if r.get('correlated_alerts') else []
    except (ValueError, TypeError):
        correlated = []
    if correlated:
        rows = ''.join(
            f'<tr><td class="mono">{_html.escape(_to_local_time(c.get("timestamp")))}</td>'
            f'<td>{_html.escape(c.get("alert_name") or "?")}</td>'
            f'<td>{_html.escape(c.get("affected_service") or "?")}</td>'
            f'<td>{_html.escape(c.get("llm_verdict") or "—")}</td>'
            f'<td>{_html.escape(c.get("rca_quality") or "—")}</td></tr>'
            for c in correlated[:15]
        )
        correlated_html = (
            '<div class="section">'
            f'<h3>Correlated alerts <span style="font-weight:400;color:var(--muted);font-size:12px">(within ±5 min)</span></h3>'
            '<table class="correlated-table"><thead><tr>'
            '<th>When (local)</th><th>Alert</th><th>Service</th><th>Verdict</th><th>Quality</th>'
            f'</tr></thead><tbody>{rows}</tbody></table></div>'
        )

    # Deep links. The pre-filtered Loki URL format changed with Grafana 13
    # (deprecated `left=` params silently 404) and the Jaeger v2 UI URL is
    # also unreliable on the current deploy. Rather than emit chips that
    # 404, we only emit the one link we know always works (Grafana's
    # alerting list) and show the raw LogQL/PromQL queries as copyable
    # text in the panel above. Users can paste them into Explore manually
    # — slightly less slick but never broken.
    links = [(f'{settings.grafana_url}/alerting/list', 'Grafana — alerting list')]
    links_html = ''.join(
        f'<a class="panel-link" href="{url}" target="_blank" rel="noopener">{_html.escape(label)}</a>'
        for url, label in links
    )
    links_block = f'<div class="section"><h3>Deep links</h3><div class="panel-links">{links_html}</div></div>'

    return (
        '<div class="panel">'
        + meta_html
        + obs_html
        + f'<div class="section"><h3>Root-cause analysis</h3><div class="body">{rca_text}</div></div>'
        + actions_html
        + evidence_html
        + f'<div class="section"><h3>Model reasoning</h3><div class="body">{reasoning_text}</div></div>'
        + anomaly_html
        + correlated_html
        + queries_html
        + links_block
        + '</div>'
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    rows = await _store.get_decisions(limit=100)
    drain_stats = _drain.get_stats() if _drain is not None else {}

    total = len(rows)
    escalated = sum(1 for r in rows if r.get('action_taken') == 'emailed')
    dismissed = sum(1 for r in rows if r.get('action_taken') == 'suppressed')
    timed_out = sum(1 for r in rows if r.get('action_taken') == 'emailed_raw')
    suppressed_pre = sum(1 for r in rows if (r.get('triage_decision') or '').lower() == 'triage_suppressed')

    body_rows = ""
    for r in rows:
        did = _html.escape(r.get('id') or '')
        ts = _html.escape(_to_local_time(r.get('timestamp')))
        alert_name = r.get('alert_name') or '—'
        service = r.get('affected_service') or '—'
        severity = (r.get('severity') or '').lower()
        action = r.get('action_taken') or '—'
        duration = int(r.get('investigation_duration_ms') or 0)
        verdict = r.get('llm_verdict') or ''

        # Data used by the client-side filter — includes everything visible + the RCA text
        search_blob = ' '.join([
            alert_name, service, r.get('alert_source') or '',
            severity, verdict, action,
            r.get('rca_report') or '', r.get('llm_reasoning') or '',
        ]).lower()

        body_rows += (
            f'<tr class="summary" data-id="{did}" data-search="{_html.escape(search_blob, quote=True)}" onclick="toggleDetail(\'{did}\')">'
            f'  <td class="chev"><span class="chev-icon"></span></td>'
            f'  <td class="mono">{ts}</td>'
            f'  <td>{_html.escape(alert_name)}</td>'
            f'  <td>{_source_tag(r.get("alert_source") or "")}</td>'
            f'  <td>{_html.escape(service)}{_deep_chips(service, alert_name)}</td>'
            f'  <td><span class="sev sev-{_html.escape(severity)}">{_html.escape(severity or "—")}</span></td>'
            f'  <td>{_verdict_pill(verdict, action)}{_quality_pill(r.get("rca_quality"))}</td>'
            f'  <td class="action action-{_html.escape(action)}" title="{_html.escape(_humanize_action(action)[1])}">{_html.escape(_humanize_action(action)[0])}</td>'
            f'  <td class="mono">{_fmt_duration_ms(duration)}</td>'
            f'</tr>'
            f'<tr class="detail" id="detail-{did}"><td colspan="9">{_render_detail_panel(r)}</td></tr>'
        )

    if not body_rows:
        body_rows = '<tr class="empty"><td colspan="9">No decisions yet. Fire an alert and watch this space.</td></tr>'

    return (
        f'<!DOCTYPE html><html lang="en"><head>'
        f'<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">'
        f'<title>RCA Decisions · Triage Service</title>'
        f'<style>{_DASHBOARD_CSS}</style>'
        f'</head><body>'
        f'<div class="container">'
        f'  <div class="header">'
        f'    <div class="eyebrow">AI root-cause triage</div>'
        f'    <h1>Decision <span class="accent">history</span></h1>'
        f'    <div class="subtitle">Recent verdicts produced by the triage pipeline. Click any row to review the full root-cause analysis.</div>'
        f'  </div>'
        f'  <div class="stats">'
        f'    <div class="stat t-total"><div class="num">{total}</div><div class="lbl">Total decisions</div></div>'
        f'    <div class="stat t-esc" title="Verdict was ESCALATE and an email was sent"><div class="num">{escalated}</div><div class="lbl">Notified</div></div>'
        f'    <div class="stat t-dismiss" title="Verdict was DISMISS — alert judged not actionable"><div class="num">{dismissed}</div><div class="lbl">Dismissed</div></div>'
        f'    <div class="stat t-suppress" title="Pre-LLM dedup — same fingerprint already seen in window"><div class="num">{suppressed_pre}</div><div class="lbl">Deduped</div></div>'
        f'    <div class="stat t-timeout" title="Pipeline exceeded its budget — raw alert forwarded with no LLM verdict"><div class="num">{timed_out}</div><div class="lbl">Timed out</div></div>'
        f'  </div>'
        f'  {_render_drain3_panel(drain_stats)}'
        f'  <div class="toolbar">'
        f'    <input id="filter" type="text" placeholder="Filter by alert name, service, verdict, or RCA text" autocomplete="off" />'
        f'    <span class="hint" id="match-count"></span>'
        f'    <span class="spacer"></span>'
        f'    <a class="explainer-link" href="/dashboard/guide" title="Read the dashboard guide — every column, code, and abbreviation explained">What do these mean?</a>'
        f'    <label class="refresh"><input id="refresh" type="checkbox" checked onchange="toggleRefresh()" /> Auto-refresh every 30 seconds <span id="refresh-state" class="refresh-state"></span></label>'
        f'  </div>'
        f'  <div class="table-card">'
        f'    <table>'
        f'      <thead><tr>'
        f'        <th></th>'
        f'        <th title="Wall-clock time the decision was persisted, in Casablanca local zone (GMT+1)">Time</th>'
        f'        <th title="Alert rule name as configured in Grafana">Alert</th>'
        f'        <th title="Where the alert came from: grafana=metric rule, drain3=log-template anomaly">Source</th>'
        f'        <th title="The service the alert is about">Service</th>'
        f'        <th title="Alert severity: critical / warning / info">Severity</th>'
        f'        <th title="LLM verdict (escalate / dismiss / inconclusive) + RCA quality pill (fits / thin / review)">Verdict</th>'
        f'        <th title="What the pipeline did downstream of the verdict (Notified / Suppressed / Dropped / Notified-no-LLM)">Action</th>'
        f'        <th title="End-to-end pipeline duration including MCP context-gathering + LLM inference">Duration</th>'
        f'      </tr></thead>'
        f'      <tbody>{body_rows}</tbody>'
        f'    </table>'
        f'  </div>'
        f'</div>'
        f'<script>{_DASHBOARD_JS}</script>'
        f'</body></html>'
    )


_GUIDE_CSS = """
  :root {
    --bg: #f6f7f3;
    --card: #ffffff;
    --card-alt: #fbfcf8;
    --ink: #1f2a23;
    --ink-soft: #3f4a42;
    --muted: #6b7a6f;
    --rule: #e0e6df;
    --rule-strong: #c8d3c5;
    --sage: #5d8c6b;
    --sage-strong: #3e7d4d;
    --sage-soft: #eef6ee;
    --warn: #a1642b;
    --warn-soft: #f6efe3;
    --danger: #b04550;
    --danger-soft: #f6e4e6;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body {
    font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
    background: var(--bg); color: var(--ink); line-height: 1.65; font-size: 15px;
    -webkit-font-smoothing: antialiased;
  }
  code, pre, .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.88em;
  }
  .container { max-width: 1080px; margin: 0 auto; padding: 0 36px 60px; }
  .header {
    padding: 36px 36px 28px; max-width: 1080px; margin: 0 auto;
  }
  .header .eyebrow {
    font-size: 11px; font-weight: 700; letter-spacing: 1.4px;
    text-transform: uppercase; color: var(--sage-strong); margin-bottom: 8px;
  }
  .header h1 {
    font-size: 30px; font-weight: 700; letter-spacing: -0.4px;
    margin-bottom: 10px; color: var(--ink);
  }
  .header h1 .accent { color: var(--sage-strong); }
  .header .subtitle { color: var(--ink-soft); max-width: 760px; }
  .header .nav-back {
    display: inline-flex; align-items: center; gap: 6px;
    margin-top: 14px; padding: 6px 12px; border-radius: 8px;
    background: var(--card); border: 1px solid var(--rule);
    color: var(--sage-strong); font-size: 13px; font-weight: 600;
    text-decoration: none;
  }
  .header .nav-back:hover { border-color: var(--sage); }
  .layout {
    display: grid; grid-template-columns: 240px 1fr; gap: 36px; margin-top: 8px;
  }
  @media (max-width: 900px) {
    .layout { grid-template-columns: 1fr; }
    .toc { position: static; }
  }
  .toc {
    position: sticky; top: 16px; align-self: start;
    background: var(--card); border: 1px solid var(--rule);
    border-radius: 12px; padding: 18px 20px; font-size: 13px;
  }
  .toc h4 {
    font-size: 11px; font-weight: 700; letter-spacing: 1.2px;
    text-transform: uppercase; color: var(--muted); margin-bottom: 10px;
  }
  .toc ol { list-style: none; }
  .toc li { margin-bottom: 4px; }
  .toc a {
    color: var(--ink-soft); text-decoration: none;
    border-bottom: 1px dashed transparent;
  }
  .toc a:hover { color: var(--sage-strong); border-bottom-color: var(--sage); }
  .toc li.sub { padding-left: 14px; font-size: 12px; }
  .toc li.sub a { color: var(--muted); }
  .content > .card {
    background: var(--card); border: 1px solid var(--rule);
    border-radius: 12px; padding: 22px 26px; margin-bottom: 18px;
  }
  .content h2 {
    font-size: 22px; font-weight: 700; margin: 0 0 14px;
    letter-spacing: -0.2px; color: var(--ink); scroll-margin-top: 16px;
    padding-bottom: 8px; border-bottom: 1px solid var(--rule);
  }
  .content h3 {
    font-size: 16px; font-weight: 700; margin: 22px 0 8px;
    color: var(--ink); scroll-margin-top: 16px;
  }
  .content h4 { font-size: 13px; font-weight: 700; margin: 16px 0 4px; color: var(--ink); }
  .content p { margin-bottom: 12px; color: var(--ink-soft); }
  .content p strong { color: var(--ink); font-weight: 600; }
  .content ul, .content ol { margin: 6px 0 14px 22px; color: var(--ink-soft); }
  .content li { margin-bottom: 5px; }
  .content code {
    background: var(--sage-soft); border: 1px solid var(--rule);
    padding: 1px 6px; border-radius: 4px; font-size: 0.85em; color: var(--sage-strong);
  }
  .content pre {
    background: var(--card-alt); border: 1px solid var(--rule);
    padding: 12px 14px; border-radius: 8px; margin: 10px 0 14px;
    overflow-x: auto; line-height: 1.5;
  }
  .content pre code { background: none; border: none; padding: 0; color: var(--ink); }
  .content a {
    color: var(--sage-strong); text-decoration: none;
    border-bottom: 1px dashed rgba(62, 125, 77, 0.4);
  }
  .content a:hover { border-bottom-style: solid; }
  table {
    width: 100%; border-collapse: collapse; margin: 8px 0 16px; font-size: 13px;
  }
  table th, table td {
    padding: 9px 12px; border-bottom: 1px solid var(--rule);
    text-align: left; vertical-align: top;
  }
  table th {
    font-size: 11px; font-weight: 700; letter-spacing: 1px;
    text-transform: uppercase; color: var(--muted); background: var(--sage-soft);
  }
  table tr:hover td { background: var(--card-alt); }
  table td.code-cell {
    font-family: ui-monospace, monospace; font-size: 12.5px;
    color: var(--sage-strong); white-space: nowrap;
  }
  table td.label-cell { font-weight: 600; color: var(--ink); white-space: nowrap; }
  .pill {
    display: inline-block; font-size: 11px; font-weight: 600;
    padding: 2px 8px; border-radius: 10px; border: 1px solid;
  }
  .pill.sage { color: var(--sage-strong); border-color: var(--sage); background: var(--sage-soft); }
  .pill.warn { color: var(--warn); border-color: var(--warn); background: var(--warn-soft); }
  .pill.danger { color: var(--danger); border-color: var(--danger); background: var(--danger-soft); }
  .pill.ink { color: var(--ink); border-color: var(--rule-strong); background: var(--card-alt); }
  .glossary dt {
    font-family: ui-monospace, monospace; font-size: 13px;
    color: var(--sage-strong); margin-top: 10px; font-weight: 600;
  }
  .glossary dt:first-child { margin-top: 0; }
  .glossary dd { margin: 3px 0 0 18px; color: var(--ink-soft); font-size: 14px; }
  .scenario {
    background: var(--sage-soft); border: 1px solid var(--rule);
    border-radius: 8px; padding: 14px 18px; margin: 12px 0;
  }
  .scenario h4 { color: var(--sage-strong); margin-top: 0; font-size: 13px; }
  .scenario p { font-size: 14px; }
  .callout {
    border-left: 3px solid var(--sage); border-radius: 0 8px 8px 0;
    padding: 12px 16px; margin: 14px 0; background: var(--sage-soft);
  }
  .callout-label {
    font-size: 11px; font-weight: 700; letter-spacing: 1px;
    text-transform: uppercase; color: var(--sage-strong); margin-bottom: 5px;
  }
  .deep-link {
    display: inline-block; margin-top: 8px; font-size: 12px;
    color: var(--muted); border-bottom: 1px dotted var(--muted);
    text-decoration: none;
  }
  .deep-link:hover { color: var(--sage-strong); border-bottom-color: var(--sage); }
"""


@app.get("/dashboard/guide", response_class=HTMLResponse)
async def dashboard_guide():
    """Local operator-reference guide for the dashboard.

    Lina 2026-04-27: pulled this out of github-pages so the link stays
    inside the same host as the dashboard itself, and recolored to match
    the sage/white palette so it's visually coherent with /dashboard.
    The fuller monitoring-docs version of the same content remains at
    https://linalaaraich.github.io/monitoring-docs/dashboard-guide.html
    for deep-dive reference, linked at the bottom of this page.
    """
    return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard Guide · Triage Service</title>
<style>{_GUIDE_CSS}</style></head><body>

<div class="header">
  <div class="eyebrow">AI root-cause triage · operator reference</div>
  <h1>Dashboard <span class="accent">guide</span></h1>
  <p class="subtitle">Every column, every internal code, every abbreviation explained.
  If a label in the triage UI is unclear, find it here. The same content as the
  monitoring-docs page, served locally so the dashboard stays self-contained.</p>
  <a href="/dashboard" class="nav-back">← Back to decisions</a>
</div>

<div class="container">
<div class="layout">

<aside class="toc">
  <h4>Contents</h4>
  <ol>
    <li><a href="#stats">1. Stats tiles</a></li>
    <li><a href="#drain3">2. Drain3 panel</a></li>
    <li><a href="#columns">3. Table columns</a></li>
    <li class="sub"><a href="#col-time">3.1 Time</a></li>
    <li class="sub"><a href="#col-alert">3.2 Alert</a></li>
    <li class="sub"><a href="#col-source">3.3 Source</a></li>
    <li class="sub"><a href="#col-service">3.4 Service</a></li>
    <li class="sub"><a href="#col-severity">3.5 Severity</a></li>
    <li class="sub"><a href="#col-verdict">3.6 Verdict + quality</a></li>
    <li class="sub"><a href="#col-action">3.7 Action</a></li>
    <li class="sub"><a href="#col-duration">3.8 Duration</a></li>
    <li><a href="#detail">4. The detail panel</a></li>
    <li><a href="#glossary">5. Codes &amp; abbreviations</a></li>
    <li><a href="#scenarios">6. Reading common rows</a></li>
  </ol>
</aside>

<article class="content">

<div class="card">
  <h2 id="stats">1. Stats tiles</h2>
  <p>The five tiles count rows in the loaded window (last 100 decisions):</p>
  <table>
    <thead><tr><th>Tile</th><th>Means</th><th>Source field</th></tr></thead>
    <tbody>
      <tr><td class="label-cell">Total decisions</td><td>Every row in the window, including suppressed and timed-out.</td><td><code>len(rows)</code></td></tr>
      <tr><td class="label-cell">Notified</td><td>Verdict was ESCALATE and the email was sent successfully.</td><td><code>action_taken == "emailed"</code></td></tr>
      <tr><td class="label-cell">Dismissed</td><td>Verdict was DISMISS — alert judged not actionable, no email.</td><td><code>action_taken == "suppressed"</code></td></tr>
      <tr><td class="label-cell">Deduped</td><td>Pre-LLM dedup hit — same alert fingerprint already seen inside the window. No LLM call.</td><td><code>triage_decision == "triage_suppressed"</code></td></tr>
      <tr><td class="label-cell">Timed out</td><td>Pipeline exceeded its budget (40 min total, 30 min per LLM call). Raw alert forwarded.</td><td><code>action_taken == "emailed_raw"</code></td></tr>
    </tbody>
  </table>
  <p>Hover any tile for the precise definition.</p>
</div>

<div class="card">
  <h2 id="drain3">2. Drain3 panel</h2>
  <p>Drain3 is an online log-template miner that runs in-process. As Loki logs flow in
  during context-gathering, Drain3 clusters lines into templates (e.g.
  <code>"&lt;*&gt; ERROR connection pool exhausted"</code>). The panel shows live state:</p>
  <table>
    <thead><tr><th>Field</th><th>Means</th></tr></thead>
    <tbody>
      <tr><td class="label-cell">Anomaly rate</td><td>Fraction of recent ingested lines that landed on a low-frequency template. Above ~5% suggests something genuinely novel; near 0% means steady state.</td></tr>
      <tr><td class="label-cell">Templates learned</td><td>Total distinct clusters in the in-memory state. Persisted to disk every 30s so restarts don't reset learning.</td></tr>
      <tr><td class="label-cell">Lines processed</td><td>Lifetime count of log lines fed through Drain3.</td></tr>
      <tr><td class="label-cell">Anomalies flagged</td><td>Count of lines tagged <code>[ANOMALY]</code> by the analyzer — those whose template is in the rare-frequency tail.</td></tr>
    </tbody>
  </table>
</div>

<div class="card">
  <h2 id="columns">3. Table columns</h2>
  <p>9 columns, left to right. The first is a chevron icon (click any row to expand it).</p>

  <h3 id="col-time">3.1 Time</h3>
  <p>When the decision was persisted, rendered in <strong>Africa/Casablanca local zone (GMT+1)</strong>.</p>

  <h3 id="col-alert">3.2 Alert</h3>
  <p>The Grafana alert rule's title (e.g. <code>HighP95Latency</code>, <code>TargetDown</code>).
  Maps 1:1 to the rule name in
  <code>monitoring-project/roles/grafana/templates/alertrules.yml.j2</code>. Synthetic alerts
  from the Drain3 self-bridge get conventional names like <code>Drain3AnomalyDetected</code>.</p>

  <h3 id="col-source">3.3 Source</h3>
  <ul>
    <li><strong><code>grafana</code></strong> — alert came in via <code>/webhook/grafana</code>.</li>
    <li><strong><code>drain3</code></strong> — synthesized by the in-process self-bridge when the anomaly threshold was crossed.</li>
  </ul>

  <h3 id="col-service">3.4 Service</h3>
  <p>The service the alert is about. Comes from <code>alert.labels.service</code>: <code>spring-boot</code>,
  <code>kong</code>, <code>otel-collector</code>, <code>monitoring</code> (the Grafana host VM),
  <code>k3s-node</code>, <code>loki</code>, <code>drain3</code>.</p>

  <h3 id="col-severity">3.5 Severity</h3>
  <p>Three values, color-coded:</p>
  <ul>
    <li><span class="pill danger">critical</span> — page now (TargetDown, OOMKill, OTel pipeline drop)</li>
    <li><span class="pill warn">warning</span> — investigate within hours (most CPU/mem/latency rules)</li>
    <li><span class="pill sage">info</span> — context only, not paging-worthy (Drain3, threshold-tuning hints)</li>
  </ul>

  <h3 id="col-verdict">3.6 Verdict + quality</h3>
  <p>Two stacked elements: the LLM's verdict (left pill) and the post-hoc RCA quality (right pill).</p>
  <p><strong>Verdict pill (LLM decision):</strong></p>
  <ul>
    <li><strong>escalate</strong> — LLM thinks this is a real issue → email sent.</li>
    <li><strong>dismiss</strong> — LLM thinks this is noise / self-resolving → no email.</li>
    <li><strong>inconclusive</strong> — LLM couldn't pick. Treated as ESCALATE downstream (safer).</li>
    <li><strong>timeout</strong> — pipeline exceeded budget. No verdict; raw alert forwarded.</li>
  </ul>
  <p><strong>Quality pill (post-hoc tag):</strong></p>
  <ul>
    <li><strong>fits</strong> (raw <code>actionable</code>) — concrete RCA + at least one valid suggested action.</li>
    <li><strong>thin</strong> (raw <code>data_starved</code>) — model hedged or evidence empty.</li>
    <li><strong>review</strong> (raw <code>needs_review</code>) — confidence below floor (0.30) or validator flagged.</li>
  </ul>

  <h3 id="col-action">3.7 Action</h3>
  <p>What the pipeline did downstream of the verdict. Renamed in 2026-04-27 from raw
  pipeline codes to engineer-friendly labels (raw code preserved next to the label in a small
  monospace tag for grep purposes):</p>
  <table>
    <thead><tr><th>Label</th><th>Raw code</th><th>Means</th></tr></thead>
    <tbody>
      <tr><td class="label-cell">Notified</td><td class="code-cell">emailed</td><td>Triage emailed the on-call (LLM produced a verdict).</td></tr>
      <tr><td class="label-cell">Notified (no LLM)</td><td class="code-cell">emailed_raw</td><td>LLM unavailable or timed out — raw alert forwarded.</td></tr>
      <tr><td class="label-cell">Suppressed</td><td class="code-cell">suppressed</td><td>Pre-LLM dedup or recent dismissed history.</td></tr>
      <tr><td class="label-cell">Dropped</td><td class="code-cell">drop_alert</td><td>Below severity threshold or matched a quiet-hours rule.</td></tr>
    </tbody>
  </table>

  <h3 id="col-duration">3.8 Duration</h3>
  <p>End-to-end pipeline duration: MCP context-gathering (~1–5s) + LLM inference (10–80s on the
  laptop GPU) + validator + persistence. Format scales: under 1s → ms, 1–60s → "12.3 s",
  over 60s → "N min M s".</p>
</div>

<div class="card">
  <h2 id="detail">4. The detail panel</h2>
  <p>Click any row to expand. Sections, top-down:</p>

  <h3>Meta-grid</h3>
  <p>9 fields giving the row's identity and core LLM facts: timestamp · decision ID ·
  alert fingerprint · service · component/signal · instance · triage path (humanized)
  · LLM confidence + quality · action + duration.</p>

  <h3>Observed value + PromQL</h3>
  <p>The lede card: the actual metric value at fire time and the PromQL that produced it.</p>

  <h3>Root-cause analysis</h3>
  <p>The LLM's narrative. 2–5 sentences typically, starting with a restatement of the
  observed value + PromQL (mandated by SYSTEM_PROMPT rule A). 10-digit Unix timestamps
  embedded by the LLM are auto-converted to <code>&lt;unix&gt; (&lt;Casablanca&gt;)</code> at render time.</p>

  <h3>Suggested actions</h3>
  <p><strong>Remediations only.</strong> As of 2026-04-27, the LLM is constrained to emit
  state-changing commands (<code>kubectl rollout restart</code>, <code>helm rollback</code>,
  <code>docker restart</code>, <code>systemctl restart</code>, <code>kubectl set resources</code>,
  <code>terraform apply</code>) — never read-only inspections like <code>kubectl get</code> or
  <code>Query Grafana: ...</code>. The triage service has already inspected the telemetry;
  that data is in evidence/RCA.</p>
  <p>Empty list = the model didn't have a concrete remediation. The pipeline falls back
  to <code>app/suggested_actions.yaml</code> templates keyed by alertname × deployment type.
  For Drain3 alerts with no correlation, the fallback is a "Shelved — awaiting recurrence" marker.</p>

  <h3>Evidence</h3>
  <p>Specific metric values, log lines, or trace IDs the LLM cited. Each entry must be
  concrete; vague entries get rejected by the validator.</p>

  <h3>Drain3 anomaly summary</h3>
  <p>If the alert was sourced by Drain3, this section shows the anomalous templates that
  triggered the fire. For Grafana-sourced alerts, anomalies found in the gathered Loki
  context are also listed here.</p>

  <h3>Correlated alerts (±5 min)</h3>
  <p>Other alerts that fired within the window. The LLM is required (rule H) to address
  these in the RCA — either "X caused Y", "they share cause Z", or "coincident timing."</p>
</div>

<div class="card">
  <h2 id="glossary">5. Codes &amp; abbreviations</h2>

  <h3>Internal codes (raw enum values stored in SQLite)</h3>
  <dl class="glossary">
    <dt>action_taken</dt>
    <dd><code>emailed</code> · <code>emailed_raw</code> · <code>suppressed</code> · <code>drop_alert</code>. See <a href="#col-action">column 3.7</a>.</dd>

    <dt>triage_decision</dt>
    <dd>Higher-level pipeline path. <code>investigate</code> = ran the full LLM pipeline.
    <code>triage_suppressed</code> = pre-LLM dedup short-path. <code>dismiss</code> /
    <code>escalate</code> = LLM verdict (echoed). <code>dismiss_shelved</code> = Drain3
    anomaly with no correlation, awaiting recurrence. <code>timeout_passthrough</code> =
    pipeline exceeded budget.</dd>

    <dt>rca_quality</dt>
    <dd><code>actionable</code> (label: <em>fits</em>) · <code>data_starved</code> (label:
    <em>thin</em>) · <code>needs_review</code> (label: <em>review</em>).</dd>

    <dt>alert_source</dt>
    <dd><code>grafana</code> or <code>drain3</code>.</dd>

    <dt>llm_verdict</dt>
    <dd><code>ESCALATE</code> · <code>DISMISS</code> · <code>INCONCLUSIVE</code>. Pipeline treats <code>INCONCLUSIVE</code> as ESCALATE downstream.</dd>

    <dt>deployment_type</dt>
    <dd><code>k8s</code> · <code>docker-vm</code> · <code>systemd</code> · <code>external</code> ·
    <code>unknown</code>. Drives the architecture-mismatch validator and template selection.</dd>
  </dl>

  <h3>Acronyms used in the UI and emails</h3>
  <dl class="glossary">
    <dt>RCA</dt><dd>Root-cause analysis — the LLM's narrative.</dd>
    <dt>MCP</dt><dd>Model Context Protocol — the contract by which the triage service queries Prometheus, Loki, Jaeger, Drain3, and rca-history (5 servers, all containerized).</dd>
    <dt>p95 / p99</dt><dd>The 95th / 99th percentile of a latency distribution. <code>histogram_quantile(0.95, ...)</code> in PromQL.</dd>
    <dt>OTel / OTLP</dt><dd>OpenTelemetry / its wire protocol. Spring-boot ships traces via OTLP; otel-collector forwards to Jaeger.</dd>
    <dt>LogQL / PromQL</dt><dd>Loki's log query language / Prometheus' metric query language.</dd>
    <dt>refId (A / B / C)</dt><dd>Grafana alert rules are 3-step pipelines: A=query, B=reduce, C=threshold-as-boolean. The observed value is B; C is just 0/1.</dd>
    <dt>fingerprint</dt><dd>Stable hash Grafana computes over alert labels. Two webhooks with the same fingerprint are the same logical alert.</dd>
    <dt>kill chain / cascade</dt><dd>A sequence of related alerts firing in close succession (disk-fills → DB-slow → connection-pool-exhaust → 503s).</dd>
    <dt>shelved</dt><dd>Drain3-specific verdict: anomaly was detected but no correlation found. Logged with <code>triage_decision=dismiss_shelved</code>; if same template recurs ≥3 times in 7 days, escalate on pattern alone.</dd>
    <dt>data_starved / thin</dt><dd>Quality tag indicating the LLM hedged because evidence was empty. Triggers a one-time bounded-agency retry (the LLM can request one extra MCP query before re-deciding).</dd>
  </dl>
</div>

<div class="card">
  <h2 id="scenarios">6. Reading common rows</h2>

  <div class="scenario">
    <h4>A — clean ESCALATE on a Java service</h4>
    <p>Verdict: <strong>escalate</strong>. Quality: <strong>fits</strong>. Action: <strong>Notified</strong>.
    Confidence ≥0.7. Suggested actions list two or three <code>kubectl set resources</code> /
    <code>kubectl rollout restart</code> commands. Evidence cites a specific Loki line and a metric value.
    The on-call has a clear next step.</p>
  </div>

  <div class="scenario">
    <h4>B — DISMISS on a noisy threshold</h4>
    <p>Verdict: <strong>dismiss</strong>. Quality: <strong>fits</strong>. Action: <strong>Dismissed</strong>
    (no email). RCA explains the metric briefly crossed the threshold and immediately fell back.
    Suggested actions point at the alertrules YAML — raise the threshold or add a <code>for: 2m</code> clause.</p>
  </div>

  <div class="scenario">
    <h4>C — Drain3 anomaly, shelved</h4>
    <p>Source: <strong>drain3</strong>. Verdict: <strong>dismiss</strong>. Triage path: <strong>Shelved</strong>
    (raw: <code>dismiss_shelved</code>). Suggested actions contain the shelve marker. RCA explains the new
    template that fired and that no metric/trace correlation was found. The system will escalate automatically
    if the same template recurs ≥3 times in 7 days.</p>
  </div>

  <div class="scenario">
    <h4>D — Deduped row</h4>
    <p>Triage path: <strong>Deduped</strong>. Verdict: empty. Action: <strong>Suppressed</strong>.
    The detail panel's "Action" line says <code>see_previous_rca:&lt;prior_id&gt;</code>. Click that
    decision for the full RCA — this row is just a marker that the same fingerprint refired in window.</p>
  </div>

  <div class="scenario">
    <h4>E — Timed out (Notified, no LLM)</h4>
    <p>Verdict: <strong>timeout</strong>. Action: <strong>Notified (no LLM)</strong>. The pipeline exceeded
    its budget. No RCA, no suggested actions — raw alert was forwarded. Investigate Ollama health if
    you see a cluster of these (<code>docker logs ai-ollama</code>).</p>
  </div>

  <div class="scenario">
    <h4>F — thin RCA (data_starved)</h4>
    <p>Verdict: <strong>escalate</strong>. Quality: <strong>thin</strong>. RCA hedges because Loki had
    0 lines or Jaeger was empty. Pipeline already retried once with bounded-agency. If still thin, the
    alert is for a service that doesn't log through the app pipeline (k3s-node, monitoring-vm).</p>
  </div>

  <div class="callout">
    <div class="callout-label">Tip</div>
    <p>The <strong>Action</strong> column tells you what the system did downstream;
    <strong>Verdict + Quality</strong> tells you what the LLM thought; the
    <strong>Triage path</strong> in the detail panel tells you which pipeline branch the alert took.
    If those three disagree, the row is interesting — open it and read the reasoning.</p>
  </div>
</div>

<div class="card">
  <h3>Deeper reading</h3>
  <p>This page covers the operator-facing UI. For the full architectural context — every
  module, every config knob, every gotcha, the philosophy decisions log, the alerts-audit
  with per-alert accuracy, and the Sprint 2 Epic 5 (UEBA) plan — see the monitoring-docs
  site:</p>
  <a class="deep-link" href="https://linalaaraich.github.io/monitoring-docs/dashboard-guide.html" target="_blank" rel="noopener">monitoring-docs version of this page (extended) →</a><br>
  <a class="deep-link" href="https://linalaaraich.github.io/monitoring-docs/" target="_blank" rel="noopener">monitoring-docs home →</a>
</div>

</article>
</div>
</div>

</body></html>"""


@app.get("/metrics")
async def metrics():
    return Response(content=get_metrics(), media_type="text/plain; charset=utf-8")
