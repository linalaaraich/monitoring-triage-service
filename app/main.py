import html as _html
import logging
import re as _re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo


# All DB timestamps are stored as bare-UTC ISO strings (see app.rca_store._utc_now). The
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


def _build_dashboard_search_blob(r: dict, local_ts: str) -> str:
    """Construct the lowercased haystack the dashboard's client-side filter
    matches against (rendered into each row's ``data-search`` attribute).

    Includes every field an operator might paste in: the decision UUID,
    the local-time timestamp string they see in the table, the raw ISO
    timestamp, the alert fingerprint, plus all visible cells and the RCA
    prose. Lina filed the original miss on 2026-05-21 — searching the
    UUID returned nothing because the blob only contained alert_name +
    service + severity + verdict + action + rca prose.
    """
    return ' '.join([
        r.get('id') or '',
        local_ts,
        r.get('timestamp') or '',
        r.get('alert_name') or '',
        r.get('affected_service') or '',
        r.get('alert_source') or '',
        (r.get('severity') or '').lower(),
        r.get('llm_verdict') or '',
        r.get('action_taken') or '',
        r.get('triage_decision') or '',
        r.get('rca_quality') or '',
        r.get('alert_fingerprint') or '',
        r.get('alert_instance') or '',
        r.get('alert_component') or '',
        r.get('rca_report') or '',
        r.get('llm_reasoning') or '',
    ]).lower()

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, Response

from app.config import settings
from app.context import ContextGatherer
from app.dedup import DedupManager
from app.drain_analyzer import DrainAnalyzer
from app.llm_client import LLMClient
from app.metrics import get_metrics, webhooks_received
from app.models import (
    Drain3Webhook,
    FeedbackRequest,
    FeedbackResponse,
    GrafanaWebhook,
    HealthResponse,
)
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

# Mount design assets for the v2 dashboard preview (Claude Design output,
# 2026-05-22 — see solution-brief.html §12 + design-prompt.html). React-via-
# CDN + Babel-in-browser; pre-compilation is a Sprint 5 polish item.
from fastapi.staticfiles import StaticFiles as _StaticFiles
import pathlib as _pathlib
_design_dir = _pathlib.Path(__file__).parent / "static" / "design"
if _design_dir.exists():
    app.mount("/static/design", _StaticFiles(directory=str(_design_dir)), name="design")


# --- Validation error logging (added 2026-04-27 to debug Grafana 422s) ---
# Logs the offending raw body + the Pydantic field errors for any webhook
# request that fails schema validation. Without this, FastAPI returns the
# 422 silently and the operator can't tell what shape Grafana actually sent.
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


@app.exception_handler(RequestValidationError)
async def _validation_logger(request, exc: RequestValidationError):
    try:
        body = await request.body()
        body_preview = body.decode("utf-8", errors="replace")[:2000]
    except Exception:
        body_preview = "<unavailable>"
    logger.warning(
        "RequestValidationError on %s %s — errors=%s body=%s",
        request.method, request.url.path,
        exc.errors()[:5],
        body_preview,
    )
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


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


_FAVICON_SVG = (Path(__file__).parent / "favicon.svg").read_text(encoding="utf-8")


@app.get("/favicon.svg")
async def favicon_svg() -> Response:
    return Response(
        content=_FAVICON_SVG,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@app.get("/favicon.ico")
async def favicon_ico() -> Response:
    return Response(
        content=_FAVICON_SVG,
        media_type="image/svg+xml",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@app.get("/decisions")
async def decisions(
    limit: int = Query(50, ge=1, le=500),
    alert_name: str | None = Query(None),
    offset: int = Query(0, ge=0),
    since_days: int | None = Query(None, ge=1, le=365),
):
    return await _store.get_decisions(
        limit=limit, alert_name=alert_name, offset=offset, since_days=since_days,
    )


@app.get("/drain3/stats")
async def drain3_stats(service: str | None = Query(None)):
    # get_stats holds a threading.Lock and iterates all drain3 clusters.
    # Run it in a thread so we don't block the event loop behind any
    # in-flight ingest batches (which also hold the same lock).
    # Per US-5.1 Phase A, supports `?service=<name>` to scope stats to
    # one service's miner; without the query param returns the
    # cross-service aggregate.
    import asyncio as _asyncio
    return await _asyncio.to_thread(_drain.get_stats, service)


# --- Closed-loop feedback (US-5.3) ---
#
# /feedback/override flips a DISMISS the operator disagrees with — similar
# future alerts (alertname + service + ±2h time-of-day match) will force-
# escalate within the active window (default 14 days).
#
# /feedback/confirm ratifies an ESCALATE the operator agrees with —
# feeds the precision metric and acts as a brake on any standing override
# for the same decision.
#
# Both endpoints are idempotent on (decision_id, feedback_type): re-posting
# updates the row in place rather than creating a duplicate. This is so
# the operator can change their mind via the same call without polluting
# the metrics.

@app.post("/feedback/override", status_code=201)
async def feedback_override(req: FeedbackRequest) -> FeedbackResponse:
    return await _record_feedback(req, feedback_type="override")


@app.post("/feedback/confirm", status_code=201)
async def feedback_confirm(req: FeedbackRequest) -> FeedbackResponse:
    return await _record_feedback(req, feedback_type="confirm")


async def _record_feedback(req: FeedbackRequest, feedback_type: str) -> FeedbackResponse:
    # Validate the decision exists — catches typos before they pollute the
    # feedback table with orphan rows.
    decisions = await _store.get_decisions(limit=1, alert_name=None)  # warmup
    cursor = await _store._db.execute(
        "SELECT id FROM rca_history WHERE id = ?", (req.decision_id,)
    )
    row = await cursor.fetchone()
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"decision_id {req.decision_id!r} not found in rca_history",
        )

    import uuid
    feedback_id = f"fb-{uuid.uuid4().hex[:12]}"
    saved = await _store.record_feedback(
        feedback_id=feedback_id,
        decision_id=req.decision_id,
        feedback_type=feedback_type,
        operator_note=req.operator_note,
        active_for_days=req.active_for_days,
    )
    return FeedbackResponse(**saved)


_DASHBOARD_CSS = """
  /* Figma-aligned design tokens. Dark by default, .light variant flips
     surface/text/border. Semantic colors (red/amber/green/blue/purple)
     map onto pre-existing helper class names so the Python renderers
     (_verdict_pill, _source_tag, _quality_pill, etc.) keep working
     unchanged. The legacy sage/--ink/--card aliases are preserved for
     the same reason, just retargeted to the new palette. */
  :root {
    --bg: #0B0D10;
    --surface: #13161B;
    --surface-2: #1A1E25;
    --surface-3: #21262E;
    --border: #262B33;
    --border-strong: #353B46;
    --text-primary: #E6E8EB;
    --text-secondary: #9BA3AF;
    --text-muted: #6B7280;
    --red: #E5484D;
    --red-soft: rgba(229, 72, 77, 0.12);
    --amber: #F5A524;
    --amber-soft: rgba(245, 165, 36, 0.12);
    --green: #2BA471;
    --green-soft: rgba(43, 164, 113, 0.12);
    --blue: #3E8FE6;
    --blue-soft: rgba(62, 143, 230, 0.12);
    --purple: #6E56CF;
    --purple-soft: rgba(110, 86, 207, 0.12);

    /* Legacy aliases — keep so existing helper output classes resolve. */
    --card: var(--surface);
    --card-alt: var(--surface-2);
    --ink: var(--text-primary);
    --ink-soft: var(--text-secondary);
    --muted: var(--text-muted);
    --rule: var(--border);
    --rule-hi: var(--border-strong);
    --sage: var(--blue);
    --sage-strong: var(--blue);
    --sage-soft: var(--blue-soft);
    --ok: var(--green);
    --warn: var(--amber);
    --warn-soft: var(--amber-soft);
    --danger: var(--red);
    --danger-soft: var(--red-soft);
    --info: var(--blue);
    --info-soft: var(--blue-soft);

    --radius: 6px;
    --radius-lg: 8px;
    --row-h: 36px;
    --gutter: 24px;
  }
  /* Light-mode tokens are scoped to :root (the <html> element) rather
     than body, so an inline <head> script can apply the class before
     the body paints — eliminating the dark-flash on every auto-refresh
     reload. */
  :root.light {
    --bg: #FFFFFF;
    --surface: #F7F8FA;
    --surface-2: #EFF1F4;
    --surface-3: #E5E8EC;
    --border: #E2E5EA;
    --border-strong: #CFD3D9;
    --text-primary: #0B0D10;
    --text-secondary: #4B5563;
    --text-muted: #6B7280;
    --red-soft: rgba(229, 72, 77, 0.10);
    --amber-soft: rgba(245, 165, 36, 0.14);
    --green-soft: rgba(43, 164, 113, 0.10);
    --blue-soft: rgba(62, 143, 230, 0.10);
    --purple-soft: rgba(110, 86, 207, 0.10);
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    background: var(--bg);
    color: var(--text-primary);
    line-height: 1.5;
    font-size: 14px;
    -webkit-font-smoothing: antialiased;
    transition: background-color .15s, color .15s;
  }

  /* App shell — TopBar + LeftNav + main content. Mirrors the Figma
     layout (h-screen flex column, then flex-1 row). */
  .app-shell { display: flex; flex-direction: column; min-height: 100vh; }
  .app-body { display: flex; flex: 1; min-height: 0; position: relative; }
  .main-area { flex: 1; min-width: 0; overflow-x: hidden; padding: var(--gutter) calc(var(--gutter) + 4px) 56px; }

  .topbar {
    height: 56px; padding: 0 var(--gutter);
    display: flex; align-items: center; justify-content: space-between;
    background: var(--surface); border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 10;
  }
  .topbar-left { display: flex; align-items: center; gap: 24px; }
  .wordmark {
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 16px; font-weight: 600; letter-spacing: -0.2px;
    color: var(--text-primary);
  }
  .topbar-right { display: flex; align-items: center; gap: 12px; }
  .icon-btn {
    background: transparent; border: 1px solid transparent;
    width: 32px; height: 32px; border-radius: var(--radius);
    color: var(--text-primary); cursor: pointer;
    display: inline-flex; align-items: center; justify-content: center;
    font-size: 16px; line-height: 1; transition: background-color .12s, border-color .12s;
  }
  .icon-btn:hover { background: var(--surface-2); border-color: var(--border); }
  .topbar .guide-link {
    font-size: 12px; color: var(--text-secondary);
    text-decoration: none; padding: 6px 10px; border-radius: var(--radius);
    border: 1px solid var(--border); transition: color .12s, border-color .12s;
  }
  .topbar .guide-link:hover { color: var(--text-primary); border-color: var(--border-strong); }
  /* Auto-refresh chip — visually paired with .guide-link so the topbar
     reads as a row of evenly-bordered controls. */
  .topbar .refresh {
    font-size: 12px; color: var(--text-secondary);
    display: inline-flex; align-items: center; gap: 8px;
    padding: 5px 10px; border-radius: var(--radius);
    border: 1px solid var(--border); background: var(--surface);
    cursor: pointer; user-select: none;
    transition: border-color .12s;
  }
  .topbar .refresh:hover { border-color: var(--border-strong); }
  .topbar .refresh input[type=checkbox] {
    margin: 0; accent-color: var(--blue); cursor: pointer;
  }
  .refresh-state { font-size: 11px; color: var(--amber); font-style: italic; margin-left: 4px; }

  /* Leftnav overlays the main-area on hover instead of reflowing it.
     The rail keeps a fixed 56px footprint via the .leftnav-spacer; the
     real .leftnav is absolutely positioned and grows over the content
     when expanded. Prevents the entire table from shifting horizontally
     every time the cursor brushes the rail. */
  .leftnav-spacer { width: 56px; flex-shrink: 0; }
  .leftnav {
    position: absolute; top: 0; bottom: 0; left: 0;
    width: 56px; z-index: 9;
    background: var(--surface); border-right: 1px solid var(--border);
    transition: width .15s ease, box-shadow .15s ease;
    overflow: hidden;
  }
  .leftnav:hover, .leftnav.expanded {
    width: 220px;
    box-shadow: 4px 0 16px rgba(0,0,0,0.25);
  }
  :root.light .leftnav:hover, :root.light .leftnav.expanded {
    box-shadow: 4px 0 16px rgba(15,23,42,0.08);
  }
  .leftnav nav { padding: 12px 8px; display: flex; flex-direction: column; gap: 2px; }
  .leftnav a, .leftnav .navitem-disabled {
    position: relative;
    display: flex; align-items: center; gap: 12px;
    padding: 8px 10px; border-radius: var(--radius);
    color: var(--text-secondary); text-decoration: none;
    font-size: 13px; white-space: nowrap; overflow: hidden;
    transition: background-color .12s, color .12s;
  }
  .leftnav a:hover { background: var(--surface-2); color: var(--text-primary); }
  .leftnav a.active { background: var(--surface-2); color: var(--text-primary); }
  .leftnav a.active::before {
    content: ""; position: absolute;
    left: 0; top: 50%; transform: translateY(-50%);
    width: 3px; height: 18px;
    background: var(--blue); border-radius: 0 2px 2px 0;
  }
  .leftnav .navitem-disabled { opacity: 0.5; cursor: not-allowed; }
  .leftnav .navitem-disabled .nav-tag {
    margin-left: auto; font-size: 9px; font-weight: 700; letter-spacing: .4px;
    text-transform: uppercase; color: var(--purple);
    padding: 1px 6px; border: 1px solid var(--purple); border-radius: 4px;
    background: var(--purple-soft);
  }
  .leftnav .nav-icon {
    width: 18px; height: 18px; flex-shrink: 0;
    display: inline-flex; align-items: center; justify-content: center;
    font-size: 14px; line-height: 1;
  }
  .leftnav .nav-label { opacity: 0; transition: opacity .15s; }
  .leftnav:hover .nav-label, .leftnav.expanded .nav-label { opacity: 1; }

  .container { max-width: 1320px; margin: 0 auto; }

  .header { margin-bottom: 18px; }
  .header .eyebrow {
    font-size: 11px; font-weight: 600; letter-spacing: 1.4px;
    text-transform: uppercase; color: var(--text-secondary); margin-bottom: 6px;
  }
  .header h1 {
    font-size: 20px; font-weight: 500; letter-spacing: -0.2px;
    color: var(--text-primary);
  }
  .header h1 .accent { color: var(--blue); }
  .header .subtitle { margin-top: 4px; color: var(--text-secondary); font-size: 13px; }

  .stats {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px; margin-bottom: 20px;
  }
  .stat {
    background: var(--surface); border: 1px solid var(--border);
    padding: 14px 16px; border-radius: var(--radius);
    display: flex; flex-direction: column; gap: 6px;
    transition: border-color .12s;
  }
  .stat:hover { border-color: var(--border-strong); }
  .stat .lbl {
    color: var(--text-secondary); font-size: 11px; font-weight: 500;
    letter-spacing: .3px; order: 1;
  }
  .stat .num {
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 24px; font-weight: 500; letter-spacing: -0.4px;
    line-height: 1.1; color: var(--text-primary); order: 2;
  }
  /* Each tile carries a 2px semantic stripe up top so the row reads as
     a consistent KPI strip rather than one accented tile next to four
     plain ones. The number color matches the stripe. */
  .stat { border-top: 2px solid var(--text-muted); }
  .stat.t-total { border-top-color: var(--blue); }
  .stat.t-total .num { color: var(--blue); }
  .stat.t-esc { border-top-color: var(--red); }
  .stat.t-esc .num { color: var(--red); }
  .stat.t-dismiss { border-top-color: var(--green); }
  .stat.t-dismiss .num { color: var(--green); }
  .stat.t-timeout { border-top-color: var(--amber); }
  .stat.t-timeout .num { color: var(--amber); }
  .stat.t-suppress { border-top-color: var(--text-secondary); }
  .stat.t-suppress .num { color: var(--text-secondary); }

  .toolbar {
    display: flex; gap: 12px; align-items: center;
    margin-bottom: 12px; flex-wrap: wrap;
  }
  .toolbar input[type=text] {
    background: var(--surface); border: 1px solid var(--border); color: var(--text-primary);
    padding: 7px 12px; border-radius: var(--radius); font-size: 13px;
    min-width: 320px; font-family: inherit;
    transition: border-color .12s, box-shadow .12s;
  }
  .toolbar input[type=text]:focus {
    outline: none; border-color: var(--blue);
    box-shadow: 0 0 0 3px rgba(62, 143, 230, 0.15);
  }
  .toolbar input[type=text]::placeholder { color: var(--text-muted); }
  .toolbar .hint { font-size: 12px; color: var(--text-muted); }
  .toolbar .spacer { flex: 1; }
  .raw-code {
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 10.5px; color: var(--text-muted); margin-left: 4px;
  }

  .table-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); overflow: hidden;
  }
  table { border-collapse: collapse; width: 100%; }
  thead th {
    background: var(--surface-2); color: var(--text-secondary);
    font-weight: 500; font-size: 11px; letter-spacing: .2px;
    text-align: left;
    padding: 8px 14px; border-bottom: 1px solid var(--border);
  }
  tbody tr.summary { cursor: pointer; transition: background-color .12s; height: var(--row-h); }
  tbody tr.summary td {
    padding: 8px 14px; font-size: 13px; border-bottom: 1px solid var(--border);
    vertical-align: middle; color: var(--text-primary);
  }
  tbody tr.summary td:nth-child(3) { color: var(--text-primary); font-weight: 500; }
  tbody tr.summary:hover { background: var(--surface-2); }
  tbody tr.summary.open { background: var(--surface-2); }
  tbody tr.summary.open td { border-bottom-color: transparent; }

  td.chev { width: 28px; text-align: center; }
  .chev-icon {
    display: inline-block; width: 0; height: 0;
    border-left: 5px solid var(--text-muted);
    border-top: 4px solid transparent;
    border-bottom: 4px solid transparent;
    transition: transform .15s;
  }
  tbody tr.summary.open .chev-icon { transform: rotate(90deg); border-left-color: var(--blue); }

  td.mono, .mono {
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px; white-space: nowrap;
  }

  /* Source tag — semantic dot + mono label, no chunky pill background.
     Keeps the tag-* class names so _source_tag() does not need to change. */
  .tag {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 2px 8px; border-radius: var(--radius);
    font-family: 'JetBrains Mono', ui-monospace, monospace;
    font-size: 11px; font-weight: 500;
    border: 1px solid var(--border); background: var(--surface-2);
    color: var(--text-secondary); letter-spacing: 0;
    text-transform: lowercase;
  }
  .tag::before {
    content: ""; display: inline-block;
    width: 6px; height: 6px; border-radius: 50%;
    background: currentColor;
  }
  .tag-grafana { color: var(--amber); }
  .tag-drain3 { color: var(--blue); }
  .tag-default { color: var(--text-muted); }

  /* Severity — small color dot + mono label. */
  .sev {
    display: inline-flex; align-items: center; gap: 6px;
    font-family: 'JetBrains Mono', ui-monospace, monospace;
    font-size: 11px; font-weight: 500; text-transform: lowercase; letter-spacing: 0;
    color: var(--text-secondary);
  }
  .sev::before {
    content: ""; display: inline-block;
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--text-muted);
  }
  .sev-critical { color: var(--text-primary); }
  .sev-critical::before { background: var(--red); }
  .sev-warning { color: var(--text-primary); }
  .sev-warning::before { background: var(--amber); }
  .sev-info, .sev-low { color: var(--text-secondary); }
  .sev-info::before, .sev-low::before { background: var(--blue); }

  /* Verdict — Figma's VerdictBadge: a colored dot followed by a mono
     uppercase label, no fill, no border. The dot color carries the
     semantic; the label stays in the primary text color so it reads as
     calmly as the surrounding cells. */
  .pill {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 0; background: transparent; border: none;
    font-family: 'JetBrains Mono', ui-monospace, monospace;
    font-size: 11px; font-weight: 500; text-transform: uppercase;
    letter-spacing: .3px;
    color: var(--text-primary);
  }
  .pill::before {
    content: ""; display: inline-block;
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--text-muted);
    flex-shrink: 0;
  }
  .pill-escalate::before { background: var(--red); }
  .pill-dismiss::before  { background: var(--green); }
  .pill-inconclusive::before { background: var(--amber); }
  .pill-none { color: var(--text-muted); }
  .pill-none::before { background: var(--text-muted); }

  /* Quality pill — flat capsule, no shouty caps, sits next to the verdict. */
  .quality {
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    font-size: 10.5px; font-weight: 500; letter-spacing: 0;
    margin-left: 6px; vertical-align: middle; color: #fff;
  }
  .quality-actionable { background: var(--green); }
  .quality-data_starved { background: var(--amber); }
  .quality-data_starved::before { content: "⚠ "; }

  /* Action column reads as supporting metadata. Severity is already
     conveyed by the verdict dot in the column to the left, so the
     action label stays in secondary text — no double-coloring. */
  .action { font-size: 12px; color: var(--text-secondary); }
  .action-emailed_raw { color: var(--amber); }

  tbody tr.detail { display: none; }
  tbody tr.detail.open { display: table-row; }
  tbody tr.detail > td {
    padding: 0; background: var(--bg);
    border-bottom: 1px solid var(--border);
  }

  .panel {
    padding: 20px 22px 22px;
    border-left: 2px solid var(--blue);
    background: var(--bg);
  }
  .panel .meta-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px 24px; margin-bottom: 18px;
  }
  .panel .m { display: flex; flex-direction: column; gap: 3px; }
  .panel .m .lbl {
    font-size: 11px; font-weight: 500; letter-spacing: .2px;
    color: var(--text-secondary);
  }
  .panel .m .val {
    font-size: 12.5px; color: var(--text-primary); font-weight: 500;
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    word-break: break-all;
  }
  .panel .m .val.normal {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    font-weight: 400;
  }

  .section { margin-top: 16px; }
  .section h3 {
    font-size: 13px; font-weight: 500; color: var(--text-primary);
    margin-bottom: 8px; letter-spacing: 0;
  }
  .section .body {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 14px 16px; color: var(--text-primary);
    font-size: 13.5px; line-height: 1.65;
    white-space: pre-wrap; word-break: break-word;
  }
  .section .body.empty { color: var(--text-muted); font-style: italic; }
  .section .body em { color: var(--text-muted); font-style: italic; }

  tbody tr.empty td {
    text-align: center; color: var(--text-muted); padding: 36px 14px;
    font-style: italic; font-size: 13px;
  }

  .drain-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px 18px; margin-bottom: 20px;
  }
  .drain-card .drain-header {
    display: flex; align-items: baseline; gap: 12px;
    margin-bottom: 14px;
  }
  .drain-card .drain-header .eyebrow {
    font-size: 11px; font-weight: 500; letter-spacing: .3px;
    color: var(--text-secondary);
  }
  .drain-card .drain-header h2 {
    font-size: 14px; font-weight: 500; color: var(--text-primary);
    letter-spacing: -0.1px;
  }
  .drain-card .drain-header .anomaly-rate {
    margin-left: auto;
    font-size: 12px; color: var(--text-secondary);
  }
  .drain-card .drain-header .anomaly-rate strong {
    color: var(--blue); font-weight: 500;
    font-family: 'JetBrains Mono', ui-monospace, monospace;
  }
  .drain-tiles {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 10px; margin-bottom: 14px;
  }
  .drain-tile {
    display: flex; flex-direction: column; gap: 4px;
    padding: 10px 14px;
    background: var(--surface-2); border: 1px solid var(--border);
    border-radius: var(--radius);
  }
  .drain-tile .lbl {
    font-size: 11px; font-weight: 500; letter-spacing: .2px;
    color: var(--text-secondary); order: 1;
  }
  .drain-tile .num {
    font-family: 'JetBrains Mono', ui-monospace, monospace;
    font-size: 18px; font-weight: 500; color: var(--text-primary);
    letter-spacing: -0.2px; order: 2;
  }
  .drain-patterns { margin-top: 6px; }
  .drain-patterns summary {
    cursor: pointer; user-select: none; list-style: none;
    font-size: 11px; font-weight: 500; letter-spacing: 0;
    color: var(--text-secondary);
    padding: 4px 0; display: inline-flex; align-items: center; gap: 6px;
  }
  .drain-patterns summary::-webkit-details-marker { display: none; }
  .drain-patterns summary::before {
    content: ""; display: inline-block; width: 0; height: 0;
    border-left: 4px solid var(--text-muted);
    border-top: 3px solid transparent; border-bottom: 3px solid transparent;
    transition: transform .15s;
  }
  .drain-patterns[open] summary::before { transform: rotate(90deg); }
  .drain-patterns summary:hover { color: var(--text-primary); }
  .drain-patterns ol {
    padding-left: 22px; margin-top: 6px;
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px; color: var(--text-secondary);
  }
  .drain-patterns ol li { padding: 2px 0; word-break: break-word; }
  .drain-patterns .none {
    color: var(--text-muted); font-style: italic; font-size: 12px; margin-top: 6px;
  }

  /* Deep-link chips on decision row — Figma-style outlined chips. */
  .deep-chip {
    display: inline-flex; align-items: center; gap: 4px;
    padding: 2px 8px; border-radius: var(--radius);
    font-family: 'JetBrains Mono', ui-monospace, monospace;
    font-size: 10.5px; font-weight: 500; letter-spacing: 0;
    border: 1px solid var(--border); color: var(--text-secondary);
    background: var(--surface-2); text-decoration: none;
    margin-left: 6px; transition: border-color .12s, color .12s;
  }
  .deep-chip:hover { border-color: var(--blue); color: var(--blue); }
  .deep-chip.dc-grafana { color: var(--amber); }
  .deep-chip.dc-grafana:hover { border-color: var(--amber); }
  .deep-chip.dc-loki { color: var(--blue); }
  .deep-chip.dc-loki:hover { border-color: var(--blue); }
  .deep-chip.dc-jaeger { color: var(--green); }
  .deep-chip.dc-jaeger:hover { border-color: var(--green); }

  /* Detail-panel richer layout — sub-cards for observed value, actions,
     evidence, correlated alerts, deep links. */
  .obs-card {
    background: var(--surface); border: 1px solid var(--border);
    border-left: 2px solid var(--blue);
    border-radius: var(--radius); padding: 14px 18px; margin-bottom: 14px;
  }
  .obs-card .obs-row { display: flex; gap: 14px; align-items: baseline; margin-bottom: 6px; }
  .obs-card .obs-row:last-child { margin-bottom: 0; }
  .obs-card .lbl {
    font-size: 11px; font-weight: 500; letter-spacing: .2px;
    color: var(--text-secondary); min-width: 140px;
  }
  .obs-card .val {
    font-family: 'JetBrains Mono', ui-monospace, monospace;
    font-size: 18px; font-weight: 500; color: var(--text-primary);
    letter-spacing: -0.2px;
  }
  .obs-card .expr {
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px; color: var(--text-primary); word-break: break-all;
    background: var(--surface-2); padding: 6px 10px;
    border: 1px solid var(--border); border-radius: var(--radius); flex: 1;
  }

  .panel-list {
    list-style: none; padding: 0; margin: 0;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); overflow: hidden;
  }
  .panel-list li {
    padding: 9px 14px; border-bottom: 1px solid var(--border);
    font-size: 13px; color: var(--text-primary); word-break: break-word;
  }
  .panel-list li:last-child { border-bottom: none; }
  .panel-list li .mono {
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px; color: var(--text-secondary);
  }

  .correlated-table {
    width: 100%; border-collapse: collapse; font-size: 12px;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); overflow: hidden;
  }
  .correlated-table th, .correlated-table td {
    padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border);
  }
  .correlated-table th {
    background: var(--surface-2); font-weight: 500; font-size: 11px;
    letter-spacing: .2px; color: var(--text-secondary);
  }
  .correlated-table tr:last-child td { border-bottom: none; }
  .correlated-table td.mono {
    font-family: 'JetBrains Mono', ui-monospace, monospace;
    color: var(--text-secondary);
  }

  .panel-links { display: flex; gap: 8px; flex-wrap: wrap; }
  .panel-link {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 6px 12px; border-radius: var(--radius);
    font-size: 12px; font-weight: 500;
    background: var(--surface); border: 1px solid var(--border);
    color: var(--text-primary); text-decoration: none;
    transition: border-color .12s, background-color .12s;
  }
  .panel-link:hover { border-color: var(--blue); background: var(--surface-2); }
  .panel-link::after {
    content: "↗"; color: var(--text-muted); font-size: 11px;
  }

  /* Placeholder for sections where the LLM emitted nothing. */
  .panel-empty {
    background: var(--surface); border: 1px dashed var(--border);
    border-radius: var(--radius); padding: 12px 16px;
    color: var(--text-muted); font-size: 12.5px; font-style: italic;
    line-height: 1.6;
  }

  /* Copyable PromQL / LogQL rows. */
  .query-row {
    display: flex; gap: 12px; align-items: center;
    margin-bottom: 8px; flex-wrap: wrap;
  }
  .query-lbl {
    font-size: 11px; font-weight: 500; letter-spacing: .2px;
    color: var(--text-secondary); min-width: 120px;
  }
  .query-code {
    flex: 1; padding: 8px 12px; border-radius: var(--radius);
    background: var(--surface); border: 1px solid var(--border);
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px; color: var(--text-primary);
    word-break: break-all;
    user-select: all;
  }

  @media (max-width: 900px) {
    .leftnav { display: none; }
    .topbar { padding: 0 16px; }
    .main-area { padding: 16px; }
    .toolbar input[type=text] { min-width: 0; width: 100%; }
    thead th:nth-child(4), tbody td:nth-child(4),
    thead th:nth-child(5), tbody td:nth-child(5) { display: none; }
  }

  .pagination {
    display: flex; flex-wrap: wrap; align-items: center; gap: 16px;
    margin-top: 18px; padding: 14px 18px;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    font-size: 13px; color: var(--text-secondary);
  }
  .pagination-info { flex: 1; min-width: 240px; }
  .pagination-info strong { color: var(--text-primary); font-weight: 600; }
  .pagination-controls { display: flex; gap: 8px; }
  .pagination-window { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
  .page-btn, .window-btn {
    display: inline-block;
    padding: 6px 12px;
    background: var(--surface-2);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    text-decoration: none;
    font-size: 12px;
    font-weight: 500;
    transition: background-color .12s, border-color .12s;
  }
  .page-btn:hover, .window-btn:hover {
    background: var(--border); border-color: var(--border-strong);
  }
  .page-btn.disabled {
    opacity: 0.45; cursor: not-allowed; pointer-events: none;
  }
  .window-btn.active {
    background: var(--blue-soft); border-color: var(--blue); color: var(--blue);
  }
  @media (max-width: 700px) {
    .pagination { flex-direction: column; align-items: stretch; gap: 10px; }
    .pagination-controls { justify-content: space-between; }
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
  // Theme is applied synchronously in the <head> via an inline script
  // before the body paints, so there is no dark-flash on reload. This
  // handler only flips the class + persists + updates the button label.
  function toggleTheme() {
    var isLight = document.documentElement.classList.toggle('light');
    try { localStorage.setItem('triage-theme', isLight ? 'light' : 'dark'); } catch (e) {}
    var btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = isLight ? '☾' : '☼';
  }
  document.addEventListener('DOMContentLoaded', function() {
    var btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = document.documentElement.classList.contains('light') ? '☾' : '☼';
    var f = document.getElementById('filter');
    if (f) f.addEventListener('input', applyFilter);
    applyFilter();
    // Auto-refresh is on by default; honour the checkbox's initial state.
    toggleRefresh();
  });
"""


def _as_list_field(value) -> list:
    """Normalize an RCA-row JSON-list field to a Python list.

    Handles three shapes the column can be in across the rollover:
    - already a list (post-2026-04-28 PM-late get_decisions boundary
      decoder ran)
    - a JSON-encoded string (legacy storage shape leak / direct DB-row
      callers / pre-fix containers)
    - None / empty (short-path persisted records, dedup duplicates)

    Never raises — malformed input returns []. Use this everywhere the
    dashboard or email renderer pulls suggested_actions / evidence /
    correlated_alerts off a row dict.
    """
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        if not value:
            return []
        try:
            parsed = _json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except (ValueError, TypeError):
            return []
    return []


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


_NAV_ITEMS = [
    # (slug, label, icon, enabled, route_or_none)
    # Decisions and Guide are real today. Everything else is the Figma /
    # Epic 5 surface area — wired into the chrome so the design space is
    # visible to reviewers + on-call eyes get used to the layout, but
    # disabled until US-5.x lands. Unicode glyphs avoid an icon dep.
    ("incidents",  "Incidents",         "◎", False, None),
    ("alerts",     "Alerts",            "◊", False, None),
    ("anomalies",  "Drain3 Anomalies",  "≋", False, None),
    ("services",   "Services",          "▦", False, None),
    ("baselines",  "Baselines",         "⌇", False, None),
    ("decisions",  "Decisions History", "↻", True,  "/dashboard"),
    ("evaluation", "Evaluation",        "✓", False, None),
    ("guide",      "Dashboard Guide",   "?", True,  "/dashboard/guide"),
]


def _render_topbar(active: str = "decisions") -> str:
    """TopBar: product wordmark + auto-refresh + guide link + theme toggle.

    Mirrors src/app/components/TopBar.tsx from the Figma source. Auto-refresh
    moved here from the in-page toolbar so the operator always sees its
    state regardless of scroll position. The Figma env-switcher (prod/
    staging) was dropped — there is only one environment in production
    today and the Epic 5 multi-env story isn't real yet, so the control
    was a UI promise without backing."""
    return (
        '<header class="topbar">'
        '  <div class="topbar-left">'
        '    <div class="wordmark">RCA Triage platform</div>'
        '  </div>'
        '  <div class="topbar-right">'
        '    <label class="refresh">'
        '      <input id="refresh" type="checkbox" checked onchange="toggleRefresh()" />'
        '      <span>Auto-refresh 30s</span>'
        '      <span id="refresh-state" class="refresh-state"></span>'
        '    </label>'
        '    <a class="guide-link" href="/dashboard/guide" title="Operator reference for every column, code, and abbreviation">What do these mean?</a>'
        '    <button type="button" id="theme-toggle" class="icon-btn" onclick="toggleTheme()" title="Toggle light / dark theme" aria-label="Toggle theme">☼</button>'
        '  </div>'
        '</header>'
    )


def _render_leftnav(active: str = "decisions") -> str:
    """LeftNav: collapsed-by-default rail; hover or focus expands.

    Mirrors src/app/components/LeftNav.tsx. The Figma design ships nine
    top-level routes; only Decisions History (this page) and Dashboard
    Guide are wired up server-side today, so the rest are rendered as
    visually-consistent disabled rows tagged with an "EPIC 5" badge so an
    on-call engineer reading the chrome immediately sees what's planned
    vs what's live. Keeps the chrome honest — no dead links."""
    items_html = []
    for slug, label, icon, enabled, route in _NAV_ITEMS:
        is_active = slug == active
        if enabled:
            cls = "active" if is_active else ""
            items_html.append(
                f'<a href="{route}" class="{cls}" title="{_html.escape(label)}">'
                f'  <span class="nav-icon">{icon}</span>'
                f'  <span class="nav-label">{_html.escape(label)}</span>'
                f'</a>'
            )
        else:
            items_html.append(
                f'<div class="navitem-disabled" title="{_html.escape(label)} — landing with Epic 5 (UEBA)">'
                f'  <span class="nav-icon">{icon}</span>'
                f'  <span class="nav-label">{_html.escape(label)}</span>'
                f'  <span class="nav-tag">epic 5</span>'
                f'</div>'
            )
    # Emits a flex-layout spacer (occupies 56px) plus the real .leftnav,
    # which is absolutely positioned and overlays the main-area on hover.
    # Keeps the table from reflowing horizontally as the cursor brushes
    # the rail.
    return (
        '<div class="leftnav-spacer"></div>'
        f'<aside class="leftnav"><nav>{"".join(items_html)}</nav></aside>'
    )


def _render_drain3_panel(stats: dict) -> str:
    """Surface DrainAnalyzer.get_stats() as a card on /dashboard.

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
    # Tolerate both shapes: post-fix get_decisions returns a list directly;
    # pre-fix (and direct DB-row callers) return a JSON-encoded string.
    actions = _as_list_field(r.get('suggested_actions'))
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
    evidence = _as_list_field(r.get('evidence'))
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
    correlated = _as_list_field(r.get('correlated_alerts'))
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
async def dashboard(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=10, le=200),
    since_days: int = Query(15, ge=1, le=365),
):
    offset = (page - 1) * size
    rows = await _store.get_decisions(limit=size, offset=offset, since_days=since_days)
    total_in_window = await _store.count_decisions(since_days=since_days)
    last_page = max(1, (total_in_window + size - 1) // size)
    drain_stats = _drain.get_stats() if _drain is not None else {}

    # Stat-card counters reflect the current page slice; the "Total decisions"
    # card is replaced with the window total so operators can see how many
    # alerts exist in the window even when the current page is small.
    escalated = sum(1 for r in rows if r.get('action_taken') == 'emailed')
    dismissed = sum(1 for r in rows if r.get('action_taken') == 'suppressed')
    timed_out = sum(1 for r in rows if r.get('action_taken') == 'emailed_raw')
    suppressed_pre = sum(1 for r in rows if (r.get('triage_decision') or '').lower() == 'triage_suppressed')
    total = total_in_window

    body_rows = ""
    for r in rows:
        raw_id = r.get('id') or ''
        local_ts = _to_local_time(r.get('timestamp'))
        did = _html.escape(raw_id)
        ts = _html.escape(local_ts)
        alert_name = r.get('alert_name') or '—'
        service = r.get('affected_service') or '—'
        severity = (r.get('severity') or '').lower()
        action = r.get('action_taken') or '—'
        duration = int(r.get('investigation_duration_ms') or 0)
        verdict = r.get('llm_verdict') or ''

        # Client-side filter input — see _build_dashboard_search_blob().
        search_blob = _build_dashboard_search_blob(r, local_ts)

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

    def _page_link(p: int, label: str, disabled: bool = False) -> str:
        if disabled:
            return f'<span class="page-btn disabled">{label}</span>'
        return f'<a class="page-btn" href="/dashboard?page={p}&amp;size={size}&amp;since_days={since_days}">{label}</a>'

    def _window_link(d: int, label: str) -> str:
        active = ' active' if d == since_days else ''
        return f'<a class="window-btn{active}" href="/dashboard?page=1&amp;size={size}&amp;since_days={d}">{label}</a>'

    pagination_html = (
        '<div class="pagination">'
        '  <div class="pagination-info">'
        f'    Page <strong>{page}</strong> of <strong>{last_page}</strong>'
        f'    &middot; {total_in_window} alert{"s" if total_in_window != 1 else ""} in last '
        f'    {since_days} day{"s" if since_days != 1 else ""}'
        '  </div>'
        '  <div class="pagination-controls">'
        f'    {_page_link(page - 1, "&larr; Prev", disabled=(page <= 1))}'
        f'    {_page_link(page + 1, "Next &rarr;", disabled=(page >= last_page))}'
        '  </div>'
        '  <div class="pagination-window">'
        '    Show last:&nbsp;'
        f'    {_window_link(7, "7 days")}'
        f'    {_window_link(15, "15 days")}'
        f'    {_window_link(30, "30 days")}'
        f'    {_window_link(365, "all")}'
        '  </div>'
        '</div>'
    )

    return (
        f'<!DOCTYPE html><html lang="en"><head>'
        f'<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">'
        f'<title>RCA Triage platform · Decisions</title>'
        f'<link rel="icon" type="image/svg+xml" href="/favicon.svg">'
        # Apply the persisted theme class to <html> SYNCHRONOUSLY, before
        # any rendering. The auto-refresh does a full page reload every
        # 30s; without this the page paints with the dark default first
        # and the JS-applied .light class arrives one frame later, which
        # the operator sees as a flash on every reload. Putting this at
        # the very top of <head> means the class is on documentElement
        # before the CSS computes against it.
        f'<script>(function(){{try{{if(localStorage.getItem("triage-theme")==="light")document.documentElement.classList.add("light");}}catch(e){{}}}})();</script>'
        f'<link rel="preconnect" href="https://fonts.googleapis.com">'
        f'<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
        f'<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">'
        f'<style>{_DASHBOARD_CSS}</style>'
        f'</head><body>'
        f'<div class="app-shell">'
        f'{_render_topbar(active="decisions")}'
        f'  <div class="app-body">'
        f'{_render_leftnav(active="decisions")}'
        f'    <main class="main-area">'
        f'      <div class="container">'
        f'        <div class="header">'
        f'          <div class="eyebrow">AI root-cause triage</div>'
        f'          <h1>Decisions <span class="accent">history</span></h1>'
        f'          <div class="subtitle">Recent verdicts produced by the triage pipeline. Click any row to review the full root-cause analysis.</div>'
        f'        </div>'
        f'        <div class="stats">'
        f'          <div class="stat t-total"><div class="num">{total}</div><div class="lbl">Total decisions</div></div>'
        f'          <div class="stat t-esc" title="Verdict was ESCALATE and an email was sent"><div class="num">{escalated}</div><div class="lbl">Notified</div></div>'
        f'          <div class="stat t-dismiss" title="Verdict was DISMISS — alert judged not actionable"><div class="num">{dismissed}</div><div class="lbl">Dismissed</div></div>'
        f'          <div class="stat t-suppress" title="Pre-LLM dedup — same fingerprint already seen in window"><div class="num">{suppressed_pre}</div><div class="lbl">Deduped</div></div>'
        f'          <div class="stat t-timeout" title="Pipeline exceeded its budget — raw alert forwarded with no LLM verdict"><div class="num">{timed_out}</div><div class="lbl">Timed out</div></div>'
        f'        </div>'
        f'        {_render_drain3_panel(drain_stats)}'
        f'        <div class="toolbar">'
        f'          <input id="filter" type="text" placeholder="Filter by alert name, service, verdict, or RCA text" autocomplete="off" />'
        f'          <span class="hint" id="match-count"></span>'
        f'        </div>'
        f'        <div class="table-card">'
        f'          <table>'
        f'            <thead><tr>'
        f'              <th></th>'
        f'              <th title="Wall-clock time the decision was persisted, in Casablanca local zone (GMT+1)">Time (local)</th>'
        f'              <th title="Alert rule name as configured in Grafana">Alert</th>'
        f'              <th title="Where the alert came from: grafana=metric rule, drain3=log-template anomaly">Source</th>'
        f'              <th title="The service the alert is about">Service</th>'
        f'              <th title="Alert severity: critical / warning / info">Severity</th>'
        f'              <th title="LLM verdict (escalate / dismiss / inconclusive) + RCA quality pill (fits / thin / review)">Verdict</th>'
        f'              <th title="What the pipeline did downstream of the verdict (Notified / Suppressed / Dropped / Notified-no-LLM)">Action</th>'
        f'              <th title="End-to-end pipeline duration including MCP context-gathering + LLM inference">Duration</th>'
        f'            </tr></thead>'
        f'            <tbody>{body_rows}</tbody>'
        f'          </table>'
        f'        </div>'
        f'        {pagination_html}'
        f'      </div>'
        f'    </main>'
        f'  </div>'
        f'</div>'
        f'<script>{_DASHBOARD_JS}</script>'
        f'</body></html>'
    )


_GUIDE_CSS = """
  /* Guide page reuses the same Figma palette + TopBar/LeftNav chrome as
     /dashboard. Tokens duplicated rather than imported because each page
     ships its <style> inline; intentional scope, intentional duplication. */
  :root {
    --bg: #0B0D10;
    --surface: #13161B;
    --surface-2: #1A1E25;
    --border: #262B33;
    --border-strong: #353B46;
    --text-primary: #E6E8EB;
    --text-secondary: #9BA3AF;
    --text-muted: #6B7280;
    --red: #E5484D;
    --amber: #F5A524;
    --green: #2BA471;
    --blue: #3E8FE6;
    --purple: #6E56CF;
    --red-soft: rgba(229,72,77,0.12);
    --amber-soft: rgba(245,165,36,0.12);
    --green-soft: rgba(43,164,113,0.12);
    --blue-soft: rgba(62,143,230,0.12);
    --purple-soft: rgba(110,86,207,0.12);
    --radius: 6px;
    --radius-lg: 8px;
    --gutter: 24px;
  }
  /* Light-mode tokens scoped to :root so the head-inlined theme script
     can apply them before the body paints — no dark-flash on reload. */
  :root.light {
    --bg: #FFFFFF; --surface: #F7F8FA; --surface-2: #EFF1F4;
    --border: #E2E5EA; --border-strong: #CFD3D9;
    --text-primary: #0B0D10; --text-secondary: #4B5563; --text-muted: #6B7280;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
    background: var(--bg); color: var(--text-primary);
    line-height: 1.65; font-size: 14px;
    -webkit-font-smoothing: antialiased;
    transition: background-color .15s, color .15s;
  }
  code, pre, .mono {
    font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.88em;
  }

  /* App shell — identical to /dashboard so navigating between the two
     pages feels seamless. */
  .app-shell { display: flex; flex-direction: column; min-height: 100vh; }
  .app-body { display: flex; flex: 1; min-height: 0; position: relative; }
  .main-area { flex: 1; min-width: 0; overflow-x: hidden; padding: var(--gutter) calc(var(--gutter) + 4px) 60px; }

  .topbar {
    height: 56px; padding: 0 var(--gutter);
    display: flex; align-items: center; justify-content: space-between;
    background: var(--surface); border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 10;
  }
  .topbar-left { display: flex; align-items: center; gap: 24px; }
  .wordmark {
    font-family: 'JetBrains Mono', ui-monospace, monospace;
    font-size: 16px; font-weight: 600; letter-spacing: -0.2px;
    color: var(--text-primary);
  }
  .topbar-right { display: flex; align-items: center; gap: 14px; }
  .topbar .guide-link {
    font-size: 12px; color: var(--text-secondary);
    text-decoration: none; padding: 6px 10px; border-radius: var(--radius);
    border: 1px solid var(--border);
  }
  .topbar .guide-link.active {
    color: var(--text-primary); border-color: var(--blue);
  }
  .icon-btn {
    background: transparent; border: 1px solid transparent;
    width: 32px; height: 32px; border-radius: var(--radius);
    color: var(--text-primary); cursor: pointer;
    display: inline-flex; align-items: center; justify-content: center;
    font-size: 16px; line-height: 1;
  }
  .icon-btn:hover { background: var(--surface-2); border-color: var(--border); }

  .leftnav-spacer { width: 56px; flex-shrink: 0; }
  .leftnav {
    position: absolute; top: 0; bottom: 0; left: 0;
    width: 56px; z-index: 9;
    background: var(--surface); border-right: 1px solid var(--border);
    transition: width .15s ease, box-shadow .15s ease;
    overflow: hidden;
  }
  .leftnav:hover {
    width: 220px;
    box-shadow: 4px 0 16px rgba(0,0,0,0.25);
  }
  :root.light .leftnav:hover { box-shadow: 4px 0 16px rgba(15,23,42,0.08); }
  .leftnav nav { padding: 12px 8px; display: flex; flex-direction: column; gap: 2px; }
  .leftnav a, .leftnav .navitem-disabled {
    display: flex; align-items: center; gap: 12px;
    padding: 8px 10px; border-radius: var(--radius);
    color: var(--text-secondary); text-decoration: none;
    font-size: 13px; white-space: nowrap; overflow: hidden;
    position: relative;
  }
  .leftnav a:hover { background: var(--surface-2); color: var(--text-primary); }
  .leftnav a.active { background: var(--surface-2); color: var(--text-primary); }
  .leftnav a.active::before {
    content: ""; position: absolute;
    left: 0; top: 50%; transform: translateY(-50%);
    width: 3px; height: 18px;
    background: var(--blue); border-radius: 0 2px 2px 0;
  }
  .leftnav .navitem-disabled { opacity: 0.5; cursor: not-allowed; }
  .leftnav .navitem-disabled .nav-tag {
    margin-left: auto; font-size: 9px; font-weight: 700; letter-spacing: .4px;
    text-transform: uppercase; color: var(--purple);
    padding: 1px 6px; border: 1px solid var(--purple); border-radius: 4px;
    background: var(--purple-soft);
  }
  .leftnav .nav-icon {
    width: 18px; height: 18px; flex-shrink: 0;
    display: inline-flex; align-items: center; justify-content: center;
    font-size: 14px; line-height: 1;
  }
  .leftnav .nav-label { opacity: 0; transition: opacity .15s; }
  .leftnav:hover .nav-label { opacity: 1; }

  .container { max-width: 1080px; margin: 0 auto; padding: 0; }
  .header { padding: 0 0 24px; }
  .header .eyebrow {
    font-size: 11px; font-weight: 500; letter-spacing: 1.2px;
    text-transform: uppercase; color: var(--text-secondary); margin-bottom: 6px;
  }
  .header h1 {
    font-size: 24px; font-weight: 500; letter-spacing: -0.3px;
    margin-bottom: 8px; color: var(--text-primary);
  }
  .header h1 .accent { color: var(--blue); }
  .header .subtitle { color: var(--text-secondary); max-width: 760px; }
  .header .nav-back {
    display: inline-flex; align-items: center; gap: 6px;
    margin-top: 14px; padding: 6px 12px; border-radius: var(--radius);
    background: var(--surface); border: 1px solid var(--border);
    color: var(--text-primary); font-size: 13px; font-weight: 500;
    text-decoration: none;
  }
  .header .nav-back:hover { border-color: var(--blue); color: var(--blue); }

  .layout {
    display: grid; grid-template-columns: 240px 1fr; gap: 28px; margin-top: 8px;
  }
  @media (max-width: 1100px) {
    .layout { grid-template-columns: 1fr; }
    .toc { position: static; }
  }
  @media (max-width: 900px) {
    .leftnav { display: none; }
    .topbar { padding: 0 16px; }
    .main-area { padding: 16px; }
  }
  .toc {
    position: sticky; top: 76px; align-self: start;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 16px 18px; font-size: 13px;
  }
  .toc h4 {
    font-size: 11px; font-weight: 500; letter-spacing: .3px;
    color: var(--text-secondary); margin-bottom: 10px;
  }
  .toc ol { list-style: none; }
  .toc li { margin-bottom: 4px; }
  .toc a {
    color: var(--text-secondary); text-decoration: none;
  }
  .toc a:hover { color: var(--blue); }
  .toc li.sub { padding-left: 14px; font-size: 12px; }
  .toc li.sub a { color: var(--text-muted); }
  .content > .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 22px 24px; margin-bottom: 16px;
  }
  .content h2 {
    font-size: 18px; font-weight: 500; margin: 0 0 14px;
    letter-spacing: -0.1px; color: var(--text-primary); scroll-margin-top: 76px;
    padding-bottom: 8px; border-bottom: 1px solid var(--border);
  }
  .content h3 {
    font-size: 14px; font-weight: 500; margin: 22px 0 8px;
    color: var(--text-primary); scroll-margin-top: 76px;
  }
  .content h4 { font-size: 13px; font-weight: 500; margin: 16px 0 4px; color: var(--text-primary); }
  .content p { margin-bottom: 10px; color: var(--text-secondary); }
  .content p strong { color: var(--text-primary); font-weight: 500; }
  .content ul, .content ol { margin: 6px 0 14px 22px; color: var(--text-secondary); }
  .content li { margin-bottom: 5px; }
  .content code {
    background: var(--surface-2); border: 1px solid var(--border);
    padding: 1px 6px; border-radius: 4px; font-size: 0.85em; color: var(--blue);
  }
  .content pre {
    background: var(--surface-2); border: 1px solid var(--border);
    padding: 12px 14px; border-radius: var(--radius); margin: 10px 0 14px;
    overflow-x: auto; line-height: 1.5;
  }
  .content pre code { background: none; border: none; padding: 0; color: var(--text-primary); }
  .content a {
    color: var(--blue); text-decoration: none;
    border-bottom: 1px dashed rgba(62, 143, 230, 0.4);
  }
  .content a:hover { border-bottom-style: solid; }
  table {
    width: 100%; border-collapse: collapse; margin: 8px 0 16px; font-size: 13px;
  }
  table th, table td {
    padding: 9px 12px; border-bottom: 1px solid var(--border);
    text-align: left; vertical-align: top;
  }
  table th {
    font-size: 11px; font-weight: 500; letter-spacing: .2px;
    color: var(--text-secondary); background: var(--surface-2);
  }
  table tr:hover td { background: var(--surface-2); }
  table td.code-cell {
    font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 12.5px;
    color: var(--blue); white-space: nowrap;
  }
  table td.label-cell { font-weight: 500; color: var(--text-primary); white-space: nowrap; }
  .pill {
    display: inline-flex; align-items: center; gap: 6px;
    font-size: 11px; font-weight: 500; padding: 2px 8px;
    border-radius: var(--radius); border: 1px solid transparent;
    font-family: 'JetBrains Mono', ui-monospace, monospace;
    text-transform: lowercase;
  }
  .pill::before {
    content: ""; display: inline-block; width: 8px; height: 8px;
    border-radius: 50%; background: currentColor;
  }
  .pill.sage { color: var(--green); background: var(--green-soft); border-color: var(--green); }
  .pill.warn { color: var(--amber); background: var(--amber-soft); border-color: var(--amber); }
  .pill.danger { color: var(--red); background: var(--red-soft); border-color: var(--red); }
  .pill.ink { color: var(--text-secondary); background: var(--surface-2); border-color: var(--border); }
  .glossary dt {
    font-family: 'JetBrains Mono', ui-monospace, monospace; font-size: 13px;
    color: var(--blue); margin-top: 10px; font-weight: 500;
  }
  .glossary dt:first-child { margin-top: 0; }
  .glossary dd { margin: 3px 0 0 18px; color: var(--text-secondary); font-size: 13.5px; }
  .scenario {
    background: var(--surface-2); border: 1px solid var(--border);
    border-left: 2px solid var(--blue);
    border-radius: var(--radius); padding: 14px 18px; margin: 12px 0;
  }
  .scenario h4 { color: var(--blue); margin-top: 0; font-size: 13px; }
  .scenario p { font-size: 13.5px; }
  .callout {
    border-left: 2px solid var(--blue); border-radius: 0 var(--radius) var(--radius) 0;
    padding: 12px 16px; margin: 14px 0; background: var(--blue-soft);
  }
  .callout-label {
    font-size: 11px; font-weight: 500; letter-spacing: .3px;
    color: var(--blue); margin-bottom: 5px;
  }
"""


_GUIDE_JS = """
  // Theme applied synchronously by the inline <head> script before paint,
  // so this handler only flips and persists.
  function toggleTheme() {
    var isLight = document.documentElement.classList.toggle('light');
    try { localStorage.setItem('triage-theme', isLight ? 'light' : 'dark'); } catch (e) {}
    var btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = isLight ? '☾' : '☼';
  }
  document.addEventListener('DOMContentLoaded', function() {
    var btn = document.getElementById('theme-toggle');
    if (btn) btn.textContent = document.documentElement.classList.contains('light') ? '☾' : '☼';
  });
"""


@app.get("/dashboard/guide", response_class=HTMLResponse)
async def dashboard_guide():
    """Local operator-reference guide for the dashboard.

    Lina 2026-04-27: pulled this out of github-pages so the link stays
    inside the same host as the dashboard itself, and recolored to match
    the sage/white palette so it's visually coherent with /dashboard.
    """
    return f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RCA Triage platform · Dashboard Guide</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<script>(function(){{try{{if(localStorage.getItem("triage-theme")==="light")document.documentElement.classList.add("light");}}catch(e){{}}}})();</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>{_GUIDE_CSS}</style></head><body>

<div class="app-shell">
{_render_topbar(active="guide")}
  <div class="app-body">
{_render_leftnav(active="guide")}
    <main class="main-area">
      <div class="container">

<div class="header">
  <div class="eyebrow">AI root-cause triage · operator reference</div>
  <h1>Dashboard <span class="accent">guide</span></h1>
  <p class="subtitle">Every column, every internal code, every abbreviation explained.
  If a label in the triage UI is unclear, find it here.</p>
  <a href="/dashboard" class="nav-back">← Back to decisions</a>
</div>

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

</article>
</div>

      </div>
    </main>
  </div>
</div>

<script>{_GUIDE_JS}</script>
</body></html>"""


# ────────────────────────────────────────────────────────────────────
# /dashboard/v2 — Claude Design output (2026-05-22 supervisor-feedback redesign)
# ────────────────────────────────────────────────────────────────────
# This route serves the v2 operator dashboard rendered via the React mockup
# from Claude Design (see solution-brief.html §12 + design-prompt.html).
# The existing /dashboard route stays unchanged — v2 is a live preview the
# supervisor can compare against the current dashboard before we swap.
#
# Implementation shape (Phase 1, 2026-05-22):
#   • React 18 + Babel-standalone via unpkg CDN (matches Claude Design's
#     output exactly; no build step needed).
#   • Design assets at /static/design/* served by the StaticFiles mount.
#   • Real /decisions data injected as window.CIRES_ALERTS via a transformer
#     that maps RCARecord → the CIRES_ALERT shape the design expects.
#   • Renders only <Dashboard mode="default"/> — not the design-canvas
#     wrapper, which is a review surface.
#   • Phase 2 (next session): detail-page route, email template wiring,
#     feedback page, then swap /dashboard → v2.

# Mapping tables for the transformer. Keep these conservative — when in
# doubt return a sensible default rather than guessing.
_V2_VERDICT_MAP = {
    "escalate": "ESCALATE",
    "dismiss": "DISMISS",
    "inconclusive": "PENDING",
    "shelved": "SHELVED",  # synthetic — derived from action_taken below
}

_V2_ALERT_NAME_PLAIN = {
    "HighP95Latency": "High p95 latency",
    "HighKongP95Latency": "High p95 latency on Kong gateway",
    "HighCpuUsage": "High CPU usage",
    "CriticalCpuUsage": "Critical CPU usage",
    "MediumCpuUsage": "Elevated CPU usage",
    "HighMemoryUsage": "High memory usage",
    "CriticalMemoryUsage": "Critical memory usage",
    "MediumMemoryUsage": "Elevated memory usage",
    "PodHighMemoryUsage": "Pod memory pressure",
    "PodHighCpuUsage": "Pod CPU saturation",
    "TargetDown": "Prometheus target down",
    "Drain3AnomalyDetected": "Novel log-template anomaly",
    "HighDiskUsage": "High disk usage",
    "CriticalDiskUsage": "Critical disk usage",
    "DiskFillingUp": "Disk filling up",
    "LokiHighDiskUsage": "Loki disk usage high",
    "LokiCriticalDiskUsage": "Loki disk usage critical",
    "LokiIngestionRateLow": "Loki ingestion rate dropped",
    "LokiDiskFillingUp": "Loki disk filling up",
    "OTelCollectorDown": "OTel collector down",
    "OTelCollectorHighSpanDropRate": "OTel collector dropping spans",
}

_V2_SERVICE_TYPE = {
    "spring-boot": "backend",
    "spring-boot-app": "backend",
    "springboot-app": "backend",
    "backend": "backend",
    "rental-backend": "backend",
    "frontend": "frontend",
    "rental-frontend": "frontend",
    "kong": "network",
    "kong-kong-proxy": "network",
    "rental-mysql": "db",
    "mysql": "db",
    "loki": "infra",
    "prometheus": "infra",
    "jaeger": "infra",
    "grafana": "infra",
    "cadvisor": "infra",
    "node-exporter": "infra",
    "monitoring": "infra",
    "otel-collector": "infra",
    "k3s-node": "infra",
    "drain3": "infra",
}

_V2_NAMESPACE = {
    "spring-boot": "app",
    "spring-boot-app": "app",
    "springboot-app": "app",
    "frontend": "frontend",
    "kong": "network",
    "kong-kong-proxy": "network",
    "backend": "rental",
    "rental-backend": "rental",
    "rental-frontend": "rental",
    "rental-mysql": "rental",
    "loki": "observability",
    "prometheus": "observability",
    "jaeger": "observability",
    "grafana": "observability",
    "otel-collector": "observability",
    "drain3": "observability",
    "k3s-node": "kube-system",
    "monitoring": "observability",
}


def _v2_humanize_duration(seconds: float) -> str:
    """'3 min ago', '1 h 24 m', '6 d 2 h' — operator-readable durations."""
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return f"{int(seconds)} s"
    if seconds < 3600:
        return f"{int(seconds // 60)} min"
    if seconds < 86400:
        h = int(seconds // 3600); m = int((seconds % 3600) // 60)
        return f"{h} h {m} m" if m else f"{h} h"
    d = int(seconds // 86400); h = int((seconds % 86400) // 3600)
    return f"{d} d {h} h" if h else f"{d} d"


def _v2_transform_row(r: dict, *, fingerprint_history: dict | None = None,
                       drain3_stats: dict | None = None,
                       now_utc=None) -> dict:
    """Map a /decisions RCARecord row → the CIRES_ALERT shape the design expects.

    `fingerprint_history`: dict mapping alert_fingerprint → list[prior_row]
    (oldest first), used to compute fireCount + history timeline.
    `drain3_stats`: optional dict from _drain.get_stats(), used for the
    Drain3 detail-page tile and the dashboard sustained indicator.
    `now_utc`: reference datetime for relTime / activeFor calculations.
    """
    import json as _json2
    from datetime import datetime, timezone, timedelta
    if now_utc is None:
        now_utc = datetime.now(timezone.utc)
    raw_id = (r.get("id") or "")
    short_id = raw_id[:8] if raw_id else "—"
    svc = (r.get("affected_service") or "—")
    alert_name = r.get("alert_name") or "—"
    fingerprint = r.get("alert_fingerprint") or ""
    verdict_lower = (r.get("llm_verdict") or "").lower()
    action_taken = (r.get("action_taken") or "").lower()

    # Verdict mapping — shelved overrides if action_taken="shelved"
    if action_taken == "shelved":
        verdict = "SHELVED"
    else:
        verdict = _V2_VERDICT_MAP.get(verdict_lower, "PENDING")

    # Fire-history aggregation. fingerprint_history is built once per request
    # by the route handler from the same /decisions slab — no extra DB hits.
    prior = (fingerprint_history or {}).get(fingerprint, [])
    fire_count = len(prior) + 1 if fingerprint else 1
    first_fire_ts = (prior[0].get("timestamp") if prior else r.get("timestamp")) or r.get("timestamp")

    # Time formatting — Tangier UTC+01:00 per the design's locale ask.
    ts_iso = r.get("timestamp") or ""
    dt = None
    try:
        dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
        # Stored timestamps are sometimes naive ISO strings (no Z, no offset).
        # Treat naive as UTC — that's the storage convention in rca_store.py.
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        tng = dt.astimezone(timezone(timedelta(hours=1)))
        time_local = tng.strftime("%Y-%m-%d %H:%M:%S")
        time_short = tng.strftime("%H:%M:%S")
        date_short = tng.strftime("%Y-%m-%d")
    except Exception:
        time_local = ts_iso[:19].replace("T", " ")
        time_short = ts_iso[11:19] if len(ts_iso) > 19 else "—"
        date_short = ts_iso[:10] if len(ts_iso) > 10 else "—"

    # relTime — "3 min ago" / "1 h 24 m ago" relative to now
    rel_time = "—"
    active_for = ""
    if dt is not None:
        rel_time = _v2_humanize_duration((now_utc - dt).total_seconds()) + " ago"
    if first_fire_ts:
        try:
            first_dt = datetime.fromisoformat(first_fire_ts.replace("Z", "+00:00"))
            if first_dt.tzinfo is None:
                first_dt = first_dt.replace(tzinfo=timezone.utc)
            active_for = _v2_humanize_duration((now_utc - first_dt).total_seconds())
        except Exception:
            pass

    # Indicator (sustained / spike / recurring). Now driven by real fire-count
    # + duration since first fire, not a heuristic on alert name.
    td_lower = (r.get("triage_decision") or "").lower()
    if td_lower in ("suppressed_duplicate", "recurrence_gated_pre_llm") or fire_count >= 3:
        indicator = "recurring"
    elif active_for and any(active_for.endswith(unit) for unit in (" h", " d")) or (
        active_for and " h " in active_for or " d " in active_for
    ):
        indicator = "sustained"
    elif action_taken == "emailed" and alert_name in ("HighKongP95Latency", "HighP95Latency",
                                                       "PodHighMemoryUsage", "CriticalCpuUsage",
                                                       "CriticalMemoryUsage"):
        indicator = "sustained"
    else:
        indicator = "spike"

    # Incident history timeline — every prior fire of this fingerprint + this row.
    history = []
    for prev in prior[-9:]:  # cap at last 9 prior fires + current = 10 total
        try:
            pdt = datetime.fromisoformat((prev.get("timestamp") or "").replace("Z", "+00:00"))
            if pdt.tzinfo is None:
                pdt = pdt.replace(tzinfo=timezone.utc)
            ptng = pdt.astimezone(timezone(timedelta(hours=1)))
            ptime = ptng.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            ptime = (prev.get("timestamp") or "")[:19]
        pverdict = _V2_VERDICT_MAP.get((prev.get("llm_verdict") or "").lower(), "PENDING")
        if (prev.get("action_taken") or "").lower() == "shelved":
            pverdict = "SHELVED"
        history.append({"time": ptime, "verdict": pverdict, "delta": "prior fire"})
    history.append({"time": time_local, "verdict": verdict, "delta": (
        "first seen" if not prior else "still active — sustained" if indicator == "sustained" else "re-fired"
    )})

    # Parse suggested_actions (stored as JSON string)
    actions = []
    raw_actions = r.get("suggested_actions") or "[]"
    try:
        if isinstance(raw_actions, str):
            parsed = _json2.loads(raw_actions)
        else:
            parsed = raw_actions
        if isinstance(parsed, list):
            for a in parsed[:3]:
                # action can be a plain string or {cmd, why} dict
                if isinstance(a, str):
                    actions.append({"cmd": a, "why": ""})
                elif isinstance(a, dict):
                    actions.append({"cmd": a.get("cmd", str(a)), "why": a.get("why", "")})
    except Exception:
        actions = [{"cmd": str(raw_actions)[:200], "why": ""}]
    if not actions:
        actions = [{"cmd": "—", "why": "No suggested action — investigate via the linked tools."}]

    # Parse evidence (stored as JSON string)
    evidence = []
    raw_ev = r.get("evidence") or "[]"
    try:
        if isinstance(raw_ev, str):
            parsed = _json2.loads(raw_ev)
        else:
            parsed = raw_ev
        if isinstance(parsed, list):
            for e in parsed[:5]:
                if isinstance(e, str):
                    evidence.append({"source": "prom", "text": e, "link": "Grafana"})
                elif isinstance(e, dict):
                    evidence.append(e)
    except Exception:
        pass

    # Tags — derive from quality + decision shape
    tags = []
    q = (r.get("rca_quality") or "").lower()
    td = (r.get("triage_decision") or "").lower()
    if q == "actionable":
        tags.append("actionable")
    if q == "data_starved":
        tags.append("data-starved")
    if q == "needs_review":
        tags.append("needs-review")
    if action_taken == "shelved":
        tags.append("shelved")
    if td == "recurrence_gated_pre_llm":
        tags.append("recurrence-gated")
    if not tags:
        tags = ["—"]

    # First sentence of the RCA report as the "reason"
    rca = r.get("rca_report") or ""
    if rca:
        end = rca.find(". ")
        reason = rca[: end + 1] if end > 0 else rca[:240]
    else:
        reason = "No RCA prose recorded."

    confidence = None
    try:
        confidence = float(r.get("llm_confidence")) if r.get("llm_confidence") not in (None, "") else None
    except Exception:
        confidence = None

    # Drain3 snapshot — surfaced for Drain3AnomalyDetected alerts on the detail
    # page; dashboard only consults `anomalyRate` for a sustained-confidence cue.
    drain3_card = {}
    if alert_name == "Drain3AnomalyDetected" and drain3_stats:
        drain3_card = {
            "learnedTotal": drain3_stats.get("total_clusters", 0),
            "anomalyRate": drain3_stats.get("recent_anomaly_rate", 0.0),
            "linesIngested24h": drain3_stats.get("total_lines_processed", 0),
            "matchedTemplate": (drain3_stats.get("top_new_patterns_per_service", {}).get(svc, [None])[0] or ""),
        }

    return {
        "id": short_id,
        "uuid": raw_id,
        "fingerprint": fingerprint[:16] or "—",
        "timeISO": ts_iso,
        "timeLocal": time_local,
        "timeShort": time_short,
        "dateShort": date_short,
        "relTime": rel_time,
        "activeFor": active_for,
        # env: heuristic for the single-cluster test bed. Real multi-env support
        # is SF-1 in Sprint 4 (extract from alert labels — `env`, `environment`,
        # or k8s namespace prefix). For now everything on observability-rca-k3s
        # reads as `prod`; rental-namespace alerts read as `stg` so the operator
        # sees at least two values in the column.
        "env": "stg" if "rental" in svc else "prod",
        "namespace": _V2_NAMESPACE.get(svc, svc[:20] or "—"),
        "serviceType": _V2_SERVICE_TYPE.get(svc, "infra"),
        "component": svc,
        "alertName": alert_name,
        "alertPlain": _V2_ALERT_NAME_PLAIN.get(alert_name, alert_name),
        "verdict": verdict,
        "severity": (r.get("severity") or "info").lower(),
        "indicator": indicator,
        "reason": reason,
        "boldSubject": svc if svc and svc != "—" else "",
        "actions": actions,
        "tags": tags,
        "confidence": confidence,
        "quality": q,
        "fireCount": fire_count,
        "history": history,
        "evidence": evidence,
        "drain3": drain3_card,
    }


@app.get("/dashboard/v2", response_class=HTMLResponse)
async def dashboard_v2(size: int = Query(50, ge=10, le=200)):
    """Preview of the 2026-05-22 redesigned dashboard.

    Renders the Claude Design <Dashboard/> component against real
    /decisions data. See solution-brief.html §12 + design-prompt.html
    for the design spec; static assets at /static/design/.
    """
    import json as _json2
    from datetime import datetime, timezone, timedelta
    now_utc = datetime.now(timezone.utc)

    # Pull a wider slab than `size` so we can build per-fingerprint history
    # before slicing to the page. 200-row cap protects /decisions latency.
    raw_rows = await _store.get_decisions(limit=200, offset=0, since_days=15)

    # Build fingerprint → prior-fires map. For each row, "prior" = every
    # OTHER row with the same fingerprint older than this one (oldest first).
    by_fp: dict[str, list] = {}
    for r in raw_rows:
        fp = r.get("alert_fingerprint") or ""
        if fp:
            by_fp.setdefault(fp, []).append(r)
    for fp in by_fp:
        by_fp[fp].sort(key=lambda x: x.get("timestamp") or "")

    # Drain3 stats once per request (used for Drain3AnomalyDetected rows)
    drain3_stats = _drain.get_stats() if _drain is not None else {}

    # Transform — for each row, pass the prior fires with the same fingerprint
    page_rows = raw_rows[:size]
    alerts = []
    for r in page_rows:
        fp = r.get("alert_fingerprint") or ""
        history_for_row = []
        if fp and fp in by_fp:
            # everything older than this row, oldest first
            for prev in by_fp[fp]:
                if (prev.get("timestamp") or "") < (r.get("timestamp") or ""):
                    history_for_row.append(prev)
        alerts.append(_v2_transform_row(
            r,
            fingerprint_history={fp: history_for_row} if fp else None,
            drain3_stats=drain3_stats,
            now_utc=now_utc,
        ))
    alerts_json = _json2.dumps(alerts, default=str)

    # Current Tangier time for the design's top-bar clock
    now_tng = now_utc.astimezone(timezone(timedelta(hours=1))).strftime("%Y-%m-%d %H:%M:%S")

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Observability · AI RCA — v2 Dashboard Preview</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/design/tokens.css"/>
<style>
  body {{ margin: 0; background: var(--bg, #0f1117); font-family: 'Inter', system-ui, sans-serif; color: var(--text, #e4e6ee); }}
  #root {{ min-height: 100vh; }}
  .v2-banner {{
    background: linear-gradient(180deg, rgba(176,126,232,.10), rgba(176,126,232,.02));
    border-bottom: 1px solid rgba(176,126,232,.35);
    padding: 8px 22px;
    font-size: 12.5px;
    color: var(--text-soft, #c0c5d0);
    display: flex; align-items: center; gap: 14px;
  }}
  .v2-banner strong {{ color: var(--accent-purple, #b07ee8); }}
  .v2-banner a {{ color: var(--accent-cyan, #40d0d0); text-decoration: none; }}
  .v2-banner a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>

<div class="v2-banner">
  <strong>v2 preview</strong>
  <span>2026-05-22 Claude Design redesign rendered against live /decisions data.</span>
  <span style="flex: 1"></span>
  <a href="/dashboard">↩ existing /dashboard</a>
  <a href="https://linalaaraich.github.io/monitoring-docs/solution-brief.html#supervisor-feedback" target="_blank">§12 feedback</a>
  <a href="https://linalaaraich.github.io/monitoring-docs/design-prompt.html" target="_blank">design prompt</a>
</div>

<div id="root"></div>

<script>
  window.CIRES_ALERTS = {alerts_json};
  window.CIRES_NOW_LOCAL = "{now_tng}";
</script>

<script src="https://unpkg.com/react@18.3.1/umd/react.development.js" crossorigin="anonymous"></script>
<script src="https://unpkg.com/react-dom@18.3.1/umd/react-dom.development.js" crossorigin="anonymous"></script>
<script src="https://unpkg.com/@babel/standalone@7.29.0/babel.min.js" crossorigin="anonymous"></script>

<script type="text/babel" src="/static/design/atoms.jsx"></script>
<script type="text/babel" src="/static/design/sidebar.jsx"></script>
<script type="text/babel" src="/static/design/dashboard.jsx"></script>

<script type="text/babel" data-presets="react">
  function App() {{
    return (
      <div className="cires" data-theme="dark" style={{{{ minHeight: "100vh" }}}}>
        <Dashboard mode="default"/>
      </div>
    );
  }}
  ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
</script>

</body>
</html>""")


@app.get("/metrics")
async def metrics():
    # US-5.3: refresh precision/recall gauges lazily before serving. Lazy
    # compute keeps the /metrics endpoint as the only DB-touching path for
    # these gauges — no background task, no cache-staleness, no extra
    # surface to fail. Cost: 4 lightweight COUNT queries per Prometheus
    # scrape (which is once every 15s by default).
    await _refresh_feedback_metrics()
    return Response(content=get_metrics(), media_type="text/plain; charset=utf-8")


async def _refresh_feedback_metrics():
    """Compute triage_precision + triage_recall from the rca_history +
    feedback tables and set the Prometheus Gauges in place.

    Definitions over the configurable window (default 7 days):
      escalates_total  = COUNT(rca_history WHERE llm_verdict='escalate' AND timestamp > since)
      dismisses_total  = COUNT(rca_history WHERE llm_verdict='dismiss' AND timestamp > since)
      confirms         = COUNT(feedback WHERE feedback_type='confirm' AND created_at > since)
      overrides        = COUNT(feedback WHERE feedback_type='override' AND created_at > since)

    Precision = TP / (TP+FP)
      TP = confirms (operator-confirmed escalations)
      FP = escalates_total - confirms (escalations the operator hasn't ratified)
        Note: this is conservative; in steady state the operator rarely confirms
        every TP, so precision is biased low. The metric becomes meaningful as
        operator habits stabilise.

    Recall = TP / (TP+FN)
      FN = overrides (DISMISSes the operator flipped to real incidents)

    Both gauges are set to 0 when the denominator is 0 (so the rate looks
    sane from a fresh deploy rather than NaN).
    """
    from app.metrics import triage_precision, triage_recall
    window = getattr(settings, "feedback_metrics_window_days", 7)
    try:
        escalates = await _store.count_decisions_by_verdict("escalate", window_days=window)
        confirms = await _store.count_feedback_in_window("confirm", window_days=window)
        overrides = await _store.count_feedback_in_window("override", window_days=window)
    except Exception as exc:
        logger.warning("Feedback metric refresh failed (non-fatal): %s", exc)
        return

    tp = confirms
    fp = max(escalates - confirms, 0)
    fn = overrides
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    triage_precision.set(precision)
    triage_recall.set(recall)
