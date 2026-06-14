import html as _html
import json as _json
import logging
import re as _re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo


def _safe_script_json(obj) -> str:
    """json.dumps for embedding inside an inline <script> block.

    Plain json.dumps does NOT escape < > & — so any payload value containing
    `</script>` (or `<script>`) breaks out of the tag = XSS. This matters for
    window.CIRES_* which embed user/URL input (the `q` filter) AND
    attacker-influenceable content (alert/log/RCA text). Escape the HTML-special
    chars + the JS line/paragraph separators to their \\uXXXX forms, which are
    valid in a JS string literal and inert in HTML. (2026-06-04 security fix.)
    """
    return (
        _json.dumps(obj, default=str)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


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
from fastapi.responses import HTMLResponse, RedirectResponse, Response

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
    notifier.store = _store  # operator-managed recipient list (2026-06-12)
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

# Process start time — used for the v2 dashboard's TopBar uptime stat.
import time as _time_at_import
_PROC_START_TIME = _time_at_import.time()

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
        "Received Drain3 webhook: tier=%s scope=%s anomalous_lines=%d anomaly_rate=%.4f",
        payload.tier,
        payload.scope,
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

# --- Notification recipients API (2026-06-12, Lina) — operator-managed ------
import re as _re_email
_EMAIL_RE = _re_email.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


from pydantic import BaseModel as _RcptBaseModel


class RecipientRequest(_RcptBaseModel):
    email: str
    label: str | None = None


@app.get("/api/recipients")
async def api_list_recipients() -> dict:
    """Recipients the escalation emails go to: the env baseline (always on) +
    the operator-managed list."""
    db = await _store.list_recipients() if _store else []
    from app.notifier import EmailNotifier
    baseline = EmailNotifier._parse_emails(settings.notification_email)
    return {"baseline": baseline, "managed": db}


@app.post("/api/recipients", status_code=201)
async def api_add_recipient(req: RecipientRequest) -> dict:
    email = (req.email or "").strip().lower()
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=422, detail=f"not a valid email: {req.email!r}")
    await _store.add_recipient(email, req.label)
    return {"ok": True, "email": email}


@app.delete("/api/recipients/{email}")
async def api_remove_recipient(email: str) -> dict:
    n = await _store.remove_recipient(email)
    if n == 0:
        raise HTTPException(status_code=404, detail=f"recipient not found: {email!r}")
    return {"ok": True, "removed": email}


@app.post("/feedback/override", status_code=201)
async def feedback_override(req: FeedbackRequest) -> FeedbackResponse:
    return await _record_feedback(req, feedback_type="override")


@app.post("/feedback/confirm", status_code=201)
async def feedback_confirm(req: FeedbackRequest) -> FeedbackResponse:
    return await _record_feedback(req, feedback_type="confirm")


# SF-7 (2026-05-23): the v2 rate-this-alert endpoint. Richer than
# override/confirm — collects rating + per-axis correctness + actual cause
# + tags + notes. The form shape comes from the Claude Design feedback.jsx
# page (supervisor-approved). Resolves the 8-char short_id back to the
# full UUID (same prefix-scan as the detail route).
from pydantic import BaseModel as _BaseModel
class V2FeedbackRequest(_BaseModel):
    rating: str | None = None              # "yes" / "no" / "partial"
    verdict_was_right: str | None = None   # "yes" / "no" / "maybe"
    action_was_right: str | None = None    # "yes" / "no" / "partial" / "n_a"
    actual_cause: str | None = None
    tags: list[str] = []
    notes: str | None = None
    rater: str | None = None

@app.post("/feedback/rate/{short_id}", status_code=201)
async def feedback_rate(short_id: str, req: V2FeedbackRequest) -> dict:
    """Save a v2-rate row for an alert identified by short_id (8-char prefix)."""
    import uuid as _uuid
    short = (short_id or "").strip().lower()
    if not short:
        raise HTTPException(status_code=400, detail="short_id is required")
    # Resolve short_id → full UUID
    scan = await _store.get_decisions(limit=500, offset=0, since_days=30)
    target = None
    for r in scan:
        if (r.get("id") or "").lower().startswith(short):
            target = r
            break
    if target is None:
        raise HTTPException(status_code=404, detail=f"No alert found with short_id prefix '{short}' in the last 30 days")
    saved = await _store.record_v2_feedback(
        feedback_id=str(_uuid.uuid4()),
        decision_id=target["id"],
        rating=req.rating,
        verdict_was_right=req.verdict_was_right,
        action_was_right=req.action_was_right,
        actual_cause=req.actual_cause,
        tags=req.tags,
        notes=req.notes,
        rater=req.rater,
    )
    return {"ok": True, "decision_id": target["id"], "saved": saved}


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
    if t == "suppressed_duplicate":
        # Legacy enum (pre-2026-06-09 recurrence change): the dedup short-path
        # used to write a standalone "See prior RCA" row with this decision.
        # 229 historical rows still carry it — keep them human-readable.
        return "Recurrence (suppressed)", "Repeat fire of an already-investigated fingerprint — dedup short-path, no LLM call (legacy row, pre-recurrence change)"
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
# /dashboard — Claude Design output (2026-05-22 supervisor-feedback redesign)
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

# Mapping tables extracted to app/v2_mappings.py (2026-05-23) so the
# notifier (escalation email) can share the same source-of-truth as the
# dashboard render. Local aliases keep the existing call-sites unchanged.
from app.v2_mappings import (
    VERDICT_MAP as _V2_VERDICT_MAP,
    ALERT_NAME_PLAIN as _V2_ALERT_NAME_PLAIN,
    SERVICE_TYPE as _V2_SERVICE_TYPE,
    NAMESPACE as _V2_NAMESPACE,
    display_namespace as _v2m_display_namespace,
    display_service as _v2m_display_service,
    env_resolver,
)


def _humanize_verdict_token(token: str) -> str:
    """N1 (2026-06-11 prod-mimic battery): legacy rows stored pointer tokens
    like `see_previous_rca:<uuid>` IN the verdict column; the services page
    rendered them raw (9 occurrences live). Collapse internals to operator
    words; real verdicts pass through."""
    t = (token or "").lower()
    if t.startswith("see_previous_rca"):
        return "recurrence"
    if t in ("escalate", "dismiss", "inconclusive"):
        return t
    return t.replace("_", " ")


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


# ──────────────────────────────────────────────────────────────────────
# 2026-06-04 (WS-2 / detail-page deep links). The detail page's
# DetailHeader has three buttons ("Open in Grafana", "Open in Loki",
# "Open in Jaeger") that previously linked to bare service roots
# (often the dead old-account IP). Operator feedback 2026-06-04 was
# explicit: "Grafana and other extra links do not work, fix that have
# them point to the exact needed page."
#
# `_build_cires_links` takes the resolved alert (after _v2_transform_row)
# and returns a {grafana, loki, jaeger} dict where each URL deep-links to
# the dashboard / Explore view the operator most likely needs for that
# specific alert shape:
#
#   * Infra alerts (Cpu / Memory / Disk on a node)      → unified-overview
#   * Latency / RequestRate (app on spring-boot / kong) → tracing-overview
#   * Drain3 / OTel collector health                    → otel-collector-health
#   * Otherwise → Grafana root (no dashboard guess beats the dashboards page)
#
# Loki + Jaeger always carry a service-name filter when the alert has a
# resolvable affected_service, so Explore / Search opens prefiltered.
# Dashboard UIDs are the ones provisioned by
# monitoring-project/roles/grafana/files/dashboards/*.json — verified
# at implementation time, not made up.
# ──────────────────────────────────────────────────────────────────────
_DASH_UID_UNIFIED = "unified-overview"
_DASH_UID_TRACING = "tracing-overview"
_DASH_UID_OTEL    = "otel-collector-health"


def _infer_evidence_source(text: str) -> str:
    """2026-06-12: classify an evidence line by which pillar it came from so
    the detail page labels it correctly (was: everything → "Prometheus").
    Returns 'loki' | 'jaeger' | 'prom' (default)."""
    t = (text or "").lower()
    if any(k in t for k in ("loki", "log line", "log template", "returned 0 lines",
                            "annotated log", " logs ", "drain3", "novel template")):
        return "loki"
    if any(k in t for k in ("jaeger", "trace", "span", "traceid", "trace_id",
                            "db.statement", "operation", "0 traces")):
        return "jaeger"
    return "prom"


def _safe_http_url(url) -> str:
    """FE-H2 (2026-06-04) — defense-in-depth href-scheme allowlist.

    Every URL emitted into a `window.CIRES_*` link or `evidence[].link`
    eventually renders as a raw `<a href>`. `_safe_script_json` only
    neutralises `</script>` breakout inside the JSON blob — it does NOTHING
    for the href scheme, so a `javascript:`/`data:`/`vbscript:` URL would
    render as a live 1-click XSS sink. Allow ONLY http(s) (plus the sentinel
    "#"); anything else collapses to "#". Single server-side chokepoint;
    atoms.jsx `safeHref` is the client backstop.
    """
    if not isinstance(url, str):
        return "#"
    u = url.strip()
    if u == "" or u == "#":
        return "#"
    # Reject control chars / whitespace that browsers strip to smuggle a
    # scheme (e.g. "java\tscript:") before the scheme check.
    if any(ord(c) < 0x20 for c in u):
        return "#"
    low = u.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return u
    # Protocol-relative ("//host/…") is acceptable (inherits page scheme).
    if u.startswith("//"):
        return u
    return "#"


def _grafana_deep_link_for_alert(alert_name: str, service: str) -> str:
    """Pick the most relevant provisioned dashboard URL for this alert.

    Returns a path of the form `/d/{uid}/{slug}?var-service=<svc>` when
    we can route confidently, else the Grafana root. Filter params are
    safe to include even when the dashboard has no matching template
    variable — Grafana ignores unknown var-* keys.
    """
    import urllib.parse as _u
    base = (settings.grafana_url or "").rstrip("/")
    name = (alert_name or "")
    svc_q = _u.quote_plus(service) if service and service != "—" else ""

    def _with_svc(path: str) -> str:
        if not svc_q:
            return f"{base}{path}"
        sep = "&" if "?" in path else "?"
        return f"{base}{path}{sep}var-service={svc_q}"

    # OTel collector health / Drain3 anomalies → collector dashboard.
    if "Drain3" in name or "Otel" in name or "OTel" in name:
        return _with_svc(f"/d/{_DASH_UID_OTEL}/otel-collector-health")
    # Latency / request-rate / error-rate → distributed tracing overview.
    # 2026-06-12: the tracing dashboard reads Jaeger, so its var-service must
    # be the canonical trace name (employees-backend, not spring-boot).
    if any(k in name for k in ("P95Latency", "Latency", "RequestRate", "ErrorRate", "HighKong", "HighP95")):
        from app.v2_mappings import trace_service_name
        tname = trace_service_name(service)
        tq = _u.quote_plus(tname) if tname and tname != "—" else ""
        path = f"/d/{_DASH_UID_TRACING}/distributed-tracing-overview"
        return f"{base}{path}?var-service={tq}" if tq else f"{base}{path}"
    # Infra (CPU / Memory / Disk / Pod) → unified overview.
    if any(k in name for k in ("Cpu", "CPU", "Memory", "Disk", "Pod", "Node", "TargetDown")):
        return _with_svc(f"/d/{_DASH_UID_UNIFIED}/unified-observability-overview")
    # Fallback: Grafana root.
    return base or "#"


def _loki_deep_link_for_alert(service: str) -> str:
    """Open Grafana Explore (Loki datasource) prefiltered to {service_name="<service>"} for ~1h.

    Loki itself has no web UI - /explore is a Grafana page that picks
    the Loki datasource. So this URL is built off settings.grafana_url,
    not settings.loki_url. The settings.loki_url field is kept for
    contexts that talk to the Loki HTTP API directly (Drain3 background
    ingestion uses loki_api_url, which is the same target host but a
    separate field; loki_url is a UI fallback only when there is no
    Grafana to point at).
    """
    import urllib.parse as _u
    import json as _j
    grafana_base = (settings.grafana_url or "").rstrip("/")
    if not grafana_base:
        # No Grafana to deep-link into - fall back to the bare Loki host
        # so the operator at least sees the upstream is reachable.
        return (settings.loki_url or "").rstrip("/") or "#"
    if not service or service == "—":
        return f"{grafana_base}/explore?orgId=1&left=%7B%22datasource%22%3A%22loki%22%7D"
    expr = f'{{service_name="{service}"}}'
    left = {
        "datasource": "loki",
        "queries": [{"refId": "A", "expr": expr, "queryType": "range"}],
        "range": {"from": "now-1h", "to": "now"},
    }
    qs = _u.urlencode({"orgId": "1", "left": _j.dumps(left, separators=(",", ":"))})
    return f"{grafana_base}/explore?{qs}"


def _jaeger_deep_link_for_alert(service: str) -> str:
    """Open the Jaeger search UI prefiltered to the affected service for ~1h."""
    import urllib.parse as _u
    base = (settings.jaeger_url or "").rstrip("/")
    if not base:
        return "#"
    if not service or service == "—":
        return base
    # 2026-06-12 (Lina link audit): use the service name Jaeger actually
    # indexes — a `spring-boot` alert must link to `employees-backend`, the
    # real trace stream (Jaeger has no `spring-boot`), or the link opens an
    # empty Jaeger search.
    from app.v2_mappings import trace_service_name
    qs = _u.urlencode({"service": trace_service_name(service), "lookback": "1h"})
    return f"{base}/search?{qs}"


def _build_cires_links(alert: dict) -> dict:
    """Compute the three CIRES_LINKS URLs for the resolved alert.

    `alert` is the dict produced by `_v2_transform_row` (has
    `alertName` + `component` keys). Returns the dict that gets
    json-dumped into the detail page's `window.CIRES_LINKS`.
    """
    alert_name = (alert.get("alertName") or "")
    service = (alert.get("component") or alert.get("boldSubject") or "") or ""
    # FE-H2: every emitted URL passes the http(s) scheme allowlist so a
    # crafted service name / label can never produce a javascript:/data: href.
    return {
        "grafana": _safe_http_url(_grafana_deep_link_for_alert(alert_name, service)),
        "loki":    _safe_http_url(_loki_deep_link_for_alert(service)),
        "jaeger":  _safe_http_url(_jaeger_deep_link_for_alert(service)),
    }


def _v2_transform_row(r: dict, *, fingerprint_history: dict | None = None,
                       drain3_stats: dict | None = None,
                       now_utc=None,
                       incident_fire_counts: dict | None = None,
                       feedback_ids: set | None = None) -> dict:
    """Map a /decisions RCARecord row → the CIRES_ALERT shape the design expects.

    `fingerprint_history`: dict mapping alert_fingerprint → list[prior_row]
    (oldest first), used to compute fireCount + history timeline.
    `drain3_stats`: optional dict from _drain.get_stats(), used for the
    Drain3 detail-page tile and the dashboard sustained indicator.
    `now_utc`: reference datetime for relTime / activeFor calculations.
    `incident_fire_counts`: F-2 (2026-06-10) — {fingerprint: fire_count}
    prefetched from the incidents table (one bulk query per page render).
    The slab-derived len(prior)+1 misses dedup-absorbed recurrences (which
    no longer write feed rows) and anything outside the 500-row/15-day slab;
    the incident entity is the source of truth, so fireCount reconciles to
    MAX(slab, incident) here — the ONE shared place — keeping feed and
    detail in agreement (they both call this transform).
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
    # F-2: reconcile against the incident entity's fire_count (counts
    # dedup-absorbed recurrences + fires outside the slab window). MAX, not
    # replace: a missing/stale incident row must never UNDER-count the slab.
    if fingerprint and incident_fire_counts:
        try:
            inc_fc = int(incident_fire_counts.get(fingerprint) or 0)
        except (TypeError, ValueError):
            inc_fc = 0
        if inc_fc > fire_count:
            fire_count = inc_fc
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
        # 2026-06-12 (Lina): make each past fire CLICKABLE to its own
        # investigation, mark whether it was a full investigation (has an
        # LLM verdict to read) vs a cheap gated/suppressed row, and flag if
        # an operator review exists for it.
        _pid = (prev.get("id") or "")
        history.append({
            "time": ptime, "verdict": pverdict, "delta": "prior fire",
            "id": _pid[:8],
            "investigated": bool((prev.get("llm_verdict") or "").strip()),
            "hasFeedback": bool(feedback_ids) and _pid in feedback_ids,
        })
    history.append({
        "time": time_local, "verdict": verdict,
        "delta": ("first seen" if not prior else "still active — sustained"
                  if indicator == "sustained" else "re-fired"),
        "id": short_id,
        "investigated": bool(verdict_lower),
        "hasFeedback": bool(feedback_ids) and raw_id in feedback_ids,
        "current": True,
    })

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
            # 2026-06-04 (WS-2 Prong 4): evidence[].link used to be the
            # bare string "Grafana" which the frontend turned into a
            # dead "#" anchor. Populate with a real Grafana deep-link
            # using the same routing helper as DetailHeader. Per-row
            # PromQL-aware Grafana Explore links (so each evidence row
            # opens its own metric) deferred to Sprint 5 (US-G-EV1)
            # so we don't block the old-account-IP fix on a bigger
            # refactor of the evidence array shape.
            # FE-H2: scheme-allowlist every evidence href (the contextual
            # Grafana link AND any link the upstream row already carried) so a
            # javascript:/data: URL can never reach the rendered <a href>.
            ev_link = _safe_http_url(_grafana_deep_link_for_alert(alert_name, svc))
            for e in parsed[:5]:
                if isinstance(e, str):
                    # 2026-06-12: infer the source from the text instead of
                    # labelling EVERY item "Prometheus" — a cross-source RCA
                    # was rendering its Loki log lines + Jaeger traces all
                    # under a Prometheus tag, hiding the very cross-signal
                    # story the platform is built on.
                    evidence.append({"source": _infer_evidence_source(e), "text": e, "link": ev_link})
                elif isinstance(e, dict):
                    if not (e.get("source") or "").strip():
                        e = {**e, "source": _infer_evidence_source(str(e.get("text", "")))}
                    # Existing dicts may carry their own link or none. If
                    # the link is empty / placeholder ("Grafana" / "#"),
                    # overwrite with the contextual URL so the row is
                    # clickable. Preserve any real URL the upstream code
                    # has already provided — but only if it survives the
                    # http(s) allowlist.
                    existing = (e.get("link") or "").strip()
                    if (not existing) or existing in ("#", "Grafana", "Loki", "Jaeger"):
                        e = {**e, "link": ev_link}
                    else:
                        e = {**e, "link": _safe_http_url(existing)}
                    evidence.append(e)
    except Exception:
        pass

    # Tags — derive from quality + decision shape
    tags = []
    q = (r.get("rca_quality") or "").lower()
    td = (r.get("triage_decision") or "").lower()
    # N2 (2026-06-11 prod-mimic battery): rca_quality grades the PROSE, but
    # "actionable" rendered on a DISMISS verdict reads as a call to action on
    # a row whose whole point is "nothing to do" (live: TargetDown dismissed
    # at 0.40 wearing an actionable tag). Suppress the tag for dismissals;
    # the honest-negative tags (data-starved/needs-review) still show.
    if q == "actionable" and verdict_lower != "dismiss":
        tags.append("actionable")
    if q == "data_starved":
        tags.append("data-starved")
    if q == "needs_review":
        tags.append("needs-review")
    if action_taken == "shelved":
        tags.append("shelved")
    if td == "recurrence_gated_pre_llm":
        tags.append("recurrence-gated")
    if td == "suppressed_duplicate":
        # F-3 (2026-06-10): legacy dedup short-path rows (pre-2026-06-09
        # recurrence change) had no humanized surface in the v2 UI — tag them
        # in the same tone as recurrence-gated so the operator sees WHY the
        # row has no verdict/confidence instead of a bare PENDING.
        tags.append("recurrence-suppressed")
    if action_taken == "consolidated":
        # 2026-06-12 co-fire consolidation: this escalation was folded into a
        # family sibling's notification — the row keeps its full verdict, the
        # tag explains why no email count shows for it.
        tags.append("consolidated")
    if not tags:
        tags = ["—"]

    # 2026-06-02 human-first reason refactor — the "reason" cell renders
    # `human_cause` (plain-English single sentence, NO PromQL / metric
    # formulas), not the first sentence of the RCA prose. Resolution order:
    #   1. The decoded `human_cause` from the JSON envelope (new rows).
    #   2. The legacy split via prose_helpers on raw-text rca_report (old rows).
    #   3. llm_reasoning as a last-resort fallback for very old rows whose
    #      rca_report is empty.
    # The technical evidence (PromQL etc.) is rendered separately in the
    # row's expanded "Technical evidence" section via `evidence`.
    from app.prose_helpers import derive_human_cause
    raw_rca = r.get("rca_report") or ""
    rca_prose_only = raw_rca
    human_cause_field = ""
    if raw_rca.startswith("{"):
        try:
            envelope = _json2.loads(raw_rca)
            if isinstance(envelope, dict):
                human_cause_field = (envelope.get("human_cause") or "").strip()
                rca_prose_only = envelope.get("rca") or ""
        except (ValueError, TypeError):
            pass
    reason = derive_human_cause(
        human_cause_field,
        rca_prose_only,
        r.get("llm_reasoning") or "",
        fallback="No RCA prose recorded.",
    )

    confidence = None
    try:
        confidence = float(r.get("llm_confidence")) if r.get("llm_confidence") not in (None, "") else None
    except Exception:
        confidence = None

    # Drain3 snapshot — only populated for Drain3AnomalyDetected alerts. Must
    # be None (falsy) for other alert types so detail.jsx's `if (!d) return null`
    # short-circuits cleanly instead of crashing on undefined nested fields.
    drain3_card = None
    if alert_name == "Drain3AnomalyDetected" and drain3_stats:
        matched_template_str = (drain3_stats.get("top_new_patterns_per_service", {}).get(svc, [""]) or [""])[0] or ""
        drain3_card = {
            "learnedTotal": drain3_stats.get("total_clusters", 0),
            "anomalyRate": drain3_stats.get("recent_anomaly_rate", 0.0),
            "linesIngested": drain3_stats.get("total_lines_processed", 0),
            "matchedTemplate": matched_template_str,
            "relatedTemplates": [],
        }

    # LLM reasoning — split llm_reasoning into discrete steps. The design's
    # ReasoningSection accesses a.reasoning.length without a null guard, so
    # an undefined here crashes the whole DetailPage. Always return a list.
    reasoning_steps = []
    llm_reasoning_text = r.get("llm_reasoning") or ""
    if llm_reasoning_text:
        # 2026-06-12: the investigation-log format is "1. checked X -> Y; 2.
        # checked Z -> W; 3. ..." — usually ONE line, semicolon-joined, with
        # numbered markers and NO newlines. The old split (newline / ". Cap")
        # found no delimiter and collapsed the whole chain to a single "1
        # steps" item. Split primarily on the numbered markers so each step
        # shows separately (Lina wants the 1->2->3 thought process visible).
        import re as _re_steps
        # Break right before "N." markers (1./2./3. ...), also tolerating a
        # leading marker and "; " / newline joins.
        parts = _re_steps.split(r"(?:^|[;\n]\s*)\s*\d+\.\s+", llm_reasoning_text)
        candidates = [p for p in parts if p and p.strip()]
        if len(candidates) <= 1:
            # No numbered markers — fall back to sentence/newline split.
            candidates = _re_steps.split(r"\n\s*|;\s+|\.\s+(?=[A-Z])", llm_reasoning_text)
        for c in candidates:
            c = c.strip().lstrip("0123456789.) ").strip()
            if c and len(c) > 4:
                reasoning_steps.append(c)
        if not reasoning_steps:
            reasoning_steps = [llm_reasoning_text.strip()]

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
        # env: render the env resolved + persisted by the pipeline
        # (env_resolver's full label-precedence chain — alert labels.env first;
        # task #11 fix 2026-06-04). Legacy rows written before the env column
        # existed have no stored value: fall back to a service-token inference
        # via env_resolver (which still maps `rental*` -> stg) and ultimately
        # to "unknown" — never a silent hardcoded "prod".
        "env": (r.get("env") or "").strip().lower()
                or env_resolver(service=svc if svc != "—" else None),
        "namespace": _v2m_display_namespace(_V2_NAMESPACE.get(svc, svc[:20] or "—")),
        "serviceType": _V2_SERVICE_TYPE.get(svc, "infra"),
        "component": _v2m_display_service(svc),
        "alertName": alert_name,
        "alertPlain": _V2_ALERT_NAME_PLAIN.get(alert_name, alert_name),
        "verdict": verdict,
        "severity": (r.get("severity") or "info").lower(),
        "indicator": indicator,
        "reason": reason,
        "boldSubject": _v2m_display_service(svc) if svc and svc != "—" else "",
        "actions": actions,
        "tags": tags,
        "confidence": confidence,
        "quality": q,
        "fireCount": fire_count,
        "history": history,
        "evidence": evidence,
        "drain3": drain3_card,
        # Detail-page-specific fields (safe defaults — detail.jsx reads these
        # without null guards in places)
        "reasoning": reasoning_steps,
        "related": [],  # populated by the detail route, not the dashboard route
        # 2026-06-12 co-fire consolidation — full uuid of the primary decision
        # this row's notification was folded into (None for normal rows), and
        # the list of sibling rows folded into THIS row (populated by the
        # dashboard route's grouping pass, empty everywhere else).
        "consolidatedInto": r.get("consolidated_into") or None,
        "consolidated": [],
        # Per-row Grafana/Loki/Jaeger deep-links so the dashboard expanded-row
        # quick-action anchors (D2) point somewhere real — the same routing the
        # detail route's CIRES_LINKS uses, computed per alert shape.
        "links": _build_cires_links({"alertName": alert_name, "component": svc}),
        "deploy": None,  # SF-11 work — placeholder for deploy-correlation card
        "promql": r.get("promql_expr") or "",
        "ip": r.get("alert_instance") or "",
    }


# ──────────────────────────────────────────────────────────────────────
# /dashboard — URL filter persistence (Sprint 4 §14 W2 Wed, 2026-05-27)
# ──────────────────────────────────────────────────────────────────────
# The v2 dashboard's filters (verdict / severity / family / range / search)
# now round-trip through the query string so a refresh, a back-button, or
# a shared link preserves the operator's view. The route reads each filter
# via a tight allowlist; unknown values fall back to the default and a
# debug log line is emitted so a crafted URL can't bypass the filter or
# inject SQL.
#
# Range translates to a since-hours window (1h / 6h / 24h / 7d / 15d → 1,
# 6, 24, 168, 360 hours). The store's get_decisions() now accepts
# since_hours alongside since_days for sub-day granularity.

# Tight allowlists — anything not in here falls back to None (= no filter).
# Verdict values match what /v2 actually surfaces (see _V2_VERDICT_MAP).
_V2_FILTER_VERDICTS = {"escalate", "dismiss", "investigate", "shelve"}
_V2_FILTER_SEVERITIES = {"critical", "warning", "info", "none"}
# Env allowlist - the same canonical-form set the resolver emits. "unknown"
# is included so the operator can filter to the gap explicitly. Kept short
# on purpose: any token outside this set silently falls back to "no filter"
# rather than letting a typo through.
_V2_FILTER_ENVS = {"prod", "stg", "preprod", "uat", "int", "dev", "qa",
                   "test", "sandbox", "canary", "infra", "demo", "unknown"}
# Family is a coarse alert-name bucket; matched as a substring LIKE on the
# alert_name column. Keep this list short - it's surfaced in the dropdown.
_V2_FILTER_FAMILIES = {
    "cpu":     "CPU",       # CpuSpike, HighCPUUsage, KongCpu...
    "memory":  "Memory",    # PodHighMemoryUsage, MemoryPressure
    "latency": "Latency",   # HighP95Latency, KongLatency
    "disk":    "Disk",      # DiskSpaceLow, DiskIOPS
    "network": "Network",   # NetworkSaturation
    "pod":     "Pod",       # PodRestart, PodHigh...
    "drain":   "Drain",     # Drain3AnomalyDetected
    "kong":    "Kong",      # Kong-prefixed
    "spring":  "Spring",    # spring-boot-prefixed
}
# Range token → since_hours. Keep aligned with what the UI exposes.
_V2_FILTER_RANGES = {
    "1h":  1.0,
    "6h":  6.0,
    "24h": 24.0,
    "7d":  24.0 * 7,
    "15d": 24.0 * 15,
}
_V2_FILTER_DEFAULT_RANGE = "15d"  # matches the pre-filter behavior (limit=500, since_days=15)


def _parse_v2_filters(
    verdict: str | None,
    severity: str | None,
    family: str | None,
    range_: str | None,
    q: str | None,
    env: str | None = None,
) -> dict:
    """Validate & normalize the /dashboard URL filter set.

    Returns a dict with always-present keys:
      - verdict, severity, family, range, q, env (each may be None / "")
      - since_hours: float (the resolved window in hours)
      - active_count: int (how many filters the operator actually set)

    Unknown / out-of-range inputs silently fall back to the default.
    Logging is debug-level so a crafted URL doesn't fill the warn log -
    the test suite asserts on the "graceful fallback" behavior.
    """
    v = (verdict or "").strip().lower()
    s = (severity or "").strip().lower()
    f = (family or "").strip().lower()
    r = (range_ or "").strip().lower()
    e = (env or "").strip().lower()
    # Search query: clamp to 200 chars; allow any printable input. The
    # search filter is applied client-side (matches the dashboard.jsx
    # data-search behavior), so SQL safety is not at risk here - but
    # we still cap to prevent oversize echo of attacker input.
    q_norm = (q or "").strip()[:200]

    v_out = v if v in _V2_FILTER_VERDICTS else None
    s_out = s if s in _V2_FILTER_SEVERITIES else None
    f_out = f if f in _V2_FILTER_FAMILIES else None
    r_out = r if r in _V2_FILTER_RANGES else _V2_FILTER_DEFAULT_RANGE
    e_out = e if e in _V2_FILTER_ENVS else None
    since_hours = _V2_FILTER_RANGES[r_out]

    active_count = sum(1 for x in (v_out, s_out, f_out, e_out, q_norm) if x)
    # Range counts only if the operator deviated from the default; otherwise
    # the "active filters" badge would always read >=1 on first load.
    if r_out != _V2_FILTER_DEFAULT_RANGE:
        active_count += 1

    return {
        "verdict": v_out,
        "severity": s_out,
        "family": f_out,
        "family_substring": _V2_FILTER_FAMILIES.get(f_out) if f_out else None,
        "range": r_out,
        "q": q_norm,
        "env": e_out,
        "since_hours": since_hours,
        "active_count": active_count,
    }


def _render_v2_filter_bar(filters: dict, page: int, size: int) -> str:
    """Server-side <form> with the active filter selections marked.

    Submits via GET on change (no JS framework — a tiny inline onchange
    handler triggers form.submit()). Bookmarking / sharing falls out for
    free because every filter lives in the URL.
    """
    import html as _h

    def _sel(value: str | None, current: str | None) -> str:
        # Empty value → the "any" option. Mark selected when the current
        # filter is unset OR matches.
        if value is None and (current is None or current == ""):
            return " selected"
        if value is not None and value == current:
            return " selected"
        return ""

    verdict_opts = "".join(
        f'<option value="{_h.escape(v)}"{_sel(v, filters["verdict"])}>{_h.escape(v.upper())}</option>'
        for v in sorted(_V2_FILTER_VERDICTS)
    )
    severity_opts = "".join(
        f'<option value="{_h.escape(s)}"{_sel(s, filters["severity"])}>{_h.escape(s)}</option>'
        for s in ("critical", "warning", "info", "none")
    )
    family_opts = "".join(
        f'<option value="{_h.escape(k)}"{_sel(k, filters["family"])}>{_h.escape(k)}</option>'
        for k in sorted(_V2_FILTER_FAMILIES.keys())
    )
    # Env dropdown - canonical order (operational tiers first, then the
    # explicit "unknown" gap). Matches the env_resolver / _V2_FILTER_ENVS
    # allowlist.
    env_order = ("prod", "stg", "preprod", "uat", "int", "dev", "qa",
                 "test", "sandbox", "canary", "unknown")
    env_opts = "".join(
        f'<option value="{_h.escape(k)}"{_sel(k, filters.get("env"))}>{_h.escape(k)}</option>'
        for k in env_order
    )
    range_opts = "".join(
        f'<option value="{_h.escape(k)}"{_sel(k, filters["range"])}>{_h.escape(k)}</option>'
        for k in ("1h", "6h", "24h", "7d", "15d")
    )
    q_val = _h.escape(filters["q"] or "", quote=True)
    return f"""
<form class="v2-filter-bar" method="get" action="/dashboard" data-v2-filter-bar>
  <label class="v2-filter-bar__lbl">Verdict
    <select name="verdict" onchange="this.form.submit()">
      <option value=""{_sel(None, filters["verdict"])}>any</option>
      {verdict_opts}
    </select>
  </label>
  <label class="v2-filter-bar__lbl">Severity
    <select name="severity" onchange="this.form.submit()">
      <option value=""{_sel(None, filters["severity"])}>any</option>
      {severity_opts}
    </select>
  </label>
  <label class="v2-filter-bar__lbl">Family
    <select name="family" onchange="this.form.submit()">
      <option value=""{_sel(None, filters["family"])}>any</option>
      {family_opts}
    </select>
  </label>
  <label class="v2-filter-bar__lbl">Env
    <select name="env" onchange="this.form.submit()">
      <option value=""{_sel(None, filters.get("env"))}>any</option>
      {env_opts}
    </select>
  </label>
  <label class="v2-filter-bar__lbl">Range
    <select name="range" onchange="this.form.submit()">
      {range_opts}
    </select>
  </label>
  <label class="v2-filter-bar__lbl v2-filter-bar__lbl--grow">Search
    <input type="search" name="q" value="{q_val}" placeholder="alert name, service, RCA text…" autocomplete="off"/>
  </label>
  <input type="hidden" name="size" value="{int(size)}"/>
  <noscript><button type="submit" class="v2-filter-bar__apply">Apply</button></noscript>
  <a class="v2-filter-bar__clear" href="/dashboard" title="Clear all filters">clear</a>
</form>
"""


# ──────────────────────────────────────────────────────────────────────
# Unified theme head-script for the React (.cires / tokens.css) pages.
# The React layer persists the theme in localStorage under "obs-rca-theme"
# and scopes its light tokens to `.cires[data-theme="light"]`. This inline
# <head> script mirrors that persisted value onto <html data-theme> BEFORE
# paint so the body background (tokens.css `html[data-theme="light"] body`)
# tracks the active theme with no dark flash, and a short poll keeps <html>
# in sync when the in-page ThemeToggle flips the value. Reading the SAME key
# the React useTheme() hook uses is what unifies the two theme systems.
_CIRES_THEME_HEAD_SCRIPT = (
    '<script>(function(){try{'
    'var apply=function(){var t=localStorage.getItem("obs-rca-theme")||"dark";'
    'document.documentElement.setAttribute("data-theme",t);};'
    'apply();setInterval(apply,500);'
    '}catch(e){}})();</script>'
)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_v2(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=10, le=200),
    verdict: str | None = Query(None, max_length=32),
    severity: str | None = Query(None, max_length=32),
    family: str | None = Query(None, max_length=32),
    range_: str | None = Query(None, alias="range", max_length=8),
    q: str | None = Query(None, max_length=200),
    env: str | None = Query(None, max_length=16),
    _partial: int | None = Query(None, ge=0, le=1),
):
    """Preview of the 2026-05-22 redesigned dashboard.

    Renders the Claude Design <Dashboard/> component against real
    /decisions data. See solution-brief.html §12 + design-prompt.html
    for the design spec; static assets at /static/design/.

    2026-05-27 (Sprint 4 §14 W2 Wed) — URL filter persistence. Five
    filters round-trip through the query string:
      ?verdict=ESCALATE&severity=critical&family=cpu&range=24h&q=...
    Each is validated against a tight allowlist; unknown values silently
    fall back to the default. The range filter translates to a
    since_hours window applied in the SQL query, not client-side.
    """
    import json as _json2
    from datetime import datetime, timezone, timedelta
    now_utc = datetime.now(timezone.utc)

    # Validate + normalize the URL filter set. Returns the active filter
    # values + the resolved since_hours window. Bad inputs fall back to
    # the default — no 500, no log spam.
    filters = _parse_v2_filters(verdict, severity, family, range_, q, env)

    # SF-4 (2026-05-23): same-alert collapsing — one row per fingerprint with
    # fireCount=N + latest timestamp instead of N separate rows. Pull a wide
    # slab from /decisions (range-bounded, cap 500 rows for perf), group by
    # fingerprint, keep the LATEST row per group as the representative, then
    # paginate the unique-fingerprint list. Detail page (/dashboard/alert/
    # {short_id}) already shows the full fire history per fingerprint.
    #
    # Sprint 4 §14 W2 Wed: filters apply BEFORE the fingerprint collapse so
    # the operator's view restricts to (e.g.) ESCALATE rows only. Search (q)
    # is intentionally NOT pushed into SQL — it's a free-text blob check
    # done client-side via data-search on each row, same shape as /dashboard.
    history_slab = await _store.get_decisions(
        limit=500,
        offset=0,
        since_hours=filters["since_hours"],
        verdict=filters["verdict"],
        severity=filters["severity"],
        alert_name_like=filters["family_substring"],
        env=filters["env"],
    )

    # Group by fingerprint. Rows without a fingerprint (legacy / internal
    # self-fires) get a synthetic key based on (alertname, service, id) so
    # they don't all collapse into one bucket.
    by_fp: dict[str, list] = {}
    for r in history_slab:
        fp = r.get("alert_fingerprint") or f"__no_fp__:{r.get('alert_name','')}:{r.get('affected_service','')}:{r.get('id','')}"
        by_fp.setdefault(fp, []).append(r)
    # Sort each group oldest→newest (needed for the transformer's prior-history list)
    for fp in by_fp:
        by_fp[fp].sort(key=lambda x: x.get("timestamp") or "")

    # Collapse: one representative per fingerprint = the LATEST row.
    representatives = []
    for fp, rows_in_fp in by_fp.items():
        latest = rows_in_fp[-1]
        representatives.append((fp, latest))
    # Sort representatives by latest-timestamp DESC for the feed
    representatives.sort(key=lambda t: t[1].get("timestamp") or "", reverse=True)

    # Pagination on the COLLAPSED list (was on raw rows before SF-4)
    total_in_window = len(representatives)
    last_page = max(1, (total_in_window + size - 1) // size)
    offset = (page - 1) * size
    page_reps = representatives[offset:offset + size]

    # Drain3 stats once per request (used for Drain3AnomalyDetected rows)
    drain3_stats = _drain.get_stats() if _drain is not None else {}

    # F-2 (2026-06-10): ONE bulk incidents query for the page's fingerprints so
    # the feed's fireCount reconciles to the incident entity — the same number
    # the detail page shows. Failure degrades to the slab count (no 500).
    incident_fire_counts: dict[str, int] = {}
    page_fps = [(rep.get("alert_fingerprint") or "") for _fp, rep in page_reps]
    try:
        incident_fire_counts = await _store.get_fire_counts_for_fingerprints(page_fps)
    except Exception as exc:
        logger.warning("feed incident fire_count prefetch failed (non-fatal): %s", exc)

    # Transform the page representatives. The transformer's fingerprint_history
    # is the OLDER rows of the same fingerprint — the fireCount + history
    # timeline come from this.
    alerts = []
    for fp, rep in page_reps:
        prior = [r for r in by_fp[fp] if (r.get("timestamp") or "") < (rep.get("timestamp") or "")]
        alerts.append(_v2_transform_row(
            rep,
            fingerprint_history={(rep.get("alert_fingerprint") or fp): prior},
            drain3_stats=drain3_stats,
            now_utc=now_utc,
            incident_fire_counts=incident_fire_counts,
        ))

    # 2026-06-12 co-fire grouping (Lina): a consolidated sibling renders
    # INSIDE its primary's row (one expandable incident row, not N), when the
    # primary is on the same page — they fire seconds apart so they almost
    # always are. If the primary fell outside the page/slab, the sibling
    # stays a standalone row wearing its "consolidated" tag (honest
    # fallback; its detail page still links the incident). Nothing is
    # dropped — every contributor stays reachable.
    by_uuid = {a["uuid"]: a for a in alerts if a.get("uuid")}
    grouped_away = set()
    for a in alerts:
        target = a.get("consolidatedInto")
        if not target:
            continue
        primary = by_uuid.get(target)
        if primary is None or primary is a:
            continue
        primary["consolidated"].append({
            "id": a["id"], "uuid": a["uuid"],
            "alertName": a["alertName"], "alertPlain": a["alertPlain"],
            "timeShort": a["timeShort"], "verdict": a["verdict"],
            "severity": a["severity"], "component": a["component"],
        })
        grouped_away.add(a["uuid"])
    if grouped_away:
        alerts = [a for a in alerts if a["uuid"] not in grouped_away]
    alerts_json = _safe_script_json(alerts)

    # ─── TopBar + sidebar stats (computed from the same slab; no new DB hits) ───
    # Use the wider history_slab (up to 200 most-recent rows in window) for the
    # 24h-bounded stats.
    midnight_utc = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    day_ago = now_utc - timedelta(days=1)
    def _ts_dt(r):
        try:
            d = datetime.fromisoformat((r.get("timestamp") or "").replace("Z", "+00:00"))
            return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d
        except Exception:
            return None
    emailed_24h = 0
    shelved_24h = 0
    cheap_path_since_midnight = 0
    llm_durations = []
    open_fingerprints = set()
    for r in history_slab:
        ts = _ts_dt(r)
        if ts is None:
            continue
        act = (r.get("action_taken") or "").lower()
        td = (r.get("triage_decision") or "").lower()
        if ts >= day_ago:
            if act == "emailed":
                emailed_24h += 1
                fp = r.get("alert_fingerprint") or ""
                if fp:
                    open_fingerprints.add(fp)
            if act == "shelved":
                shelved_24h += 1
            dur = r.get("investigation_duration_ms") or 0
            if dur > 0:
                llm_durations.append(dur / 1000.0)
        if ts >= midnight_utc and td in ("triage_suppressed", "suppressed_duplicate", "recurrence_gated_pre_llm"):
            cheap_path_since_midnight += 1
    llm_durations.sort()
    median_latency_s = round(llm_durations[len(llm_durations) // 2], 1) if llm_durations else 0.0

    # Process uptime — _PROC_START is set at import time below.
    import time as _t
    uptime_sec = int(_t.time() - _PROC_START_TIME)

    dashboard_stats = {
        "uptimeSec": uptime_sec,
        "openAlerts": len(open_fingerprints),
        "emailed24h": emailed_24h,
        "shelved24h": shelved_24h,
        "medianLatency": median_latency_s,
        "cheap_path_since_midnight": cheap_path_since_midnight,
    }
    sidebar_badges = {
        "triage": len(open_fingerprints),
        "incidents": len(by_fp),  # distinct fingerprints in window
        "anomalies": (drain3_stats.get("total_anomalies") or 0),
    }
    pagination = {
        "page": page,
        "size": size,
        "total": total_in_window,
        "lastPage": last_page,
        "shown": len(alerts),
    }

    # Current Tangier time for the design's top-bar clock
    now_tng = now_utc.astimezone(timezone(timedelta(hours=1))).strftime("%Y-%m-%d %H:%M:%S")

    # Server-rendered filter bar. The React layer doesn't need to know about
    # filters - the page is reloaded on every change, and the alerts payload
    # arrives already filtered.
    # (legacy server-rendered v2 filter bar removed 2026-06-04 — the React app
    # renders its own FilterBar; the duplicate dark bar above #root is gone.)
    # Mirror the resolved filter set into window.CIRES_FILTERS so the React
    # layer can surface "active filters" badges + the empty-filtered state.
    filters_payload = {
        "verdict": filters["verdict"],
        "severity": filters["severity"],
        "family": filters["family"],
        "range": filters["range"],
        "q": filters["q"],
        "env": filters["env"],
        "activeCount": filters["active_count"],
    }

    # 2026-06-02 - partial-refresh JSON branch. The browser polls
    # /dashboard?_partial=1 every 60 seconds (see the inline poll script
    # below) and the React layer swaps window.CIRES_ALERTS + top-bar stats
    # in place without remounting the Dashboard component. Returns a
    # JSON envelope; on any error the client falls back to full reload.
    if _partial == 1:
        from fastapi.responses import JSONResponse
        return JSONResponse({
            "alerts": alerts,
            "dashboard_stats": dashboard_stats,
            "sidebar_badges": sidebar_badges,
            "pagination": pagination,
            "filters": filters_payload,
            "now_local": now_tng,
        })

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Observability AI RCA - Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/design/tokens.css"/>
{_CIRES_THEME_HEAD_SCRIPT}
<style>
  body {{ margin: 0; background: var(--bg, #0f1117); font-family: 'Inter', system-ui, sans-serif; color: var(--text, #e4e6ee); }}
  #root {{ min-height: 100vh; }}
  /* Server-rendered URL-persistent filter bar — sits above the React feed
     so a refresh / shared link keeps the operator's view. Each <select>
     auto-submits on change; the "copy URL" button is purely cosmetic
     (the URL itself is already the share mechanism). */
  .v2-filter-bar {{
    display: flex; flex-wrap: wrap; align-items: flex-end; gap: 10px 14px;
    padding: 10px 22px;
    background: var(--bg-soft, #13151e);
    border-bottom: 1px solid var(--border, #2a2d3a);
    font-size: 12.5px;
  }}
  .v2-filter-bar__lbl {{
    display: flex; flex-direction: column; gap: 4px;
    color: var(--muted, #8890a0);
    text-transform: uppercase; letter-spacing: 0.06em; font-size: 10.5px;
  }}
  .v2-filter-bar__lbl--grow {{ flex: 1; min-width: 200px; }}
  .v2-filter-bar select,
  .v2-filter-bar input[type="search"] {{
    background: var(--card, #1a1d27);
    color: var(--text, #e4e6ee);
    border: 1px solid var(--border, #2a2d3a);
    border-radius: 6px;
    padding: 5px 9px;
    font-size: 12.5px;
    font-family: inherit;
    min-width: 100px;
  }}
  .v2-filter-bar input[type="search"] {{ width: 100%; }}
  .v2-filter-bar select:focus,
  .v2-filter-bar input[type="search"]:focus {{
    outline: none; border-color: var(--accent-purple, #b07ee8);
  }}
  .v2-filter-bar__clear,
  .v2-filter-bar__share,
  .v2-filter-bar__apply {{
    background: transparent;
    color: var(--accent-cyan, #40d0d0);
    border: 1px solid var(--border, #2a2d3a);
    border-radius: 6px;
    padding: 5px 11px;
    font-size: 12px;
    font-family: inherit;
    cursor: pointer;
    text-decoration: none;
  }}
  .v2-filter-bar__clear:hover,
  .v2-filter-bar__share:hover,
  .v2-filter-bar__apply:hover {{
    background: var(--card-hi, #232838);
  }}
  /* 2026-06-02 - top-bar partial-refresh pip. Rendered by TopBar in
     atoms.jsx when window.cires_partial_refresh is wired. Tiny dot +
     label; the dot pulses while a fetch is in flight. */
  .cires-refresh-pip {{
    display: inline-flex; align-items: center; gap: 6px;
    padding: 4px 9px; border-radius: 999px;
    background: var(--card, #1a1d27);
    border: 1px solid var(--border, #2a2d3a);
    font-size: 11px; color: var(--muted, #8890a0);
    user-select: none;
  }}
  .cires-refresh-pip .dot {{
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--accent-green, #6bcf7f);
    transition: background 200ms;
  }}
  .cires-refresh-pip[data-state="loading"] .dot {{
    background: var(--accent-yellow, #e0d060);
    animation: cires-pip-pulse 800ms ease-in-out infinite;
  }}
  .cires-refresh-pip[data-state="error"] .dot {{
    background: var(--accent-red, #e06070);
  }}
  @keyframes cires-pip-pulse {{
    0%, 100% {{ opacity: 1; }}
    50% {{ opacity: 0.4; }}
  }}
  /* Responsive baseline for the filter bar - wrap to one column under
     768px so the dropdowns stay tappable. */
  @media (max-width: 768px) {{
    .v2-filter-bar {{ flex-direction: column; align-items: stretch; gap: 8px; padding: 10px 14px; }}
    .v2-filter-bar__lbl {{ width: 100%; }}
    .v2-filter-bar select,
    .v2-filter-bar input[type="search"] {{ width: 100%; }}
  }}
</style>
</head>
<body>

<!-- 2026-06-04: removed the legacy server-rendered v2-filter-bar that rendered
     here ABOVE the React app — it was a duplicate dark bar stacked on top of
     the React chrome (which has its own FilterBar). The React app owns the UI. -->

<div id="root"></div>

<script>
  window.CIRES_ALERTS = {alerts_json};
  window.CIRES_NOW_LOCAL = "{now_tng}";
  window.CIRES_PAGINATION = {_safe_script_json(pagination)};
  window.CIRES_DASHBOARD_STATS = {_safe_script_json(dashboard_stats)};
  window.CIRES_SIDEBAR_BADGES = {_safe_script_json(sidebar_badges)};
  window.CIRES_FILTERS = {_safe_script_json(filters_payload)};

  // 2026-06-02 - partial-refresh poll. Replaces the previous
  // meta-refresh full-page reload so the operator's expanded-row +
  // scroll position + filter focus survive a refresh.
  // Re-fetches /dashboard?_partial=1 every 60 s, mutates window.CIRES_*
  // in place, and dispatches "cires:refreshed" so the React tree picks
  // up the change via its event listeners (Dashboard + TopBar).
  //
  // 3-consecutive-failure fallback: if the partial endpoint errors out
  // three times in a row, do a full reload so the operator still sees
  // a refreshed page. The fail counter resets on success.
  (function() {{
    var failCount = 0;
    var pip = null;
    function setPipState(s) {{
      if (!pip) pip = document.getElementById("cires-refresh-pip");
      if (pip) pip.setAttribute("data-state", s);
    }}
    function buildPartialUrl() {{
      var u = new URL(window.location.href);
      u.searchParams.set("_partial", "1");
      return u.toString();
    }}
    async function refresh() {{
      setPipState("loading");
      try {{
        var r = await fetch(buildPartialUrl(), {{ headers: {{ "Accept": "application/json" }} }});
        if (!r.ok) throw new Error("HTTP " + r.status);
        var data = await r.json();
        window.CIRES_ALERTS          = data.alerts          || window.CIRES_ALERTS;
        window.CIRES_DASHBOARD_STATS = data.dashboard_stats || window.CIRES_DASHBOARD_STATS;
        window.CIRES_SIDEBAR_BADGES  = data.sidebar_badges  || window.CIRES_SIDEBAR_BADGES;
        window.CIRES_PAGINATION      = data.pagination      || window.CIRES_PAGINATION;
        window.CIRES_FILTERS         = data.filters         || window.CIRES_FILTERS;
        window.CIRES_NOW_LOCAL       = data.now_local       || window.CIRES_NOW_LOCAL;
        failCount = 0;
        setPipState("idle");
        window.dispatchEvent(new CustomEvent("cires:refreshed", {{ detail: data }}));
      }} catch (e) {{
        failCount += 1;
        setPipState("error");
        if (failCount >= 3) {{
          console.warn("[CIRES] partial refresh failed 3x, falling back to full reload");
          window.location.reload();
        }}
      }}
    }}
    window.cires_partial_refresh = refresh;
    setInterval(refresh, 60000);
  }})();
</script>

<script src="https://unpkg.com/react@18.3.1/umd/react.development.js" crossorigin="anonymous"></script>
<script src="https://unpkg.com/react-dom@18.3.1/umd/react-dom.development.js" crossorigin="anonymous"></script>
<script src="https://unpkg.com/@babel/standalone@7.29.0/babel.min.js" crossorigin="anonymous"></script>

<script type="text/babel" src="/static/design/atoms.jsx"></script>
<script type="text/babel" src="/static/design/sidebar.jsx"></script>
<script type="text/babel" src="/static/design/dashboard.jsx"></script>

<script type="text/babel" data-presets="react">
  function App() {{
    // Drive the wrapper's data-theme from the persisted obs-rca-theme
    // (not a hardcoded "dark") so light mode actually applies: the
    // tokens.css light overrides are scoped to `.cires[data-theme="light"]`.
    // useTheme() also re-renders when the TopBar ThemeToggle flips the
    // persisted value, keeping the wrapper in sync with the live toggle.
    const [theme] = window.useTheme();
    return (
      <div className="cires" data-theme={{theme}} style={{{{ minHeight: "100vh" }}}}>
        <Dashboard mode="default"/>
      </div>
    );
  }}
  ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
</script>

</body>
</html>""")


# ──────────────────────────────────────────────────────────────────────
# /dashboard/kpi — Phase 3.A.KPI platform-health surface
# ──────────────────────────────────────────────────────────────────────
# Sprint 4 §14 Wed item (pulled forward to Mon 2026-05-25). The supervisor-
# asked-for "platform health at a glance" page: six live KPIs computed from
# the local RCAStore + a tiny optional Ollama probe, plus two pragmatic
# static KPIs (MCP-invariant + test suite count) for completeness.
#
# Operator-cognitive-load doctrine: every KPI answers a question an on-call
# operator actually asks. See app/kpi_queries.py for the per-KPI rationale.
#
# Refresh policy: meta http-equiv refresh at 60 s — protects SQLite from
# query churn while still feeling "live enough" to an operator monitoring
# the surface during incident response.
def _render_insight_sidebar(active: str = "") -> str:
    """Single source of truth for the server-rendered insight/incident sidebar.

    2026-06-13 — replaces seven inline copies that had drifted apart, and
    mirrors the React sidebar.jsx NAV_GROUPS exactly so the two chromes can
    never disagree (coherence). The 2026-06-13 nav: the Sprint-5 placeholder
    items (Drain3 engine, Integrations) are dropped from the surface; Stats is
    merged into Evaluation (/dashboard/kpi); Services is merged into the
    Incidents page. `active` is the nav item id to highlight.
    """
    def item(item_id: str, href: str, label: str) -> str:
        cls = ("kpi-sidebar__item kpi-sidebar__item--active"
               if item_id == active else "kpi-sidebar__item")
        return f'<a class="{cls}" href="{href}">{label}</a>'
    return f"""
  <aside class="kpi-sidebar">
    <div class="kpi-sidebar__brand">
      <div class="kpi-sidebar__brand-mark"></div>
      <div>
        <div class="kpi-sidebar__brand-title">Observability</div>
        <div class="kpi-sidebar__brand-sub">AI RCA &middot; v0.1.0</div>
      </div>
    </div>
    <div class="kpi-sidebar__group">
      <div class="kpi-sidebar__group-label">Incident response</div>
      {item("triage", "/dashboard", "Triage feed")}
      {item("incidents", "/dashboard/incidents", "Incidents")}
      {item("anomalies", "/dashboard/anomalies", "Anomalies")}
    </div>
    <div class="kpi-sidebar__group">
      <div class="kpi-sidebar__group-label">Insights</div>
      {item("kpi", "/dashboard/kpi", "Evaluation")}
    </div>
    <div class="kpi-sidebar__group">
      <div class="kpi-sidebar__group-label">Configuration</div>
      {item("alerts", "/dashboard/alerts", "Alerts")}
      {item("settings", "/dashboard/settings", "Settings")}
    </div>
  </aside>"""


# 2026-06-13 — Stats merged into the Evaluation (/dashboard/kpi) page. The
# stats-* CSS + the section renderer below are shared so the merged page and
# any future caller stay byte-identical. /dashboard/stats now redirects here.
_STATS_SECTION_CSS = """
  .stats-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; padding: 4px 22px 22px; }
  @media (max-width: 980px) { .stats-grid { grid-template-columns: 1fr; } }
  .stats-card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px 18px; }
  .stats-card--wide { grid-column: 1 / -1; }
  .stats-card__title { font-size: 13px; font-weight: 600; color: var(--text); margin-bottom: 4px; }
  .stats-card__q { font-size: 11.5px; color: var(--muted); margin-bottom: 12px; }
  .stats-bar-row { display: grid; grid-template-columns: 190px 1fr 44px; align-items: center; gap: 10px; margin-bottom: 8px; }
  .stats-bar-label { font-size: 12.5px; color: var(--text-soft); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .stats-bar-track { background: var(--bg-soft); border: 1px solid var(--border); border-radius: 5px; height: 14px; overflow: hidden; }
  .stats-bar-fill { height: 100%; border-radius: 5px; }
  .stats-bar-fill--blue { background: var(--accent-blue); }
  .stats-bar-fill--red  { background: var(--accent-red); }
  .stats-bar-val { font-family: var(--font-mono); font-size: 12.5px; color: var(--text); font-weight: 600; text-align: right; }
  .stats-table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .stats-table thead th { text-align: left; padding: 8px 10px; background: var(--bg-soft); border-bottom: 1px solid var(--border); font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; }
  .stats-table tbody td { padding: 8px 10px; border-bottom: 1px solid var(--border); color: var(--text-soft); }
  .stats-table tbody tr:last-child td { border-bottom: none; }
  .stats-fam-name { color: var(--text); font-weight: 500; }
  .stats-fam-total { font-family: var(--font-mono); color: var(--text); font-weight: 600; }
  .stats-pair { color: var(--muted); }
  .stats-pair b { color: var(--text); }
  .stats-muted { color: var(--muted); }
  .stats-fp__big { font-family: var(--font-mono); font-size: 34px; font-weight: 600; color: var(--accent-red); line-height: 1.1; margin: 4px 0 8px; }
  .stats-fp__sub { font-size: 12px; color: var(--muted); line-height: 1.5; }
  .stats-fp__sub code { font-family: var(--font-mono); background: var(--bg-soft); padding: 1px 5px; border-radius: 4px; font-size: 11px; }
  .stats-empty { font-size: 12.5px; color: var(--muted); padding: 8px 0; }
  .eval-subhead { padding: 16px 22px 0; font-size: 14px; font-weight: 600; color: var(--text); }
  .eval-subhead__q { font-size: 12px; font-weight: 400; color: var(--muted); margin-top: 2px; }
"""


def _render_stats_sections(agg: dict) -> str:
    """Render the 7-day trend cards (noisiest alerts, escalated services,
    verdict mix, RCA archetypes, FP proxy) as the inner `.stats-grid`.

    Shared by the merged Evaluation page. `agg` is RCAStore.get_stats_aggregates.
    """
    def _esc(s) -> str:
        return _html.escape(str(s)) if s is not None else ""

    noisiest = agg.get("noisiest_alerts", [])
    escalated = agg.get("escalated_services", [])
    families = agg.get("verdict_by_family", [])
    fp = agg.get("false_positive", {})
    archetypes = agg.get("archetypes_used", [])

    def _bars(items, label_key, value_key, accent):
        if not items:
            return "<div class='stats-empty'>No data in the last 7 days.</div>"
        mx = max((int(i[value_key]) for i in items), default=0) or 1
        parts = []
        for i in items:
            v = int(i[value_key])
            pct = int(round(100 * v / mx))
            parts.append(
                f'<div class="stats-bar-row"><div class="stats-bar-label">{_esc(i[label_key])}</div>'
                f'<div class="stats-bar-track"><div class="stats-bar-fill stats-bar-fill--{accent}" style="width:{pct}%"></div></div>'
                f'<div class="stats-bar-val">{v}</div></div>'
            )
        return "".join(parts)

    noisiest_html = _bars(noisiest, "alert_name", "count", "blue")
    escalated_html = _bars(escalated, "service", "escalates", "red")

    if families:
        fam_rows = []
        for f in families:
            verds = f.get("verdicts", {})
            mix = " &middot; ".join(
                f"<span class='stats-pair'>{_esc(k)} <b>{v}</b></span>"
                for k, v in sorted(verds.items(), key=lambda kv: kv[1], reverse=True)
            ) or "<span class='stats-muted'>—</span>"
            fam_rows.append(
                f'<tr><td class="stats-fam-name">{_esc(f["alert_name"])}</td>'
                f'<td class="stats-fam-total">{int(f.get("total", 0))}</td><td>{mix}</td></tr>'
            )
        families_html = (
            '<table class="stats-table"><thead><tr><th>Alert family</th><th>Fires</th>'
            f'<th>Verdict mix</th></tr></thead><tbody>{"".join(fam_rows)}</tbody></table>'
        )
    else:
        families_html = "<div class='stats-empty'>No verdicts recorded in the last 7 days.</div>"

    if archetypes:
        arch_rows = []
        for a in archetypes:
            rate = a.get("actionable_rate")
            rate_disp = f"{rate * 100:.0f}%" if rate is not None else "—"
            arch_rows.append(
                f'<tr><td class="stats-fam-name">{_esc(a.get("exemplar_id"))}</td>'
                f'<td class="stats-fam-total">{int(a.get("count", 0))}</td>'
                f'<td class="stats-fam-total">{rate_disp}</td></tr>'
            )
        archetypes_html = (
            '<table class="stats-table"><thead><tr><th>Archetype (exemplar id)</th><th>Used</th>'
            f'<th>Actionable rate</th></tr></thead><tbody>{"".join(arch_rows)}</tbody></table>'
        )
    else:
        archetypes_html = (
            "<div class='stats-empty'>No archetype usage recorded in the last 7 days yet "
            "&mdash; this fills in as new decisions record which exemplar they used.</div>"
        )

    if fp.get("wired"):
        rate = fp.get("rate")
        rate_disp = f"{rate * 100:.0f}%" if rate is not None else "—"
        fp_html = (
            f'<div class="stats-fp__big">{_esc(rate_disp)}</div>'
            f'<div class="stats-fp__sub">{int(fp.get("overrides", 0))} of {int(fp.get("rated", 0))} '
            "reviewed alerts had their verdict corrected by an operator.</div>"
        )
    else:
        fp_html = (
            '<div class="stats-fp__big stats-muted">n/a</div>'
            '<div class="stats-fp__sub">No operator reviews in the last 7 days yet &mdash; '
            "this fills in automatically as alerts get rated.</div>"
        )

    return f"""
    <div class="stats-grid">
      <div class="stats-card"><div class="stats-card__title">Noisiest alerts</div><div class="stats-card__q">Top 10 alert rules by total fires.</div>{noisiest_html}</div>
      <div class="stats-card"><div class="stats-card__title">Most-escalated services</div><div class="stats-card__q">Top 5 services by escalated alerts.</div>{escalated_html}</div>
      <div class="stats-card stats-card--wide"><div class="stats-card__title">Verdict mix per alert family</div><div class="stats-card__q">How each alert family was triaged (top 10 by fires).</div>{families_html}</div>
      <div class="stats-card stats-card--wide"><div class="stats-card__title">RCA archetypes used</div><div class="stats-card__q">Which exemplar archetype the prompt builder selected per decision, and how often that decision came out actionable.</div>{archetypes_html}</div>
      <div class="stats-card"><div class="stats-card__title">False-positive proxy</div><div class="stats-card__q">How often a person corrected the platform's verdict.</div>{fp_html}</div>
    </div>"""


@app.get("/dashboard/kpi", response_class=HTMLResponse)
async def dashboard_v2_kpi():
    """Platform-health KPI surface — 6 live + 2 static numbers in a 2x4 grid.

    Reads from the existing RCAStore connection; no new data paths.
    Renders server-side HTML matching the v2 design tokens (tokens.css)
    so the look-and-feel is identical to /dashboard without pulling in
    the React layer the feed needs.
    """
    from app.kpi_queries import compute_kpis
    from datetime import datetime, timezone, timedelta

    kpis = await compute_kpis(_store, ollama_url=settings.ollama_url)
    # Merged Evaluation page (2026-06-13): the 7-day trend stats live below the
    # KPI cards on this same page. Failure degrades to an empty trends block.
    stats_agg: dict = {}
    if _store is not None:
        try:
            stats_agg = await _store.get_stats_aggregates(days=7)
        except Exception as exc:
            logger.warning("stats aggregates query failed (non-fatal): %s", exc)
    stats_sections = _render_stats_sections(stats_agg)
    now_tng = datetime.now(timezone.utc).astimezone(
        timezone(timedelta(hours=1))
    ).strftime("%Y-%m-%d %H:%M:%S")

    # KPI card order matches the "operator questions" list in kpi_queries.py.
    # Each entry: (key, big-label-title, accent-class, mini-question)
    cards = [
        ("emails_per_day",        "Emails sent",         "blue",   "Am I getting paged too much?"),
        ("false_positive_rate",   "False-positive rate", "red",    "Are my pages actually right?"),
        ("median_latency",        "Median latency",      "cyan",   "Is the pipeline slow today?"),
        ("cheap_path_pct",        "Cheap-path absorbed", "green",  "How much load skipped the LLM?"),
        ("archetype_coverage",    "Archetype coverage",  "purple", "What alert shapes are we seeing?"),
        ("gpu_util",              "GPU status",          "yellow", "Is the inference box healthy?"),
        # 2026-06-13: the two static cards (MCP firewall "0 leaks", Tests
        # passing "581/581") were dropped — they were hand-stamped constants
        # that drifted stale (suite is now 900+) and read as live numbers.
        # The Evaluation page now shows only live-computed KPIs.
    ]

    def _esc(s: str) -> str:
        return _html.escape(str(s))

    # Build the cards HTML — big number on top, label below, sub-line as
    # muted footer. Accent color shows via the left border tint.
    card_html_parts = []
    for key, title, accent, question in cards:
        k = kpis.get(key) or {}
        label = _esc(k.get("label", "—"))
        sub = _esc(k.get("sub", ""))
        # The "value" prefix on the big number renders the digits for the
        # regex \d+ test. When the label itself contains digits we use it
        # as-is; when it's a textual placeholder ("n/a") we surface the
        # raw value separately so the operator can still see "0" + n/a.
        card_html_parts.append(f"""
    <div class="kpi-card kpi-card--{accent}">
      <div class="kpi-card__question">{_esc(question)}</div>
      <div class="kpi-card__value">{label}</div>
      <div class="kpi-card__title">{_esc(title)}</div>
      <div class="kpi-card__sub">{sub}</div>
    </div>""")
    cards_html = "".join(card_html_parts)

    # Sidebar mirrors the v2 React sidebar's NAV_GROUPS shape — same labels,
    # same icon names, but rendered as anchors so an operator can click
    # straight back to /dashboard from the KPI surface.
    sidebar_html = _render_insight_sidebar("kpi")

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta http-equiv="refresh" content="60"/>
<title>Observability &middot; KPI &middot; Evaluation</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/design/tokens.css"/>
{_CIRES_THEME_HEAD_SCRIPT}
<style>
  body {{
    margin: 0;
    background: var(--bg, #0f1117);
    font-family: 'Inter', system-ui, sans-serif;
    color: var(--text, #e4e6ee);
    min-height: 100vh;
  }}
  .kpi-shell {{ display: flex; min-height: 100vh; }}

  /* Sidebar — server-rendered twin of app/static/design/sidebar.jsx */
  .kpi-sidebar {{
    width: 224px; flex-shrink: 0;
    background: var(--bg-soft, #13151e);
    border-right: 1px solid var(--border, #2a2d3a);
    padding: 0 0 14px;
    display: flex; flex-direction: column;
  }}
  .kpi-sidebar__brand {{
    display: flex; align-items: center; gap: 10px;
    padding: 14px 14px 14px 16px;
    border-bottom: 1px solid var(--border);
    height: 60px;
  }}
  .kpi-sidebar__brand-mark {{
    width: 28px; height: 28px; border-radius: 8px;
    background: linear-gradient(135deg, #4ea8de, #b07ee8);
    flex-shrink: 0;
  }}
  .kpi-sidebar__brand-title {{ font-size: 13.5px; font-weight: 600; color: var(--text); }}
  .kpi-sidebar__brand-sub {{ font-size: 11px; color: var(--muted); letter-spacing: 0.04em; }}
  .kpi-sidebar__group {{ padding: 12px; margin-bottom: 6px; }}
  .kpi-sidebar__group-label {{
    font-size: 10px; color: var(--muted-2);
    text-transform: uppercase; letter-spacing: 0.12em;
    padding: 0 12px 6px; font-weight: 600;
  }}
  .kpi-sidebar__item {{
    display: block; padding: 8px 12px;
    border-radius: 8px; text-decoration: none;
    color: var(--text-soft);
    font-size: 13px;
    transition: background .12s;
  }}
  .kpi-sidebar__item:hover {{ background: var(--card-hi); color: var(--text); }}
  .kpi-sidebar__item--active {{
    background: var(--card-hi); color: var(--text);
    border: 1px solid var(--border-hi);
    font-weight: 500;
    box-shadow: inset 2.5px 0 0 var(--accent-blue);
  }}

  /* Main column */
  .kpi-main {{ flex: 1; min-width: 0; display: flex; flex-direction: column; }}
  .kpi-header {{
    padding: 18px 22px 8px;
    border-bottom: 1px solid var(--border);
    display: flex; align-items: baseline; justify-content: space-between;
  }}
  .kpi-header__title {{ font-size: 18px; font-weight: 600; color: var(--text); }}
  .kpi-header__sub {{ font-size: 12.5px; color: var(--muted); margin-top: 4px; }}
  .kpi-header__time {{
    font-family: var(--font-mono); font-size: 11.5px;
    color: var(--muted); letter-spacing: 0.02em;
  }}
  .kpi-header__time .live-dot {{ margin-right: 6px; vertical-align: middle; }}

  /* KPI grid — 4 across on desktop, collapses to 2 on narrower screens */
  .kpi-grid {{
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 14px;
    padding: 18px 22px 22px;
  }}
  @media (max-width: 1100px) {{ .kpi-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} }}
  @media (max-width: 620px)  {{ .kpi-grid {{ grid-template-columns: 1fr; }} }}

  .kpi-card {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px 18px 18px;
    display: flex; flex-direction: column; gap: 6px;
    border-left: 3px solid var(--border-hi);
    min-height: 160px;
  }}
  .kpi-card--blue   {{ border-left-color: var(--accent-blue); }}
  .kpi-card--red    {{ border-left-color: var(--accent-red); }}
  .kpi-card--cyan   {{ border-left-color: var(--accent-cyan); }}
  .kpi-card--green  {{ border-left-color: var(--accent-green); }}
  .kpi-card--purple {{ border-left-color: var(--accent-purple); }}
  .kpi-card--yellow {{ border-left-color: var(--accent-yellow); }}

  .kpi-card__question {{
    font-size: 11px; color: var(--muted);
    text-transform: uppercase; letter-spacing: 0.08em;
    font-weight: 600;
  }}
  .kpi-card__value {{
    font-family: var(--font-mono);
    font-size: 30px; font-weight: 600;
    color: var(--text);
    line-height: 1.1;
    letter-spacing: -0.01em;
    margin-top: 2px;
  }}
  .kpi-card__title {{
    font-size: 14px; font-weight: 500; color: var(--text-soft);
    margin-top: 2px;
  }}
  .kpi-card__sub {{
    font-size: 12px; color: var(--muted);
    margin-top: auto; padding-top: 8px;
    border-top: 1px solid var(--border);
    line-height: 1.4;
  }}

  /* Footer note */
  .kpi-foot {{
    padding: 12px 22px 22px;
    font-size: 11.5px;
    color: var(--muted);
    border-top: 1px solid var(--border);
  }}
{_STATS_SECTION_CSS}
</style>
</head>
<body>

<div class="kpi-shell">
  {sidebar_html}
  <main class="kpi-main">
    <div class="kpi-header">
      <div>
        <div class="kpi-header__title">Evaluation</div>
        <div class="kpi-header__sub">How well the platform is doing &mdash; live health numbers up top, 7-day trends below. Refreshed every minute.</div>
      </div>
      <div class="kpi-header__time">
        <span class="live-dot"></span>{_esc(now_tng)} GMT+1
      </div>
    </div>

    <div class="eval-subhead">Platform health<div class="eval-subhead__q">Each card answers one operator question &mdash; the big number is the answer.</div></div>
    <div class="kpi-grid">{cards_html}
    </div>

    <div class="eval-subhead">Trends &middot; last 7 days<div class="eval-subhead__q">The noisiest alerts, the most-affected services, and how the platform triaged them.</div></div>
    {stats_sections}

    <div class="kpi-foot">
      Auto-refresh: 60 s.
    </div>
  </main>
</div>

</body>
</html>""")


# ──────────────────────────────────────────────────────────────────────
# /dashboard/services — per-service read-only summary
# ──────────────────────────────────────────────────────────────────────
# Fills out a previously-dead sidebar item. One row per distinct
# affected_service over the last 7 days, with the counts an operator
# wants when triaging "which service has been noisy lately": total
# decisions, breakdown by action_taken / llm_verdict / severity, last
# fire timestamp, and the dominant alertname.
#
# Server-rendered HTML in the same chrome as /dashboard/kpi
# (sidebar twin, dark theme, 60s meta-refresh). Service names link
# back to the filtered triage feed via the existing ?q= URL filter.
# Read-only — no writes, no Grafana API, all data via RCAStore (which
# is itself the canonical writer; the MCP-only invariant is preserved).
@app.get("/dashboard/services", response_class=HTMLResponse)
async def dashboard_services_redirect():
    """2026-06-13 — Services merged into the Incidents page as a toggle view.
    Old links/bookmarks land on the services view."""
    return RedirectResponse(url="/dashboard/incidents?view=services", status_code=301)


@app.get("/dashboard/alerts", response_class=HTMLResponse)
async def dashboard_v2_alerts():
    """Per-alertname summary for the last 7 days.

    Pulls from RCAStore.get_alert_summary() — pure SQL aggregation over
    the same rca_history rows the rest of the v2 surface reads from.
    No Grafana API call, no annotation write, no MCP-new path.
    """
    from datetime import datetime, timezone, timedelta

    now_tng = datetime.now(timezone.utc).astimezone(
        timezone(timedelta(hours=1))
    ).strftime("%Y-%m-%d %H:%M:%S")

    # Empty-store path (lifespan-not-run / fresh DB) — render the
    # "no alerts seen yet" affordance instead of a bare table.
    rows: list[dict]
    if _store is None:
        rows = []
    else:
        try:
            rows = await _store.get_alert_summary(days=7)
        except Exception as exc:  # never 500 the sidebar page
            logger.warning("get_alert_summary failed: %s", exc)
            rows = []

    def _esc(s) -> str:
        return _html.escape(str(s))

    # Verdict colour mapping — same palette the triage feed uses so
    # operators carry the colour grammar from page to page.
    _VERDICT_ACCENT = {
        "escalate":     "var(--accent-red)",
        "dismiss":      "var(--accent-green)",
        "inconclusive": "var(--accent-yellow)",
    }
    _SEVERITY_ACCENT = {
        "critical":     "var(--accent-red)",
        "page":         "var(--accent-red)",
        "warning":      "var(--accent-yellow)",
        "info":         "var(--accent-cyan)",
    }

    # Build the table rows. Noisy rows (ratio > 0.5) get the row--noisy
    # class so the highlight class actually applies — tested below.
    body_parts = []
    for r in rows:
        name = _esc(r.get("alert_name", "(unknown)"))
        fires = int(r.get("fires", 0))
        emails = int(r.get("emails", 0))
        ratio = float(r.get("email_ratio", 0.0))
        verdict = _esc(r.get("dominant_verdict", "(none)"))
        severity = _esc(r.get("dominant_severity", "(unknown)"))
        was_gated = bool(r.get("was_gated", False))
        last_fire_local = _esc(_to_local_time(r.get("last_fire") or ""))

        is_noisy = ratio > 0.5 and fires > 0
        row_class = "alerts-row alerts-row--noisy" if is_noisy else "alerts-row"

        v_color = _VERDICT_ACCENT.get(r.get("dominant_verdict", ""), "var(--muted)")
        s_color = _SEVERITY_ACCENT.get(r.get("dominant_severity", ""), "var(--muted)")

        # Gate column: human label only — per-rule thresholds live on the
        # Grafana rule, so we only say whether the filter has kicked in.
        if was_gated:
            gate_cell = (
                '<span class="alerts-pill alerts-pill--gated" '
                'title="At least one fire of this rule was held back automatically because it was a repeat.">'
                'filtered'
                '</span>'
            )
        else:
            gate_cell = (
                '<span class="alerts-pill alerts-pill--ungated" '
                'title="No fires of this rule were held back by the repeat-alert filter in this window.">'
                '&mdash;'
                '</span>'
            )

        ratio_pct = f"{ratio * 100:.0f}%" if fires > 0 else "—"

        body_parts.append(f"""
      <tr class="{row_class}">
        <td class="alerts-cell alerts-cell--name">{name}</td>
        <td class="alerts-cell alerts-cell--num">{fires}</td>
        <td class="alerts-cell alerts-cell--num">{emails}</td>
        <td class="alerts-cell alerts-cell--num alerts-cell--ratio">{ratio_pct}</td>
        <td class="alerts-cell">
          <span class="alerts-pill" style="color:{v_color};border-color:color-mix(in oklab, {v_color} 35%, transparent);">{verdict}</span>
        </td>
        <td class="alerts-cell">
          <span class="alerts-pill" style="color:{s_color};border-color:color-mix(in oklab, {s_color} 35%, transparent);">{severity}</span>
        </td>
        <td class="alerts-cell alerts-cell--mono">{last_fire_local or "—"}</td>
        <td class="alerts-cell">{gate_cell}</td>
      </tr>""")

    if rows:
        table_body_html = "".join(body_parts)
        empty_html = ""
    else:
        # "no alerts seen yet" affordance — exercised by the empty-DB test.
        table_body_html = ""
        empty_html = """
      <div class="alerts-empty">
        <div class="alerts-empty__title">no alerts seen yet</div>
        <div class="alerts-empty__sub">
          No alerts have come through in the last 7 days.
          New ones will appear here as they arrive.
        </div>
      </div>"""

    # Sidebar — server-rendered twin of the React sidebar. The Alerts item
    # is the active one on this page.
    sidebar_html = _render_insight_sidebar("alerts")

    # Counts for the header — gives the operator a quick read on how many
    # distinct rules we're surfacing without making them count rows.
    n_alerts = len(rows)
    n_noisy = sum(1 for r in rows if r.get("email_ratio", 0.0) > 0.5 and r.get("fires", 0) > 0)
    n_gated = sum(1 for r in rows if r.get("was_gated"))

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta http-equiv="refresh" content="60"/>
<title>Observability &middot; Alerts &middot; per-rule summary</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/design/tokens.css"/>
{_CIRES_THEME_HEAD_SCRIPT}
<style>
  body {{
    margin: 0;
    background: var(--bg, #0f1117);
    font-family: 'Inter', system-ui, sans-serif;
    color: var(--text, #e4e6ee);
    min-height: 100vh;
  }}
  .kpi-shell {{ display: flex; min-height: 100vh; }}

  /* Sidebar — twin of app/static/design/sidebar.jsx */
  .kpi-sidebar {{
    width: 224px; flex-shrink: 0;
    background: var(--bg-soft, #13151e);
    border-right: 1px solid var(--border, #2a2d3a);
    padding: 0 0 14px;
    display: flex; flex-direction: column;
  }}
  .kpi-sidebar__brand {{
    display: flex; align-items: center; gap: 10px;
    padding: 14px 14px 14px 16px;
    border-bottom: 1px solid var(--border);
    height: 60px;
  }}
  .kpi-sidebar__brand-mark {{
    width: 28px; height: 28px; border-radius: 8px;
    background: linear-gradient(135deg, #4ea8de, #b07ee8);
    flex-shrink: 0;
  }}
  .kpi-sidebar__brand-title {{ font-size: 13.5px; font-weight: 600; color: var(--text); }}
  .kpi-sidebar__brand-sub {{ font-size: 11px; color: var(--muted); letter-spacing: 0.04em; }}
  .kpi-sidebar__group {{ padding: 12px; margin-bottom: 6px; }}
  .kpi-sidebar__group-label {{
    font-size: 10px; color: var(--muted-2);
    text-transform: uppercase; letter-spacing: 0.12em;
    padding: 0 12px 6px; font-weight: 600;
  }}
  .kpi-sidebar__item {{
    display: block; padding: 8px 12px;
    border-radius: 8px; text-decoration: none;
    color: var(--text-soft);
    font-size: 13px;
    transition: background .12s;
  }}
  .kpi-sidebar__item:hover {{ background: var(--card-hi); color: var(--text); }}
  .kpi-sidebar__item--active {{
    background: var(--card-hi); color: var(--text);
    border: 1px solid var(--border-hi);
    font-weight: 500;
    box-shadow: inset 2.5px 0 0 var(--accent-blue);
  }}

  /* Main column */
  .kpi-main {{ flex: 1; min-width: 0; display: flex; flex-direction: column; }}
  .kpi-header {{
    padding: 18px 22px 8px;
    border-bottom: 1px solid var(--border);
    display: flex; align-items: baseline; justify-content: space-between;
  }}
  .kpi-header__title {{ font-size: 18px; font-weight: 600; color: var(--text); }}
  .kpi-header__sub {{ font-size: 12.5px; color: var(--muted); margin-top: 4px; }}
  .kpi-header__time {{
    font-family: var(--font-mono); font-size: 11.5px;
    color: var(--muted); letter-spacing: 0.02em;
  }}

  /* Counts strip */
  .alerts-counts {{
    display: flex; gap: 18px;
    padding: 12px 22px 4px;
    font-size: 12px; color: var(--muted);
  }}
  .alerts-counts strong {{
    color: var(--text); font-family: var(--font-mono);
    font-weight: 600;
  }}

  /* Table */
  .alerts-table-wrap {{
    padding: 12px 22px 22px;
    overflow-x: auto;
  }}
  table.alerts-table {{
    width: 100%; border-collapse: separate; border-spacing: 0;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    font-size: 12.5px;
  }}
  .alerts-table thead th {{
    text-align: left;
    padding: 10px 12px;
    background: var(--bg-soft);
    border-bottom: 1px solid var(--border);
    font-weight: 600; color: var(--muted);
    text-transform: uppercase; font-size: 10.5px;
    letter-spacing: 0.08em;
  }}
  .alerts-cell {{
    padding: 9px 12px;
    border-bottom: 1px solid var(--border);
    color: var(--text-soft);
    vertical-align: middle;
  }}
  .alerts-cell--name {{ color: var(--text); font-weight: 500; }}
  .alerts-cell--num  {{ font-family: var(--font-mono); text-align: right; font-feature-settings: "tnum"; }}
  .alerts-cell--mono {{ font-family: var(--font-mono); font-size: 11.5px; color: var(--muted); }}
  .alerts-cell--ratio {{ color: var(--muted); }}
  .alerts-row:hover {{ background: var(--card-hi); }}

  /* Noisy-row highlight — rows where emails/fires > 0.50. Tinted bg +
     a brighter ratio cell so the eye lands on the noise candidates. */
  .alerts-row--noisy {{
    background: color-mix(in oklab, var(--accent-red) 8%, transparent);
  }}
  .alerts-row--noisy .alerts-cell--ratio {{
    color: var(--accent-red); font-weight: 600;
  }}
  .alerts-row--noisy .alerts-cell--name::after {{
    content: " · noisy";
    font-size: 10px; font-weight: 500;
    color: var(--accent-red);
    margin-left: 6px;
    text-transform: uppercase; letter-spacing: 0.06em;
  }}

  .alerts-pill {{
    display: inline-block;
    padding: 1.5px 7px; border-radius: 999px;
    border: 1px solid var(--border);
    font-size: 11px; font-weight: 500;
    font-family: var(--font-mono);
    background: transparent;
  }}
  .alerts-pill--gated {{
    color: var(--accent-purple);
    border-color: color-mix(in oklab, var(--accent-purple) 35%, transparent);
  }}
  .alerts-pill--ungated {{ color: var(--muted-2); }}

  .alerts-empty {{
    margin: 18px 22px 22px;
    padding: 28px 22px;
    background: var(--card);
    border: 1px dashed var(--border);
    border-radius: 10px;
    text-align: center;
  }}
  .alerts-empty__title {{
    font-size: 14px; color: var(--text); font-weight: 600;
    margin-bottom: 4px;
  }}
  .alerts-empty__sub {{ font-size: 12px; color: var(--muted); }}
  .alerts-empty__sub code {{
    font-family: var(--font-mono); font-size: 11.5px;
    background: var(--bg); padding: 1px 5px; border-radius: 4px;
    border: 1px solid var(--border); color: var(--text-soft);
  }}

  .alerts-foot {{
    padding: 12px 22px 22px;
    font-size: 11.5px;
    color: var(--muted-2);
    border-top: 1px solid var(--border);
  }}
</style>
</head>
<body>

<div class="kpi-shell">
  {sidebar_html}
  <main class="kpi-main">
    <div class="kpi-header">
      <div>
        <div class="kpi-header__title">Alerts</div>
        <div class="kpi-header__sub">Which alert rules fired over the last 7 days, and how noisy each one is.</div>
      </div>
      <div class="kpi-header__time">{_esc(now_tng)} GMT+1</div>
    </div>

    <div class="alerts-counts">
      <span><strong>{n_alerts}</strong> alert rules seen</span>
      <span><strong>{n_noisy}</strong> flagged noisy (most fires reach the inbox)</span>
      <span><strong>{n_gated}</strong> quieted by the repeat-alert filter</span>
    </div>

    {empty_html}

    <div class="alerts-table-wrap">
      <table class="alerts-table">
        <thead>
          <tr>
            <th>Alert name</th>
            <th style="text-align:right">Fires</th>
            <th style="text-align:right">Emails</th>
            <th style="text-align:right">Email ratio</th>
            <th>Dominant verdict</th>
            <th>Dominant severity</th>
            <th>Last fire</th>
            <th>Repeat filter</th>
          </tr>
        </thead>
        <tbody>{table_body_html}</tbody>
      </table>
    </div>

    <div class="alerts-foot">
      Auto-refresh: 60 s.
    </div>
  </main>
</div>

</body>
</html>""")


@app.get("/dashboard/alert/{short_id}", response_class=HTMLResponse)
async def dashboard_v2_alert(short_id: str):
    """Phase 2.1 — alert detail page click-through from /dashboard.

    Resolves the 8-char short_id back to the full UUID (by scanning the
    most-recent 500 rows), transforms via the same _v2_transform_row
    pipeline, and renders the design's <DetailPage> component.
    Related alerts in a ±10 min window are populated for the right
    sidebar.
    """
    import json as _json2
    from datetime import datetime, timezone, timedelta
    now_utc = datetime.now(timezone.utc)

    # Resolve short_id (8-char prefix) → full UUID by scanning recent rows
    scan = await _store.get_decisions(limit=500, offset=0, since_days=15)
    short_id = (short_id or "").strip().lower()
    target = None
    for r in scan:
        rid = (r.get("id") or "").lower()
        if rid.startswith(short_id):
            target = r
            break
    if target is None:
        # F-4 (2026-06-10): incident click-throughs link the incident's LATEST
        # rca_history row, which can be older than the 15-day scan window
        # (long-lived incidents). Fall back to a direct id-prefix lookup so
        # those links resolve instead of 404ing.
        try:
            target = await _store.get_decision_by_id_prefix(short_id)
        except Exception:
            target = None
    if target is None:
        raise HTTPException(status_code=404, detail=f"No alert found with short_id prefix '{short_id}'")

    # Build fingerprint history from the same scan
    fp = target.get("alert_fingerprint") or ""
    history_rows = []
    if fp:
        for r in scan:
            if (r.get("alert_fingerprint") or "") == fp and (r.get("timestamp") or "") < (target.get("timestamp") or ""):
                history_rows.append(r)
        history_rows.sort(key=lambda x: x.get("timestamp") or "")

    # Related alerts — ±10 min window on the same namespace or affected_service
    target_ts_str = target.get("timestamp") or ""
    related = []
    try:
        target_dt = datetime.fromisoformat(target_ts_str.replace("Z", "+00:00"))
        if target_dt.tzinfo is None:
            target_dt = target_dt.replace(tzinfo=timezone.utc)
        win_lo = target_dt - timedelta(minutes=10)
        win_hi = target_dt + timedelta(minutes=10)
        for r in scan:
            if (r.get("id") or "") == target.get("id"):
                continue
            try:
                rdt = datetime.fromisoformat((r.get("timestamp") or "").replace("Z", "+00:00"))
                if rdt.tzinfo is None:
                    rdt = rdt.replace(tzinfo=timezone.utc)
            except Exception:
                continue
            if win_lo <= rdt <= win_hi:
                same_ns = (r.get("affected_service") or "") == (target.get("affected_service") or "")
                if same_ns:
                    related.append(r)
                    if len(related) >= 5:
                        break
    except Exception:
        pass

    drain3_stats = _drain.get_stats() if _drain is not None else {}

    # RC-4 (2026-06-09) / F-2 (2026-06-10) — recurrence count from the incident
    # entity, which also counts dedup-suppressed re-fires (those no longer write
    # a feed row). The fingerprint_history below only sees FULL investigate
    # rows. Reconciliation now lives INSIDE _v2_transform_row (the one shared
    # transform), so feed and detail render the same fireCount by construction;
    # here we just prefetch this fingerprint's incident count. Failure degrades
    # to the slab count, no 500.
    incident_fire_counts: dict[str, int] = {}
    if fp:
        try:
            incident = await _store.get_incident_by_fingerprint(fp)
            if incident:
                incident_fire_counts = {fp: int(incident.get("fire_count") or 0)}
        except Exception:
            pass

    # Transform target
    # 2026-06-12 (Lina): which fires in this incident's history have an
    # operator review? One query over all the fingerprint's decisions.
    try:
        _fb_ids = await _store.feedback_ids_for(
            [target.get("id")] + [hr.get("id") for hr in history_rows]
        )
    except Exception:
        _fb_ids = set()
    alert = _v2_transform_row(
        target,
        fingerprint_history={fp: history_rows} if fp else None,
        drain3_stats=drain3_stats,
        now_utc=now_utc,
        incident_fire_counts=incident_fire_counts,
        feedback_ids=_fb_ids,
    )
    # Transform related — the design's RelatedSidebar reads `a.related` and
    # accesses {id, title, time, verdict} on each entry. Shape them
    # explicitly so we don't depend on the full CIRES_ALERT object.
    related_simplified = []
    for r in related:
        rt = _v2_transform_row(r, drain3_stats=drain3_stats, now_utc=now_utc)
        related_simplified.append({
            "id": rt["id"],
            "title": rt["alertPlain"],
            "time": rt["timeShort"] or rt["relTime"],
            "verdict": rt["verdict"],
        })
    alert["related"] = related_simplified

    # Top-bar/sidebar stats reuse the dashboard transform so the chrome
    # looks the same. Compute the same way as the dashboard route.
    midnight_utc = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    day_ago = now_utc - timedelta(days=1)
    def _ts_dt(r):
        try:
            d = datetime.fromisoformat((r.get("timestamp") or "").replace("Z", "+00:00"))
            return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d
        except Exception:
            return None
    emailed_24h = 0; shelved_24h = 0; cheap_path_since_midnight = 0
    llm_durations = []; open_fingerprints = set()
    by_fp_count: dict[str, int] = {}
    for r in scan:
        ts = _ts_dt(r)
        if ts is None:
            continue
        act = (r.get("action_taken") or "").lower()
        td = (r.get("triage_decision") or "").lower()
        rfp = r.get("alert_fingerprint") or ""
        if rfp:
            by_fp_count[rfp] = by_fp_count.get(rfp, 0) + 1
        if ts >= day_ago:
            if act == "emailed":
                emailed_24h += 1
                if rfp: open_fingerprints.add(rfp)
            if act == "shelved":
                shelved_24h += 1
            dur = r.get("investigation_duration_ms") or 0
            if dur > 0:
                llm_durations.append(dur / 1000.0)
        if ts >= midnight_utc and td in ("triage_suppressed", "suppressed_duplicate", "recurrence_gated_pre_llm"):
            cheap_path_since_midnight += 1
    llm_durations.sort()
    median_latency_s = round(llm_durations[len(llm_durations) // 2], 1) if llm_durations else 0.0
    import time as _t
    uptime_sec = int(_t.time() - _PROC_START_TIME)
    dashboard_stats = {
        "uptimeSec": uptime_sec,
        "openAlerts": len(open_fingerprints),
        "emailed24h": emailed_24h,
        "shelved24h": shelved_24h,
        "medianLatency": median_latency_s,
        "cheap_path_since_midnight": cheap_path_since_midnight,
    }
    sidebar_badges = {
        "triage": len(open_fingerprints),
        "incidents": len(by_fp_count),
        "anomalies": (drain3_stats.get("total_anomalies") or 0),
    }
    now_tng = now_utc.astimezone(timezone(timedelta(hours=1))).strftime("%Y-%m-%d %H:%M:%S")
    alert_json = _safe_script_json(alert)

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Alert {short_id} — Observability · AI RCA</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/design/tokens.css"/>
{_CIRES_THEME_HEAD_SCRIPT}
<style>
  body {{ margin: 0; background: var(--bg, #0f1117); font-family: 'Inter', system-ui, sans-serif; color: var(--text, #e4e6ee); }}
  #root {{ min-height: 100vh; }}
  /* 2026-06-04 (WS-2): removed the .page-banner chrome strip that
     used to render "detail page | Alert {{id}} | back to feed" above
     the React TopBar. It duplicated information already shown in
     TopBar + DetailHeader and Lina explicitly called it useless. The
     DetailHeader's back-arrow button (detail.jsx:15) now carries the
     back-to-/dashboard nav. The full-UUID is reachable in the Raw
     Data accordion at the bottom of the detail page. */
</style>
</head>
<body>

<div id="root"></div>

<script>
  window.CIRES_ALERT = {alert_json};
  window.CIRES_NOW_LOCAL = "{now_tng}";
  window.CIRES_DASHBOARD_STATS = {_safe_script_json(dashboard_stats)};
  window.CIRES_SIDEBAR_BADGES = {_safe_script_json(sidebar_badges)};
  // 2026-06-04 (WS-2) - real Grafana/Loki/Jaeger deep-links for
  // DetailHeader buttons. detail.jsx reads window.CIRES_LINKS with a
  // "#" fallback so the design canvas page still renders standalone.
  // Each URL is now contextual to THIS alert (alert-name + service):
  // Grafana routes to unified-overview / tracing-overview /
  // otel-collector-health based on the alert family; Loki opens
  // Explore prefiltered to {{service_name="<svc>"}}; Jaeger opens
  // /search prefiltered to ?service=<svc>&lookback=1h. See
  // `_build_cires_links` for the routing table.
  window.CIRES_LINKS = {_safe_script_json(_build_cires_links(alert))};
</script>

<script src="https://unpkg.com/react@18.3.1/umd/react.development.js" crossorigin="anonymous"></script>
<script src="https://unpkg.com/react-dom@18.3.1/umd/react-dom.development.js" crossorigin="anonymous"></script>
<script src="https://unpkg.com/@babel/standalone@7.29.0/babel.min.js" crossorigin="anonymous"></script>

<script type="text/babel" src="/static/design/atoms.jsx"></script>
<script type="text/babel" src="/static/design/sidebar.jsx"></script>
<script type="text/babel" src="/static/design/detail.jsx"></script>

<script type="text/babel" data-presets="react">
  function App() {{
    return <DetailPage a={{window.CIRES_ALERT}}/>;
  }}
  ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
</script>

</body>
</html>""")


@app.get("/dashboard/alert/{short_id}/rate", response_class=HTMLResponse)
async def dashboard_v2_alert_rate(short_id: str):
    """SF-7 (2026-05-23) — operator feedback page for a specific alert.

    Renders the design's <FeedbackForm/> component (from feedback.jsx)
    against the resolved alert. Submit posts to /feedback/rate/{short_id}.
    """
    import json as _json2
    from datetime import datetime, timezone, timedelta
    now_utc = datetime.now(timezone.utc)

    scan = await _store.get_decisions(limit=500, offset=0, since_days=30)
    short = (short_id or "").strip().lower()
    target = None
    for r in scan:
        if (r.get("id") or "").lower().startswith(short):
            target = r
            break
    if target is None:
        raise HTTPException(status_code=404, detail=f"No alert found with short_id prefix '{short}' in the last 30 days")

    drain3_stats = _drain.get_stats() if _drain is not None else {}
    alert = _v2_transform_row(target, drain3_stats=drain3_stats, now_utc=now_utc)
    alert_json = _safe_script_json(alert)
    now_tng = now_utc.astimezone(timezone(timedelta(hours=1))).strftime("%Y-%m-%d %H:%M:%S")

    # 2026-06-04 (WS-2 F-008): rate page now wraps the form in the
    # platform's Sidebar+TopBar chrome. Compute the same dashboard
    # stats / sidebar badges the detail route computes so TopBar
    # renders the same numbers and the operator does not feel
    # stranded in a no-chrome focus mode.
    midnight_utc = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    day_ago = now_utc - timedelta(days=1)
    def _ts_dt_rate(r):
        try:
            d = datetime.fromisoformat((r.get("timestamp") or "").replace("Z", "+00:00"))
            return d.replace(tzinfo=timezone.utc) if d.tzinfo is None else d
        except Exception:
            return None
    emailed_24h = 0; shelved_24h = 0; cheap_path_since_midnight = 0
    llm_durations = []; open_fingerprints = set()
    by_fp_count: dict[str, int] = {}
    for r in scan:
        ts = _ts_dt_rate(r)
        if ts is None:
            continue
        act = (r.get("action_taken") or "").lower()
        td = (r.get("triage_decision") or "").lower()
        rfp = r.get("alert_fingerprint") or ""
        if rfp:
            by_fp_count[rfp] = by_fp_count.get(rfp, 0) + 1
        if ts >= day_ago:
            if act == "emailed":
                emailed_24h += 1
                if rfp: open_fingerprints.add(rfp)
            if act == "shelved":
                shelved_24h += 1
            dur = r.get("investigation_duration_ms") or 0
            if dur > 0:
                llm_durations.append(dur / 1000.0)
        if ts >= midnight_utc and td in ("triage_suppressed", "suppressed_duplicate", "recurrence_gated_pre_llm"):
            cheap_path_since_midnight += 1
    llm_durations.sort()
    median_latency_s = round(llm_durations[len(llm_durations) // 2], 1) if llm_durations else 0.0
    import time as _t
    uptime_sec = int(_t.time() - _PROC_START_TIME)
    dashboard_stats = {
        "uptimeSec": uptime_sec,
        "openAlerts": len(open_fingerprints),
        "emailed24h": emailed_24h,
        "shelved24h": shelved_24h,
        "medianLatency": median_latency_s,
        "cheap_path_since_midnight": cheap_path_since_midnight,
    }
    sidebar_badges = {
        "triage": len(open_fingerprints),
        "incidents": len(by_fp_count),
        "anomalies": (drain3_stats.get("total_anomalies") or 0),
    }

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Rate alert {short_id} — Observability · AI RCA</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/design/tokens.css"/>
{_CIRES_THEME_HEAD_SCRIPT}
<style>
  body {{ margin: 0; background: var(--bg, #0f1117); font-family: 'Inter', system-ui, sans-serif; color: var(--text, #e4e6ee); }}
  #root {{ min-height: 100vh; }}
  /* 2026-06-04 (WS-2): removed the .page-banner chrome strip Lina
     called useless; the form now lives inside the platform's
     Sidebar+TopBar chrome (see <App/> below) so the operator can
     navigate without browser-back. The form's own FeedbackHeader
     already shows alert id + identity pills. */
</style>
</head>
<body>

<div id="root"></div>

<script>
  // SF-7: design's feedback.jsx reads from window.CIRES_ALERTS[0]; we
  // inject a single-element array so the form picks up the right alert.
  window.CIRES_ALERTS = [{alert_json}];
  window.CIRES_ALERT = {alert_json};
  window.CIRES_NOW_LOCAL = "{now_tng}";
  window.CIRES_RATE_SHORT_ID = {_safe_script_json(short)};
  window.CIRES_DASHBOARD_STATS = {_safe_script_json(dashboard_stats)};
  window.CIRES_SIDEBAR_BADGES = {_safe_script_json(sidebar_badges)};

  // Submit handler — POST to /feedback/rate/{{short_id}}, on success
  // re-render with the submitted state.
  window.cires_submit_rating = async function(payload) {{
    const r = await fetch(`/feedback/rate/${{window.CIRES_RATE_SHORT_ID}}`, {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify(payload),
    }});
    if (!r.ok) throw new Error(`HTTP ${{r.status}}`);
    return r.json();
  }};
</script>

<script src="https://unpkg.com/react@18.3.1/umd/react.development.js" crossorigin="anonymous"></script>
<script src="https://unpkg.com/react-dom@18.3.1/umd/react-dom.development.js" crossorigin="anonymous"></script>
<script src="https://unpkg.com/@babel/standalone@7.29.0/babel.min.js" crossorigin="anonymous"></script>

<script type="text/babel" src="/static/design/atoms.jsx"></script>
<script type="text/babel" src="/static/design/sidebar.jsx"></script>
<script type="text/babel" src="/static/design/feedback.jsx"></script>

<script type="text/babel" data-presets="react">
  // 2026-06-04 (WS-2 F-008): wrap FeedbackEmpty in the platform's
  // Sidebar + TopBar chrome so the operator has nav + theme + stats
  // exactly like the detail page. Was previously a chrome-less form.
  function App() {{
    const [theme] = window.useTheme();
    const [collapsed, setCollapsed] = window.useSidebarCollapsed();
    return (
      <div className="cires" data-theme={{theme}} style={{{{ background: "var(--bg)", minHeight: "100vh", display: "flex" }}}}>
        <window.Sidebar active="triage" collapsed={{collapsed}} onToggleCollapse={{() => setCollapsed(!collapsed)}}/>
        <div style={{{{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}}}>
          <TopBar page="detail"/>
          <div style={{{{ flex: 1, minWidth: 0 }}}}>
            <FeedbackEmpty/>
          </div>
        </div>
      </div>
    );
  }}
  ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
</script>

</body>
</html>""")


# ──────────────────────────────────────────────────────────────────────
# /dashboard/v2/{path} → /dashboard/{path} — backward-compat redirect
# ──────────────────────────────────────────────────────────────────────
# The 2026-06-01 production cutover made v2 THE dashboard; the /v2/*
# URL prefix is gone. This permanent redirect catches any lingering
# Tailscale bookmarks (or supervisor-demo links) so they don't 404 during
# the transition. 301 (not 302) so browsers + reverse proxies cache the
# new location. Two declarations so the bare /dashboard/v2 form skips
# FastAPI's auto-trailing-slash 307 hop and lands on /dashboard directly.
@app.get("/dashboard/v2")
async def dashboard_v2_root_legacy_redirect():
    return RedirectResponse(url="/dashboard", status_code=301)


@app.get("/dashboard/v2/{path:path}")
async def dashboard_v2_legacy_redirect(path: str):
    target = f"/dashboard/{path}" if path else "/dashboard"
    return RedirectResponse(url=target, status_code=301)


# ----------------------------------------------------------------------
# 2026-06-02 - Sprint 5 placeholder pages
# ----------------------------------------------------------------------
# The React sidebar (sidebar.jsx) surfaces 9 nav items. Pre-overhaul,
# five of them ("Incidents", "Anomalies", "Stats", "Drain3 engine",
# "Integrations") had no href - clicking them was a no-op or, worse, a
# 404. The frontend overhaul wires real hrefs and lands them on this
# shared placeholder so the operator never sees a dead click.
#
# Each route resolves to one of EPIC13 / EPIC14 / EPIC15 (Sprint 5
# scope). The placeholder keeps the sidebar visible so the operator
# can navigate back without a back-button hunt; "back to triage feed"
# CTA points at /dashboard.
_SPRINT5_PLACEHOLDER_SURFACES = {
    "incidents": {
        "title": "Incidents",
        "epic":  "EPIC13",
        "why":   "Long-running multi-alert incident timeline. Today the feed "
                 "shows alerts; Sprint 5 stitches them into incidents with "
                 "open/close lifecycle.",
    },
    "anomalies": {
        "title": "Anomalies",
        "epic":  "EPIC14",
        "why":   "Drain3 anomaly surface. Today anomalies fire as alerts; "
                 "Sprint 5 gives them a dedicated trending view.",
    },
    "stats": {
        "title": "Stats",
        "epic":  "EPIC15",
        "why":   "Aggregated trends across services / time. Today /dashboard/kpi "
                 "covers platform-health KPIs; Sprint 5 adds business-level stats.",
    },
    "drain3": {
        "title": "Drain3 engine",
        "epic":  "EPIC14",
        "why":   "Live drain3 template explorer. Today /drain3/stats returns "
                 "JSON; Sprint 5 wraps it in an operator-readable surface.",
    },
    "integrations": {
        "title": "Integrations",
        "epic":  "EPIC15",
        "why":   "External integration health (Grafana, Loki, Prometheus, "
                 "Jaeger, MCP bridges). Today /health returns one line; "
                 "Sprint 5 breaks it down per integration.",
    },
}


def _render_sprint5_placeholder(slug: str) -> HTMLResponse:
    """Single shared template for the five Sprint-5 placeholder routes.

    Renders a minimal page with the design tokens.css applied (so the
    look matches the rest of the dashboard) plus a clear "coming Sprint 5"
    message and a CTA back to /dashboard. The sidebar isn't shown here
    intentionally - it's a React component that needs the alerts payload
    to render badges, and we don't want to spin up the full Dashboard
    chrome just to show a 4-line placeholder.
    """
    meta = _SPRINT5_PLACEHOLDER_SURFACES[slug]
    title = _html.escape(meta["title"])
    epic  = _html.escape(meta["epic"])
    why   = _html.escape(meta["why"])
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{title} - coming Sprint 5</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/design/tokens.css"/>
{_CIRES_THEME_HEAD_SCRIPT}
<style>
  body {{ margin: 0; background: var(--bg, #0f1117); font-family: 'Inter', system-ui, sans-serif; color: var(--text, #e4e6ee); }}
  .sprint5-wrap {{
    min-height: 100vh;
    display: flex; align-items: center; justify-content: center;
    padding: 40px 24px;
  }}
  .sprint5-card {{
    max-width: 560px; width: 100%;
    background: var(--card, #1a1d27);
    border: 1px solid var(--border, #2a2d3a);
    border-radius: 12px;
    padding: 36px 32px;
    box-shadow: var(--shadow-md, 0 12px 28px rgba(0,0,0,.45));
  }}
  .sprint5-eyebrow {{
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.12em;
    color: var(--accent-purple, #b07ee8);
    margin-bottom: 10px;
  }}
  .sprint5-title {{
    font-size: 26px; font-weight: 600;
    color: var(--text, #e4e6ee);
    margin: 0 0 18px 0;
  }}
  .sprint5-msg {{
    font-size: 14px; line-height: 1.55;
    color: var(--text-soft, #c0c5d0);
    margin-bottom: 22px;
  }}
  .sprint5-why {{
    font-size: 13px; line-height: 1.5;
    color: var(--muted, #8890a0);
    border-left: 3px solid var(--border-hi, #3a3f52);
    padding: 8px 0 8px 14px;
    margin-bottom: 26px;
  }}
  .sprint5-cta {{
    display: inline-block;
    background: var(--accent-cyan, #40d0d0);
    color: var(--bg, #0f1117);
    text-decoration: none; font-weight: 600; font-size: 13px;
    padding: 9px 16px; border-radius: 7px;
  }}
  .sprint5-cta:hover {{ filter: brightness(1.1); }}
  .sprint5-back {{
    display: inline-block; margin-left: 14px;
    color: var(--muted, #8890a0); font-size: 12.5px;
    text-decoration: none;
  }}
  .sprint5-back:hover {{ color: var(--text-soft, #c0c5d0); }}
</style>
</head>
<body>
<div class="sprint5-wrap">
  <div class="sprint5-card">
    <div class="sprint5-eyebrow">{epic} - planned Sprint 5</div>
    <h1 class="sprint5-title">{title}</h1>
    <p class="sprint5-msg">This surface is planned for Sprint 5. It is not built yet.</p>
    <div class="sprint5-why">{why}</div>
    <a class="sprint5-cta" href="/dashboard">Back to triage feed</a>
    <a class="sprint5-back" href="/dashboard/kpi">View platform KPIs</a>
  </div>
</div>
</body>
</html>""")


def _fmt_duration(seconds: int) -> str:
    """Human-readable span: '3d 4h', '2h 15m', '45m', '30s'. 0 → 'just now'.

    Used by the incidents page to render last_seen − first_seen prominently.
    Coarse on purpose — two units max so the operator gets a glanceable
    'how long has this been flapping' answer, not a stopwatch.
    """
    s = int(seconds or 0)
    if s <= 0:
        return "just now"
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m, sec = divmod(rem, 60)
    if d:
        return f"{d}d {h}h" if h else f"{d}d"
    if h:
        return f"{h}h {m}m" if m else f"{h}h"
    if m:
        return f"{m}m"
    return f"{sec}s"


# ──────────────────────────────────────────────────────────────────────
# /dashboard/incidents — S5-INC-02 — one row per incident (fingerprint)
# ──────────────────────────────────────────────────────────────────────
# Grouped twin of the triage feed: the same flapping rule that produces 40
# feed rows is ONE incident here. Reads the first-class incidents table
# (S5-INC-01) via RCAStore.get_incidents — current DISMISS incidents are
# hidden by default (the canonical lowercased 'dismiss' verdict token).
# fire_count + duration (last_seen − first_seen) are the prominent columns.
# Server-rendered in the same chrome as /dashboard/services. Read-only,
# all data via RCAStore (the canonical writer) — MCP-invariant clean.
def _render_services_section(services: list[dict]) -> tuple[str, str]:
    """(chips_html, table_html) for the per-service 7-day rollup — shared by the
    merged Incidents/Services page (2026-06-13)."""
    import urllib.parse as _urllib

    def _esc(s) -> str:
        return _html.escape(str(s)) if s is not None else ""

    n_services = len(services)
    total_decisions = sum(s["total"] for s in services)
    total_emails = sum(s["actions"].get("emailed", 0) for s in services)
    emails_per_day = round(total_emails / 7.0, 1) if total_emails else 0
    chips_html = f"""
    <div class="svc-chips">
      <div class="svc-chip"><span class="svc-chip__n">{n_services}</span><span class="svc-chip__l">services seen</span></div>
      <div class="svc-chip"><span class="svc-chip__n">{total_decisions}</span><span class="svc-chip__l">decisions</span></div>
      <div class="svc-chip"><span class="svc-chip__n">{emails_per_day}</span><span class="svc-chip__l">emails / day avg</span></div>
    </div>"""
    if services:
        def _fmt(d: dict) -> str:
            if not d:
                return "<span class='svc-muted'>—</span>"
            items = sorted(d.items(), key=lambda kv: kv[1], reverse=True)
            return " &middot; ".join(
                f"<span class='svc-pair'>{_esc(_humanize_verdict_token(k))} <b>{v}</b></span>"
                for k, v in items
            )
        rows = []
        for s in services:
            svc = s["service"] or ""
            q = _urllib.quote_plus(svc)
            lf = s["last_fire"] or "—"
            if lf and lf != "—":
                lf = lf[:16].replace("T", " ")
            rows.append(
                f'<tr><td class="svc-cell-name"><a href="/dashboard?q={q}">{_esc(_v2m_display_service(svc))}</a></td>'
                f'<td class="svc-cell-num">{s["total"]}</td>'
                f'<td>{_fmt(s["actions"])}</td><td>{_fmt(s["verdicts"])}</td><td>{_fmt(s["severities"])}</td>'
                f'<td class="svc-cell-mono">{_esc(lf)}</td>'
                f'<td class="svc-cell-alert">{_esc(s["top_alertname"] or "—")}</td></tr>'
            )
        table_html = (
            '<table class="svc-table"><thead><tr><th>Service</th><th>Total</th><th>By action</th>'
            '<th>By verdict</th><th>By severity</th><th>Last fire</th><th>Top alert</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table>'
        )
    else:
        table_html = ('<div class="svc-empty"><div class="svc-empty__title">No services yet</div>'
                      '<div class="svc-empty__sub">No service activity in the last 7 days.</div></div>')
    return chips_html, table_html


@app.get("/dashboard/incidents", response_class=HTMLResponse)
async def dashboard_sprint5_incidents(view: str = Query("incidents", max_length=12)):
    """Incident surface — one row per alert_fingerprint, sorted by recency.

    2026-06-13: Services merged in as a second view (segmented toggle). Both
    answer "what's noisy"; incidents group by fingerprint, services by service.
    Server-side toggle via ?view= (survives the 60 s meta-refresh; no JS)."""
    import urllib.parse as _urllib
    from datetime import datetime, timezone, timedelta

    incidents: list[dict] = []
    if _store is not None:
        try:
            incidents = await _store.get_incidents(limit=200, exclude_dismissed=True)
        except Exception as exc:
            logger.warning("incidents query failed (non-fatal): %s", exc)
            incidents = []

    now_tng = datetime.now(timezone.utc).astimezone(
        timezone(timedelta(hours=1))
    ).strftime("%Y-%m-%d %H:%M:%S")

    def _esc(s) -> str:
        return _html.escape(str(s)) if s is not None else ""

    # ── Headline chips.
    n_incidents = len(incidents)
    total_fires = sum(int(i.get("fire_count") or 0) for i in incidents)
    noisiest = max(
        (int(i.get("fire_count") or 0) for i in incidents), default=0
    )
    chips_html = f"""
    <div class="svc-chips">
      <div class="svc-chip"><span class="svc-chip__n">{n_incidents}</span><span class="svc-chip__l">open incidents</span></div>
      <div class="svc-chip"><span class="svc-chip__n">{total_fires}</span><span class="svc-chip__l">total fires</span></div>
      <div class="svc-chip"><span class="svc-chip__n">{noisiest}</span><span class="svc-chip__l">noisiest (fires)</span></div>
    </div>"""

    if incidents:
        row_html_parts = []
        for inc in incidents:
            name = inc.get("alert_name") or "(unknown)"
            svc = inc.get("affected_service") or ""
            q_param = _urllib.quote_plus(svc) if svc else ""
            svc_cell = (
                f'<a href="/dashboard?q={q_param}">{_esc(_v2m_display_service(svc))}</a>'
                if svc else "<span class='svc-muted'>—</span>"
            )
            verdict = inc.get("current_verdict") or "(none)"
            severity = inc.get("current_severity") or "(unknown)"
            fire_count = int(inc.get("fire_count") or 0)
            duration = _fmt_duration(inc.get("duration_seconds") or 0)
            last_fire = inc.get("last_seen") or "—"
            if last_fire and last_fire != "—":
                last_fire = last_fire[:16].replace("T", " ")
            first_fire = inc.get("first_seen") or "—"
            if first_fire and first_fire != "—":
                first_fire = first_fire[:16].replace("T", " ")
            # F-4 (2026-06-10): click-through to the alert detail page via the
            # incident's most-recent rca_history row (incidents are keyed by
            # fingerprint; the detail route resolves by decision short_id —
            # with an id-prefix fallback for rows older than its 15-day scan).
            # Same pattern as the service cell's <a href> link. Incidents with
            # no rca_history row (recurrence-only orphans) stay plain text.
            latest_id = (inc.get("latest_decision_id") or "").strip()
            name_cell = (
                f'<a href="/dashboard/alert/{_esc(latest_id[:8])}">{_esc(name)}</a>'
                if latest_id else _esc(name)
            )
            row_html_parts.append(f"""
        <tr>
          <td class="svc-cell-name">{name_cell}</td>
          <td>{svc_cell}</td>
          <td class="inc-cell-fires">{fire_count}</td>
          <td class="inc-cell-dur">{_esc(duration)}</td>
          <td>{_esc(verdict)}</td>
          <td>{_esc(severity)}</td>
          <td class="svc-cell-mono">{_esc(first_fire)}</td>
          <td class="svc-cell-mono">{_esc(last_fire)}</td>
        </tr>""")
        table_body_html = "".join(row_html_parts)
        table_html = f"""
    <table class="svc-table">
      <thead>
        <tr>
          <th>Alert</th>
          <th>Service</th>
          <th>Fires</th>
          <th>Duration</th>
          <th>Verdict</th>
          <th>Severity</th>
          <th>First seen</th>
          <th>Last seen</th>
        </tr>
      </thead>
      <tbody>{table_body_html}
      </tbody>
    </table>"""
    else:
        table_html = """
    <div class="svc-empty">
      <div class="svc-empty__title">No open incidents</div>
      <div class="svc-empty__sub">Nothing is currently open. New alerts will be grouped into incidents here as they arrive.</div>
    </div>"""

    # ── Services view (merged 2026-06-13): same page, segmented toggle.
    view = "services" if view == "services" else "incidents"
    services: list[dict] = []
    if _store is not None:
        try:
            services = await _store.get_service_summary(days=7)
        except Exception as exc:
            logger.warning("services summary query failed (non-fatal): %s", exc)
            services = []
    svc_chips, svc_table = _render_services_section(services)
    if view == "services":
        active_chips, active_table = svc_chips, svc_table
        head_sub = "Per-service activity over the last 7 days — what each service generated and how it was triaged."
        foot = "Each row is one service. <em>Total</em> is its decisions in the window; the breakdowns show how they were actioned, triaged, and rated. Auto-refresh: 60 s."
    else:
        active_chips, active_table = chips_html, table_html
        head_sub = "Repeated alerts grouped into one line per ongoing issue."
        foot = "Each row is one incident. <em>Fires</em> counts how many times it alerted; <em>Duration</em> is how long it has been going on. Auto-refresh: 60 s."

    def _seg(v: str, label: str) -> str:
        cls = "seg-toggle__btn seg-toggle__btn--active" if v == view else "seg-toggle__btn"
        return f'<a class="{cls}" href="/dashboard/incidents?view={v}">{label}</a>'
    toggle_html = (f'<div class="seg-toggle">{_seg("incidents", "Incidents")}'
                   f'{_seg("services", "Services")}</div>')

    sidebar_html = _render_insight_sidebar("incidents")

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta http-equiv="refresh" content="60"/>
<title>Observability &middot; Incidents</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/design/tokens.css"/>
{_CIRES_THEME_HEAD_SCRIPT}
<style>
  body {{ margin: 0; background: var(--bg, #0f1117); font-family: 'Inter', system-ui, sans-serif; color: var(--text, #e4e6ee); min-height: 100vh; }}
  .kpi-shell {{ display: flex; min-height: 100vh; }}
  .kpi-sidebar {{ width: 224px; flex-shrink: 0; background: var(--bg-soft, #13151e); border-right: 1px solid var(--border, #2a2d3a); padding: 0 0 14px; display: flex; flex-direction: column; }}
  .kpi-sidebar__brand {{ display: flex; align-items: center; gap: 10px; padding: 14px 14px 14px 16px; border-bottom: 1px solid var(--border); height: 60px; }}
  .kpi-sidebar__brand-mark {{ width: 28px; height: 28px; border-radius: 8px; background: linear-gradient(135deg, #4ea8de, #b07ee8); flex-shrink: 0; }}
  .kpi-sidebar__brand-title {{ font-size: 13.5px; font-weight: 600; color: var(--text); }}
  .kpi-sidebar__brand-sub {{ font-size: 11px; color: var(--muted); letter-spacing: 0.04em; }}
  .kpi-sidebar__group {{ padding: 12px; margin-bottom: 6px; }}
  .kpi-sidebar__group-label {{ font-size: 10px; color: var(--muted-2); text-transform: uppercase; letter-spacing: 0.12em; padding: 0 12px 6px; font-weight: 600; }}
  .kpi-sidebar__item {{ display: block; padding: 8px 12px; border-radius: 8px; text-decoration: none; color: var(--text-soft); font-size: 13px; transition: background .12s; }}
  .kpi-sidebar__item:hover {{ background: var(--card-hi); color: var(--text); }}
  .kpi-sidebar__item--active {{ background: var(--card-hi); color: var(--text); border: 1px solid var(--border-hi); font-weight: 500; box-shadow: inset 2.5px 0 0 var(--accent-blue); }}
  .kpi-main {{ flex: 1; min-width: 0; display: flex; flex-direction: column; }}
  .kpi-header {{ padding: 18px 22px 8px; border-bottom: 1px solid var(--border); display: flex; align-items: baseline; justify-content: space-between; }}
  .kpi-header__title {{ font-size: 18px; font-weight: 600; color: var(--text); }}
  .kpi-header__sub {{ font-size: 12.5px; color: var(--muted); margin-top: 4px; }}
  .kpi-header__time {{ font-family: var(--font-mono); font-size: 11.5px; color: var(--muted); letter-spacing: 0.02em; }}
  .svc-chips {{ display: flex; gap: 14px; padding: 18px 22px 6px; flex-wrap: wrap; }}
  .svc-chip {{ background: var(--card); border: 1px solid var(--border); border-left: 3px solid var(--accent-purple); border-radius: 10px; padding: 10px 16px; display: flex; flex-direction: column; gap: 2px; min-width: 140px; }}
  .svc-chip__n {{ font-family: var(--font-mono); font-size: 22px; font-weight: 600; color: var(--text); line-height: 1.1; }}
  .svc-chip__l {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; }}
  .svc-table-wrap {{ padding: 14px 22px 22px; }}
  .svc-table {{ width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; font-size: 13px; }}
  .svc-table thead th {{ text-align: left; padding: 10px 14px; background: var(--bg-soft); border-bottom: 1px solid var(--border); font-size: 11px; color: var(--muted-2); text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; }}
  .svc-table tbody td {{ padding: 10px 14px; border-bottom: 1px solid var(--border); color: var(--text-soft); vertical-align: top; }}
  .svc-table tbody tr:last-child td {{ border-bottom: none; }}
  .svc-table tbody tr:hover td {{ background: var(--card-hi); }}
  .svc-cell-name {{ color: var(--text); font-weight: 500; }}
  .svc-cell-name a {{ color: var(--accent-cyan); text-decoration: none; font-weight: 500; }}
  .svc-cell-name a:hover {{ text-decoration: underline; }}
  .inc-cell-fires {{ font-family: var(--font-mono); color: var(--accent-yellow); font-weight: 600; }}
  .inc-cell-dur {{ font-family: var(--font-mono); color: var(--text); font-weight: 600; }}
  .svc-cell-mono {{ font-family: var(--font-mono); color: var(--muted); font-size: 12px; white-space: nowrap; }}
  .svc-muted {{ color: var(--muted); }}
  .svc-cell-num {{ font-family: var(--font-mono); color: var(--text); font-weight: 600; }}
  .svc-pair {{ color: var(--muted); }}
  .svc-pair b {{ color: var(--text); }}
  .svc-cell-alert {{ font-size: 12px; color: var(--text-soft); }}
  .svc-empty {{ margin: 18px 22px; padding: 36px 28px; background: var(--card); border: 1px dashed var(--border); border-radius: 12px; text-align: center; color: var(--muted); }}
  .svc-empty__title {{ font-size: 15px; font-weight: 600; color: var(--text-soft); margin-bottom: 6px; }}
  .svc-empty__sub {{ font-size: 12.5px; }}
  .svc-empty code {{ font-family: var(--font-mono); background: var(--bg-soft); padding: 1px 5px; border-radius: 4px; font-size: 11.5px; }}
  .seg-toggle {{ display: inline-flex; gap: 3px; margin: 16px 22px 0; background: var(--bg-soft); border: 1px solid var(--border); border-radius: 9px; padding: 3px; }}
  .seg-toggle__btn {{ padding: 6px 18px; border-radius: 7px; font-size: 13px; font-weight: 500; color: var(--muted); text-decoration: none; transition: background .12s, color .12s; }}
  .seg-toggle__btn:hover {{ color: var(--text); }}
  .seg-toggle__btn--active {{ background: var(--card-hi); color: var(--text); border: 1px solid var(--border-hi); }}
  .kpi-foot {{ padding: 12px 22px 22px; font-size: 11.5px; color: var(--muted); border-top: 1px solid var(--border); }}
  .kpi-foot strong {{ color: var(--muted); }}
</style>
</head>
<body>

<div class="kpi-shell">
  {sidebar_html}
  <main class="kpi-main">
    <div class="kpi-header">
      <div>
        <div class="kpi-header__title">Incidents &amp; services</div>
        <div class="kpi-header__sub">{head_sub}</div>
      </div>
      <div class="kpi-header__time">
        <span class="live-dot"></span>{_esc(now_tng)} GMT+1
      </div>
    </div>

    {toggle_html}
    {active_chips}

    <div class="svc-table-wrap">{active_table}
    </div>

    <div class="kpi-foot">
      {foot}
    </div>
  </main>
</div>

</body>
</html>""")


# ──────────────────────────────────────────────────────────────────────
# /dashboard/anomalies — S5-INC-04 — detective-signal aggregation
# ──────────────────────────────────────────────────────────────────────
# Surfaces the four detective signals that already exist in the pipeline.
# Aggregate, do NOT recompute:
#   (a) Drain3 novel templates  — live, from DrainAnalyzer.get_stats()
#       (in-memory miner state; not persisted for a historical view).
#   (b) Entity-baseline σ-claims — computed on-demand from Prometheus via the
#       MCP bridge inside the pipeline (app/entity_baselines.py). NOT persisted
#       and not queryable here without a Prometheus read, which would violate
#       the MCP-only-read invariant for these pages → honest "not persisted".
#   (c) Recurrence-gate fires    — PERSISTED on rca_history
#       (triage_decision='recurrence_gated_pre_llm'); real historical view.
#   (d) Adaptive-threshold widened-but-not-fired ratio — no persisted store
#       (only referenced in the LLM prompt text; no widen/fire counters are
#       written anywhere) → honest "not persisted".
# Read-only. Drain3 stats are in-process miner state (not an external read);
# recurrence fires come via RCAStore. MCP-invariant clean.
@app.get("/dashboard/anomalies", response_class=HTMLResponse)
async def dashboard_sprint5_anomalies():
    """Detective-signal surface — aggregates the four existing signals."""
    import asyncio as _asyncio
    from datetime import datetime, timezone, timedelta

    def _esc(s) -> str:
        return _html.escape(str(s)) if s is not None else ""

    # (a) Drain3 novel templates — live miner state.
    drain_stats = {}
    if _drain is not None:
        try:
            drain_stats = await _asyncio.to_thread(_drain.get_stats)
        except Exception as exc:
            logger.warning("drain3 stats for anomalies page failed (non-fatal): %s", exc)
            drain_stats = {}
    novel_templates = (drain_stats.get("top_new_patterns") or [])[:10]
    anomaly_rate = drain_stats.get("recent_anomaly_rate", 0)
    total_clusters = drain_stats.get("total_clusters", 0)

    if novel_templates:
        novel_html = "".join(
            f"<li class='anom-tmpl'>{_esc(t)}</li>" for t in novel_templates
        )
        novel_html = f"<ul class='anom-list'>{novel_html}</ul>"
    else:
        novel_html = "<div class='anom-empty'>No new log patterns in the current window.</div>"

    # (c) Recurrence-gate fires — persisted, real historical view.
    rec = {"total": 0, "by_alert": []}
    if _store is not None:
        try:
            rec = await _store.get_recurrence_gate_fires(hours=24, limit=20)
        except Exception as exc:
            logger.warning("recurrence-gate query for anomalies page failed (non-fatal): %s", exc)
            rec = {"total": 0, "by_alert": []}
    if rec["by_alert"]:
        rec_rows = "".join(
            f"<tr><td class='anom-fam'>{_esc(b['alert_name'])}</td><td class='anom-num'>{int(b['count'])}</td></tr>"
            for b in rec["by_alert"]
        )
        rec_html = f"""
      <table class="anom-table">
        <thead><tr><th>Alert</th><th>Held back (24h)</th></tr></thead>
        <tbody>{rec_rows}</tbody>
      </table>"""
    else:
        rec_html = "<div class='anom-empty'>No repeated alerts were held back in the last 24 h.</div>"

    now_tng = datetime.now(timezone.utc).astimezone(
        timezone(timedelta(hours=1))
    ).strftime("%Y-%m-%d %H:%M:%S")

    sidebar_html = _render_insight_sidebar("anomalies")

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<meta http-equiv="refresh" content="60"/>
<title>Observability &middot; Anomalies</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/design/tokens.css"/>
{_CIRES_THEME_HEAD_SCRIPT}
<style>
  body {{ margin: 0; background: var(--bg, #0f1117); font-family: 'Inter', system-ui, sans-serif; color: var(--text, #e4e6ee); min-height: 100vh; }}
  .kpi-shell {{ display: flex; min-height: 100vh; }}
  .kpi-sidebar {{ width: 224px; flex-shrink: 0; background: var(--bg-soft, #13151e); border-right: 1px solid var(--border, #2a2d3a); padding: 0 0 14px; display: flex; flex-direction: column; }}
  .kpi-sidebar__brand {{ display: flex; align-items: center; gap: 10px; padding: 14px 14px 14px 16px; border-bottom: 1px solid var(--border); height: 60px; }}
  .kpi-sidebar__brand-mark {{ width: 28px; height: 28px; border-radius: 8px; background: linear-gradient(135deg, #4ea8de, #b07ee8); flex-shrink: 0; }}
  .kpi-sidebar__brand-title {{ font-size: 13.5px; font-weight: 600; color: var(--text); }}
  .kpi-sidebar__brand-sub {{ font-size: 11px; color: var(--muted); letter-spacing: 0.04em; }}
  .kpi-sidebar__group {{ padding: 12px; margin-bottom: 6px; }}
  .kpi-sidebar__group-label {{ font-size: 10px; color: var(--muted-2); text-transform: uppercase; letter-spacing: 0.12em; padding: 0 12px 6px; font-weight: 600; }}
  .kpi-sidebar__item {{ display: block; padding: 8px 12px; border-radius: 8px; text-decoration: none; color: var(--text-soft); font-size: 13px; transition: background .12s; }}
  .kpi-sidebar__item:hover {{ background: var(--card-hi); color: var(--text); }}
  .kpi-sidebar__item--active {{ background: var(--card-hi); color: var(--text); border: 1px solid var(--border-hi); font-weight: 500; box-shadow: inset 2.5px 0 0 var(--accent-blue); }}
  .kpi-main {{ flex: 1; min-width: 0; display: flex; flex-direction: column; }}
  .kpi-header {{ padding: 18px 22px 8px; border-bottom: 1px solid var(--border); display: flex; align-items: baseline; justify-content: space-between; }}
  .kpi-header__title {{ font-size: 18px; font-weight: 600; color: var(--text); }}
  .kpi-header__sub {{ font-size: 12.5px; color: var(--muted); margin-top: 4px; }}
  .kpi-header__time {{ font-family: var(--font-mono); font-size: 11.5px; color: var(--muted); letter-spacing: 0.02em; }}

  .anom-sections {{ padding: 18px 22px 22px; display: flex; flex-direction: column; gap: 16px; }}
  .anom-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px 18px; border-left: 3px solid var(--accent-cyan); }}
  .anom-card__head {{ display: flex; align-items: baseline; gap: 10px; margin-bottom: 4px; }}
  .anom-card__title {{ font-size: 14px; font-weight: 600; color: var(--text); }}
  .anom-card__q {{ font-size: 11.5px; color: var(--muted); margin-bottom: 12px; }}
  .anom-stat-row {{ display: flex; gap: 18px; margin-bottom: 12px; }}
  .anom-stat {{ display: flex; flex-direction: column; gap: 2px; }}
  .anom-stat__n {{ font-family: var(--font-mono); font-size: 20px; font-weight: 600; color: var(--text); }}
  .anom-stat__l {{ font-size: 10.5px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; }}
  .anom-list {{ margin: 0; padding: 0; list-style: none; }}
  .anom-tmpl {{ font-family: var(--font-mono); font-size: 12px; color: var(--text-soft); padding: 5px 8px; background: var(--bg-soft); border-radius: 6px; margin-bottom: 5px; word-break: break-word; }}
  .anom-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .anom-table thead th {{ text-align: left; padding: 7px 10px; background: var(--bg-soft); border-bottom: 1px solid var(--border); font-size: 11px; color: var(--muted-2); text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; }}
  .anom-table tbody td {{ padding: 7px 10px; border-bottom: 1px solid var(--border); color: var(--text-soft); }}
  .anom-table tbody tr:last-child td {{ border-bottom: none; }}
  .anom-fam {{ color: var(--text); font-weight: 500; }}
  .anom-num {{ font-family: var(--font-mono); color: var(--accent-yellow); font-weight: 600; }}
  .anom-empty {{ font-size: 12.5px; color: var(--muted-2); padding: 6px 0; }}
  .kpi-foot {{ padding: 12px 22px 22px; font-size: 11.5px; color: var(--muted-2); border-top: 1px solid var(--border); }}
</style>
</head>
<body>

<div class="kpi-shell">
  {sidebar_html}
  <main class="kpi-main">
    <div class="kpi-header">
      <div>
        <div class="kpi-header__title">Anomalies</div>
        <div class="kpi-header__sub">Unusual patterns the platform has spotted in logs and alerts.</div>
      </div>
      <div class="kpi-header__time">
        <span class="live-dot"></span>{_esc(now_tng)} GMT+1
      </div>
    </div>

    <div class="anom-sections">

      <div class="anom-card">
        <div class="anom-card__head">
          <span class="anom-card__title">New log patterns</span>
        </div>
        <div class="anom-card__q">Log messages that don't look like anything seen before &mdash; often the first sign of a new problem.</div>
        <div class="anom-stat-row">
          <div class="anom-stat"><span class="anom-stat__n">{_esc(total_clusters)}</span><span class="anom-stat__l">known patterns</span></div>
          <div class="anom-stat"><span class="anom-stat__n">{_esc(anomaly_rate)}</span><span class="anom-stat__l">recent anomaly rate</span></div>
        </div>
        {novel_html}
      </div>

      <div class="anom-card">
        <div class="anom-card__head">
          <span class="anom-card__title">Repeated alerts held back</span>
        </div>
        <div class="anom-card__q">Alerts automatically held back in the last 24 hours because they were repeats of a known issue.</div>
        <div class="anom-stat-row">
          <div class="anom-stat"><span class="anom-stat__n">{int(rec["total"])}</span><span class="anom-stat__l">held back (24h)</span></div>
        </div>
        {rec_html}
      </div>

    </div>

    <div class="kpi-foot">
      Auto-refresh: 60 s.
    </div>
  </main>
</div>

</body>
</html>""")


# ──────────────────────────────────────────────────────────────────────
# /dashboard/stats — S5-INC-03 — insight aggregates over rca_history
# ──────────────────────────────────────────────────────────────────────
# Pure read aggregation, no new schema: top-10 noisiest alerts, top-5
# most-escalated services, verdict mix per alert family, and a false-positive
# proxy from the feedback table (verdict_was_right='no'). Same chrome /
# tokens.css idiom as the KPI + services pages. Read-only via RCAStore —
# MCP-invariant clean.
@app.get("/dashboard/settings", response_class=HTMLResponse)
async def dashboard_settings():
    """2026-06-12 (Lina): operator settings — manage who receives the
    escalation emails, editable here (no redeploy)."""
    sidebar_html = _render_insight_sidebar("settings")
    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Observability &middot; Settings</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/static/design/tokens.css"/>
{_CIRES_THEME_HEAD_SCRIPT}
<style>
  body {{ margin:0; background:var(--bg,#0f1117); color:var(--text,#e8eaf2); font-family:'Inter',-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
  .kpi-shell {{ display:flex; min-height:100vh; }}
  /* sidebar CSS (shared with the other secondary pages) */
  .kpi-sidebar {{ width: 224px; flex-shrink: 0; background: var(--bg-soft, #13151e); border-right: 1px solid var(--border, #2a2d3a); padding: 0 0 14px; display: flex; flex-direction: column; }}
  .kpi-sidebar__brand {{ display: flex; align-items: center; gap: 10px; padding: 14px 14px 14px 16px; border-bottom: 1px solid var(--border); height: 60px; }}
  .kpi-sidebar__brand-mark {{ width: 28px; height: 28px; border-radius: 8px; background: linear-gradient(135deg, #4ea8de, #b07ee8); flex-shrink: 0; }}
  .kpi-sidebar__brand-title {{ font-size: 13.5px; font-weight: 600; color: var(--text); }}
  .kpi-sidebar__brand-sub {{ font-size: 11px; color: var(--muted); letter-spacing: 0.04em; }}
  .kpi-sidebar__group {{ padding: 12px; margin-bottom: 6px; }}
  .kpi-sidebar__group-label {{ font-size: 10px; color: var(--muted-2); text-transform: uppercase; letter-spacing: 0.12em; padding: 0 12px 6px; font-weight: 600; }}
  .kpi-sidebar__item {{ display: block; padding: 8px 12px; border-radius: 8px; text-decoration: none; color: var(--text-soft); font-size: 13px; transition: background .12s; }}
  .kpi-sidebar__item:hover {{ background: var(--card-hi); color: var(--text); }}
  .kpi-sidebar__item--active {{ background: var(--card-hi); color: var(--text); border: 1px solid var(--border-hi); font-weight: 500; box-shadow: inset 2.5px 0 0 var(--accent-blue); }}
  .kpi-main {{ flex:1; padding:32px 40px; max-width:760px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  .sub {{ color:var(--text-soft,#9aa3b8); font-size:13.5px; margin-bottom:22px; }}
  .card {{ background:var(--card,#1a1d27); border:1px solid var(--border,#2a2d3a); border-radius:12px; padding:18px 22px; margin:16px 0; }}
  .card h2 {{ font-size:14px; margin:0 0 10px; color:var(--accent-cyan,#5bc8d8); }}
  .rcpt {{ display:flex; align-items:center; justify-content:space-between; padding:9px 12px; border:1px solid var(--border,#2a2d3a); border-radius:8px; margin:6px 0; background:var(--bg,#11131b); font-size:14px; }}
  .rcpt .meta {{ color:var(--text-soft,#9aa3b8); font-size:12px; }}
  .baseline {{ opacity:.7; }}
  .pill {{ font-size:10.5px; font-weight:600; padding:1px 8px; border-radius:10px; border:1px solid var(--border,#2a2d3a); color:var(--text-soft,#9aa3b8); }}
  button {{ font-family:inherit; cursor:pointer; border-radius:7px; border:1px solid var(--border,#2a2d3a); }}
  .rm {{ background:rgba(224,96,112,.10); border-color:rgba(224,96,112,.4); color:#e06070; padding:4px 10px; font-size:12px; }}
  .add {{ background:rgba(91,200,216,.15); border-color:rgba(91,200,216,.45); color:#9ad4f2; padding:8px 16px; font-size:13px; font-weight:500; }}
  input {{ font-family:inherit; font-size:14px; padding:8px 11px; border-radius:7px; border:1px solid var(--border,#2a2d3a); background:var(--bg,#11131b); color:var(--text,#e8eaf2); }}
  .row {{ display:flex; gap:8px; margin-top:10px; flex-wrap:wrap; }}
  .msg {{ font-size:12.5px; margin-top:8px; min-height:16px; }}
  a.back {{ color:var(--accent-cyan,#5bc8d8); font-size:13px; text-decoration:none; }}
</style></head>
<body>
<div class="kpi-shell">
  {sidebar_html}
  <main class="kpi-main">
    <a class="back" href="/dashboard">&larr; back to triage feed</a>
    <h1 style="margin-top:14px">Escalation email recipients</h1>
    <div class="sub">Everyone listed here receives the email when an alert escalates. Changes apply immediately — no redeploy.</div>
    <div class="card">
      <h2>Always-on (set at deploy time)</h2>
      <div id="baseline"></div>
    </div>
    <div class="card">
      <h2>Managed here</h2>
      <div id="managed"></div>
      <div class="row">
        <input id="email" type="email" placeholder="name@cires.ma" style="flex:1; min-width:220px">
        <input id="label" type="text" placeholder="label (optional, e.g. NOC)" style="flex:1; min-width:150px">
        <button class="add" onclick="addRcpt()">Add recipient</button>
      </div>
      <div class="msg" id="msg"></div>
    </div>
  </main>
</div>
<script>
async function load() {{
  const r = await fetch('/api/recipients'); const d = await r.json();
  document.getElementById('baseline').innerHTML = (d.baseline.length ? d.baseline : ['(none configured)']).map(function(e){{
    return '<div class="rcpt baseline"><span>'+e+'</span><span class="pill">always-on</span></div>'; }}).join('');
  const mg = document.getElementById('managed');
  mg.innerHTML = d.managed.length ? d.managed.map(function(x){{
    return '<div class="rcpt"><span>'+x.email+(x.label ? ' <span class="meta">· '+x.label+'</span>' : '')+'</span>'
      + '<button class="rm" onclick="rm(\\''+x.email+'\\')">remove</button></div>'; }}).join('')
    : '<div class="sub" style="margin:4px 0 0">No extra recipients yet — add one below.</div>';
}}
async function addRcpt() {{
  const email = document.getElementById('email').value.trim();
  const label = document.getElementById('label').value.trim();
  const msg = document.getElementById('msg');
  const r = await fetch('/api/recipients', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify({{email:email, label:label}})}});
  if (r.ok) {{ document.getElementById('email').value=''; document.getElementById('label').value=''; msg.style.color='var(--accent-green,#6fd388)'; msg.textContent='Added \\u2713'; load(); }}
  else {{ const e = await r.json().catch(function(){{return {{}};}}); msg.style.color='#e06070'; msg.textContent = (e && e.detail) || 'Could not add — check the address.'; }}
}}
async function rm(email) {{ const r = await fetch('/api/recipients/' + encodeURIComponent(email), {{method:'DELETE'}}); if (r.ok) load(); }}
load();
</script>
</body></html>""")


@app.get("/dashboard/stats", response_class=HTMLResponse)
async def dashboard_stats_redirect():
    """2026-06-13 — Stats merged into the Evaluation page. Old links/bookmarks
    keep working via a permanent redirect."""
    return RedirectResponse(url="/dashboard/kpi", status_code=301)


@app.get("/dashboard/drain3", response_class=HTMLResponse)
async def dashboard_sprint5_drain3():
    return _render_sprint5_placeholder("drain3")


@app.get("/dashboard/integrations", response_class=HTMLResponse)
async def dashboard_sprint5_integrations():
    return _render_sprint5_placeholder("integrations")


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
