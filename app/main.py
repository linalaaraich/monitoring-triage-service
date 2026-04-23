import html as _html
import logging
import time
from contextlib import asynccontextmanager

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
    return _drain.get_stats()


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
  .drain-patterns .lbl {
    font-size: 10.5px; font-weight: 700; letter-spacing: 1px;
    text-transform: uppercase; color: var(--muted);
    margin-bottom: 6px;
  }
  .drain-patterns ol {
    padding-left: 22px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px; color: var(--ink-soft);
  }
  .drain-patterns ol li { padding: 2px 0; word-break: break-word; }
  .drain-patterns .none {
    color: var(--muted); font-style: italic; font-size: 12px;
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
      window._refreshTimer = setInterval(function() { window.location.reload(); }, 30000);
    } else {
      clearInterval(window._refreshTimer);
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

    Absent (older rows before the migration) renders as empty string so
    the summary row stays clean.
    """
    if not quality:
        return ""
    cls = 'quality-actionable' if quality == 'actionable' else 'quality-data_starved'
    label = _html.escape(quality.replace('_', ' '))
    return f'<span class="quality {cls}">{label}</span>'


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
        '  <div class="drain-patterns">'
        '    <div class="lbl">Most recent templates</div>'
        f'    {pattern_html}'
        '  </div>'
        '</div>'
    )


def _render_detail_panel(r: dict) -> str:
    did = _html.escape(r.get('id') or '')
    ts_full = _html.escape(r.get('timestamp') or '')
    fingerprint = _html.escape(r.get('alert_fingerprint') or '—')
    triage = _html.escape(r.get('triage_decision') or '—')
    confidence = _html.escape(str(r.get('llm_confidence') or '—'))
    action = _html.escape(r.get('action_taken') or '—')
    duration = int(r.get('investigation_duration_ms') or 0)

    rca = _html.escape(r.get('rca_report') or '')
    reasoning = _html.escape(r.get('llm_reasoning') or '')
    rca_cls = 'body' if rca else 'body empty'
    reasoning_cls = 'body' if reasoning else 'body empty'
    rca_text = rca or '(no RCA report captured — decision took the suppress or timeout path)'
    reasoning_text = reasoning or '(no reasoning captured)'

    return (
        f'<div class="panel">'
        f'  <div class="meta-grid">'
        f'    <div class="m"><div class="lbl">Timestamp (UTC)</div><div class="val">{ts_full}</div></div>'
        f'    <div class="m"><div class="lbl">Decision ID</div><div class="val">{did}</div></div>'
        f'    <div class="m"><div class="lbl">Alert fingerprint</div><div class="val">{fingerprint}</div></div>'
        f'    <div class="m"><div class="lbl">Triage path</div><div class="val normal">{triage}</div></div>'
        f'    <div class="m"><div class="lbl">LLM confidence</div><div class="val normal">{confidence}</div></div>'
        f'    <div class="m"><div class="lbl">Action</div><div class="val normal">{action} · {_fmt_duration_ms(duration)}</div></div>'
        f'    <div class="m"><div class="lbl">RCA quality</div><div class="val normal">{_html.escape(r.get("rca_quality") or "—").replace("_"," ")}</div></div>'
        f'  </div>'
        f'  <div class="section">'
        f'    <h3>Root-cause analysis</h3>'
        f'    <div class="{rca_cls}">{rca_text}</div>'
        f'  </div>'
        f'  <div class="section">'
        f'    <h3>Model reasoning</h3>'
        f'    <div class="{reasoning_cls}">{reasoning_text}</div>'
        f'  </div>'
        f'</div>'
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
        ts = _html.escape((r.get('timestamp') or '')[:19].replace('T', ' '))
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
            f'  <td>{_html.escape(service)}</td>'
            f'  <td><span class="sev sev-{_html.escape(severity)}">{_html.escape(severity or "—")}</span></td>'
            f'  <td>{_verdict_pill(verdict, action)}{_quality_pill(r.get("rca_quality"))}</td>'
            f'  <td class="action action-{_html.escape(action)}">{_html.escape(action)}</td>'
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
        f'    <div class="stat t-esc"><div class="num">{escalated}</div><div class="lbl">Escalated</div></div>'
        f'    <div class="stat t-dismiss"><div class="num">{dismissed}</div><div class="lbl">Dismissed</div></div>'
        f'    <div class="stat t-suppress"><div class="num">{suppressed_pre}</div><div class="lbl">Pre-LLM suppressed</div></div>'
        f'    <div class="stat t-timeout"><div class="num">{timed_out}</div><div class="lbl">Timed out</div></div>'
        f'  </div>'
        f'  {_render_drain3_panel(drain_stats)}'
        f'  <div class="toolbar">'
        f'    <input id="filter" type="text" placeholder="Filter by alert name, service, verdict, or RCA text" autocomplete="off" />'
        f'    <span class="hint" id="match-count"></span>'
        f'    <span class="spacer"></span>'
        f'    <label class="refresh"><input id="refresh" type="checkbox" checked onchange="toggleRefresh()" /> Auto-refresh every 30 seconds</label>'
        f'  </div>'
        f'  <div class="table-card">'
        f'    <table>'
        f'      <thead><tr>'
        f'        <th></th><th>Time (UTC)</th><th>Alert</th><th>Source</th><th>Service</th>'
        f'        <th>Severity</th><th>Verdict</th><th>Action</th><th>Duration</th>'
        f'      </tr></thead>'
        f'      <tbody>{body_rows}</tbody>'
        f'    </table>'
        f'  </div>'
        f'</div>'
        f'<script>{_DASHBOARD_JS}</script>'
        f'</body></html>'
    )


@app.get("/metrics")
async def metrics():
    return Response(content=get_metrics(), media_type="text/plain; charset=utf-8")
