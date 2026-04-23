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
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:'Inter','Segoe UI',system-ui,sans-serif; background:#0f1117; color:#e4e6ee; padding:24px 32px 48px; }
  a { color:#4ea8de; text-decoration:none; }
  a:hover { text-decoration:underline; }
  .header { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:16px; margin-bottom:20px; }
  .header h1 { font-size:22px; font-weight:700; letter-spacing:-.3px; }
  .header h1 span { color:#b07ee8; }
  .header .docs-link { font-size:12px; color:#8890a0; border:1px solid #2a2d3a; padding:6px 12px; border-radius:6px; }
  .header .docs-link:hover { border-color:#4ea8de; color:#4ea8de; text-decoration:none; }

  .stats { display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:12px; margin-bottom:20px; }
  .stat { background:#1a1d27; border:1px solid #2a2d3a; padding:14px 18px; border-radius:10px; display:flex; flex-direction:column; gap:2px; }
  .stat .num { font-size:26px; font-weight:700; letter-spacing:-.3px; }
  .stat .lbl { color:#8890a0; font-size:11px; font-weight:600; letter-spacing:.5px; text-transform:uppercase; }
  .stat.t-total .num { color:#e4e6ee; }
  .stat.t-esc .num { color:#e06070; }
  .stat.t-dismiss .num { color:#6bcf7f; }
  .stat.t-timeout .num { color:#f0a050; }
  .stat.t-suppress .num { color:#b07ee8; }

  .toolbar { display:flex; gap:12px; align-items:center; margin-bottom:10px; flex-wrap:wrap; }
  .toolbar input[type=text] {
    background:#1a1d27; border:1px solid #2a2d3a; color:#e4e6ee; padding:8px 12px;
    border-radius:6px; font-size:13px; min-width:260px; font-family:inherit;
  }
  .toolbar input[type=text]:focus { outline:none; border-color:#4ea8de; }
  .toolbar .hint { font-size:11px; color:#8890a0; }
  .toolbar .spacer { flex:1; }
  .toolbar label.refresh { font-size:12px; color:#8890a0; display:flex; align-items:center; gap:6px; cursor:pointer; user-select:none; }

  table { border-collapse:collapse; width:100%; background:#13151e; border:1px solid #2a2d3a; border-radius:8px; overflow:hidden; }
  thead th {
    background:#1a1d27; color:#8890a0; font-weight:700; font-size:10.5px; letter-spacing:.8px;
    text-transform:uppercase; text-align:left; padding:10px 12px; border-bottom:1px solid #2a2d3a;
    position:sticky; top:0; z-index:1;
  }
  tbody tr.summary { cursor:pointer; transition:background .12s; }
  tbody tr.summary td { padding:10px 12px; font-size:13px; border-bottom:1px solid #23262f; vertical-align:middle; }
  tbody tr.summary:hover { background:#181b25; }
  tbody tr.summary.open { background:#1e2230; }
  tbody tr.summary td.chev { width:24px; color:#8890a0; font-size:11px; text-align:center; transition:transform .15s; }
  tbody tr.summary.open td.chev { transform:rotate(90deg); color:#e4e6ee; }
  tbody tr.summary td.mono { font-family:'JetBrains Mono',ui-monospace,monospace; color:#c0c5d0; font-size:12px; white-space:nowrap; }

  .tag { display:inline-block; padding:2px 8px; border-radius:10px; font-size:10.5px; font-weight:600;
         border:1px solid; letter-spacing:.3px; }
  .tag-grafana { color:#f0a050; border-color:rgba(240,160,80,.35); background:rgba(240,160,80,.08); }
  .tag-drain3  { color:#40d0d0; border-color:rgba(64,208,208,.35); background:rgba(64,208,208,.08); }
  .tag-default { color:#8890a0; border-color:#2a2d3a; background:#1a1d27; }

  .sev { font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.5px; }
  .sev-critical { color:#e06070; }
  .sev-warning { color:#f0a050; }
  .sev-info, .sev-low { color:#8890a0; }

  .pill { display:inline-block; padding:3px 10px; border-radius:10px; font-size:11px; font-weight:700; letter-spacing:.4px; text-transform:uppercase; }
  .pill-escalate { background:rgba(224,96,112,.15); color:#e06070; border:1px solid rgba(224,96,112,.35); }
  .pill-dismiss  { background:rgba(107,207,127,.12); color:#6bcf7f; border:1px solid rgba(107,207,127,.35); }
  .pill-inconclusive { background:rgba(224,208,96,.1); color:#e0d060; border:1px solid rgba(224,208,96,.3); }
  .pill-none { background:#1a1d27; color:#8890a0; border:1px solid #2a2d3a; }

  .action { font-size:11.5px; color:#c0c5d0; }
  .action-emailed { color:#e06070; }
  .action-emailed_raw { color:#f0a050; }
  .action-suppressed { color:#6bcf7f; }

  tbody tr.detail { display:none; }
  tbody tr.detail.open { display:table-row; }
  tbody tr.detail > td { padding:0; background:#12141c; border-bottom:1px solid #2a2d3a; }

  .panel { padding:18px 22px 22px; border-left:3px solid #b07ee8; background:linear-gradient(90deg, rgba(176,126,232,.06), #12141c 60%); }
  .panel .meta-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:12px 20px; margin-bottom:16px; }
  .panel .m { display:flex; flex-direction:column; gap:2px; }
  .panel .m .lbl { font-size:10px; font-weight:700; letter-spacing:1px; text-transform:uppercase; color:#8890a0; }
  .panel .m .val { font-size:12.5px; color:#e4e6ee; font-family:'JetBrains Mono',ui-monospace,monospace; word-break:break-all; }
  .panel .m .val.normal { font-family:'Inter',system-ui,sans-serif; }

  .section { margin-top:14px; }
  .section h3 { font-size:12px; font-weight:700; color:#4ea8de; letter-spacing:1px; text-transform:uppercase; margin-bottom:6px; display:flex; align-items:center; gap:6px; }
  .section .body {
    background:#0f1117; border:1px solid #2a2d3a; border-radius:6px; padding:12px 14px;
    color:#c0c5d0; font-size:13px; line-height:1.6; white-space:pre-wrap; word-break:break-word;
  }
  .section .body.empty { color:#555; font-style:italic; }
  .section.reason h3 { color:#b07ee8; }
  .section.rca h3 { color:#6bcf7f; }

  tbody tr.empty td {
    text-align:center; color:#555; padding:32px 12px; font-style:italic;
  }

  @media(max-width:700px) {
    body { padding:16px; }
    .toolbar input[type=text] { min-width:0; width:100%; }
    thead th:nth-child(4), tbody td:nth-child(4),
    thead th:nth-child(5), tbody td:nth-child(5) { display:none; }
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
  });
"""


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
        f'    <div class="m"><div class="lbl">Action</div><div class="val normal">{action} · {duration}ms</div></div>'
        f'  </div>'
        f'  <div class="section rca">'
        f'    <h3>🤖 Root-cause analysis</h3>'
        f'    <div class="{rca_cls}">{rca_text}</div>'
        f'  </div>'
        f'  <div class="section reason">'
        f'    <h3>💭 LLM reasoning</h3>'
        f'    <div class="{reasoning_cls}">{reasoning_text}</div>'
        f'  </div>'
        f'</div>'
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    rows = await _store.get_decisions(limit=100)

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
            f'  <td class="chev">▶</td>'
            f'  <td class="mono">{ts}</td>'
            f'  <td>{_html.escape(alert_name)}</td>'
            f'  <td>{_source_tag(r.get("alert_source") or "")}</td>'
            f'  <td>{_html.escape(service)}</td>'
            f'  <td><span class="sev sev-{_html.escape(severity)}">{_html.escape(severity or "—")}</span></td>'
            f'  <td>{_verdict_pill(verdict, action)}</td>'
            f'  <td class="action action-{_html.escape(action)}">{_html.escape(action)}</td>'
            f'  <td class="mono">{duration} ms</td>'
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
        f'<div class="header">'
        f'  <h1>RCA Decision <span>History</span></h1>'
        f'  <a class="docs-link" href="https://linalaaraich.github.io/monitoring-docs/triage-service.html" target="_blank" rel="noopener">📖 Triage service docs →</a>'
        f'</div>'
        f'<div class="stats">'
        f'  <div class="stat t-total"><div class="num">{total}</div><div class="lbl">Total decisions</div></div>'
        f'  <div class="stat t-esc"><div class="num">{escalated}</div><div class="lbl">Escalated</div></div>'
        f'  <div class="stat t-dismiss"><div class="num">{dismissed}</div><div class="lbl">Dismissed</div></div>'
        f'  <div class="stat t-suppress"><div class="num">{suppressed_pre}</div><div class="lbl">Pre-LLM suppressed</div></div>'
        f'  <div class="stat t-timeout"><div class="num">{timed_out}</div><div class="lbl">Timed out</div></div>'
        f'</div>'
        f'<div class="toolbar">'
        f'  <input id="filter" type="text" placeholder="Filter by alert name, service, verdict, RCA text..." autocomplete="off" />'
        f'  <span class="hint" id="match-count"></span>'
        f'  <span class="spacer"></span>'
        f'  <label class="refresh"><input id="refresh" type="checkbox" onchange="toggleRefresh()" /> Auto-refresh 30s</label>'
        f'</div>'
        f'<table>'
        f'<thead><tr>'
        f'<th></th><th>Time (UTC)</th><th>Alert</th><th>Source</th><th>Service</th>'
        f'<th>Severity</th><th>Verdict</th><th>Action</th><th>Duration</th>'
        f'</tr></thead>'
        f'<tbody>{body_rows}</tbody>'
        f'</table>'
        f'<script>{_DASHBOARD_JS}</script>'
        f'</body></html>'
    )


@app.get("/metrics")
async def metrics():
    return Response(content=get_metrics(), media_type="text/plain; charset=utf-8")
