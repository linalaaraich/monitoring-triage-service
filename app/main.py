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


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    rows = await _store.get_decisions(limit=100)
    table_rows = ""
    for r in rows:
        verdict_color = "#4caf50" if r.get("action_taken") == "suppressed" else "#f44336"
        table_rows += f"""<tr>
            <td>{r.get('timestamp','')[:19]}</td>
            <td>{r.get('alert_name','')}</td>
            <td>{r.get('alert_source','')}</td>
            <td>{r.get('affected_service','')}</td>
            <td>{r.get('severity','')}</td>
            <td style="color:{verdict_color};font-weight:bold">{r.get('llm_verdict','—')}</td>
            <td>{r.get('action_taken','')}</td>
            <td>{r.get('investigation_duration_ms',0)}ms</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><title>RCA Decision History</title>
<style>
body {{ font-family: -apple-system, sans-serif; background: #0f1117; color: #e0e0e0; margin: 0; padding: 24px; }}
h1 {{ color: #bb86fc; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 16px; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #2a2d37; font-size: 13px; }}
th {{ background: #1a1d27; color: #aaa; font-weight: 600; position: sticky; top: 0; }}
tr:hover {{ background: #1a1d27; }}
.stats {{ display: flex; gap: 24px; margin: 16px 0; }}
.stat {{ background: #1a1d27; padding: 16px 24px; border-radius: 8px; }}
.stat-num {{ font-size: 28px; font-weight: bold; }}
.stat-label {{ color: #888; font-size: 12px; margin-top: 4px; }}
</style></head><body>
<h1>RCA Decision History</h1>
<div class="stats">
  <div class="stat"><div class="stat-num">{len(rows)}</div><div class="stat-label">Total Decisions</div></div>
  <div class="stat"><div class="stat-num" style="color:#f44336">{sum(1 for r in rows if r.get('action_taken')=='emailed')}</div><div class="stat-label">Escalated</div></div>
  <div class="stat"><div class="stat-num" style="color:#4caf50">{sum(1 for r in rows if r.get('action_taken')=='suppressed')}</div><div class="stat-label">Dismissed</div></div>
  <div class="stat"><div class="stat-num" style="color:#ff9800">{sum(1 for r in rows if r.get('action_taken')=='emailed_raw')}</div><div class="stat-label">Timeouts</div></div>
</div>
<table>
<thead><tr><th>Time</th><th>Alert</th><th>Source</th><th>Service</th><th>Severity</th><th>Verdict</th><th>Action</th><th>Duration</th></tr></thead>
<tbody>{table_rows if table_rows else '<tr><td colspan="8" style="text-align:center;color:#666">No decisions yet. Waiting for alerts...</td></tr>'}</tbody>
</table>
</body></html>"""


@app.get("/metrics")
async def metrics():
    return Response(content=get_metrics(), media_type="text/plain; charset=utf-8")
