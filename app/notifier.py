import logging
from collections import Counter
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib

from app.config import settings
from app.metrics import triage_email_sent_total
from app.models import GatheredContext, GrafanaAlert, LLMDecision, RCARecord

logger = logging.getLogger(__name__)


def _severity_pill_class(severity: str) -> str:
    s = (severity or "").lower()
    if s in ("critical", "high"):
        return "pill-danger"
    if s in ("warning", "warn", "medium"):
        return "pill-warn"
    return "pill-info"


def _top_log_issues(ctx: GatheredContext | None, top_n: int = 3) -> list[tuple[str, int]]:
    """Most frequent annotated log lines; highlights [ANOMALY] over [KNOWN]."""
    if ctx is None:
        return []
    lines = ctx.annotated_logs or ctx.logs or []
    if not lines:
        return []
    counter: Counter[str] = Counter()
    for raw in lines:
        line = str(raw).strip()
        if not line:
            continue
        counter[" ".join(line.split())[:140]] += 1
    return counter.most_common(top_n)


def _slowest_span_summary(ctx: GatheredContext | None) -> str:
    if ctx is None or not ctx.traces:
        return "N/A"
    try:
        slowest = max(ctx.traces, key=lambda t: int(t.get("duration") or t.get("duration_us") or 0))
    except ValueError:
        return "N/A"
    name = slowest.get("operationName") or slowest.get("span_name") or "unknown-span"
    duration_us = int(slowest.get("duration") or slowest.get("duration_us") or 0)
    return f"{name} ({duration_us / 1000.0:.2f} ms)"


def _metrics_preview(ctx: GatheredContext | None) -> str:
    if ctx is None or not ctx.metrics:
        return "N/A"
    query = ctx.metrics.get("query") or ctx.metrics.get("promql") or "metrics"
    values = ctx.metrics.get("values") or ctx.metrics.get("result") or []
    count = len(values) if isinstance(values, list) else "?"
    return f"{query} — {count} points"


def _quick_links(alert: GrafanaAlert) -> dict[str, str]:
    """Extract Grafana quick-links from alert annotations / generatorURL."""
    annotations = alert.annotations or {}
    links: dict[str, str] = {}
    for key, label in [
        ("Source", "View Alert"),
        ("source", "View Alert"),
        ("DashboardURL", "View Dashboard"),
        ("dashboardURL", "View Dashboard"),
        ("PanelURL", "View Panel"),
        ("panelURL", "View Panel"),
        ("Silence", "Create Silence"),
        ("silence", "Create Silence"),
    ]:
        url = annotations.get(key)
        if url and label not in links:
            links[label] = url
    if alert.generatorURL and "View Alert" not in links:
        links["View Alert"] = alert.generatorURL
    return links


_EMAIL_CSS = """
  :root {
    --bg: #ffffff; --card: #f7f9ff; --muted: #5b6b8b; --text: #0b1b3a;
    --border: rgba(11, 27, 58, .12); --danger: #d64550;
    --warn: #c27c0e; --info: #1f6feb; --ok: #0f766e;
  }
  body { margin: 0; padding: 0; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    line-height: 1.45; }
  a { color: #0b5bd3; text-decoration: none; } a:hover { text-decoration: underline; }
  .container { max-width: 860px; margin: 0 auto; padding: 24px 16px; }
  .hero { background: radial-gradient(1200px 600px at 10% -10%, rgba(31,111,235,.22), transparent 55%),
    radial-gradient(900px 500px at 90% 0%, rgba(214,69,80,.16), transparent 58%),
    linear-gradient(180deg, rgba(11,27,58,.04), rgba(11,27,58,.02));
    border: 1px solid var(--border); border-radius: 16px; padding: 18px 18px 16px; }
  .hero-top { display: flex; gap: 12px; align-items: center; justify-content: space-between; flex-wrap: wrap; }
  .title { font-size: 22px; margin: 0; }
  .subtitle { margin: 6px 0 0; color: var(--muted); font-size: 13px; }
  .pill { display: inline-block; padding: 6px 10px; border-radius: 999px;
    border: 1px solid var(--border); font-weight: 700; font-size: 12px;
    background: rgba(11,27,58,.03); }
  .pill-danger { border-color: rgba(214,69,80,.35); color: #7a1f28; background: rgba(214,69,80,.08); }
  .pill-warn { border-color: rgba(194,124,14,.30); color: #6a3f07; background: rgba(194,124,14,.10); }
  .pill-info { border-color: rgba(31,111,235,.30); color: #0b2e7a; background: rgba(31,111,235,.08); }
  .grid { display: grid; grid-template-columns: 1fr; gap: 14px; margin-top: 14px; }
  .card { background: var(--card); border: 1px solid var(--border);
    border-radius: 14px; padding: 14px 14px 10px; }
  .card h2 { font-size: 16px; margin: 0 0 10px; }
  .kvs { width: 100%; border-collapse: collapse; }
  .kvs td { padding: 8px 0; border-bottom: 1px solid rgba(11,27,58,.08); vertical-align: top; }
  .kvs tr:last-child td { border-bottom: none; }
  .k { width: 180px; color: var(--muted); font-weight: 700; }
  .v { color: var(--text); word-break: break-word; }
  .badge { display: inline-flex; gap: 8px; align-items: center; padding: 10px 12px;
    border-radius: 12px; border: 1px solid var(--border); font-weight: 800; }
  .badge-escalate { background: rgba(214,69,80,.10); border-color: rgba(214,69,80,.28); }
  .badge-dismiss  { background: rgba(15,118,110,.09); border-color: rgba(15,118,110,.25); }
  .badge small { display: block; font-weight: 700; color: var(--muted); margin-top: 2px; }
  .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px; white-space: pre-wrap; word-break: break-word;
    background: rgba(11,27,58,.03); border: 1px dashed rgba(11,27,58,.18);
    padding: 10px; border-radius: 10px; margin: 8px 0 0; }
  ul { margin: 8px 0 0; padding-left: 18px; }
  .footer { text-align: center; margin-top: 18px; color: var(--muted); font-size: 12px; }
  @media (min-width: 900px) {
    .grid { grid-template-columns: 1.15fr .85fr; align-items: start; }
    .span2 { grid-column: span 2; }
  }
"""


class EmailNotifier:
    async def send_escalation(
        self,
        alert: GrafanaAlert,
        decision: LLMDecision,
        record: RCARecord,
        history_count: int = 0,
        ctx: GatheredContext | None = None,
    ):
        severity = (decision.severity or alert.severity or "warning").upper()
        subject = f"[ALERT] {severity}: {alert.alertname} — {alert.service}"
        body = self._build_escalation_body(alert, decision, record, history_count, ctx)
        await self._send(subject, body)

    async def send_timeout_alert(self, alert: GrafanaAlert):
        subject = f"[ALERT] TIMEOUT: {alert.alertname} — AI triage timed out"
        body = self._build_timeout_body(alert)
        await self._send(subject, body)

    def _build_escalation_body(
        self,
        alert: GrafanaAlert,
        decision: LLMDecision,
        record: RCARecord,
        history_count: int,
        ctx: GatheredContext | None,
    ) -> str:
        env = alert.labels.get("deployment_environment") or alert.labels.get("env") or "N/A"
        severity_upper = (decision.severity or alert.severity or "warning").upper()
        pill_class = _severity_pill_class(decision.severity or alert.severity)

        quick_links = _quick_links(alert)
        links_html = "".join(
            f'<li><a href="{url}">{label}</a></li>' for label, url in quick_links.items()
        ) or "<li>No links available</li>"

        top_issues = _top_log_issues(ctx)
        log_issues_html = (
            "".join(f"<li>{msg} ({count}x)</li>" for msg, count in top_issues)
            if top_issues else "<li>No significant log patterns detected</li>"
        )

        actions_html = "".join(
            f"<li>{a}</li>" for a in decision.suggested_actions
        ) or "<li>Review the alert manually</li>"
        evidence_html = "".join(
            f"<li>{e}</li>" for e in decision.evidence
        ) or "<li>See Grafana dashboards</li>"

        anomaly_summary = decision.anomaly_summary or (
            ctx.anomaly_summary if ctx else ""
        ) or "No Drain3 anomalies detected."

        badge_class = "badge-escalate"
        confidence_pct = f"{decision.confidence * 100:.0f}%" if decision.confidence else "—"

        metrics_card = (
            f'<h3>Metrics (Prometheus)</h3>'
            f'<div class="mono">{_metrics_preview(ctx)}</div>'
            if ctx and ctx.metrics else '<p>No metrics collected</p>'
        )
        logs_card = (
            f'<h3>Logs (Loki, Drain3-annotated)</h3>'
            f'<p><span class="pill pill-info">{len(ctx.annotated_logs or ctx.logs or [])} lines analyzed</span></p>'
            f'<p><b>Top log patterns</b></p>'
            f'<ul>{log_issues_html}</ul>'
            if ctx and (ctx.annotated_logs or ctx.logs) else '<p>No logs collected</p>'
        )
        traces_card = (
            f'<h3>Traces (Jaeger)</h3>'
            f'<table class="kvs">'
            f'<tr><td class="k">Traces</td><td class="v">{len(ctx.traces)}</td></tr>'
            f'<tr><td class="k">Slowest span</td><td class="v">{_slowest_span_summary(ctx)}</td></tr>'
            f'</table>'
            if ctx and ctx.traces else '<p>No traces collected</p>'
        )

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>{_EMAIL_CSS}</style></head><body>
<div class="container">
  <div class="hero">
    <div class="hero-top">
      <div>
        <h1 class="title">Alert escalated: {alert.alertname}</h1>
        <p class="subtitle">CIRES AI triage produced a root cause analysis</p>
      </div>
      <div><span class="pill {pill_class}">SEVERITY: {severity_upper}</span></div>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h2>Alert details</h2>
      <table class="kvs">
        <tr><td class="k">Name</td><td class="v">{alert.alertname}</td></tr>
        <tr><td class="k">Service</td><td class="v">{alert.service}</td></tr>
        <tr><td class="k">Severity</td><td class="v">{severity_upper}</td></tr>
        <tr><td class="k">Instance</td><td class="v">{alert.instance}</td></tr>
        <tr><td class="k">Environment</td><td class="v">{env}</td></tr>
        <tr><td class="k">Fired at</td><td class="v">{alert.startsAt}</td></tr>
        <tr><td class="k">Status</td><td class="v">{alert.status}</td></tr>
      </table>
      <div class="mono">{alert.annotations.get('description') or alert.annotations.get('summary') or '(no description)'}</div>
    </div>

    <div class="card">
      <h2>RCA verdict</h2>
      <div class="badge {badge_class}">
        <div>Decision: {decision.decision.value}
          <small>Confidence: {confidence_pct}</small>
        </div>
      </div>
      <div class="mono">Reason: {decision.reason}

Root cause:
{decision.rca}

Anomaly summary: {anomaly_summary}</div>
      <h3>Suggested actions</h3>
      <ul>{actions_html}</ul>
      <h3>Evidence</h3>
      <ul>{evidence_html}</ul>
    </div>
  </div>

  <div class="card span2">
    <h2>Collected context</h2>
    {metrics_card}
    {logs_card}
    {traces_card}
  </div>

  <div class="card span2">
    <h2>Quick links</h2>
    <ul>{links_html}</ul>
  </div>

  <div class="card span2">
    <h2>History</h2>
    <p>This alert has fired <strong>{history_count}</strong> time(s) in the last 7 days.</p>
  </div>

  <div class="footer">
    <p>CIRES Observability — investigation took {record.investigation_duration_ms}ms — RCA ID: {record.id}</p>
  </div>
</div>
</body></html>"""

    def _build_timeout_body(self, alert: GrafanaAlert) -> str:
        env = alert.labels.get("deployment_environment") or alert.labels.get("env") or "N/A"
        quick_links = _quick_links(alert)
        links_html = "".join(
            f'<li><a href="{url}">{label}</a></li>' for label, url in quick_links.items()
        ) or "<li>No links available</li>"
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>{_EMAIL_CSS}</style></head><body>
<div class="container">
  <div class="hero">
    <div class="hero-top">
      <div>
        <h1 class="title">AI triage timeout — raw alert forwarded</h1>
        <p class="subtitle">The pipeline did not complete within {settings.pipeline_timeout}s. Forwarding without AI analysis.</p>
      </div>
      <div><span class="pill pill-warn">TIMEOUT</span></div>
    </div>
  </div>
  <div class="card">
    <h2>Alert details</h2>
    <table class="kvs">
      <tr><td class="k">Name</td><td class="v">{alert.alertname}</td></tr>
      <tr><td class="k">Service</td><td class="v">{alert.service}</td></tr>
      <tr><td class="k">Severity</td><td class="v">{alert.severity.upper()}</td></tr>
      <tr><td class="k">Instance</td><td class="v">{alert.instance}</td></tr>
      <tr><td class="k">Environment</td><td class="v">{env}</td></tr>
      <tr><td class="k">Fired at</td><td class="v">{alert.startsAt}</td></tr>
      <tr><td class="k">Summary</td><td class="v">{alert.annotations.get('summary', 'N/A')}</td></tr>
      <tr><td class="k">Description</td><td class="v">{alert.annotations.get('description', 'N/A')}</td></tr>
    </table>
  </div>
  <div class="card"><h2>Quick links</h2><ul>{links_html}</ul></div>
  <div class="footer"><p>Timeout after {settings.pipeline_timeout}s. AI triage service may be overloaded or Ollama unresponsive.</p></div>
</div></body></html>"""

    async def _send(self, subject: str, html_body: str):
        if not settings.smtp_user or not settings.smtp_password:
            logger.warning("SMTP credentials not configured — skipping email send")
            triage_email_sent_total.labels(status="skipped").inc()
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.smtp_from
        msg["To"] = settings.notification_email
        msg.attach(MIMEText(html_body, "html"))

        try:
            await aiosmtplib.send(
                msg,
                hostname=settings.smtp_host,
                port=settings.smtp_port,
                username=settings.smtp_user,
                password=settings.smtp_password,
                start_tls=True,
            )
            logger.info("Email sent: %s", subject)
            triage_email_sent_total.labels(status="sent").inc()
        except Exception as e:
            logger.error("SMTP send failed (non-fatal): %s", e)
            triage_email_sent_total.labels(status="failed").inc()
