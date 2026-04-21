import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib

from app.config import settings
from app.metrics import triage_email_sent_total
from app.models import GrafanaAlert, LLMDecision, RCARecord

logger = logging.getLogger(__name__)


class EmailNotifier:
    async def send_escalation(
        self, alert: GrafanaAlert, decision: LLMDecision, record: RCARecord, history_count: int = 0
    ):
        subject = f"[ALERT] {decision.severity}: {alert.alertname} — {alert.service}"

        body = f"""<html><body style="font-family: sans-serif; color: #333;">
<h2 style="color: #d32f2f;">Alert Escalated: {alert.alertname}</h2>

<table style="border-collapse:collapse; margin-bottom:16px;">
  <tr><td style="padding:4px 12px; font-weight:bold;">Alert</td><td style="padding:4px 12px;">{alert.alertname}</td></tr>
  <tr><td style="padding:4px 12px; font-weight:bold;">Service</td><td style="padding:4px 12px;">{alert.service}</td></tr>
  <tr><td style="padding:4px 12px; font-weight:bold;">Severity</td><td style="padding:4px 12px;">{decision.severity}</td></tr>
  <tr><td style="padding:4px 12px; font-weight:bold;">Fired At</td><td style="padding:4px 12px;">{alert.startsAt}</td></tr>
  <tr><td style="padding:4px 12px; font-weight:bold;">Instance</td><td style="padding:4px 12px;">{alert.instance}</td></tr>
</table>

<h3>Root Cause Analysis</h3>
<p>{decision.rca}</p>

<h3>Reason</h3>
<p>{decision.reason}</p>

<h3>Anomaly Summary</h3>
<p>{decision.anomaly_summary or "No Drain3 anomalies detected."}</p>

<h3>Suggested Actions</h3>
<ul>
{"".join(f"<li>{a}</li>" for a in decision.suggested_actions) if decision.suggested_actions else "<li>Review the alert manually</li>"}
</ul>

<h3>Evidence</h3>
<ul>
{"".join(f"<li>{e}</li>" for e in decision.evidence) if decision.evidence else "<li>See Grafana dashboards</li>"}
</ul>

<h3>History</h3>
<p>This alert has fired <strong>{history_count}</strong> time(s) in the last 7 days.</p>

<hr>
<p style="color:#888; font-size:12px;">
  Investigation took {record.investigation_duration_ms}ms.
  <a href="{settings.grafana_url}/d/unified-overview">Grafana Dashboard</a> |
  RCA ID: {record.id}
</p>
</body></html>"""

        await self._send(subject, body)

    async def send_timeout_alert(self, alert: GrafanaAlert):
        subject = f"[ALERT] TIMEOUT: {alert.alertname} — AI triage timed out"

        body = f"""<html><body style="font-family: sans-serif; color: #333;">
<h2 style="color: #ff9800;">AI Triage Timeout — Raw Alert Forwarded</h2>
<p>The AI triage pipeline did not complete within {settings.pipeline_timeout} seconds.
This raw alert is forwarded without AI analysis as a safety measure.</p>

<table style="border-collapse:collapse; margin-bottom:16px;">
  <tr><td style="padding:4px 12px; font-weight:bold;">Alert</td><td style="padding:4px 12px;">{alert.alertname}</td></tr>
  <tr><td style="padding:4px 12px; font-weight:bold;">Service</td><td style="padding:4px 12px;">{alert.service}</td></tr>
  <tr><td style="padding:4px 12px; font-weight:bold;">Severity</td><td style="padding:4px 12px;">{alert.severity}</td></tr>
  <tr><td style="padding:4px 12px; font-weight:bold;">Fired At</td><td style="padding:4px 12px;">{alert.startsAt}</td></tr>
  <tr><td style="padding:4px 12px; font-weight:bold;">Summary</td><td style="padding:4px 12px;">{alert.annotations.get("summary", "N/A")}</td></tr>
  <tr><td style="padding:4px 12px; font-weight:bold;">Description</td><td style="padding:4px 12px;">{alert.annotations.get("description", "N/A")}</td></tr>
</table>

<p>Please investigate manually. Check <a href="{settings.grafana_url}/d/unified-overview">Grafana Dashboard</a>.</p>

<hr>
<p style="color:#888; font-size:12px;">Timeout after {settings.pipeline_timeout}s. AI triage service may be overloaded or Ollama unresponsive.</p>
</body></html>"""

        await self._send(subject, body)

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
