import logging
import re
from collections import Counter
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from zoneinfo import ZoneInfo


# Keep render-time-zone logic in sync with app.main._to_local_time.
# Duplicated instead of imported to avoid circular deps (notifier is
# imported from pipeline which is imported before main).
_LOCAL_TZ = ZoneInfo("Africa/Casablanca")


# Match 10-digit Unix timestamps the LLM sometimes embeds in prose
# (1500000000–2099999999 covers 2017–2036 in seconds). Same helper logic
# as main._humanize_unix_timestamps; duplicated here to avoid a circular
# import (main imports notifier, not the other way around).
_UNIX_TS_PATTERN = re.compile(r"\b(1[5-9][0-9]{8}|2[0-9]{9})\b")


def _humanize_unix_timestamps(text: str) -> str:
    """Replace any 10-digit Unix timestamp with `<unix> (<local>)`."""
    if not text:
        return text
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo("Africa/Casablanca")
    except ImportError:
        return text
    def _sub(m):
        try:
            from datetime import datetime
            local = datetime.fromtimestamp(int(m.group(1)), tz=tz)
            return f"{m.group(1)} ({local.strftime('%Y-%m-%d %H:%M')})"
        except (ValueError, OverflowError):
            return m.group(0)
    return _UNIX_TS_PATTERN.sub(_sub, text)


def _to_local_time(iso_utc_str: str | None, with_zone_label: bool = False) -> str:
    if not iso_utc_str:
        return ""
    s = iso_utc_str.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return iso_utc_str
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local = dt.astimezone(_LOCAL_TZ)
    base = local.strftime("%Y-%m-%d %H:%M:%S")
    return f"{base} Casablanca" if with_zone_label else base

import aiosmtplib

from app.config import settings
from app.metrics import triage_email_sent_total
from app.models import GatheredContext, GrafanaAlert, LLMDecision, RCARecord

logger = logging.getLogger(__name__)


def _instance_display(instance: str | None) -> str:
    """Render a raw alert instance ("10.0.1.194:9100") with its friendly
    hostname + role ("observability-rca-k3s · node-exporter"), falling back
    to the raw value when we don't have a mapping for either piece.
    """
    if not instance or instance == "unknown":
        return "unknown"
    raw = instance
    host, _, port = instance.partition(":")
    parts = [raw]
    friendly = []
    if host in settings.instance_hosts:
        friendly.append(settings.instance_hosts[host])
    if port in settings.instance_ports:
        friendly.append(settings.instance_ports[port])
    if friendly:
        parts.append("(" + " · ".join(friendly) + ")")
    return " ".join(parts)


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
    trace_dicts = [t for t in ctx.traces if isinstance(t, dict)]
    if not trace_dicts:
        return f"{len(ctx.traces)} traces (non-dict payload)"
    try:
        slowest = max(
            trace_dicts,
            key=lambda t: int(t.get("duration") or t.get("duration_us") or 0),
        )
    except (ValueError, TypeError):
        return "N/A"
    name = slowest.get("operationName") or slowest.get("span_name") or "unknown-span"
    duration_us = int(slowest.get("duration") or slowest.get("duration_us") or 0)
    return f"{name} ({duration_us / 1000.0:.2f} ms)"


def _top_traces_rows(ctx: GatheredContext | None, top_n: int = 8) -> str:
    """Render the top-N slowest traces as table rows for the email. Each row
    is a clickable link into the Jaeger UI (the trace's own permalink).
    """
    if ctx is None or not ctx.traces:
        return '<tr><td class="v" colspan="3"><i>No traces collected</i></td></tr>'
    trace_dicts = [t for t in ctx.traces if isinstance(t, dict)]
    if not trace_dicts:
        return f'<tr><td class="v" colspan="3"><i>{len(ctx.traces)} traces (non-dict payload)</i></td></tr>'

    def _dur(t):
        return int(t.get("duration") or t.get("duration_us") or 0)

    slowest = sorted(trace_dicts, key=_dur, reverse=True)[:top_n]
    rows = []
    for t in slowest:
        name = t.get("operationName") or t.get("span_name") or "unknown-span"
        tid = t.get("traceID") or t.get("trace_id") or ""
        dur_ms = _dur(t) / 1000.0
        svc = t.get("serviceName") or t.get("process", {}).get("serviceName") or "—"
        if tid:
            link = f'{settings.jaeger_url}/trace/{tid}'
            name_cell = f'<a href="{link}">{name}</a>'
        else:
            name_cell = name
        rows.append(
            f'<tr><td class="v">{name_cell}</td>'
            f'<td class="v mono-inline">{svc}</td>'
            f'<td class="v mono-inline" style="text-align:right">{dur_ms:.1f} ms</td></tr>'
        )
    return "\n".join(rows)


def _observed_value_block(alert: GrafanaAlert) -> str:
    """Render the alert's observed metric value + PromQL as the lede card —
    this is the single most useful piece of data in the whole email and we
    want the on-call to see it without scrolling.
    """
    values = alert.values or {}
    expr = alert.annotations.get("expr", "")
    if not values and not expr:
        return ""

    from app.llm_client import pick_primary_value
    value_display = ""
    if values:
        primary_ref, primary_val = pick_primary_value(values)
        value_display = f"<strong>{primary_val}</strong> <span class=\"mute\">(refId={primary_ref})</span>"
        rest = [(k, v) for k, v in sorted(values.items()) if k != primary_ref]
        if rest:
            rest_str = ", ".join(f"{k}={v}" for k, v in rest)
            value_display += f' <span class="mute">[{rest_str}]</span>'
    else:
        value_display = '<span class="mute">(not in webhook payload)</span>'

    return (
        '<div class="card span2" style="border-left: 4px solid var(--info);">'
        '<h2>Observed at fire time</h2>'
        '<table class="kvs">'
        f'<tr><td class="k">Observed value</td><td class="v" style="font-size:18px">{value_display}</td></tr>'
        f'<tr><td class="k">PromQL</td><td class="v mono-inline">{expr or "(not provided by rule)"}</td></tr>'
        '</table>'
        '</div>'
    )


def _correlated_alerts_block(correlated: list[dict]) -> str:
    """Render a compact list of other alerts that fired within the same
    correlation window, so the on-call can see cascade patterns at a glance.
    """
    if not correlated:
        return ""
    rows = []
    for c in correlated[:10]:
        rows.append(
            f'<tr><td class="v mono-inline">{_to_local_time(c.get("timestamp"))}</td>'
            f'<td class="v">{c.get("alert_name","?")}</td>'
            f'<td class="v">{c.get("affected_service","?")}</td>'
            f'<td class="v">{c.get("llm_verdict") or "—"}</td></tr>'
        )
    return (
        '<div class="card span2">'
        f'<h2>Correlated alerts <span class="mute">(within ±5 min)</span></h2>'
        '<table class="kvs"><thead><tr>'
        '<th class="k">When</th><th class="k">Alert</th><th class="k">Service</th><th class="k">Verdict</th>'
        '</tr></thead><tbody>'
        + "\n".join(rows) + '</tbody></table></div>'
    )


def _deep_links(alert: GrafanaAlert) -> dict[str, str]:
    """Build deep-links into the three pillar UIs so the recipient can
    verify/investigate without hand-editing URLs. Keyed on labels we know
    are present after the 2026-04-23 rule enrichment.
    """
    links: dict[str, str] = {}

    # Grafana — generatorURL from webhook is authoritative when populated
    if alert.generatorURL:
        links["Open alert in Grafana"] = alert.generatorURL

    # Loki and Jaeger deep-links: the pre-filtered Explore URL format
    # changed with Grafana 13 and the Jaeger v2 UI URL is inconsistent on
    # the current deploy. Rather than email broken chips that 404, we
    # omit them entirely — the LogQL/PromQL queries are rendered as
    # copyable text elsewhere in the email body.

    # Pre-existing alert annotations (runbook etc)
    for key, label in [
        ("runbook_url", "Runbook"),
        ("dashboard_url", "Dashboard"),
        ("DashboardURL", "Dashboard"),
        ("Silence", "Create Silence"),
        ("silence", "Create Silence"),
    ]:
        url = alert.annotations.get(key) or alert.labels.get(key)
        if url and label not in links:
            links[label] = url

    return links


def _metrics_preview(ctx: GatheredContext | None) -> str:
    # ctx.metrics is typed dict but pydantic doesn't validate assignment.
    # Defend against the MCP returning a string or a list.
    if ctx is None or not ctx.metrics:
        return "N/A"
    if not isinstance(ctx.metrics, dict):
        return f"{type(ctx.metrics).__name__} payload ({len(ctx.metrics)} items)"
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
  .mono-inline { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px; color: var(--text); }
  .mute { color: var(--muted); font-weight: 400; }
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
        correlated: list[dict] | None = None,
    ):
        # SF-6 (2026-05-23) — v2 email shape, per the supervisor-approved
        # Claude Design output. Brief subject + 4-button body. Operator-
        # cognitive-load doctrine (§12.1 in solution-brief): names not
        # metrics, brief not verbose, one ACTION not a list.
        subject = self._v2_subject(alert, decision, record)
        body = self._build_v2_escalation_body(
            alert, decision, record, history_count, ctx, correlated or []
        )
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
        correlated: list[dict],
    ) -> str:
        env = alert.labels.get("deployment_environment") or alert.labels.get("env") or "N/A"
        component = alert.labels.get("component") or "—"
        signal = alert.labels.get("signal") or "—"
        severity_upper = (decision.severity or alert.severity or "warning").upper()
        pill_class = _severity_pill_class(decision.severity or alert.severity)

        deep = _deep_links(alert)
        links_html = "".join(
            f'<li><a href="{url}">{label}</a> <span class="mute">— {url}</span></li>'
            for label, url in deep.items()
        ) or "<li>No links available</li>"

        top_issues = _top_log_issues(ctx, top_n=6)
        log_issues_html = (
            "".join(f"<li>{msg} <span class=\"mute\">({count}x)</span></li>" for msg, count in top_issues)
            if top_issues else "<li>No significant log patterns detected</li>"
        )

        actions_html = "".join(
            f"<li>{a}</li>" for a in decision.suggested_actions
        )
        if not actions_html:
            # Empty suggested_actions can mean two things: the LLM emitted
            # nothing AND no template fallback fired (rare, pre-clamp legacy),
            # OR the F-4 clamp stripped templated/untrustworthy actions and
            # populated diagnostic_steps instead (US-3.9 / Tier 0). The
            # message differs because the operator action differs — heads-up
            # vs. "go look at the diagnostic steps below."
            if decision.diagnostic_steps:
                actions_html = (
                    "<li><em>Withheld — confidence clamped to 0.40. "
                    "See <strong>diagnostic steps</strong> below for read-only "
                    "investigation pivots, then return to remediation once a "
                    "specific cause is named with trace or metric evidence.</em></li>"
                )
            else:
                actions_html = "<li><em>(no concrete remediation proposed — see RCA above; treat as a heads-up)</em></li>"
        # US-3.9 (Tier 0): diagnostic_steps surfaces alert-aware read-only
        # verbs when the F-4 clamp fires (or when the LLM chose investigation
        # over remediation). Rendered as its own card below "Suggested
        # actions" so the visual distinction is clear.
        diagnostic_html = "".join(
            f"<li>{d}</li>" for d in (decision.diagnostic_steps or [])
        )
        diagnostic_block = (
            f'<h3>Diagnostic steps <span class="mute">— read-only; investigate before remediating</span></h3>'
            f'<ul>{diagnostic_html}</ul>'
        ) if diagnostic_html else ""
        evidence_html = "".join(
            f"<li>{e}</li>" for e in decision.evidence
        ) or "<li><em>(no specific evidence cited — RCA reasoned from the observed value alone)</em></li>"

        # Map internal rca_quality to engineer-friendly labels (matches dashboard).
        _quality_label_map = {
            "actionable":   "fits — concrete RCA + valid suggested action",
            "data_starved": "thin — model hedged or evidence empty",
            "needs_review": "review — confidence below floor or validator flagged",
        }
        quality_human = _quality_label_map.get(record.rca_quality or "", record.rca_quality or "unknown")

        # Render fired_at in Casablanca local zone for the body — matches the
        # rest of the UI and the dashboard column. Raw ISO is shown alongside
        # so SRE folks can copy-paste into Grafana time-range pickers.
        fired_local = _to_local_time(alert.startsAt, with_zone_label=True)

        anomaly_summary = decision.anomaly_summary or (
            ctx.anomaly_summary if ctx else ""
        ) or "No Drain3 anomalies detected."

        badge_class = "badge-escalate"
        confidence_pct = f"{decision.confidence * 100:.0f}%" if decision.confidence else "—"

        metrics_card = (
            f'<h3>Metrics (Prometheus)</h3>'
            f'<div class="mono">{_metrics_preview(ctx)}</div>'
            if ctx and ctx.metrics else '<p class="mute">No metrics collected for service=' + alert.service + '</p>'
        )
        logs_card = (
            f'<h3>Logs (Loki, Drain3-annotated)</h3>'
            f'<p><span class="pill pill-info">{len(ctx.annotated_logs or ctx.logs or [])} lines analyzed</span>'
            f' <span class="mute">· anomaly summary: {anomaly_summary}</span></p>'
            f'<p><b>Top log patterns</b></p>'
            f'<ul>{log_issues_html}</ul>'
            if ctx and (ctx.annotated_logs or ctx.logs) else '<p class="mute">No service-scoped logs collected (expected for node-level alerts)</p>'
        )
        traces_card = (
            f'<h3>Traces (Jaeger) <span class="mute">— top {min(8, len(ctx.traces))} by duration</span></h3>'
            f'<table class="kvs"><thead><tr>'
            f'<th class="k">Operation</th><th class="k">Service</th><th class="k" style="text-align:right">Duration</th>'
            f'</tr></thead><tbody>{_top_traces_rows(ctx, top_n=8)}</tbody></table>'
            if ctx and ctx.traces else '<p class="mute">No traces collected (expected for non-traced services — k3s-node, loki, monitoring)</p>'
        )

        observed_block = _observed_value_block(alert)
        correlated_block = _correlated_alerts_block(correlated)

        # Service display: if alert.service is a readable label (not an IP),
        # show it with a hint of where to look; instance still has the raw
        # IP:port for SRE reference.
        service_display = alert.service if alert.service and alert.service != "unknown" else "unknown (add service label to the rule)"

        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>{_EMAIL_CSS}</style></head><body>
<div class="container">
  <div class="hero">
    <div class="hero-top">
      <div>
        <h1 class="title">Alert escalated: {alert.alertname}</h1>
        <p class="subtitle">CIRES AI triage — service <strong>{service_display}</strong> · component <strong>{component}</strong> · signal <strong>{signal}</strong></p>
      </div>
      <div><span class="pill {pill_class}">SEVERITY: {severity_upper}</span></div>
    </div>
  </div>

  <div class="grid">
    {observed_block}

    <div class="card">
      <h2>Alert details</h2>
      <table class="kvs">
        <tr><td class="k">Name</td><td class="v">{alert.alertname}</td></tr>
        <tr><td class="k">Service</td><td class="v"><strong>{service_display}</strong></td></tr>
        <tr><td class="k">Component</td><td class="v">{component}</td></tr>
        <tr><td class="k">Severity</td><td class="v">{severity_upper}</td></tr>
        <tr><td class="k">Instance</td><td class="v">{_instance_display(alert.instance)}</td></tr>
        <tr><td class="k">Environment</td><td class="v">{env}</td></tr>
        <tr><td class="k">Fired at</td><td class="v">{fired_local} <span class="mute">· raw: {alert.startsAt}</span></td></tr>
        <tr><td class="k">Status</td><td class="v">{alert.status}</td></tr>
      </table>
      <div class="mono">{alert.annotations.get('description') or alert.annotations.get('summary') or '(no description)'}</div>
    </div>

    <div class="card">
      <h2>RCA verdict</h2>
      <div class="badge {badge_class}">
        <div>Decision: {decision.decision.value}
          <small>Confidence: {confidence_pct} · Quality: {quality_human}</small>
        </div>
      </div>
      <div class="mono">Reason: {_humanize_unix_timestamps(decision.reason or '')}

Root cause:
{_humanize_unix_timestamps(decision.rca or '')}</div>
      <h3>Suggested actions</h3>
      <ul>{actions_html}</ul>
      {diagnostic_block}
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

  {correlated_block}

  <div class="card span2">
    <h2>Deep links</h2>
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
      <tr><td class="k">Instance</td><td class="v">{_instance_display(alert.instance)}</td></tr>
      <tr><td class="k">Environment</td><td class="v">{env}</td></tr>
      <tr><td class="k">Fired at</td><td class="v">{alert.startsAt}</td></tr>
      <tr><td class="k">Summary</td><td class="v">{alert.annotations.get('summary', 'N/A')}</td></tr>
      <tr><td class="k">Description</td><td class="v">{alert.annotations.get('description', 'N/A')}</td></tr>
    </table>
  </div>
  <div class="card"><h2>Quick links</h2><ul>{links_html}</ul></div>
  <div class="footer"><p>Timeout after {settings.pipeline_timeout}s. AI triage service may be overloaded or Ollama unresponsive.</p></div>
</div></body></html>"""

    # ────────────────────────────────────────────────────────────
    # SF-6 (2026-05-23) — v2 email shape
    # ────────────────────────────────────────────────────────────

    def _v2_subject(self, alert: GrafanaAlert, decision: LLMDecision,
                    record: RCARecord) -> str:
        """Subject format: [env] [namespace] [VERDICT] alertPlain.

        Capped at ~70 chars; alertPlain truncated if needed. Verdict comes
        from action_taken (SHELVED) or the LLM verdict (ESCALATE/DISMISS).
        """
        from app.v2_mappings import design_shape_for_alert
        action_taken = getattr(record, "action_taken", "") or ""
        verdict_lower = decision.decision.value.lower() if hasattr(decision.decision, "value") else str(decision.decision).lower()
        shape = design_shape_for_alert(
            alertname=alert.alertname,
            service=alert.service,
            verdict_lower=verdict_lower,
            action_taken=action_taken,
        )
        env = shape["env"]
        ns = shape["namespace"]
        verdict = shape["verdict"]
        plain = shape["alertPlain"]
        # Trim if needed to stay under ~70 chars total
        prefix = f"[{env}] [{ns}] [{verdict}] "
        max_plain = max(20, 70 - len(prefix))
        if len(plain) > max_plain:
            plain = plain[: max_plain - 1] + "…"
        return prefix + plain

    def _build_v2_escalation_body(
        self,
        alert: GrafanaAlert,
        decision: LLMDecision,
        record: RCARecord,
        history_count: int,
        ctx: GatheredContext | None,
        correlated: list[dict],
    ) -> str:
        """Brief operator-readable HTML email (per design's email.jsx).

        Structure: banner (verdict + severity + active-for) → identity pills
        (env/ns/service-type/component) → big WHAT → 3 blocks (Why /
        Suggested action / Severity) → 4 buttons → footer. Every CSS rule
        inlined (email clients strip <style> blocks).
        """
        import html as _html
        from datetime import datetime, timezone, timedelta
        from app.v2_mappings import design_shape_for_alert

        action_taken = getattr(record, "action_taken", "") or ""
        verdict_lower = decision.decision.value.lower() if hasattr(decision.decision, "value") else str(decision.decision).lower()
        shape = design_shape_for_alert(
            alertname=alert.alertname,
            service=alert.service,
            verdict_lower=verdict_lower,
            action_taken=action_taken,
        )
        env = shape["env"]
        ns = shape["namespace"]
        svc_type = shape["serviceType"]
        component = shape["component"]
        plain = shape["alertPlain"]
        verdict = shape["verdict"]
        severity = (decision.severity or alert.severity or "warning").lower()

        short_id = (record.id or "")[:8] or "—"
        full_id = record.id or "—"

        # Tangier-local time for the footer.
        try:
            ts_iso = getattr(record, "timestamp", None) or datetime.now(timezone.utc).isoformat()
            dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00")) if isinstance(ts_iso, str) else ts_iso
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            tng = dt.astimezone(timezone(timedelta(hours=1)))
            time_local = tng.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            time_local = "—"

        # The four button URLs.
        dashboard_url = f"{settings.triage_dashboard_url.rstrip('/')}/dashboard/alert/{short_id}"
        rate_url = f"{settings.triage_dashboard_url.rstrip('/')}/dashboard/alert/{short_id}/rate"
        grafana_url = alert.generatorURL or settings.grafana_url
        loki_url = settings.loki_url
        # jaeger_url = settings.jaeger_url  # not in the 4-button row per design

        # The 3 mid blocks.
        reason_html = _html.escape((decision.rca or decision.reason or "No RCA prose recorded.").strip())
        # Truncate to first sentence + bold the component name inline.
        end = reason_html.find(". ")
        reason_short = reason_html[: end + 1] if end > 0 and end < 260 else reason_html[:260]
        if component and component != "—" and component in reason_short:
            bold = f'<strong style="color:#e8dca0;font-family:JetBrains Mono,monospace;font-weight:600">{_html.escape(component)}</strong>'
            reason_short = reason_short.replace(_html.escape(component), bold, 1)

        # First suggested action only — design shows one inline + says "more on detail page".
        action_cmd = "—"
        if decision.suggested_actions:
            first = decision.suggested_actions[0]
            action_cmd = first if isinstance(first, str) else first.get("cmd", str(first))
        action_cmd_html = _html.escape(action_cmd)

        # Pill helpers — inline-styled to match the design palette.
        def _pill(text: str, color: str, bg: str = None) -> str:
            bg = bg or f"rgba(0,0,0,0)"
            return (f'<span style="display:inline-block;font-size:11px;font-weight:600;'
                    f'padding:4px 10px;border-radius:12px;border:1px solid {color};'
                    f'color:{color};background:{bg};letter-spacing:.2px">{_html.escape(text)}</span>')

        env_colors = {
            "prod": "#e06070", "preprod": "#f0a050", "stg": "#f0a050",
            "uat": "#4ea8de", "int": "#4ea8de", "dev": "#8890a0",
        }
        verdict_colors = {
            "ESCALATE": "#e06070", "DISMISS": "#8890a0",
            "SHELVED": "#f0a050", "PENDING": "#4ea8de",
        }
        severity_colors = {"critical": "#e06070", "warning": "#f0a050", "info": "#4ea8de"}

        env_pill = _pill(env, env_colors.get(env, "#8890a0"), bg=f"rgba(224,96,112,.08)" if env == "prod" else "rgba(136,144,160,.06)")
        ns_pill = _pill(ns, "#8890a0", bg="rgba(136,144,160,.06)")
        svc_pill = _pill(svc_type, "#8890a0", bg="rgba(136,144,160,.06)")
        comp_pill = _pill(component, "#8890a0", bg="rgba(136,144,160,.06)")
        verdict_pill = _pill(verdict, verdict_colors.get(verdict, "#8890a0"), bg=f"rgba(224,96,112,.08)" if verdict == "ESCALATE" else "rgba(136,144,160,.06)")
        severity_pill = _pill(severity, severity_colors.get(severity, "#8890a0"), bg="rgba(240,160,80,.08)" if severity == "warning" else "rgba(224,96,112,.08)" if severity == "critical" else "rgba(78,168,222,.08)")

        active_for_str = "active fire"  # SF-6 placeholder; real value needs history aggregation

        # Three EmailBlocks — Why / Suggested action / Severity. Use 100% width
        # tables for email-client layout (grid/flex inconsistent across clients).
        body_html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_html.escape(self._v2_subject(alert, decision, record))}</title>
</head>
<body style="margin:0;padding:0;background:#0a0b0f;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;color:#e4e6ee">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#0a0b0f">
  <tr><td align="center" style="padding:24px 16px">
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:680px;background:#0f1117;border-radius:14px;border:1px solid #2a2d3a;overflow:hidden">

    <tr><td style="padding:28px 30px 0">
      <!-- Banner -->
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:linear-gradient(180deg,rgba(224,96,112,.10),rgba(224,96,112,.02));border:1px solid rgba(224,96,112,.35);border-radius:12px;margin-bottom:22px"><tr><td style="padding:14px 18px">
        {verdict_pill} &nbsp; {severity_pill} &nbsp; <span style="font-size:12px;color:#8890a0">{active_for_str}</span>
      </td></tr></table>

      <!-- Identity pills -->
      <div style="margin-bottom:16px">
        {env_pill} {ns_pill} {svc_pill} {comp_pill}
      </div>

      <!-- WHAT -->
      <h1 style="margin:0 0 4px;font-size:24px;font-weight:600;color:#e4e6ee;line-height:1.3">{_html.escape(plain)}</h1>
      <div style="font-size:12.5px;color:#8890a0;margin-bottom:20px">
        Alert <span style="font-family:JetBrains Mono,monospace;color:#c0c5d0">{_html.escape(short_id)}</span> · {_html.escape(time_local)} Tangier
      </div>

      <!-- Why block -->
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#1a1d27;border:1px solid #2a2d3a;border-radius:10px;margin-bottom:10px"><tr><td style="padding:12px 14px">
        <div style="font-size:10.5px;font-weight:600;color:#8890a0;text-transform:uppercase;letter-spacing:.1px;margin-bottom:6px">Why</div>
        <div style="font-size:14px;line-height:1.5;color:#e4e6ee">{reason_short}</div>
      </td></tr></table>

      <!-- Suggested action block -->
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#1a1d27;border:1px solid #2a2d3a;border-radius:10px;margin-bottom:22px"><tr><td style="padding:12px 14px">
        <div style="font-size:10.5px;font-weight:600;color:#8890a0;text-transform:uppercase;letter-spacing:.1px;margin-bottom:6px">Suggested action</div>
        <div style="background:#0a0c11;border:1px solid #2a2d3a;border-radius:6px;padding:8px 10px;font-family:JetBrains Mono,monospace;font-size:12px;color:#e4e6ee;word-break:break-all">
          <span style="color:#40d0d0">$</span> {action_cmd_html}
        </div>
      </td></tr></table>

      <!-- Buttons row -->
      <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
        <td style="padding-right:8px"><a href="{_html.escape(dashboard_url)}" style="display:inline-block;padding:9px 14px;border-radius:8px;font-size:13px;font-weight:500;background:rgba(78,168,222,.18);border:1px solid rgba(78,168,222,.45);color:#b9dcf2;text-decoration:none">View on dashboard →</a></td>
        <td style="padding-right:8px"><a href="{_html.escape(grafana_url)}" style="display:inline-block;padding:9px 14px;border-radius:8px;font-size:13px;font-weight:500;background:#1a1d27;border:1px solid #2a2d3a;color:#e4e6ee;text-decoration:none">Open Grafana ↗</a></td>
        <td style="padding-right:8px"><a href="{_html.escape(loki_url)}" style="display:inline-block;padding:9px 14px;border-radius:8px;font-size:13px;font-weight:500;background:#1a1d27;border:1px solid #2a2d3a;color:#e4e6ee;text-decoration:none">Open Loki ↗</a></td>
        <td><a href="{_html.escape(rate_url)}" style="display:inline-block;padding:9px 14px;border-radius:8px;font-size:13px;font-weight:500;background:#1a1d27;border:1px solid #2a2d3a;color:#e4e6ee;text-decoration:none">Rate this alert</a></td>
      </tr></table>

      <!-- Footer -->
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-top:22px;padding-top:14px;border-top:1px solid #2a2d3a"><tr>
        <td style="font-size:11.5px;color:#5b6172;line-height:1.6">
          Alert <span style="font-family:JetBrains Mono,monospace">{_html.escape(full_id)}</span> · {_html.escape(time_local)} Tangier (UTC+01:00)
        </td>
        <td align="right" style="font-size:11.5px;color:#5b6172">
          AI RCA Triage Platform <span style="font-family:JetBrains Mono,monospace">v0.1.0</span>
        </td>
      </tr></table>

    </td></tr>
    <tr><td style="height:24px"></td></tr>
  </table>
  </td></tr>
</table>
</body></html>"""
        return body_html

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
