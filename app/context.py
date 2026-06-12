import asyncio
import logging
import re as _re
import time
from datetime import datetime, timezone

import httpx

from app.config import settings
from app.metrics import triage_mcp_duration_seconds, triage_mcp_requests_total
from app.models import GatheredContext, GrafanaAlert

logger = logging.getLogger(__name__)


class MCPQueryRejected(Exception):
    """Raised when an MCP tool call returns a 4xx — i.e. the LLM/pipeline
    issued a malformed or invalid query (bad PromQL/LogQL, unknown param),
    NOT a source outage. Carries the upstream status + a truncated detail so
    the prompt can tell the model "your query was rejected" rather than the
    misleading "source unavailable" (a 4xx and a 5xx previously surfaced
    identically — misc.md issue 6 / task #3).
    """

    def __init__(self, server: str, status: int, detail: str = ""):
        self.server = server
        self.status = status
        self.detail = (detail or "")[:300]
        super().__init__(f"{server} query rejected (HTTP {status}): {self.detail}")


def _mcp_error_label(source: str, exc: BaseException) -> str:
    """Build the context-error line for a failed pillar fetch, distinguishing
    a query rejection (4xx — the query was bad) from a source outage
    (5xx / connection — the source is down). The triage prompt renders these
    so the LLM can tell "fix your query" from "this source has no data."
    """
    if isinstance(exc, MCPQueryRejected):
        return (
            f"[{source}] query rejected (HTTP {exc.status}): {exc.detail} "
            f"— the source is reachable but the query was invalid; "
            f"do not conclude {source} is down."
        )
    return f"[{source}] unavailable: {exc}"


def _parse_alert_time(alert_time: str) -> float | None:
    """Parse an ISO 8601 alert startsAt string to epoch seconds (float).

    Returns None if the input is empty, malformed, or in the future. The
    caller should fall back to relative-window behaviour ('Xm' / 'now') so
    that a bad timestamp never blocks context gathering.
    """
    if not alert_time:
        return None
    try:
        # fromisoformat accepts '+00:00' but not the trailing 'Z' until 3.11.
        normalized = alert_time.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        epoch = dt.timestamp()
        # Future timestamps (NTP skew, replay with a bogus startsAt) → fall back.
        if epoch > time.time() + 60:
            return None
        return epoch
    except (ValueError, TypeError):
        return None


def _prom_result_empty(data) -> bool:
    """True if a Prometheus MCP response carries no series.

    The MCP server passes the Prometheus JSON through largely unchanged, so
    a populated response looks like `{"status":"success","data":{"result":[...]}}`
    and an empty one has `result: []`. Be generous about the shape: we've
    also seen the MCP return a raw list or a plain `{"result":[]}` wrapper.
    """
    if not data:
        return True
    if isinstance(data, list):
        return len(data) == 0
    if isinstance(data, dict):
        # {"data": {"result": [...]}} — standard Prom wrapper
        inner = data.get("data", data)
        if isinstance(inner, dict):
            result = inner.get("result")
            if result is None:
                return False  # unknown shape — don't second-guess, treat as non-empty
            return len(result) == 0
    return False


# Kubernetes workload alerts (2026-06-10 stress-test finding) -----------------
# KubeWorkloadDown / KubeWorkloadReplicasDeficit / PodCrashLooping carry their
# root cause in kube-state-metrics + pod phase, NOT in app metrics/logs/traces.
# The default service-scoped `{job=~".*<svc>.*"}` Prometheus query matches no
# series for these, so the LLM saw an empty context and hedged "cannot
# determine" — which the shelved-in-disguise gate then suppressed, so a
# genuinely-down critical workload never paged. Query the deployment's replica
# counts, namespace pod phase, and last-terminated reason instead, so the model
# gets real evidence (0/N available, pod Pending/unschedulable, OOMKilled) and
# can name the cause. kube-state-metrics labels (verified live): `deployment`,
# `exported_namespace`, `exported_pod`, `phase`.
_KUBE_WORKLOAD_ALERTS = {
    "PodCrashLooping", "PodHighMemoryUsage", "PodHighCpuUsage",
    "KubeContainerRestarting", "KubePodNotReady",
}


def _is_kube_workload_alert(alert) -> bool:
    name = alert.alertname or ""
    return name.startswith("Kube") or name in _KUBE_WORKLOAD_ALERTS


# Fix F (2026-06-11): deploy-bridge check ------------------------------------
# Until today the platform had NO deploy data source, so a deploy-as-cause
# RCA could only ever be fabricated (one shipped; the validator now rejects
# ungrounded deploy claims). The deploy MCP (:8096) derives rollouts from
# kube-state-metrics series already in Prometheus. For the two alert classes
# where "did someone just deploy?" is a live question — kube-workload alerts
# and Drain3 log-novelty alerts — we make ONE extra MCP call scoped to the
# alert's namespace+service and render the answer deterministically. Both
# directions are evidence: a rollout minutes before the alert is a groundable
# cause candidate; an empty answer RULES deploy-regression OUT.
_DEPLOY_CHECK_WINDOW = "2h"


def _is_deploy_check_alert(alert) -> bool:
    return _is_kube_workload_alert(alert) or (alert.alertname or "") == "Drain3AnomalyDetected"


def _fmt_minutes(minutes: float) -> str:
    """'14 min' below 2h, '3.2 h' above — keeps the prompt line readable."""
    if minutes >= 120:
        return f"{minutes / 60:.1f} h"
    return f"{minutes:.0f} min"


def _summarize_recent_deploys(
    deploys, service: str, alert_epoch: float | None
) -> str | None:
    """Deterministically render the deploy bridge's answer in plain English.

    `deploys` is the /tools/recent_deploys JSON: a list of rollout records
    (newest RS per deployment inside the window), [] meaning "nothing rolled".
    Returns None only on an unusable shape — an EMPTY list is a meaningful
    grounded negative and gets its own sentence.
    """
    if not isinstance(deploys, list):
        return None
    if not deploys:
        return (
            f"No deploys of {service} in the last {_DEPLOY_CHECK_WINDOW} — "
            "deploy-regression can be RULED OUT as the cause."
        )
    lines = []
    for d in deploys[:3]:
        if not isinstance(d, dict):
            continue
        deployment = d.get("deployment", service)
        replicaset = d.get("replicaset", "?")
        rollout_epoch = _parse_alert_time(d.get("rollout_time_iso", ""))
        age_minutes = d.get("age_minutes")
        if alert_epoch is not None and rollout_epoch is not None:
            delta_min = (alert_epoch - rollout_epoch) / 60
            if delta_min >= 0:
                when = f"rolled {_fmt_minutes(delta_min)} before this alert"
            else:
                when = (
                    f"rolled {_fmt_minutes(-delta_min)} AFTER this alert fired "
                    "(cannot have caused it)"
                )
        elif isinstance(age_minutes, (int, float)):
            when = f"rolled {_fmt_minutes(age_minutes)} ago"
        else:
            when = "rolled recently"
        line = f"Recent rollout: deployment {deployment} {when} (replicaset {replicaset}"
        prior = d.get("prior_replicaset")
        prior_age = d.get("prior_replicaset_age_minutes")
        if prior and isinstance(prior_age, (int, float)):
            line += f", replacing {prior} which had run {_fmt_minutes(prior_age)}"
        line += ")."
        lines.append(line)
    return "\n".join(lines) if lines else None


def _summarize_kube_workload_state(data: dict | None, service: str) -> str | None:
    """Deterministically pre-interpret the kube-state context result into
    plain-English facts (2026-06-10 iteration 5).

    The raw query_range JSON demonstrably does NOT work as prompt evidence:
    with available=0/unavailable=1/phase=Pending sitting in `### Metrics`,
    the 14b still wrote "Prometheus does not show any anomalous metric
    values" (decisions 13b15c81/1b177fa4 — the induced ad outage). The model
    can read a categorical smoking gun (reason="OOMKilled" was named at 0.95
    first-pass) but does not infer 'available=0 means the workload is down'
    from numeric series. Same lesson as the metric interpreter (3.4) and the
    crash-loop digest: fixed-shape results get interpreted in code, and the
    model confirms rather than computes.

    Returns None when the result has no kube-state series (non-kube alerts,
    MCP miss) — the prompt then renders nothing extra.
    """
    if not isinstance(data, dict):
        return None
    series = data.get("result") or []
    if not isinstance(series, list):
        return None

    def _latest(s):
        vals = s.get("values") or ([s["value"]] if s.get("value") else [])
        if not vals:
            return None
        try:
            return float(vals[-1][1])
        except (TypeError, ValueError, IndexError):
            return None

    # 2026-06-11 (post-battery fix): pending/termination facts are SCOPED to
    # the alert's own service. The namespace-wide version let the model
    # borrow a NEIGHBOR's OOMKilled as this alert's cause — live decisions
    # 0e892b15/1dc8f6be named "ad is being OOMKilled" for an unschedulable
    # Pending outage while image-provider OOM-looped in the same namespace.
    # Cross-service context is reduced to a count with an explicit
    # do-not-attribute guard (no reason strings the model could copy).
    replicas: dict[str, float] = {}
    pending: list[str] = []
    terminations: list[str] = []
    other_pending = 0
    other_terminations = 0
    for s in series:
        if not isinstance(s, dict):
            continue
        m = s.get("metric") or {}
        v = _latest(s)
        if v is None:
            continue
        kpi = m.get("kpi")
        name = m.get("__name__", "")
        pod = m.get("exported_pod") or m.get("pod") or "?"
        mine = pod.startswith(service + "-") or pod == service
        if kpi in ("spec_replicas", "replicas_available", "replicas_unavailable"):
            replicas[kpi] = v
        elif name == "kube_pod_status_phase" and v >= 1:
            if mine:
                pending.append(f"{pod} phase={m.get('phase', '?')}")
            else:
                other_pending += 1
        elif name == "kube_pod_container_status_last_terminated_reason" and v >= 1:
            if mine:
                terminations.append(f"{pod}: {m.get('reason', '?')}")
            else:
                other_terminations += 1

    if not (replicas or pending or terminations):
        return None

    lines: list[str] = []
    if replicas:
        spec = replicas.get("spec_replicas")
        avail = replicas.get("replicas_available")
        unavail = replicas.get("replicas_unavailable")
        state = (
            f"Deployment {service}: spec={spec:.0f}" if spec is not None else f"Deployment {service}:"
        )
        if avail is not None:
            state += f", available={avail:.0f}"
        if unavail is not None:
            state += f", unavailable={unavail:.0f}"
        state += " (latest values)."
        if avail == 0 and (spec or 0) > 0:
            state += (
                f" => {service} currently has ZERO available replicas — the workload IS down;"
                " that is the alert's mechanism, not 'insufficient data'."
            )
        lines.append(state)
    if pending:
        line = (
            f"Non-running pods of {service}: " + "; ".join(sorted(set(pending))[:6])
            + ". A Pending pod that never schedules (e.g. unsatisfiable nodeSelector/"
            "resources) keeps the deployment at 0 available."
        )
        if not terminations:
            # 2026-06-11: explicit negative — with clean history and scoped
            # evidence the model STILL guessed "likely OOMKilled" for a
            # Pending outage (decision 66c98bcc); OOM is its generic-bias
            # answer for k8s unavailability, so rule it out in words when
            # the evidence rules it out.
            line += (
                f" => READY VERDICT: {service} is down because its pod cannot be "
                "SCHEDULED (Pending) — a placement/configuration problem (node "
                "selector, resources, taints). It is NOT a crash and NOT OOM: "
                f"{service}'s pods have ZERO recent terminations. Do not mention "
                "OOM or memory limits in your cause."
            )
        lines.append(line)
    if terminations:
        lines.append(
            f"Recent container terminations of {service} (last_terminated_reason): "
            + "; ".join(sorted(set(terminations))[:6]) + "."
        )
    if not terminations and not pending and replicas.get("replicas_available") == 0:
        lines.append(
            f"No termination or non-running-pod evidence for {service}'s own pods in "
            "the window — if the deployment is unavailable, suspect rollout/scheduling "
            "(pod replaced or never started) rather than crashes."
        )
    if other_pending or other_terminations:
        lines.append(
            f"(Context only — OTHER services in this namespace: {other_pending} "
            f"non-running pod(s), {other_terminations} recent termination(s). These "
            f"belong to OTHER workloads — do NOT attribute their failure modes to "
            f"{service}.)"
        )
    return "\n".join(lines)


def _kube_state_promql(service: str, namespace: str) -> str:
    """Build a kube-state-metrics PromQL union for a workload alert. Returns the
    deployment's desired/available/unavailable replica counts plus, when the
    namespace is known, any non-Running pods and recent container termination
    reasons in that namespace."""
    d = f'deployment="{service}"'
    # 2026-06-10 (iteration 4): the three kube_deployment_* series carry
    # IDENTICAL label sets — they differ only in __name__, which PromQL set
    # operators ignore when matching — so a bare `A or B or C` union
    # COLLAPSES to spec_replicas alone. Live proof: for the induced ad
    # outage the context returned only spec_replicas=1; the decisive
    # available=0 / unavailable=1 never reached the prompt and the RCA
    # hedged (decisions c1b11a03/79c43dd6). Same bug class as the
    # `or vector(80)` label-loss of 2026-06-03 (blocker A2). label_replace
    # with an empty source label mints a discriminator label per part, so
    # the label sets differ and the union keeps all three.
    parts = [
        f'label_replace(kube_deployment_spec_replicas{{{d}}}, "kpi", "spec_replicas", "", "")',
        f'label_replace(kube_deployment_status_replicas_available{{{d}}}, "kpi", "replicas_available", "", "")',
        f'label_replace(kube_deployment_status_replicas_unavailable{{{d}}}, "kpi", "replicas_unavailable", "", "")',
    ]
    if namespace and namespace != "unknown":
        ns = f'exported_namespace="{namespace}"'
        parts.append(f'kube_pod_status_phase{{{ns},phase=~"Pending|Failed|Unknown"}} > 0')
        parts.append(f"kube_pod_container_status_last_terminated_reason{{{ns}}} > 0")
    return " or ".join(parts)


# S3-HF-07 PII sanitizer ------------------------------------------------------
# Span `db.statement` tags can include literal parameter values, e.g.
#   WHERE customer_id = 12345 AND email = 'lina@…' AND created_at > '2026-04-12'
# We never want raw values in the LLM prompt. Replace single-quoted literals
# and bare numeric literals with `?` so the LLM sees the query shape but not
# the data. This matches the conservative approach used by ORMs producing
# parameterised SQL.

_SQL_QUOTED_LITERAL = _re.compile(r"'(?:[^']|'')*'")
_SQL_NUMERIC_LITERAL = _re.compile(r"(?<![A-Za-z_0-9])-?\d+(?:\.\d+)?")


def _sanitize_db_statement(stmt: str) -> str:
    """Replace literal parameter values in a SQL statement with `?`."""
    if not stmt or not isinstance(stmt, str):
        return stmt
    stripped = _SQL_QUOTED_LITERAL.sub("?", stmt)
    stripped = _SQL_NUMERIC_LITERAL.sub("?", stripped)
    return stripped


def _sanitize_deep_trace(trace: dict) -> dict:
    """Walk a /tools/get_trace response and sanitize sensitive tag values.

    Targets: `db.statement` (SQL with literals), `http.target` (may contain
    user IDs in path). Leaves structural fields (span_id, operation,
    duration_ms, parent_span_id, error) intact so the LLM still sees the
    shape of the request.
    """
    if not isinstance(trace, dict):
        return trace
    out = dict(trace)
    sanitized_spans = []
    for span in out.get("spans", []) or []:
        if not isinstance(span, dict):
            sanitized_spans.append(span)
            continue
        span_copy = dict(span)
        tags = dict(span_copy.get("tags", {}) or {})
        if "db.statement" in tags:
            tags["db.statement"] = _sanitize_db_statement(tags["db.statement"])
        if "http.target" in tags and isinstance(tags["http.target"], str):
            # Replace numeric path segments (likely IDs) with `:id`.
            tags["http.target"] = _re.sub(r"/\d+", "/:id", tags["http.target"])
        span_copy["tags"] = tags
        sanitized_spans.append(span_copy)
    out["spans"] = sanitized_spans
    return out


# 2026-06-12 (Lina: "traces must be DECISIVE evidence for latency — name the
# downstream culprit"). A real otel-demo frontend trace serializes to ~13-15K
# chars across 16-21 spans in trace-TREE order (root frontend-proxy/frontend
# spans first, deep downstream spans like product-catalog/recommendation
# last). _cap_json caps the prompt render at 6000 chars, so the FIRST ~8
# spans survive — all frontend/proxy — and the slow DOWNSTREAM span gets
# truncated out entirely. The model then only ever sees "frontend is slow",
# restates the alert, and the validator demotes it to data_starved. That is
# the bug behind every missing trace-decisive RCA.
#
# Fix: before rendering, (a) sort spans by duration DESC so the slowest span
# is first and always survives the cap, (b) slim each span to the
# load-bearing fields so the whole ranked breakdown fits well under the cap.
# We keep the raw-tree intact in sanitize; this is purely the prompt view.
_DEEP_TRACE_TOP_SPANS = 15
_SPAN_KEEP_FIELDS = (
    "service", "operation", "duration_ms", "status_code", "error",
    "parent_span_id", "span_id",
)
# Tag keys worth surfacing to the LLM (already PII-sanitized in sanitize):
# they name WHAT the slow span was doing (a SQL statement, an HTTP target,
# a gRPC method, an error message).
_SPAN_KEEP_TAGS = (
    "db.statement", "db.system", "http.target", "http.method",
    "rpc.method", "rpc.service", "error.message", "exception.message",
)


def _compact_deep_trace(trace: dict) -> dict:
    """Rank-and-slim a sanitized deep trace for the LLM prompt.

    Returns a dict with spans sorted by duration_ms DESC, trimmed to the
    top-N, each span reduced to load-bearing fields + a small set of
    descriptive tags. Guarantees the slowest (usually downstream) span is
    first so it survives the prompt's char cap — the whole point: the model
    must be able to NAME the downstream culprit span, not just the root.
    """
    if not isinstance(trace, dict):
        return trace
    spans = [s for s in (trace.get("spans") or []) if isinstance(s, dict)]
    spans_sorted = sorted(
        spans, key=lambda s: s.get("duration_ms", 0) or 0, reverse=True
    )
    slim = []
    for s in spans_sorted[:_DEEP_TRACE_TOP_SPANS]:
        row = {k: s[k] for k in _SPAN_KEEP_FIELDS if k in s}
        tags = s.get("tags", {}) or {}
        kept_tags = {k: tags[k] for k in _SPAN_KEEP_TAGS if k in tags}
        if kept_tags:
            row["tags"] = kept_tags
        slim.append(row)
    out = {
        "trace_id": trace.get("trace_id"),
        "span_count": trace.get("span_count", len(spans)),
        "spans_shown": len(slim),
        "spans": slim,
    }
    return out


# Services that are the alert's OWN request-entry tier, not a downstream
# dependency. The frontend latency alert names "frontend"; frontend-proxy and
# the Next.js frontend itself are that same edge — the operator already knows
# the edge is slow (that's the alert). The decisive evidence is the slowest
# span in a DIFFERENT service. For the otel-demo edge that's frontend /
# frontend-proxy / load-generator; callers can extend via `own_services`.
_EDGE_TIER_SERVICES = {"frontend", "frontend-proxy", "load-generator"}


def _deep_trace_summary(trace: dict, own_services: set | None = None) -> str:
    """One deterministic ranked line: the slowest span, its service, and its
    share of the trace's wall-clock — handed to the LLM so it can't miss the
    downstream culprit even if it skims the JSON.

    Names BOTH the slowest span overall AND the slowest span belonging to a
    service OUTSIDE the alert's own edge tier — i.e. the downstream dependency
    the alert name doesn't mention. That second clause is the whole point of
    trace-decisive RCA.

    Example: "Slowest span: frontend-proxy ingress 1320ms (100% of 1320ms
    trace wall-clock). Slowest downstream dependency: product-catalog
    GetProduct 1030ms (78%)."
    """
    if not isinstance(trace, dict):
        return ""
    spans = [s for s in (trace.get("spans") or []) if isinstance(s, dict)]
    if not spans:
        return ""
    edge = _EDGE_TIER_SERVICES | (own_services or set())
    by_dur = sorted(spans, key=lambda s: s.get("duration_ms", 0) or 0, reverse=True)
    total = max((s.get("duration_ms", 0) or 0) for s in spans) or 0
    top = by_dur[0]
    top_dur = top.get("duration_ms", 0) or 0
    pct = f"{(top_dur / total * 100):.0f}%" if total else "?"
    parts = [
        f"Slowest span: {top.get('service','?')} {(top.get('operation') or '')[:60]} "
        f"{top_dur:.0f}ms ({pct} of {total:.0f}ms trace wall-clock)."
    ]
    # Slowest span in a service OUTSIDE the edge tier — the downstream culprit.
    for s in by_dur:
        if s.get("service") not in edge:
            d = s.get("duration_ms", 0) or 0
            dpct = f"{(d / total * 100):.0f}%" if total else "?"
            parts.append(
                f" Slowest downstream dependency: {s.get('service','?')} "
                f"{(s.get('operation') or '')[:50]} {d:.0f}ms ({dpct})."
            )
            break
    return "".join(parts)


def _absolute_window(alert_epoch: float, window_minutes: int) -> tuple[float, float]:
    """Build an absolute context window anchored on the alert's startsAt.

    Skewed slightly before the alert (metrics + logs from 'a little before')
    but includes a small look-ahead too so fast-moving incidents aren't
    clipped. Both bounds are clamped to <= now (Prometheus/Loki/Jaeger do
    not return future data anyway, but being explicit avoids confusing
    error surfaces from the MCPs).

    For a 10-minute window: [alert_time - 8min, alert_time + 2min],
    clamped to now.
    """
    lookahead_seconds = 2 * 60
    lookbehind_seconds = max(0, (window_minutes - 2) * 60)
    now = time.time()
    start = alert_epoch - lookbehind_seconds
    end = min(alert_epoch + lookahead_seconds, now)
    return start, end


class ContextGatherer:
    def __init__(self):
        self._client = httpx.AsyncClient(timeout=settings.context_timeout)

    async def close(self):
        await self._client.aclose()

    async def gather(
        self, alert: GrafanaAlert
    ) -> GatheredContext:
        """Gather context from all three pillars in parallel.

        If alert.startsAt (Grafana startsAt) parses cleanly, all three pillars
        share an absolute time window anchored on the alert itself. This
        is the correlation guarantee — metrics/logs/traces for the alert's
        timeframe, not for whenever the LLM happens to wake up.

        We pass the full alert down to each pillar fetch so fallback queries
        can key on alert.instance or alert.annotations.expr when service-scoped
        queries return nothing (which is the common case for node-level alerts
        like HighCpuUsage where `service=k3s-node` matches no `job=~".*k3s-node.*"` series).
        """
        start = time.monotonic()
        alert_epoch = _parse_alert_time(alert.startsAt)
        abs_window = (
            _absolute_window(alert_epoch, settings.prometheus_range_minutes)
            if alert_epoch is not None
            else None
        )

        prom_task = self._fetch_prometheus(alert, abs_window)
        loki_task = self._fetch_loki(alert, abs_window)
        jaeger_task = self._fetch_jaeger(alert, abs_window)

        results = await asyncio.gather(
            prom_task, loki_task, jaeger_task, return_exceptions=True
        )

        total_ms = int((time.monotonic() - start) * 1000)

        ctx = GatheredContext(total_ms=total_ms)
        errors = []

        if isinstance(results[0], Exception):
            errors.append(_mcp_error_label("Prometheus", results[0]))
            ctx.prometheus_ms = settings.context_timeout * 1000
        else:
            ctx.metrics, ctx.prometheus_ms = results[0]
            ctx.sources_available += 1
            if _is_kube_workload_alert(alert):
                ctx.kube_workload_summary = _summarize_kube_workload_state(
                    ctx.metrics, alert.service
                )

        if isinstance(results[1], Exception):
            errors.append(_mcp_error_label("Loki", results[1]))
            ctx.loki_ms = settings.context_timeout * 1000
        else:
            ctx.logs, ctx.loki_ms, ctx.loki_is_fallback = results[1]
            ctx.sources_available += 1

        if isinstance(results[2], Exception):
            errors.append(_mcp_error_label("Jaeger", results[2]))
            ctx.jaeger_ms = settings.context_timeout * 1000
        else:
            ctx.traces, ctx.jaeger_ms = results[2]
            ctx.sources_available += 1

            # S3-HF-07: deep-trace gather. One additional MCP call to drill
            # into per-span attributes of the slowest trace, gated on alert
            # archetype + trace duration. Non-fatal if it fails; the
            # first-pass RCA still ships.
            #
            # /tools/find_traces returns either a list directly OR a wrapper
            # dict like {"traces": [...], "count": N} depending on MCP
            # version — unwrap defensively so the gate sees the list.
            traces_list = (
                ctx.traces.get("traces", []) if isinstance(ctx.traces, dict)
                else (ctx.traces or [])
            )
            if self._should_fetch_deep_trace(alert, traces_list):
                trace_id = self._pick_slowest_trace_id(traces_list)
                if trace_id:
                    deep, deep_ms = await self._fetch_deep_trace(trace_id)
                    ctx.deep_trace = deep
                    ctx.deep_trace_ms = deep_ms
                    if deep:
                        ctx.deep_trace_summary = _deep_trace_summary(
                            deep, own_services={alert.service} if alert.service else None
                        )

        # Fix F (2026-06-11): ONE extra MCP call to the deploy bridge for
        # kube-workload + Drain3 alerts — "did someone just deploy this
        # service?" answered from real kube-state-metrics rollout data,
        # through the bridge (MCP-only invariant), never Prometheus directly.
        # Non-fatal: a bridge miss just means no deploy line in the prompt,
        # and the validator keeps rejecting ungrounded deploy claims.
        if _is_deploy_check_alert(alert) and alert.service and alert.service != "unknown":
            try:
                deploys, deploy_ms = await self._fetch_recent_deploys(alert)
                ctx.recent_deploys_summary = _summarize_recent_deploys(
                    deploys, alert.service, alert_epoch
                )
                ctx.total_ms += deploy_ms
            except Exception as exc:
                logger.warning("Deploy bridge check failed (non-fatal): %s", exc)

        ctx.errors = errors

        window_desc = (
            f"abs [{abs_window[0]:.0f},{abs_window[1]:.0f}]"
            if abs_window
            else f"rel last {settings.prometheus_range_minutes}m"
        )
        logger.info(
            "Context gathered: prometheus=%dms loki=%dms jaeger=%dms total=%dms sources=%d window=%s",
            ctx.prometheus_ms,
            ctx.loki_ms,
            ctx.jaeger_ms,
            ctx.total_ms,
            ctx.sources_available,
            window_desc,
        )
        # 2026-06-12 (Lina: "baseline must include ALL correlated data — accurate
        # from the start"). One explicit completeness line per investigation so
        # it is VISIBLE whether pass #1 had the full correlated picture, rather
        # than a silent missing pillar.
        _has_metrics = (not _prom_result_empty(ctx.metrics)) if ctx.metrics else False
        # Count RAW logs too, not just the drain3-annotated subset — the model
        # reasons over both, so an "annotated-only" check undercounts (2026-06-12
        # live: a latency RCA cross-referenced frontend error logs that this line
        # had reported as logs=False because they weren't drain3-annotated).
        _has_logs = bool(ctx.annotated_logs) or bool(ctx.logs)
        _trace_list = (
            ctx.traces.get("traces", []) if isinstance(ctx.traces, dict)
            else (ctx.traces or [])
        )
        _deep_n = len((ctx.deep_trace or {}).get("spans", [])) if ctx.deep_trace else 0
        logger.info(
            "Investigation completeness for %s/%s: metrics=%s logs=%s traces=%s "
            "deep_trace=%s spans=%d",
            alert.alertname, alert.service,
            _has_metrics, _has_logs, bool(_trace_list),
            bool(ctx.deep_trace), _deep_n,
        )
        return ctx

    async def _fetch_prometheus(
        self, alert: GrafanaAlert, abs_window: tuple[float, float] | None
    ) -> tuple[dict, int]:
        """Query Prometheus with service-scoped PromQL, fall back to:
          1) the rule's own PromQL expression (from annotations.expr) — authoritative,
          2) an instance-scoped query (useful for node-level alerts), if we have one.

        The primary `{job=~".*<service>.*"}` query matches nothing for service
        labels like `k3s-node` or `monitoring` since those aren't job values —
        that's the case that previously produced "insufficient data" RCAs.
        """
        service = alert.service
        # Kube workload alerts: query kube-state-metrics for the deployment
        # instead of the (always-empty) service-job match, so the LLM sees the
        # replica deficit / pod phase that actually explains the alert.
        if _is_kube_workload_alert(alert):
            primary_promql = _kube_state_promql(service, alert.labels.get("namespace", ""))
        else:
            primary_promql = f'{{job=~".*{service}.*"}}'
        primary = {
            "promql": primary_promql,
            "step": "60s",
        }
        if abs_window:
            primary["start"] = f"{abs_window[0]:.3f}"
            primary["end"] = f"{abs_window[1]:.3f}"
        else:
            primary["start"] = f"{settings.prometheus_range_minutes}m"
            primary["end"] = "now"

        data, ms = await self._mcp_call(
            server="prometheus",
            url=f"{settings.prometheus_mcp_url}/tools/query_range",
            params=primary,
        )

        if _prom_result_empty(data):
            # Try the rule's own PromQL first — it's exactly what Grafana
            # evaluated, so we know it returns a value when the alert fires.
            fallback_promql = alert.annotations.get("expr", "").strip()
            if not fallback_promql and alert.instance and alert.instance != "unknown":
                # Instance-scoped fallback for node-level alerts that don't carry
                # an `expr` annotation yet.
                fallback_promql = f'{{instance="{alert.instance}"}}'
            if fallback_promql:
                fb_params = dict(primary, promql=fallback_promql)
                logger.info(
                    "Prometheus primary empty for service=%s — falling back to %r",
                    service, fallback_promql[:80],
                )
                fb_data, fb_ms = await self._mcp_call(
                    server="prometheus",
                    url=f"{settings.prometheus_mcp_url}/tools/query_range",
                    params=fb_params,
                )
                if not _prom_result_empty(fb_data):
                    return fb_data, ms + fb_ms
                # Fallback also empty — return primary (the LLM prompt will
                # note the miss rather than hallucinate).
        return data, ms

    async def _fetch_recent_deploys(self, alert: GrafanaAlert) -> tuple[list, int]:
        """Ask the deploy MCP for rollouts of this alert's service (Fix F).

        Scoped to the alert's namespace + service over a fixed 2h lookback.
        Returns the bridge's JSON list (possibly empty — a meaningful
        grounded negative) plus elapsed ms. Raises on bridge failure; the
        caller treats that as non-fatal.
        """
        params = {
            "namespace": alert.labels.get("namespace", ""),
            "service": alert.service,
            "window": _DEPLOY_CHECK_WINDOW,
        }
        return await self._mcp_call(
            server="deploy",
            url=f"{settings.deploy_mcp_url}/tools/recent_deploys",
            params=params,
        )

    async def _fetch_loki(
        self, alert: GrafanaAlert, abs_window: tuple[float, float] | None
    ) -> tuple[list[str], int, bool]:
        """Query Loki with service-scoped logs, with a narrow fallback only
        when the alert is genuinely about logs.

        Returns (lines, duration_ms, is_fallback). The caller uses `is_fallback`
        to label the prompt section — ambient logs get flagged as "NOT alert-
        specific" so the LLM treats them as background, not evidence. Earlier
        iterations fell back unconditionally, which caused a small model to
        misread any-service log volume as the alert's observed metric.

        Fallback is gated on signal=log (alert is specifically about log
        flow, e.g. LokiIngestionRateLow) — metric-signal alerts don't benefit
        from random ambient log lines and get hurt by the noise.
        """
        service = alert.service
        signal = alert.labels.get("signal", "")
        primary = {
            "logql": f'{{service_name="{service}"}}',
            "limit": settings.loki_log_limit,
        }
        if abs_window:
            primary["start"] = str(int(abs_window[0] * 1_000_000_000))
            primary["end"] = str(int(abs_window[1] * 1_000_000_000))
        else:
            primary["start"] = f"{settings.prometheus_range_minutes}m"
            primary["end"] = "now"

        data, ms = await self._mcp_call(
            server="loki",
            url=f"{settings.loki_mcp_url}/tools/query_logs",
            params=primary,
        )
        lines = data if isinstance(data, list) else data.get("lines", [])

        if not lines and signal == "log":
            # Only log-signal alerts benefit from ambient fallback — e.g.
            # LokiIngestionRateLow where "any logs at all?" is the question.
            fb_params = dict(primary)
            fb_params["logql"] = '{service_name=~".+"}'
            fb_params["limit"] = min(settings.loki_log_limit, 50)
            logger.info(
                "Loki primary empty for signal=log service=%s — falling back to any-service (limit=%d)",
                service, fb_params["limit"],
            )
            fb_data, fb_ms = await self._mcp_call(
                server="loki",
                url=f"{settings.loki_mcp_url}/tools/query_logs",
                params=fb_params,
            )
            fb_lines = fb_data if isinstance(fb_data, list) else fb_data.get("lines", [])
            if fb_lines:
                return fb_lines, ms + fb_ms, True
        return lines, ms, False

    # -------------------------------------------------------------------
    # S3-HF-07 (2026-05-19): Tier 1 deep trace gather
    #
    # When the alert is latency-flavoured AND `_fetch_jaeger` returned at
    # least one trace, we make one extra MCP call to /tools/get_trace on
    # the slowest trace and surface per-span attributes (db.statement,
    # http.target, error tags) to the LLM. Cost ceiling: exactly one
    # extra MCP roundtrip per qualifying alert, gated by alert-name
    # pattern so non-latency alerts (OOM, disk, target-down) skip it.
    #
    # PII: `db.statement` tags may contain literal parameter values
    # (e.g. `WHERE email = 'lina@…'`). We sanitize before injection via
    # _sanitize_db_statement so the LLM never sees the raw values.
    # -------------------------------------------------------------------

    _LATENCY_ALERTNAME_PATTERN = _re.compile(r"^.*P95Latency$|^.*ErrorRate$", _re.IGNORECASE)

    # 2026-06-12: lowered 500 -> 200ms. The 500ms floor was tuned against the
    # spring-boot/kong path (single-service, multi-second OOM-driven traces).
    # On the otel-demo microservice bed the REAL slow-but-successful traces
    # under an induced downstream fault (recommendationCacheFailure) sit
    # intermittently at ~200ms-1s — and the 10-trace find_traces SAMPLE often
    # catches only the sub-500ms ones in any given evaluation, so the gate
    # kept declining to drill even while a 1s trace existed seconds earlier
    # (live: HighDemoFrontendP95Latency fired with p95=9.9s but the sampled
    # slowest was 144ms, gate=False, no span breakdown). For an alert that is
    # ALREADY latency-flavoured and firing, a 200ms trace is well worth the
    # ONE extra non-fatal MCP roundtrip to surface the downstream span. Floor,
    # not zero, so a genuinely all-fast sample (healthy blip / false positive)
    # still skips the drill.
    _DEEP_TRACE_MIN_MS = 200

    def _should_fetch_deep_trace(self, alert: GrafanaAlert, traces: list[dict]) -> bool:
        """Decide whether the deep-trace MCP call is worth firing.

        Three gates: (a) the alertname matches the latency / error-rate
        pattern; (b) we have at least one trace from find_traces; (c) the
        slowest trace's duration is meaningful (>= _DEEP_TRACE_MIN_MS — very
        short traces rarely warrant a span breakdown).
        """
        if not traces:
            return False
        if not self._LATENCY_ALERTNAME_PATTERN.match(alert.alertname or ""):
            return False
        slowest = max(
            (t for t in traces if isinstance(t, dict)),
            key=lambda t: t.get("duration_ms", 0) or 0,
            default=None,
        )
        if slowest is None:
            return False
        return (slowest.get("duration_ms", 0) or 0) >= self._DEEP_TRACE_MIN_MS

    def _pick_slowest_trace_id(self, traces: list[dict]) -> str | None:
        candidates = [t for t in traces if isinstance(t, dict) and t.get("trace_id")]
        if not candidates:
            return None
        slowest = max(candidates, key=lambda t: t.get("duration_ms", 0) or 0)
        return slowest.get("trace_id")

    async def _fetch_deep_trace(self, trace_id: str) -> tuple[dict | None, int]:
        """Fetch full span detail for one trace via jaeger-mcp /tools/get_trace.

        Returns (sanitized_payload, elapsed_ms). On any failure returns
        (None, ms) — non-fatal; the first-pass RCA still ships.
        """
        try:
            data, ms = await self._mcp_call(
                server="jaeger",
                url=f"{settings.jaeger_mcp_url}/tools/get_trace",
                params={"trace_id": trace_id},
            )
        except Exception as exc:
            logger.debug("Deep trace fetch failed: %s", exc)
            return None, 0
        if not isinstance(data, dict) or data.get("error"):
            return None, ms
        # Sanitize (PII) THEN compact (rank+slim) so the slowest downstream
        # span survives the prompt char cap and the model can name it.
        return _compact_deep_trace(_sanitize_deep_trace(data)), ms

    async def _fetch_jaeger(
        self, alert: GrafanaAlert, abs_window: tuple[float, float] | None
    ) -> tuple[list[dict], int]:
        """Query Jaeger for traces. For node-level alerts (service=k3s-node,
        monitoring, loki, etc.) there are no traces — skip the call entirely
        to avoid a 500 ms wasted round-trip that always returns empty.
        """
        service = alert.service
        # 2026-06-12 (Lina: "investigate metrics, logs AND traces no matter
        # what — never guess"). This used to be a 3-service ALLOWLIST
        # (spring-boot/kong/otel-collector) that silently skipped Jaeger for
        # EVERY other service — including all 22 otel-demo services and the
        # employees-* app — so "traces are absent" was the CODE not querying,
        # and the model guessed a cause without trace evidence (live:
        # a69ac64a named a feature flag at 0.85 with "Jaeger traces absent").
        # Inverted to a DENYLIST of infra/node services that genuinely emit
        # no app traces; everything else IS queried. The Jaeger MCP returns
        # fast-empty when a service truly has none, so the only cost of a
        # false include is one ~100ms round-trip — far cheaper than a guess.
        from app.v2_mappings import is_infra_service
        _NON_TRACED = {
            "k3s-node", "monitoring", "monitoring-vm", "loki", "prometheus",
            "jaeger", "grafana", "node-exporter", "node_exporter", "cadvisor",
            "kube-state-metrics", "dcgm-exporter", "drain3", "ollama",
            "coredns", "host-syslog", "gpu-stack", "unknown",
        }
        if not service or service in _NON_TRACED or is_infra_service(service):
            return [], 0
        # The OTel service.name for the employees app is "spring-boot" even
        # though the operator-facing label is employees-backend — map back so
        # the Jaeger query hits the real trace stream.
        trace_service = "spring-boot" if service in ("employees-backend", "employees-gateway") else service

        params = {
            "service": trace_service,
            "limit": settings.jaeger_trace_limit,
        }
        if abs_window:
            params["start"] = str(int(abs_window[0] * 1_000_000))
            params["end"] = str(int(abs_window[1] * 1_000_000))
        else:
            params["start"] = f"{settings.prometheus_range_minutes}m"
            params["end"] = "now"
        return await self._mcp_call(
            server="jaeger",
            url=f"{settings.jaeger_mcp_url}/tools/find_traces",
            params=params,
        )

    async def _mcp_call(self, server: str, url: str, params: dict) -> tuple:
        """Execute an MCP server HTTP call with metrics instrumentation.

        Error semantics (misc.md issue 6 / task #3): a 4xx means the query
        the LLM/pipeline issued was rejected (bad PromQL/LogQL, invalid
        param) — the source is healthy, the query is the problem. We raise
        the distinct `MCPQueryRejected` so the gather block can label the
        prompt section "query rejected by <source>" instead of the misleading
        "source unavailable". 5xx / connection errors keep the
        source-unavailable semantics (a generic exception).
        """
        start = time.monotonic()
        try:
            resp = await self._client.get(url, params=params)
            resp.raise_for_status()
            ms = int((time.monotonic() - start) * 1000)
            elapsed = (time.monotonic() - start)
            triage_mcp_requests_total.labels(server=server, status="success").inc()
            triage_mcp_duration_seconds.labels(server=server).observe(elapsed)
            return resp.json(), ms
        except httpx.HTTPStatusError as exc:
            elapsed = time.monotonic() - start
            triage_mcp_duration_seconds.labels(server=server).observe(elapsed)
            status = exc.response.status_code
            if 400 <= status < 500:
                # Query fumble, not an outage — distinct metric + exception.
                triage_mcp_requests_total.labels(server=server, status="query_rejected").inc()
                detail = ""
                try:
                    detail = exc.response.text
                except Exception:
                    detail = ""
                raise MCPQueryRejected(server, status, detail) from exc
            # 5xx — the source itself failed.
            triage_mcp_requests_total.labels(server=server, status="error").inc()
            raise exc
        except Exception as exc:
            elapsed = time.monotonic() - start
            triage_mcp_requests_total.labels(server=server, status="error").inc()
            triage_mcp_duration_seconds.labels(server=server).observe(elapsed)
            raise exc
