"""Bounded-agency retry for data-starved RCAs.

When the first LLM pass is tagged data_starved or INCONCLUSIVE, instead
of just scolding the model ("don't hedge"), give it the ability to
request ONE additional MCP query from a fixed whitelist. The model
returns a structured tool request; we execute it, then re-prompt with
the new evidence.

Properties of this design (all deliberate):
  - EXACTLY ONE extra call max — bounded cost/latency, ~30-60s ceiling
  - Whitelisted tools with Pydantic-validated args — no hallucinated
    fields, no arbitrary command execution
  - Still reproducible — same inputs + same tool result → same output
    at temperature=0
  - Uses the MCPs as-is — no agent framework, no loops, no chains

See app/pipeline.py for how this slots into the retry flow (replaces
the old "just tell the model to try harder" path).
"""
from __future__ import annotations

import json
import logging
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from app.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool whitelist + arg schemas
# ---------------------------------------------------------------------------

class PrometheusQueryArgs(BaseModel):
    """Single instant-query against Prometheus. The model supplies one
    PromQL string; we run it at the current instant."""
    expr: str = Field(..., description="PromQL instant-query expression")

class LokiQueryRangeArgs(BaseModel):
    """Range query against Loki. The model supplies a LogQL selector and
    a lookback in seconds; we fetch up to 50 lines."""
    query: str = Field(..., description="LogQL selector, e.g. {service_name=\"spring-boot\"} |~ \"error\"")
    lookback_seconds: int = Field(300, ge=30, le=3600)

class JaegerGetTracesArgs(BaseModel):
    """Fetch traces for a service, optionally filtered by operation
    or minimum duration."""
    service: str = Field(..., description="Service name as registered with Jaeger")
    operation: str | None = Field(None, description="Optional operation name filter")
    min_duration_ms: int = Field(0, ge=0, description="Drop traces shorter than this")
    limit: int = Field(5, ge=1, le=20)

class RCAHistorySimilarArgs(BaseModel):
    """Find recent similar decisions to the one being investigated.

    Post-S3-HF-05 (2026-05-19) this routes through rca_history_mcp's
    /tools/get_similar_decisions endpoint (not a direct DB read), so
    `min_quality` is forwarded to the MCP for quality-filtered retrieval.
    Default "actionable" — the retry should learn only from prior RCAs
    that were judged good. Set to "data_starved" or "needs_review" to
    widen if the actionable-only set is empty.
    """
    alert_name: str
    affected_service: str | None = None
    days: int = Field(7, ge=1, le=30)
    limit: int = Field(3, ge=1, le=10)
    min_quality: str = Field(
        "actionable",
        description="Minimum rca_quality (actionable | data_starved | needs_review)",
    )

class RCAHistoryListExemplarsArgs(BaseModel):
    """List all curated RCA exemplars (canonical good-RCA shapes).
    No args — returns the full archetype catalogue."""
    pass

class RCAHistoryGetExemplarArgs(BaseModel):
    """Fetch one exemplar by id. Use when the pre-injected exemplar is the
    wrong archetype and you want a different one."""
    exemplar_id: str = Field(..., description="Exemplar id, e.g. 'oom-loop'")


class RCAHistoryListFeedbackArgs(BaseModel):
    """Phase 6 (2026-06-03) — list operator feedback rows for similar past
    alerts. The hybrid feedback-loop design ALWAYS proactively injects the
    HIGH-VALUE subset (verdict_was_right='no' OR non-empty actual_cause)
    into the initial prompt; this tool surfaces the BROADER corpus on
    demand so the LLM can read positive ratings, action_was_right notes,
    and tag chips that didn't pass the high-value filter."""
    alert_name: str = Field(..., description="Alert name to match")
    service: str | None = Field(None, description="Affected service to match. Omit for alert-name-only filter.")
    days: int = Field(14, ge=1, le=180, description="Days to look back")
    limit: int = Field(5, ge=1, le=20, description="Max records to return")


# Mapping from tool name → arg schema class. The model picks a tool by
# name; we parse args into the matching schema (which rejects extras).
_TOOL_SCHEMAS: dict[str, type[BaseModel]] = {
    "prometheus.query":            PrometheusQueryArgs,
    "loki.query_range":            LokiQueryRangeArgs,
    "jaeger.get_traces":           JaegerGetTracesArgs,
    "rca_history.similar":         RCAHistorySimilarArgs,
    "rca_history.list_exemplars":  RCAHistoryListExemplarsArgs,
    "rca_history.get_exemplar":    RCAHistoryGetExemplarArgs,
    "rca_history.list_feedback":   RCAHistoryListFeedbackArgs,
}


TOOLS_DESCRIPTION = """## Available tools (pick EXACTLY ONE)

If you can't reach a confident verdict on this alert with the evidence
already in the prompt, you may request ONE additional MCP query. Return
a JSON object with `tool_request` set, and OMIT `decision`/`rca`/etc.
for this turn. We'll run the query and re-prompt you with the result.

  {"tool_request": {"name": "<tool_name>", "args": {...}}}

Tool catalog:

- prometheus.query
    args: { "expr": "<PromQL instant-query>" }
    use when: the observed value is thin and you want to sample an
    adjacent metric (e.g. to compare CPU against memory, or check a
    rate over a different window).

- loki.query_range
    args: { "query": "<LogQL>", "lookback_seconds": <30-3600> }
    use when: the service-scoped Loki result was empty and you want to
    try a different selector (different service label, pattern match,
    error keywords).

- jaeger.get_traces
    args: { "service": "<name>", "operation": "<opt>", "min_duration_ms": <opt>, "limit": <1-20> }
    use when: Jaeger returned 0 traces and you want to look at a
    traced-neighbor service, or filter for slow traces specifically.

- rca_history.similar
    args: { "alert_name": "<name>", "affected_service": "<opt>", "days": <1-30>, "limit": <1-10>, "min_quality": "<actionable|data_starved|needs_review>" }
    use when: this alert has fired before and you want to see what
    prior RCAs concluded / what actions were tried. min_quality
    defaults to "actionable" — only RCAs judged good are returned.
    Widen to "data_starved" or "needs_review" if the actionable-only
    set is empty.

- rca_history.list_exemplars
    args: {}
    use when: the pre-injected reference exemplar at the top of this prompt
    doesn't fit the archetype you're seeing, and you want to scan the full
    catalogue of canonical good-RCA shapes (15 archetypes — OOM-loop,
    upstream-latency, cascade incidents, network-firewall, TLS expiry, etc.).
    Returns id + archetype + one-line gist for each.

- rca_history.get_exemplar
    args: { "exemplar_id": "<id from list_exemplars>" }
    use when: you found a better-fitting archetype via list_exemplars and
    want its full RCA shape, evidence shape, and actions shape. Returns the
    full structured exemplar (the same content as the pre-injected reference).

- rca_history.list_feedback
    args: { "alert_name": "<name>", "service": "<opt>", "days": <1-180>, "limit": <1-20> }
    use when: you want to see what operators have rated/said about similar
    past alerts that aren't already in your proactive feedback block. The
    proactive block at the top of this prompt carries ONLY high-value
    feedback (verdict_was_right='no' OR non-empty actual_cause); this tool
    returns the broader corpus including positive ratings, action_was_right
    notes, and tag chips. Useful when you want a more complete picture of
    operator opinion on this alert pattern before committing to a verdict.

If none of these will help, return the normal decision JSON with
best-effort reasoning and a needs_review-worthy confidence.
"""


class ToolRequest(BaseModel):
    """Parsed tool_request from the LLM's first-pass JSON."""
    name: str
    args: dict[str, Any] = Field(default_factory=dict)


def build_crashloop_tool_request(alert) -> ToolRequest:
    """Deterministic agency query for crash-loop / restart alerts.

    Iteration 2 of the 2026-06-10 micro-cycle: the playbook alone was not
    enough — live induction (image-provider OOM at 4Mi) showed the 14b model
    repeatedly emitting malformed tool_request JSON ("LLM JSON parse failed"
    x3), so the agency pass fell back to the plain anti-hedge retry which
    has NO tool offer and no KSM evidence in context → "Cannot determine"
    again (decisions 03fd08ea accounting re-fire, and the image-provider
    row at 13:18). For an alert family whose decisive evidence is ALWAYS
    the same three series, asking the model to compose the query is pure
    downside. The pipeline now auto-executes the playbook's combined query
    (still through prometheus-mcp — MCP-only invariant intact) and goes
    straight to the evidence-laden retry prompt."""
    from app.llm_client import crashloop_evidence_query, crashloop_pod_prefix
    namespace = alert.labels.get("namespace", "") or "unknown"
    prefix = crashloop_pod_prefix(alert)
    return ToolRequest(
        name="prometheus.query",
        args={"expr": crashloop_evidence_query(namespace, prefix)},
    )


def digest_crashloop_evidence(
    tool_result: dict[str, Any], service: str, namespace: str
) -> str | None:
    """Deterministically pre-interpret the fixed-shape crash-loop evidence
    query into plain-English facts for the retry prompt.

    Iteration 3 of the 2026-06-10 micro-cycle. Iteration 2 made the QUERY
    deterministic, and the live re-induction proved it executed and returned
    decisive series (replayed at 14:26:40: reason="OOMKilled"=1, 15 restarts
    /2h, limit 4Mi) — yet the 14b model, handed that as a raw JSON series
    dump, still hedged "cannot determine" (decisions 5a8231f8/6899cb1b),
    fighting the response format the whole way ("LLM JSON parse failed"
    every pass). Same lesson one level up: for a fixed-shape result, asking
    the model to INTERPRET raw series is pure downside. This digest is the
    metric-interpreter pattern (lifecycle 3.4) applied to the agency result:
    parse the three evidence families in code and hand the model finished
    facts plus a ready verdict sentence it only has to confirm.

    Returns None when the result is empty/unparseable — caller falls back
    to the raw tool_result_to_prompt_block.
    """
    inner = tool_result.get("result")
    if not isinstance(inner, dict):
        return None
    series = inner.get("result") or []
    if not isinstance(series, list) or not series:
        return None

    reasons: dict[str, str] = {}          # pod -> termination reason
    restarts: dict[str, float] = {}       # pod -> increase over the window
    limits: dict[str, float] = {}         # pod -> memory limit bytes
    for s in series:
        if not isinstance(s, dict):
            continue
        metric = s.get("metric") or {}
        pod = metric.get("exported_pod") or metric.get("pod") or "?"
        name = metric.get("__name__", "")
        try:
            value = float((s.get("value") or [None, "nan"])[1])
        except (TypeError, ValueError):
            continue
        if name == "kube_pod_container_status_last_terminated_reason":
            if value >= 1 and metric.get("reason"):
                reasons[pod] = metric["reason"]
        elif name == "kube_pod_container_resource_limits":
            limits[pod] = value
        elif name == "":
            # increase() drops __name__ — the only nameless family in the
            # union is the restart increase.
            restarts[pod] = value

    if not (reasons or restarts):
        return None

    lines = [
        "## Crash-loop evidence — PRE-INTERPRETED FACTS "
        "(extracted deterministically from Prometheus via MCP; trust them as ground truth):"
    ]
    looping = {p: n for p, n in restarts.items() if n >= 1}
    for pod, reason in reasons.items():
        lines.append(f"- Pod {pod}: last termination reason = {reason}.")
    for pod, n in sorted(restarts.items(), key=lambda kv: -kv[1]):
        if n >= 1:
            lines.append(f"- Pod {pod}: restarted {n:.0f}x inside the query window.")
    for pod, b in limits.items():
        lines.append(f"- Pod {pod}: memory limit = {b / 1048576:.0f} MiB.")
    quiet = sorted(set(restarts) - set(looping))
    if quiet:
        lines.append(
            "- Pods with ZERO restarts in the window (e.g. replacements after "
            "a deploy roll): " + ", ".join(quiet) + "."
        )

    # Ready verdict the model only has to confirm/adapt — never compose.
    oom_pods = [p for p, r in reasons.items() if r == "OOMKilled"]
    if oom_pods:
        pod = oom_pods[0]
        n = restarts.get(pod)
        lim = limits.get(pod)
        verdict = (
            f"=> READY VERDICT (state this unless the facts above contradict it): "
            f"the {service} container in namespace {namespace} is being OOMKilled — "
        )
        verdict += (
            f"its memory limit ({lim / 1048576:.0f} MiB) is too small for the workload"
            if lim is not None
            else "its memory limit is too small for the workload"
        )
        if n:
            verdict += f"; it restarted {n:.0f}x in the query window"
        verdict += (
            ". Remedy: raise the memory limit on the deployment and verify the "
            "restart counter flattens. If the looping pod no longer exists or its "
            "recent restarts are zero, the loop has ENDED (trailing-window alert) — "
            "say that, named, with verdict dismiss/monitor. This is a DETERMINED "
            "cause; 'cannot determine' is wrong."
        )
        lines.append(verdict)
    elif reasons:
        pod, reason = next(iter(reasons.items()))
        lines.append(
            f"=> READY VERDICT (adapt to the facts above): the {service} container "
            f"in namespace {namespace} is crash-looping with termination reason "
            f"'{reason}' — name that mechanism (bad config / boot failure / etc.); "
            "rollback-first if every restart dies at the same step. 'Cannot "
            "determine' is wrong: the termination reason above IS the determination."
        )
    return "\n".join(lines)


def parse_tool_request(raw_llm_json: str | dict) -> ToolRequest | None:
    """If the LLM emitted `{"tool_request": {...}}`, parse + validate it.
    Returns None if the response was a normal decision (no tool request).

    Accepts either the raw JSON string or an already-parsed dict.
    Malformed requests return None with a warning — the caller then
    falls back to the normal anti-hedge retry."""
    try:
        data = json.loads(raw_llm_json) if isinstance(raw_llm_json, str) else raw_llm_json
    except Exception:
        return None

    tr = data.get("tool_request") if isinstance(data, dict) else None
    if not tr or not isinstance(tr, dict):
        return None
    name = tr.get("name")
    if name not in _TOOL_SCHEMAS:
        logger.warning("LLM requested unknown tool %r — rejecting", name)
        return None
    schema = _TOOL_SCHEMAS[name]
    try:
        validated = schema(**tr.get("args", {}))
    except ValidationError as e:
        logger.warning("LLM tool request args invalid for %s: %s", name, e)
        return None
    return ToolRequest(name=name, args=validated.model_dump())


async def execute_tool(
    request: ToolRequest,
    context_gatherer,           # app.context.ContextGatherer (unused — kept for signature)
    store,                      # app.rca_store.RCAStore
) -> dict[str, Any]:
    """Run the whitelisted MCP query and return a result dict the LLM can
    read. Never raises — errors are returned as {"error": "..."}.

    MCPs are called via direct HTTP against the settings URLs — same pattern
    as context.ContextGatherer._mcp_call but without the metrics wrappers
    (this is retry-only traffic, not the primary path). Routes MUST mirror
    the deployed MCP surface, which is /tools/* only: prometheus-mcp exposes
    /tools/query_instant, loki-mcp /tools/query_logs, jaeger-mcp
    /tools/find_traces (the bare /query, /query_range, /traces routes do not
    exist on the MCP image and 404 — see context.py for the canonical paths).
    """
    import httpx
    name = request.name
    args = request.args
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            if name == "prometheus.query":
                # prometheus-mcp /tools/query_instant takes `promql` (our
                # schema names it `expr`).
                r = await client.get(
                    f"{settings.prometheus_mcp_url}/tools/query_instant",
                    params={"promql": args["expr"]},
                )
                r.raise_for_status()
                return {"tool": name, "args": args, "result": r.json()}
            elif name == "loki.query_range":
                # loki-mcp /tools/query_logs takes `logql` + a relative `start`
                # string ("Nm"); our schema gives a LogQL `query` and an
                # integer `lookback_seconds`.
                lookback = args.get("lookback_seconds", 300)
                r = await client.get(
                    f"{settings.loki_mcp_url}/tools/query_logs",
                    params={
                        "logql": args["query"],
                        "start": f"{max(1, lookback // 60)}m",
                        "limit": 50,
                    },
                )
                r.raise_for_status()
                return {"tool": name, "args": args, "result": r.json()}
            elif name == "jaeger.get_traces":
                # jaeger-mcp /tools/find_traces takes service/operation/limit.
                # It has no min_duration_ms filter (the MCP surface exposes a
                # `tags` filter instead), so that schema arg is accepted from
                # the LLM but not forwarded.
                params = {
                    "service": args["service"],
                    "limit": args.get("limit", 5),
                }
                if args.get("operation"):
                    params["operation"] = args["operation"]
                r = await client.get(
                    f"{settings.jaeger_mcp_url}/tools/find_traces",
                    params=params,
                )
                r.raise_for_status()
                return {"tool": name, "args": args, "result": r.json()}
            elif name == "rca_history.similar":
                # S3-HF-05 (2026-05-19): closes the second MCP-only-invariant
                # bypass. Was a direct in-process call to store.get_decisions
                # (no quality filter, no service filter in practice); now
                # routes through rca_history_mcp's /tools/get_similar_decisions
                # which adds proper quality-filtering. Same MCP that
                # entity_baselines.py goes through post-S3-HF-04.
                params = {
                    "alert_name": args["alert_name"],
                    "days": args.get("days", 7),
                    "limit": args.get("limit", 3),
                    "min_quality": args.get("min_quality", "actionable"),
                }
                if args.get("affected_service"):
                    params["affected_service"] = args["affected_service"]
                r = await client.get(
                    f"{settings.rca_history_mcp_url}/tools/get_similar_decisions",
                    params=params,
                )
                r.raise_for_status()
                return {"tool": name, "args": args, "result": r.json()}
            elif name == "rca_history.list_exemplars":
                # `from app import exemplars` is intentional and exempt from
                # the MCP-only data-access invariant — exemplars are local
                # configuration (compiled-into-service YAML scaffolding the
                # prompt), not external data the LLM could hallucinate. The
                # CI lint (S3-HF-08) carries this exemption explicitly.
                from app import exemplars as _ex
                return {"tool": name, "args": args, "result": _ex.list_all()}
            elif name == "rca_history.get_exemplar":
                # See note on rca_history.list_exemplars above re. exemption.
                from app import exemplars as _ex
                ex = _ex.get_by_id(args["exemplar_id"])
                if ex is None:
                    return {"tool": name, "args": args, "error": f"exemplar_not_found:{args['exemplar_id']}"}
                return {"tool": name, "args": args, "result": ex}
            elif name == "rca_history.list_feedback":
                # Phase 6 (2026-06-03) — broader operator-feedback corpus.
                # Routes through rca_history_mcp's /tools/list_feedback so
                # the MCP-only data-access invariant holds (no direct DB
                # read from the bounded-agency path). Sister to the
                # proactive corrective_feedback block built in the
                # pipeline pre-call.
                params = {
                    "alert_name": args["alert_name"],
                    "days": args.get("days", 14),
                    "limit": args.get("limit", 5),
                }
                if args.get("service"):
                    params["service"] = args["service"]
                r = await client.get(
                    f"{settings.rca_history_mcp_url}/tools/list_feedback",
                    params=params,
                )
                r.raise_for_status()
                return {"tool": name, "args": args, "result": r.json()}
            else:
                return {"tool": name, "args": args, "error": f"unknown_tool:{name}"}
    except httpx.HTTPStatusError as e:
        # Distinguish a query fumble (4xx — the LLM's args were invalid) from
        # a source outage (5xx) so the retry prompt tells the model to FIX its
        # query rather than abandon the source (misc.md issue 6 / task #3).
        status = e.response.status_code
        detail = ""
        try:
            detail = (e.response.text or "")[:300]
        except Exception:
            detail = ""
        if 400 <= status < 500:
            logger.warning("Tool %s query rejected (HTTP %s): %s", name, status, detail)
            return {
                "tool": name, "args": args,
                "error_kind": "query_rejected",
                "upstream_status": status,
                "error": f"query_rejected (HTTP {status}): {detail}",
            }
        logger.warning("Tool %s upstream error (HTTP %s): %s", name, status, e)
        return {
            "tool": name, "args": args,
            "error_kind": "source_unavailable",
            "upstream_status": status,
            "error": f"source_unavailable (HTTP {status}): {e}",
        }
    except httpx.HTTPError as e:
        # Connection / timeout — the source is unreachable, not a bad query.
        logger.warning("Tool %s HTTP error: %s", name, e)
        return {
            "tool": name, "args": args,
            "error_kind": "source_unavailable",
            "error": f"source_unavailable: {e}",
        }
    except Exception as e:
        logger.warning("Tool %s execution failed: %s", name, e)
        return {"tool": name, "args": args, "error": str(e)}


def tool_result_to_prompt_block(result: dict[str, Any]) -> str:
    """Format an executed tool result for inclusion in the retry prompt."""
    tool = result.get("tool", "?")
    args = result.get("args", {})
    args_str = ", ".join(f"{k}={v!r}" for k, v in args.items())
    if "error" in result:
        kind = result.get("error_kind")
        if kind == "query_rejected":
            return (
                f"## Additional MCP query you requested: {tool}({args_str})\n"
                f"QUERY REJECTED: {result['error']}\n"
                "The source is reachable but your query was invalid (bad "
                "syntax or parameters). Do NOT conclude the source is down or "
                "that data is missing — your query was the problem. Reason "
                "from the original evidence; do not invent a source-outage "
                "root cause."
            )
        return (
            f"## Additional MCP query you requested: {tool}({args_str})\n"
            f"ERROR: {result['error']}\n"
            "Factor this into your decision — the source was unavailable, so "
            "treat the original evidence as your only source."
        )
    body = result.get("result")
    body_str = json.dumps(body, indent=2, default=str) if body is not None else "(empty result)"
    # Truncate to keep the retry prompt within reasonable size
    if len(body_str) > 6000:
        body_str = body_str[:6000] + "\n... (truncated)"
    return (
        f"## Additional MCP query you requested: {tool}({args_str})\n"
        f"RESULT:\n{body_str}\n\n"
        "Use this new evidence together with the original prompt to reach a "
        "confident verdict. Emit the normal decision JSON this time — NO "
        "more tool requests. This was your one allowed extra call."
    )


__all__ = [
    "TOOLS_DESCRIPTION",
    "ToolRequest",
    "build_crashloop_tool_request",
    "digest_crashloop_evidence",
    "parse_tool_request",
    "execute_tool",
    "tool_result_to_prompt_block",
]
