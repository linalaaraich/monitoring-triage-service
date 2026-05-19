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


# Mapping from tool name → arg schema class. The model picks a tool by
# name; we parse args into the matching schema (which rejects extras).
_TOOL_SCHEMAS: dict[str, type[BaseModel]] = {
    "prometheus.query":            PrometheusQueryArgs,
    "loki.query_range":            LokiQueryRangeArgs,
    "jaeger.get_traces":           JaegerGetTracesArgs,
    "rca_history.similar":         RCAHistorySimilarArgs,
    "rca_history.list_exemplars":  RCAHistoryListExemplarsArgs,
    "rca_history.get_exemplar":    RCAHistoryGetExemplarArgs,
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
    catalogue of canonical good-RCA shapes (11 archetypes — OOM-loop,
    upstream-latency, cascade incidents, network-firewall, TLS expiry, etc.).
    Returns id + archetype + one-line gist for each.

- rca_history.get_exemplar
    args: { "exemplar_id": "<id from list_exemplars>" }
    use when: you found a better-fitting archetype via list_exemplars and
    want its full RCA shape, evidence shape, and actions shape. Returns the
    full structured exemplar (the same content as the pre-injected reference).

If none of these will help, return the normal decision JSON with
best-effort reasoning and a needs_review-worthy confidence.
"""


class ToolRequest(BaseModel):
    """Parsed tool_request from the LLM's first-pass JSON."""
    name: str
    args: dict[str, Any] = Field(default_factory=dict)


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
    (this is retry-only traffic, not the primary path). Each MCP has a
    straightforward REST surface: prometheus-mcp exposes /query,
    loki-mcp /query_range, jaeger-mcp /traces.
    """
    import httpx
    name = request.name
    args = request.args
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            if name == "prometheus.query":
                r = await client.get(
                    f"{settings.prometheus_mcp_url}/query",
                    params={"expr": args["expr"]},
                )
                r.raise_for_status()
                return {"tool": name, "args": args, "result": r.json()}
            elif name == "loki.query_range":
                r = await client.get(
                    f"{settings.loki_mcp_url}/query_range",
                    params={
                        "query": args["query"],
                        "lookback_seconds": args.get("lookback_seconds", 300),
                    },
                )
                r.raise_for_status()
                return {"tool": name, "args": args, "result": r.json()}
            elif name == "jaeger.get_traces":
                r = await client.get(
                    f"{settings.jaeger_mcp_url}/traces",
                    params={
                        "service": args["service"],
                        "operation": args.get("operation") or "",
                        "min_duration_ms": args.get("min_duration_ms", 0),
                        "limit": args.get("limit", 5),
                    },
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
            else:
                return {"tool": name, "args": args, "error": f"unknown_tool:{name}"}
    except httpx.HTTPError as e:
        logger.warning("Tool %s HTTP error: %s", name, e)
        return {"tool": name, "args": args, "error": f"mcp_http_error:{e}"}
    except Exception as e:
        logger.warning("Tool %s execution failed: %s", name, e)
        return {"tool": name, "args": args, "error": str(e)}


def tool_result_to_prompt_block(result: dict[str, Any]) -> str:
    """Format an executed tool result for inclusion in the retry prompt."""
    tool = result.get("tool", "?")
    args = result.get("args", {})
    args_str = ", ".join(f"{k}={v!r}" for k, v in args.items())
    if "error" in result:
        return (
            f"## Additional MCP query you requested: {tool}({args_str})\n"
            f"ERROR: {result['error']}\n"
            "Factor this into your decision — the tool failed, so treat the "
            "original evidence as your only source."
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
    "parse_tool_request",
    "execute_tool",
    "tool_result_to_prompt_block",
]
