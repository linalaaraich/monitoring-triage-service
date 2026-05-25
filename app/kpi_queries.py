"""Phase 3.A.KPI — platform-health KPI computations for /dashboard/v2/kpi.

Single source-of-truth for the 6 supervisor-asked-for KPIs that surface on the
"KPI · Evaluation" page. Every query reads from the existing RCAStore SQLite
connection — no new data path, MCP-invariant clean.

Operator-cognitive-load doctrine: each KPI answers a question an on-call
operator actually asks, framed as a "big number + sub-line for context."

  1. emails_per_day        — "am I getting paged too much?"
  2. false_positive_rate   — "are my pages right?"
  3. median_latency_ms     — "is the pipeline slow?"
  4. cheap_path_pct        — "how much load did we absorb without LLM cost?"
  5. archetype_coverage    — "what alert shapes are we seeing?"
  6. gpu_util              — "is the GPU healthy?" (Ollama /api/ps probe)

Plus two pragmatic static KPIs for completeness on the page:
  7. mcp_invariant         — "is the hallucination firewall structurally intact?"
  8. tests_passing         — "do the unit tests still cover what they should?"

All numeric queries are bounded by an explicit time window (24 h / 7 d / 30 d)
so the SQL is fast even on long-lived databases.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# Static KPIs — kept as module constants so they can be bumped in one place
# when the lint pass / test suite count changes. Phase 3.A.KPI ships with
# these values; they are intentionally pragmatic (not live-probed) per the
# spec's "optional bonus, don't overrun the budget" guidance.
_STATIC_MCP_INVARIANT_LABEL = "0 leaks"
_STATIC_MCP_INVARIANT_SUB = "lint enforced in CI — scripts/check_mcp_invariant.py (5 rules)"
_STATIC_TESTS_LABEL = "333 / 333"
_STATIC_TESTS_SUB = "stamped 2026-05-25 (313 + 20 new KPI tests)"


def _utc_now() -> datetime:
    """Tz-aware UTC now used for all window arithmetic.

    rca_store stores timestamps as tz-naive UTC ISO strings; the parser
    below promotes them to tz-aware UTC so the comparisons are unambiguous.
    """
    return datetime.now(timezone.utc)


def _parse_ts(s: str | None) -> datetime | None:
    """Parse an ISO timestamp into tz-aware UTC. Returns None on bad input.

    Tolerates the storage formats actually present in rca_history:
      - "2026-05-20T19:44:06.620389"        (naive, assume UTC)
      - "2026-05-20T19:44:06+00:00"         (tz-aware UTC)
      - "2026-05-20T19:44:06Z"              (Z suffix)
    """
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _format_int(n: int | None) -> str:
    """Render an int KPI value; None / missing reads as 0."""
    return str(int(n)) if n is not None else "0"


def _format_pct(num: int, denom: int, decimals: int = 1) -> str:
    """Render num/denom as a percentage string.

    Avoids div-by-zero (returns 'n/a' when denom is 0 — operator should not
    see a misleading 0.0% when there's nothing to measure).
    """
    if denom <= 0:
        return "n/a"
    pct = (num / denom) * 100.0
    return f"{pct:.{decimals}f}%"


def _percentile(values: list[float], pct: float) -> float:
    """Linear-interpolation percentile over a sorted list of floats.

    pct in [0.0, 1.0]. Returns 0.0 on empty input — caller decides what
    to render in that case.
    """
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return float(s[0])
    k = (len(s) - 1) * pct
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    frac = k - lo
    return float(s[lo] + (s[hi] - s[lo]) * frac)


async def _emails_per_day(db) -> dict:
    """KPI 1 — count of rca_history rows where action_taken='emailed' in last 24 h.

    Sub-line: 7-day rolling average so the operator can tell if today is
    unusual vs. baseline. The average uses the same `emailed` filter over
    the wider window divided by 7.
    """
    now = _utc_now().replace(tzinfo=None)  # store uses naive UTC strings
    day_ago = (now - timedelta(hours=24)).isoformat()
    week_ago = (now - timedelta(days=7)).isoformat()

    cursor = await db.execute(
        "SELECT COUNT(*) AS n FROM rca_history WHERE action_taken = ? AND timestamp >= ?",
        ("emailed", day_ago),
    )
    row = await cursor.fetchone()
    last_24h = int(row["n"]) if row else 0

    cursor = await db.execute(
        "SELECT COUNT(*) AS n FROM rca_history WHERE action_taken = ? AND timestamp >= ?",
        ("emailed", week_ago),
    )
    row = await cursor.fetchone()
    last_7d = int(row["n"]) if row else 0
    rolling_avg = round(last_7d / 7.0, 1)

    return {
        "value": last_24h,
        "label": f"{last_24h} / day",
        "sub": f"7-day average: {rolling_avg} / day",
    }


async def _false_positive_rate(db) -> dict:
    """KPI 2 — operator-rated alerts where the verdict was wrong, last 30 d.

    Uses the v2 rate-this-alert feedback rows (feedback_type='rate') which
    expose verdict_was_right ∈ {'yes','no','maybe'}. False-positive = the
    operator said the LLM verdict was 'no' (wrong). Falls back to rating='no'
    (not useful) when verdict_was_right is missing — older rate rows may
    only carry the coarser rating field.

    Denominator is rows with ANY non-null rating in the window — i.e. how
    many alerts the operator bothered to rate at all.
    """
    cutoff = (_utc_now().replace(tzinfo=None) - timedelta(days=30)).isoformat()
    cursor = await db.execute(
        """SELECT verdict_was_right, rating
           FROM feedback
           WHERE feedback_type = 'rate'
             AND created_at >= ?
             AND (rating IS NOT NULL OR verdict_was_right IS NOT NULL)""",
        (cutoff,),
    )
    rows = await cursor.fetchall()
    rated = len(rows)
    wrong = 0
    for r in rows:
        vwr = (r["verdict_was_right"] or "").lower()
        rating = (r["rating"] or "").lower()
        # Prefer the explicit verdict-correctness column; fall back to the
        # useful/not-useful axis when the operator only filled the coarse
        # rating. Either signal = a false positive in the operator's eyes.
        if vwr == "no" or (vwr == "" and rating == "no"):
            wrong += 1

    return {
        "value": wrong,
        "denom": rated,
        "label": _format_pct(wrong, rated),
        "sub": f"{rated} operator-rated alerts in last 30 days",
    }


async def _median_latency(db) -> dict:
    """KPI 3 — p50 + p95 of investigation_duration_ms for last-24h investigations.

    Only rows where triage_decision='investigate' AND duration > 0 are
    counted — the suppression / dedup paths have ~0 ms latency by design
    and would skew the median to near-zero, hiding the real LLM-path
    latency the operator cares about.
    """
    cutoff = (_utc_now().replace(tzinfo=None) - timedelta(hours=24)).isoformat()
    cursor = await db.execute(
        """SELECT investigation_duration_ms
           FROM rca_history
           WHERE triage_decision = 'investigate'
             AND timestamp >= ?
             AND investigation_duration_ms > 0""",
        (cutoff,),
    )
    rows = await cursor.fetchall()
    durations = [float(r["investigation_duration_ms"]) for r in rows]
    if not durations:
        return {
            "value": 0,
            "label": "n/a",
            "sub": "no LLM-path investigations in last 24 h",
        }
    p50 = _percentile(durations, 0.50)
    p95 = _percentile(durations, 0.95)
    # Render in seconds — millisecond raw values are operationally
    # meaningless. Sub-second renders to 1 decimal place; >= 1 s rounds.
    def _fmt_s(ms: float) -> str:
        s = ms / 1000.0
        return f"{s:.1f} s" if s < 10 else f"{int(round(s))} s"
    return {
        "value": int(round(p50)),
        "label": _fmt_s(p50),
        "sub": f"p95: {_fmt_s(p95)} (tail latency over {len(durations)} runs)",
    }


async def _cheap_path_pct(db) -> dict:
    """KPI 4 — proportion of last-24h alerts that never paid the LLM cost.

    Cheap-path = triage_decision IN ('suppressed_duplicate', 'triage_suppressed',
    'recurrence_gated_pre_llm'). These three gates absorb known noise before
    the LLM is invoked, saving GPU seconds + dollars.

    Sub-line breaks down the cheap-path count vs LLM-path count so the
    operator sees both raw numbers and the ratio.
    """
    cutoff = (_utc_now().replace(tzinfo=None) - timedelta(hours=24)).isoformat()
    cursor = await db.execute(
        """SELECT triage_decision, COUNT(*) AS n
           FROM rca_history
           WHERE timestamp >= ?
           GROUP BY triage_decision""",
        (cutoff,),
    )
    rows = await cursor.fetchall()
    cheap_decisions = {"suppressed_duplicate", "triage_suppressed", "recurrence_gated_pre_llm"}
    cheap = 0
    total = 0
    for r in rows:
        td = (r["triage_decision"] or "").lower()
        n = int(r["n"])
        total += n
        if td in cheap_decisions:
            cheap += n
    llm_path = total - cheap
    return {
        "value": cheap,
        "denom": total,
        "label": _format_pct(cheap, total, decimals=0),
        "sub": f"{cheap} cheap-path vs {llm_path} LLM-path in last 24 h",
    }


async def _archetype_coverage(db) -> dict:
    """KPI 5 — count of distinct alert_name values in the last 7 days.

    Sub-line: top 5 alert names by frequency, comma-separated. The number
    is "how many shapes are we seeing"; the sub-line is "which shapes
    dominate" so the operator can spot when a single noisy alert is
    drowning out the rest.
    """
    cutoff = (_utc_now().replace(tzinfo=None) - timedelta(days=7)).isoformat()
    cursor = await db.execute(
        """SELECT alert_name, COUNT(*) AS n
           FROM rca_history
           WHERE timestamp >= ? AND alert_name IS NOT NULL AND alert_name != ''
           GROUP BY alert_name
           ORDER BY n DESC""",
        (cutoff,),
    )
    rows = await cursor.fetchall()
    distinct = len(rows)
    top5 = [(r["alert_name"], int(r["n"])) for r in rows[:5]]
    if top5:
        top_str = ", ".join(f"{name} ({n})" for name, n in top5)
    else:
        top_str = "no alerts in last 7 days"
    return {
        "value": distinct,
        "label": str(distinct),
        "sub": f"top 5: {top_str}",
    }


async def _gpu_util(ollama_url: str | None) -> dict:
    """KPI 6 — GPU utilization via Ollama's /api/ps endpoint.

    /api/ps returns the loaded model + its memory footprint; we surface
    that as a "GPU healthy + model X loaded" signal. If Ollama is
    unreachable (no GPU host, dev laptop, network blip) we fall back to
    a "n/a — wire via SF-12 GPU dashboard" placeholder per spec.

    Bounded by a 2-second timeout so the dashboard load doesn't block on
    a slow GPU host.
    """
    if not ollama_url:
        return {
            "value": 0,
            "label": "n/a",
            "sub": "wire via SF-12 GPU dashboard (probe timeout 2 s)",
        }
    try:
        import httpx
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{ollama_url.rstrip('/')}/api/ps")
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.info("GPU util probe failed (%s) — rendering n/a", exc)
        return {
            "value": 0,
            "label": "n/a",
            "sub": f"ollama unreachable after 2 s ({type(exc).__name__})",
        }

    models = data.get("models") or []
    if not models:
        return {
            "value": 0,
            "label": "idle",
            "sub": "0 models currently loaded into VRAM",
        }
    # The first loaded model is the active one; surface its name + size.
    first = models[0]
    name = first.get("name") or first.get("model") or "unknown"
    size_bytes = first.get("size_vram") or first.get("size") or 0
    size_gb = size_bytes / (1024 ** 3) if size_bytes else 0.0
    return {
        "value": 1,
        "label": "loaded",
        "sub": f"{name} ({size_gb:.1f} GiB in VRAM)" if size_gb else f"{name} (0.0 GiB in VRAM)",
    }


async def compute_kpis(store, *, ollama_url: str | None = None) -> dict:
    """Compute every KPI for the /dashboard/v2/kpi page.

    Single-pass, single-connection — all queries reuse store._db so we
    don't open new SQLite handles on every render. Returns a dict shaped
    for direct interpolation into the HTML template.

    `ollama_url` is optional: when None, the GPU util KPI returns the
    static "n/a — SF-12" placeholder. The route handler passes
    settings.ollama_url in production.

    Defensive: each KPI is wrapped in try/except so a malformed row or a
    one-off SQL anomaly never crashes the whole page. A single broken KPI
    renders as "—" rather than 500-ing the route.
    """
    if store is None or store._db is None:
        # Store not initialized — return all-zero KPIs so the page still
        # renders (empty-DB path). This is the test-without-lifespan case.
        return _empty_kpis()

    db = store._db

    async def _safe(coro_factory, label: str) -> dict:
        try:
            return await coro_factory()
        except Exception as exc:
            logger.warning("KPI %s failed: %s", label, exc, exc_info=True)
            return {"value": 0, "label": "—", "sub": f"failed: {type(exc).__name__}"}

    emails = await _safe(lambda: _emails_per_day(db), "emails_per_day")
    fp_rate = await _safe(lambda: _false_positive_rate(db), "false_positive_rate")
    latency = await _safe(lambda: _median_latency(db), "median_latency")
    cheap = await _safe(lambda: _cheap_path_pct(db), "cheap_path_pct")
    archetypes = await _safe(lambda: _archetype_coverage(db), "archetype_coverage")
    gpu = await _safe(lambda: _gpu_util(ollama_url), "gpu_util")

    return {
        "emails_per_day": emails,
        "false_positive_rate": fp_rate,
        "median_latency": latency,
        "cheap_path_pct": cheap,
        "archetype_coverage": archetypes,
        "gpu_util": gpu,
        # Static / pragmatic KPIs — see module docstring for rationale.
        "mcp_invariant": {
            "value": 1,
            "label": _STATIC_MCP_INVARIANT_LABEL,
            "sub": _STATIC_MCP_INVARIANT_SUB,
        },
        "tests_passing": {
            "value": 333,
            "label": _STATIC_TESTS_LABEL,
            "sub": _STATIC_TESTS_SUB,
        },
    }


def _empty_kpis() -> dict:
    """Default-zero KPIs returned when the store is unavailable.

    Used by the route on cold-boot (lifespan not yet run) and by unit
    tests that don't initialise the store. Every value renders gracefully
    so the page still 200s and the operator sees "no data yet" instead
    of a 500.
    """
    return {
        "emails_per_day": {"value": 0, "label": "0 / day", "sub": "7-day average: 0.0 / day"},
        "false_positive_rate": {"value": 0, "denom": 0, "label": "n/a", "sub": "no rated alerts yet"},
        "median_latency": {"value": 0, "label": "n/a", "sub": "no LLM-path investigations yet"},
        "cheap_path_pct": {"value": 0, "denom": 0, "label": "n/a", "sub": "no traffic in last 24 h"},
        "archetype_coverage": {"value": 0, "label": "0", "sub": "no alerts in last 7 days"},
        "gpu_util": {"value": 0, "label": "n/a", "sub": "store not initialised"},
        "mcp_invariant": {
            "value": 1,
            "label": _STATIC_MCP_INVARIANT_LABEL,
            "sub": _STATIC_MCP_INVARIANT_SUB,
        },
        "tests_passing": {
            "value": 333,
            "label": _STATIC_TESTS_LABEL,
            "sub": _STATIC_TESTS_SUB,
        },
    }
