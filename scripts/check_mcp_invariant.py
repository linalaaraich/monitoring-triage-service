#!/usr/bin/env python3
"""S3-HF-08 — MCP-only data-access invariant lint.

The invariant: every external data source the LLM downstream will see must
come through an MCP bridge. Direct `httpx`/`requests`/in-process DB or
exemplar reads in the LLM-gathering path bypass the hallucination firewall.

What this lint catches
----------------------
1. Direct connection strings to raw observability stack ports
     :9090 (Prometheus), :3100 (Loki), :16686 (Jaeger) — anywhere in app/.
     The MCP path is :8091 (prom-mcp), :8092 (loki-mcp), :8093 (jaeger-mcp),
     :8095 (rca-history-mcp). If you need to talk to Prometheus, talk to
     the MCP — never to Prometheus directly.

2. Direct `import aiosqlite` outside the canonical writer (rca_store.py)
     and boot-time code (main.py lifespan). Read paths must go through
     rca_history_mcp.

3. `from app.exemplars import …` or `from app import exemplars` outside the
     documented exempt files. Exemplars are compiled-in configuration, not
     external data — the exemption is intentional, but the list is bounded
     so a NEW caller has to be explicitly added here with a rationale.

Exemption protocol
------------------
If you have a legitimate need to violate the rule (e.g. a boot-time
schema migration), add the file to the appropriate ALLOW set below
AND leave a one-line comment in the violating code referencing this
script. Don't silently exempt — make the choice visible.

This script is intentionally regex-based, not AST-based — it's a
fast pre-commit / CI guard, not a deep static analyser. False
positives are preferable to silent passes.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APP_DIR = ROOT / "app"


# ---------------------------------------------------------------------------
# Rule 1 — direct connection strings to raw observability stack
# ---------------------------------------------------------------------------
# Match `:9090`, `:3100`, `:16686` when preceded by something that looks
# like a host or URL (e.g. `prometheus:9090`, `localhost:9090`, `:9090/api`).
# The MCP ports (:809x, :8200, :8500) and the triage service's own port
# (:8090) are explicitly excluded.
_DIRECT_OBSERVABILITY_PORTS = re.compile(
    r"[a-z0-9_\-./]:(9090|3100|16686)(?![0-9])", re.IGNORECASE
)

# `/api/v1/query` is the Prometheus HTTP API path; the MCP wraps it but
# doesn't expose this path. So a hit on `/api/v1/query` outside the MCP
# servers themselves means direct Prometheus.
_PROMETHEUS_API_PATH = re.compile(r"/api/v1/query")

# Files allowed to declare or use raw observability URLs / API paths.
# Each entry needs a one-line rationale.
_ALLOW_DIRECT_OBSERVABILITY = {
    "app/config.py":            "settings fields carrying raw URLs — config, not calls",
    "app/drain_analyzer.py":    "Drain3 background poller — its INPUT path; the LLM never sees its raw lines, only the aggregated anomaly signal",
    "app/startup_backfill.py":  "boot-time exempt — pre-load rca_history from Grafana datasource proxy at lifespan startup",
}


# ---------------------------------------------------------------------------
# Rule 2 — direct aiosqlite import
# ---------------------------------------------------------------------------
_AIOSQLITE_IMPORT = re.compile(r"^\s*import\s+aiosqlite\b|^\s*from\s+aiosqlite\b")
_ALLOW_AIOSQLITE = {
    "app/rca_store.py",   # canonical writer — the MCP reads through this file
    "app/main.py",        # boot-time exempt (lifespan handler may open DB)
}


# ---------------------------------------------------------------------------
# Rule 3 — exemplar in-process import
# ---------------------------------------------------------------------------
_EXEMPLAR_IMPORT = re.compile(
    r"^\s*from\s+app\.exemplars\b|^\s*from\s+app\s+import\s+exemplars\b"
)
_ALLOW_EXEMPLAR_IMPORT = {
    "app/exemplars/__init__.py",   # the module itself
    "app/exemplars.py",            # legacy single-file location, if it exists
    "app/bounded_agency.py",       # documented exemption — exemplars are config
    "app/llm_client.py",           # documented exemption — same rationale
    "app/pipeline.py",             # documented exemption — same rationale
}


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def _relative(path: Path) -> str:
    return str(path.relative_to(ROOT))


def check_file(path: Path) -> list[tuple[str, int, str]]:
    """Return a list of (file, line, rule) tuples for any violations."""
    rel = _relative(path)
    findings: list[tuple[str, int, str]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return findings

    for lineno, line in enumerate(text.splitlines(), start=1):
        # Skip comments and docstrings (best-effort — line-level only)
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        # Rule 1 — direct observability port / Prometheus API path
        if rel not in _ALLOW_DIRECT_OBSERVABILITY:
            if _DIRECT_OBSERVABILITY_PORTS.search(line):
                findings.append((rel, lineno, "direct-observability-port"))
            if _PROMETHEUS_API_PATH.search(line):
                findings.append((rel, lineno, "direct-prometheus-api-path"))

        # Rule 2 — aiosqlite import
        if _AIOSQLITE_IMPORT.match(line) and rel not in _ALLOW_AIOSQLITE:
            findings.append((rel, lineno, "direct-aiosqlite-import"))

        # Rule 3 — exemplar in-process import
        if _EXEMPLAR_IMPORT.match(line) and rel not in _ALLOW_EXEMPLAR_IMPORT:
            findings.append((rel, lineno, "direct-exemplar-import"))

    return findings


def main() -> int:
    if not APP_DIR.is_dir():
        print(f"FATAL: {APP_DIR} not found", file=sys.stderr)
        return 2

    all_findings: list[tuple[str, int, str]] = []
    for path in sorted(APP_DIR.rglob("*.py")):
        all_findings.extend(check_file(path))

    if not all_findings:
        print(f"OK — MCP-only invariant clean across {APP_DIR.relative_to(ROOT)}/")
        return 0

    print(f"FAIL — MCP-only invariant violated ({len(all_findings)} finding(s)):")
    for rel, lineno, rule in all_findings:
        print(f"  {rel}:{lineno}  [{rule}]")
    print()
    print(
        "If this violation is legitimate (boot-time code, canonical writer,\n"
        "documented exemption), edit scripts/check_mcp_invariant.py and add\n"
        "the file to the appropriate ALLOW set with a one-line rationale.\n"
        "Never silently exempt by deleting the rule — make the choice visible."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
