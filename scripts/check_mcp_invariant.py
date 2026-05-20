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

4. References to `settings.grafana_url` / `settings.loki_api_url` /
     `settings.jaeger_url` outside `startup_backfill.py` + `drain_analyzer.py`.
     Rule 1 catches raw ports but misses the Grafana datasource-proxy bypass
     on :3000 (the settings field carries that URL). Added 2026-05-20 after
     the fanout-agent hunt surfaced the gap.

5. Owner-gated yaml/json loads of in-tree config files. A second module
     loading `hallucination_blocklist.yaml`, `suggested_actions.yaml`,
     `library.yaml`, or `bypass_llm.yaml` outside its declared owner module
     is a silent bypass of the canonical owner — those YAML reads mutate
     the LLM output (drop actions, fill suggested_actions, set the exemplar
     block, gate the LLM call). Added 2026-05-20.

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
# Rule 4 — direct httpx calls to settings.{grafana,loki,jaeger}_url
# ---------------------------------------------------------------------------
# Surfaced 2026-05-20 fanout-hunt: Rule 1 catches raw ports :9090/:3100/:16686
# but misses the Grafana datasource-proxy bypass at port :3000 (which routes
# Prometheus queries through Grafana). The settings fields themselves carry
# the bypass URLs. A new caller of settings.grafana_url / settings.loki_api_url
# (note: distinct from settings.loki_mcp_url) / settings.jaeger_url that
# issues an HTTP request through them — outside the boot-time / Drain3-input
# paths — is a bypass the LLM-gathering path could exploit.
#
# The rule requires BOTH: (a) a reference to settings.{grafana,loki,jaeger}_url
# AND (b) an HTTP-call context on the same line — httpx.*, client.{get,post,…},
# requests.*, aiohttp.*, await *.get/post(. UI-link consumers (`<a href=…>`,
# action-template `{grafana}` substitutions, Jaeger trace permalinks in the
# notifier) are intentionally NOT flagged — they render URLs for operators
# to click, they don't fetch data through the URL.
_RAW_SETTINGS_URL_REF = re.compile(
    r"settings\.(grafana_url|loki_api_url|jaeger_url)\b"
)
_HTTP_CALL_CONTEXT = re.compile(
    r"\b(httpx|requests|aiohttp)\.\w+\s*\(|"
    r"\bclient\.(get|post|put|patch|delete|request|stream)\s*\(|"
    r"\bawait\s+\w+\.(get|post|put|patch|delete|request)\s*\("
)
_ALLOW_RAW_SETTINGS_URL = {
    "app/config.py":            "settings field declaration — config, not calls",
    "app/startup_backfill.py":  "boot-time exempt — Grafana datasource proxy backfill",
    "app/drain_analyzer.py":    "Drain3 INPUT path — see _ALLOW_DIRECT_OBSERVABILITY rationale",
}


# ---------------------------------------------------------------------------
# Rule 5 — owner-gated yaml/json reads of in-tree config files
# ---------------------------------------------------------------------------
# Surfaced 2026-05-20 fanout-hunt: response_validator, action_templates, and
# the exemplar loader each read a YAML file and the result mutates the LLM
# output (drops actions / fills suggested_actions / sets the exemplar prompt
# block). Today only the importing module reads each file, but the lint
# never asserts that — a second module loading the same YAML would be a
# silent bypass of the canonical owner.
#
# Each `(filename, owner_module)` pair below pins the file to its owner.
# yaml.safe_load / json.load of the keyed filename outside the owner is a
# bypass.
_YAML_OWNER_MAP: dict[str, str] = {
    "hallucination_blocklist.yaml": "app/response_validator.py",
    "suggested_actions.yaml":       "app/action_templates.py",
    "library.yaml":                 "app/exemplars/__init__.py",
    "bypass_llm.yaml":              "app/policy.py",  # US-3-CO13 placeholder (file may not yet exist)
}
_YAML_OR_JSON_LOAD = re.compile(
    r"\b(yaml\.safe_load|json\.load)\s*\("
)
# Best-effort filename detector — matches `…/<name>.yaml` or `<name>.yaml`
# referenced in the same line or the surrounding 3 lines.
_YAML_FILENAME = re.compile(r"([\w.-]+\.(?:yaml|yml|json))")


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

    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
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

        # Rule 4 — raw settings.*_url reference in an HTTP-call context
        if (
            rel not in _ALLOW_RAW_SETTINGS_URL
            and _RAW_SETTINGS_URL_REF.search(line)
            and _HTTP_CALL_CONTEXT.search(line)
        ):
            findings.append((rel, lineno, "raw-settings-url-fetch"))

        # Rule 5 — yaml/json load of an owner-gated config file
        # (look at the load call's line ±3 for a yaml filename)
        if _YAML_OR_JSON_LOAD.search(line):
            window_start = max(0, lineno - 4)
            window_end = min(len(lines), lineno + 3)
            window = "\n".join(lines[window_start:window_end])
            for fname in _YAML_FILENAME.findall(window):
                owner = _YAML_OWNER_MAP.get(fname)
                if owner and rel != owner:
                    findings.append(
                        (rel, lineno, f"owner-gated-yaml-load:{fname}→{owner}")
                    )

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
