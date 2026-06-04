"""FE-H2 (2026-06-04) — href-scheme allowlist (defense-in-depth XSS).

Every URL emitted into a `window.CIRES_*` link or `evidence[].link` eventually
renders as a raw `<a href>`. `_safe_script_json` only neutralises `</script>`
breakout inside the JSON blob — it does NOTHING for the href scheme, so a
`javascript:`/`data:`/`vbscript:` URL would render as a live 1-click XSS sink.

`_safe_http_url` is the server-side chokepoint (applied in `_build_cires_links`
and the evidence-link builder); atoms.jsx `safeHref` is the client backstop.
These tests pin the server allowlist + prove a crafted link can't survive into
the transformed row / CIRES_LINKS.
"""
from __future__ import annotations

from app.main import _build_cires_links, _safe_http_url, _v2_transform_row


# ── helper unit tests ──────────────────────────────────────────────────────

def test_http_and_https_pass_through():
    assert _safe_http_url("http://grafana.local/d/x") == "http://grafana.local/d/x"
    assert _safe_http_url("https://grafana.local/d/x") == "https://grafana.local/d/x"


def test_protocol_relative_allowed():
    assert _safe_http_url("//grafana.local/d/x") == "//grafana.local/d/x"


def test_javascript_scheme_collapses_to_hash():
    assert _safe_http_url("javascript:alert(1)") == "#"
    assert _safe_http_url("JavaScript:alert(1)") == "#"


def test_data_and_vbscript_schemes_collapse():
    assert _safe_http_url("data:text/html,<script>alert(1)</script>") == "#"
    assert _safe_http_url("vbscript:msgbox(1)") == "#"


def test_control_char_smuggled_scheme_collapses():
    # "java\tscript:" — browsers strip the tab and execute; allowlist rejects.
    assert _safe_http_url("java\tscript:alert(1)") == "#"
    assert _safe_http_url("java\nscript:alert(1)") == "#"


def test_empty_none_and_hash_return_hash():
    assert _safe_http_url("") == "#"
    assert _safe_http_url("   ") == "#"
    assert _safe_http_url("#") == "#"
    assert _safe_http_url(None) == "#"
    assert _safe_http_url(12345) == "#"


def test_relative_path_collapses():
    # An unexpected relative/scheme-less URL is not a deep link we emit.
    assert _safe_http_url("/dashboard") == "#"
    assert _safe_http_url("ftp://x") == "#"


# ── chokepoint integration: a crafted link never survives ────────────────────

def test_evidence_link_with_javascript_scheme_is_dropped():
    """A stored evidence row carrying a javascript: link must be neutralised
    by the _v2_transform_row evidence builder."""
    import json
    row = {
        "id": "deadbeef-0000-0000-0000-000000000000",
        "alert_name": "HighCpuUsage",
        "affected_service": "k3s-node",
        "rca_report": "named cause",
        "evidence": json.dumps([
            {"source": "prom", "text": "cpu high", "link": "javascript:alert(document.cookie)"},
        ]),
    }
    out = _v2_transform_row(row)
    links = [e.get("link") for e in out.get("evidence", []) if isinstance(e, dict)]
    assert links, "expected at least one evidence row"
    for link in links:
        assert not link.lower().startswith("javascript:")
    assert "javascript:alert(document.cookie)" not in links


def test_build_cires_links_only_emits_http():
    out = _build_cires_links({"alertName": "HighCpuUsage", "component": "k3s-node"})
    for v in out.values():
        assert v == "#" or v.lower().startswith(("http://", "https://", "//")), v
