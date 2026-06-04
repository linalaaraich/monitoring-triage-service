"""XSS regression — REAL DATA payload surface (2026-06-04).

Prior sessions hardened two surfaces:
  - `_safe_script_json` escapes < > & + line/paragraph separators for every
    window.CIRES_* inline-<script> JSON blob (breakout defense).
  - `_safe_http_url` / atoms.jsx `safeHref` allowlist evidence/CIRES link
    schemes (javascript:/data:/vbscript: → "#").

There is already a test for the `?q=` query surface (test_dashboard_search /
the filters tests) and unit tests for the two helpers (test_safe_href_scheme).
What was MISSING: a test that drives malicious content through the REAL data
payload fields the dashboard actually renders — alert name/text, RCA report
prose, log lines, evidence link URLs, affected_service — and asserts the
end-to-end rendered HTML (the actual /dashboard and /dashboard/alert/{id}
responses) contains no XSS breakout.

This test plants a hostile row in the store, renders both pages through the
real ASGI app, and asserts:
  - NO unescaped `</script>` after our window.CIRES_* injection blobs
  - NO raw `javascript:` (or data:/vbscript:) href reaches the payload
  - the unicode line/paragraph separators are escaped (not raw)
  - the payload IS present (escaped) — i.e. we didn't just drop the row
"""
from __future__ import annotations

import json
import os
import tempfile
import uuid

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as app_main
from app.models import RCARecord
from app.rca_store import RCAStore, _utc_now


# The hostile fragments we smuggle through each real payload field.
SCRIPT_BREAKOUT = "</script><img src=x onerror=alert(1)>"
JS_HREF = "javascript:alert(document.cookie)"
DATA_HREF = "data:text/html,<script>alert(1)</script>"
LINE_SEP = " "  # JS line separator — raw, this terminates a JS string
PARA_SEP = " "


@pytest_asyncio.fixture
async def hostile_store():
    """A store containing one row whose EVERY rendered field carries a
    different XSS payload."""
    db_path = os.path.join(tempfile.gettempdir(), f"test_xss_{uuid.uuid4().hex}.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()

    rec = RCARecord(
        id="badc0ffe-0000-4000-8000-000000000001",
        alert_name=f"Pwn{SCRIPT_BREAKOUT}Alert",
        affected_service=f"svc{SCRIPT_BREAKOUT}",
        alert_fingerprint="fp-xss-1",
        severity="critical",
        triage_decision="investigate",
        llm_verdict="escalate",
        # RCA report prose with a script breakout + unicode separators.
        rca_report=f"Root cause: heap exhausted {SCRIPT_BREAKOUT} {LINE_SEP}{PARA_SEP} end.",
        # llm_reasoning becomes reasoning steps + log-ish lines on the page.
        # NOTE: hostile SCHEME payloads (javascript:/data:) belong only on the
        # evidence/link href surfaces below — in a text field they are inert,
        # rendered as an escaped JSON string value, never as an href.
        llm_reasoning=f"log line one {SCRIPT_BREAKOUT}\nlog line two {SCRIPT_BREAKOUT}",
        action_taken="emailed",
        rca_quality="actionable",
        suggested_actions=json.dumps([f"run {SCRIPT_BREAKOUT}"]),
        # Evidence carries hostile link schemes through the real evidence path —
        # the actual href surface that _safe_http_url guards.
        evidence=json.dumps([
            {"source": "prom", "text": f"cpu {SCRIPT_BREAKOUT}", "link": JS_HREF},
            {"source": "loki", "text": "mem", "link": DATA_HREF},
        ]),
    )
    rec.timestamp = _utc_now()
    await s.save_decision(rec)
    yield s
    await s.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest_asyncio.fixture
async def client(hostile_store):
    """Wire the hostile store + a real (empty) drain analyzer into the app."""
    saved_store = app_main._store
    saved_drain = app_main._drain
    app_main._store = hostile_store
    # Real analyzer would be fine, but a tiny stub keeps the test hermetic and
    # avoids touching the drain3 state dir.
    class _DrainStub:
        def get_stats(self, *a, **k):
            return {"total_clusters": 0, "total_anomalies": 0,
                    "recent_anomaly_rate": 0.0, "total_lines_processed": 0,
                    "top_new_patterns_per_service": {}}
    app_main._drain = _DrainStub()
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    app_main._store = saved_store
    app_main._drain = saved_drain


def _assert_no_xss_breakout(html: str):
    """Shared assertions for any rendered page that injects the hostile row."""
    # The hostile row's content must NOT appear as a raw </script> close tag.
    # Our own template legitimately contains </script> tags closing the inline
    # blocks — so we specifically assert the BREAKOUT marker (which pairs the
    # close tag with an <img onerror>) never appears verbatim.
    assert SCRIPT_BREAKOUT not in html, "raw </script><img> breakout leaked into HTML"
    assert "<img src=x onerror=alert(1)>" not in html, "raw onerror img leaked"
    # The escaped form MUST be what got emitted (proves the data was rendered,
    # just neutralised).
    assert "\\u003c/script\\u003e\\u003cimg" in html or "\\u003c/script" in html, \
        "expected the escaped \\u003c/script form in the JSON blob"
    # No live javascript:/data:/vbscript: href reaches the page.
    assert "javascript:alert(document.cookie)" not in html
    assert JS_HREF not in html
    assert DATA_HREF not in html
    # Unicode line/paragraph separators must be escaped, never raw (raw ones
    # terminate the JS string literal mid-blob = breakout).
    assert LINE_SEP not in html, "raw U+2028 line separator leaked into a script blob"
    assert PARA_SEP not in html, "raw U+2029 paragraph separator leaked into a script blob"


@pytest.mark.asyncio
async def test_dashboard_payload_surface_no_xss(client):
    resp = await client.get("/dashboard")
    assert resp.status_code == 200
    html = resp.text
    # Sanity: the hostile row actually made it onto the page (escaped form).
    assert "window.CIRES_ALERTS" in html
    _assert_no_xss_breakout(html)


@pytest.mark.asyncio
async def test_detail_page_payload_surface_no_xss(client):
    # short_id is the first 8 chars of the UUID.
    resp = await client.get("/dashboard/alert/badc0ffe")
    assert resp.status_code == 200, resp.text[:300]
    html = resp.text
    assert "window.CIRES_ALERT" in html
    _assert_no_xss_breakout(html)


@pytest.mark.asyncio
async def test_evidence_links_neutralised_in_detail(client):
    """The evidence javascript:/data: hrefs must be collapsed to '#' before
    reaching window.CIRES_ALERT.evidence[].link."""
    resp = await client.get("/dashboard/alert/badc0ffe")
    assert resp.status_code == 200
    html = resp.text
    # No hostile scheme survives anywhere in the evidence payload.
    assert "javascript:" not in html.lower()
    assert "data:text/html" not in html.lower()
    assert "vbscript:" not in html.lower()
