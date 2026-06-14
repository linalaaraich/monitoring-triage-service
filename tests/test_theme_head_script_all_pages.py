"""FE-L1 (2026-06-04) — light mode must apply platform-wide.

`_CIRES_THEME_HEAD_SCRIPT` mirrors localStorage["obs-rca-theme"] onto
`<html data-theme>` before paint so the tokens.css light overrides (scoped to
`html[data-theme="light"]` / `.cires[data-theme="light"]`) take effect. It was
previously included on ONLY the 3 React routes (dashboard/detail/rate), so the
server-rendered kpi/services/alerts/stats pages + the Sprint-5 stub pages were
dark-only — an operator who toggled light on /dashboard saw dark everywhere
else. These tests pin the script into the <head> of every tokens.css page so
it can't regress.
"""
from __future__ import annotations

import os
import tempfile

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import main as app_main
from app.rca_store import RCAStore


# Every server-rendered page that links tokens.css and should inherit the
# operator's theme choice. (The React routes already had the script; included
# here so the guard covers them too.)
_THEME_PAGES = [
    "/dashboard",
    "/dashboard/kpi",
    "/dashboard/alerts",
    "/dashboard/incidents",
    "/dashboard/anomalies",
    "/dashboard/drain3",
    "/dashboard/integrations",
]


@pytest_asyncio.fixture
async def themed_client():
    db_path = os.path.join(tempfile.gettempdir(), "test_theme_head_script.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    store = RCAStore(db_path)
    await store.init_db()
    saved = app_main._store
    app_main._store = store
    transport = ASGITransport(app=app_main.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app_main._store = saved
    await store.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.mark.asyncio
@pytest.mark.parametrize("path", _THEME_PAGES)
async def test_theme_head_script_present_in_head(themed_client, path):
    r = await themed_client.get(path)
    assert r.status_code == 200, f"{path} did not 200"
    body = r.text
    assert "</head>" in body, f"{path} has no </head>"
    head = body.split("</head>", 1)[0]
    # The script reads the obs-rca-theme key and sets data-theme on <html>
    # before paint — both markers must be in <head>.
    assert "obs-rca-theme" in head, f"{path} missing obs-rca-theme key in <head>"
    assert 'setAttribute("data-theme"' in head, (
        f"{path} missing data-theme head-script"
    )
