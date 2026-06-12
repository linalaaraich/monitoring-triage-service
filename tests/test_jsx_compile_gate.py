"""JSX compile gate (2026-06-12).

Every .jsx under app/static/design is compiled in the browser by
@babel/standalone at page load. A syntax error in ANY of them means React
never mounts and the page renders blank while still returning HTTP 200 —
exactly what happened to every individual alert page when 7664ec0 left a
stray ``))}`` in detail.jsx (the map's expression-body closer survived a
conversion to a block body).

This test runs scripts/check_jsx_compiles.js under node with the same
compiler the browser uses. It looks for @babel/standalone next to the
repo and in a couple of known local harness locations; CI installs it
explicitly (see .github/workflows/ci.yml) so the gate never skips there.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check_jsx_compiles.js"
DESIGN_DIR = REPO / "app" / "static" / "design"

# Places @babel/standalone may already live when running outside CI.
_CANDIDATE_NODE_PATHS = [
    REPO / "node_modules",
    Path("/tmp/render-harness/node_modules"),
]


def _babel_node_path() -> str | None:
    for p in _CANDIDATE_NODE_PATHS:
        if (p / "@babel" / "standalone").is_dir():
            return str(p)
    return None


def test_all_design_jsx_files_compile():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed — JSX gate enforced in CI")
    node_path = _babel_node_path()
    if node_path is None:
        pytest.skip("@babel/standalone not found — JSX gate enforced in CI")

    env = {**os.environ, "NODE_PATH": node_path}
    proc = subprocess.run(
        [node, str(SCRIPT), str(DESIGN_DIR)],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    assert proc.returncode == 0, (
        f"JSX compile gate failed:\n{proc.stdout}\n{proc.stderr}"
    )


def test_gate_covers_every_design_file():
    # The gate is only meaningful if the directory it scans is the one the
    # pages actually load from — guard against a silent rename/move.
    jsx = sorted(p.name for p in DESIGN_DIR.glob("*.jsx"))
    assert "detail.jsx" in jsx and "atoms.jsx" in jsx and "sidebar.jsx" in jsx
    assert len(jsx) >= 6, f"expected the full design set, found {jsx}"
