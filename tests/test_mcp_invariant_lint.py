"""S3-HF-08 — self-test for the MCP invariant lint.

Two concerns:
  1. The lint itself runs clean on the current codebase (we don't ship
     a CI guard that fails on day one).
  2. The lint actually catches synthesised violations — so a regression
     wouldn't slip past silently.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
LINT_SCRIPT = REPO / "scripts" / "check_mcp_invariant.py"


def test_lint_clean_on_current_codebase():
    """The lint must currently pass — exit 0 — on the codebase as
    committed. If this fails, either a real violation was introduced
    (fix the code) or a legitimate exemption is missing (edit the lint's
    ALLOW set with a rationale)."""
    result = subprocess.run(
        [sys.executable, str(LINT_SCRIPT)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"Lint failed unexpectedly. stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "MCP-only invariant clean" in result.stdout


def test_lint_catches_synthetic_violation(tmp_path, monkeypatch):
    """Drop a synthesised offender file into a stub repo, point the lint
    at it, and confirm it exits non-zero with the right rule name."""
    fake_repo = tmp_path / "fake_repo"
    (fake_repo / "app").mkdir(parents=True)
    (fake_repo / "scripts").mkdir(parents=True)
    # Copy the lint script in
    (fake_repo / "scripts" / "check_mcp_invariant.py").write_text(
        LINT_SCRIPT.read_text()
    )
    # Drop a synthesised violation
    (fake_repo / "app" / "naughty.py").write_text(
        "import httpx\n"
        "async def go():\n"
        "    async with httpx.AsyncClient() as c:\n"
        "        await c.get('http://prometheus:9090/api/v1/query', params={'query': 'up'})\n"
    )
    result = subprocess.run(
        [sys.executable, str(fake_repo / "scripts" / "check_mcp_invariant.py")],
        capture_output=True, text=True, cwd=str(fake_repo),
    )
    assert result.returncode == 1
    assert "naughty.py" in result.stdout
    # The :9090 hit and the /api/v1/query hit should both surface.
    assert "direct-observability-port" in result.stdout
    assert "direct-prometheus-api-path" in result.stdout


def test_lint_catches_synthetic_aiosqlite_import(tmp_path):
    fake_repo = tmp_path / "fake_repo"
    (fake_repo / "app").mkdir(parents=True)
    (fake_repo / "scripts").mkdir(parents=True)
    (fake_repo / "scripts" / "check_mcp_invariant.py").write_text(
        LINT_SCRIPT.read_text()
    )
    (fake_repo / "app" / "rogue_db.py").write_text(
        "import aiosqlite\n"
        "async def read_decisions():\n"
        "    async with aiosqlite.connect('/tmp/x.db') as db:\n"
        "        return await db.execute('SELECT * FROM rca_history')\n"
    )
    result = subprocess.run(
        [sys.executable, str(fake_repo / "scripts" / "check_mcp_invariant.py")],
        capture_output=True, text=True, cwd=str(fake_repo),
    )
    assert result.returncode == 1
    assert "rogue_db.py" in result.stdout
    assert "direct-aiosqlite-import" in result.stdout


def test_lint_catches_synthetic_exemplar_import(tmp_path):
    fake_repo = tmp_path / "fake_repo"
    (fake_repo / "app").mkdir(parents=True)
    (fake_repo / "scripts").mkdir(parents=True)
    (fake_repo / "scripts" / "check_mcp_invariant.py").write_text(
        LINT_SCRIPT.read_text()
    )
    (fake_repo / "app" / "new_caller.py").write_text(
        "from app.exemplars import get_by_id\n"
        "def use():\n"
        "    return get_by_id('oom-loop')\n"
    )
    result = subprocess.run(
        [sys.executable, str(fake_repo / "scripts" / "check_mcp_invariant.py")],
        capture_output=True, text=True, cwd=str(fake_repo),
    )
    assert result.returncode == 1
    assert "new_caller.py" in result.stdout
    assert "direct-exemplar-import" in result.stdout
