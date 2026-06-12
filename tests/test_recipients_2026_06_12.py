"""2026-06-12 (Lina): multiple, UI-configurable escalation email recipients."""
import os
import tempfile

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock

from app.notifier import EmailNotifier
from app.rca_store import RCAStore


@pytest_asyncio.fixture
async def store():
    db_path = os.path.join(tempfile.gettempdir(), "test_recipients.db")
    if os.path.exists(db_path):
        os.unlink(db_path)
    s = RCAStore(db_path)
    await s.init_db()
    yield s
    await s.close()
    os.unlink(db_path)


def test_parse_emails_splits_dedups_lowercases():
    assert EmailNotifier._parse_emails("A@x.com, b@Y.com; a@x.com  c@z.com") == [
        "a@x.com", "b@y.com", "c@z.com"]
    assert EmailNotifier._parse_emails("") == []
    assert EmailNotifier._parse_emails("notanemail") == []


@pytest.mark.asyncio
async def test_resolve_recipients_unions_env_and_store(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "notification_email", "oncall@cires.ma, lead@cires.ma")
    n = EmailNotifier.__new__(EmailNotifier)
    n.store = MagicMock()
    n.store.list_recipients = AsyncMock(return_value=[
        {"email": "noc@cires.ma", "label": "NOC"},
        {"email": "lead@cires.ma", "label": None},  # dup of env — must not double
    ])
    out = await n._resolve_recipients()
    assert out == ["oncall@cires.ma", "lead@cires.ma", "noc@cires.ma"]


@pytest.mark.asyncio
async def test_resolve_recipients_env_only_when_no_store(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "notification_email", "solo@cires.ma")
    n = EmailNotifier.__new__(EmailNotifier)
    n.store = None
    out = await n._resolve_recipients()
    assert out == ["solo@cires.ma"]


@pytest.mark.asyncio
async def test_store_recipient_crud(store):
    assert await store.list_recipients() == []
    await store.add_recipient("Team@CIRES.ma", "Team")
    rows = await store.list_recipients()
    assert len(rows) == 1 and rows[0]["email"] == "team@cires.ma" and rows[0]["label"] == "Team"
    # idempotent upsert (no duplicate)
    await store.add_recipient("team@cires.ma", "Team NOC")
    rows = await store.list_recipients()
    assert len(rows) == 1 and rows[0]["label"] == "Team NOC"
    assert await store.remove_recipient("team@cires.ma") == 1
    assert await store.list_recipients() == []
    assert await store.remove_recipient("team@cires.ma") == 0  # already gone


def test_email_regex_validates():
    from app.main import _EMAIL_RE
    assert _EMAIL_RE.match("a@b.co")
    assert _EMAIL_RE.match("first.last@cires.ma")
    assert not _EMAIL_RE.match("bad")
    assert not _EMAIL_RE.match("a@b")
    assert not _EMAIL_RE.match("a @b.co")
