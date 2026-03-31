import asyncio

import pytest
import pytest_asyncio

from app.dedup import DedupManager


@pytest.fixture
def dedup():
    return DedupManager(window_seconds=2)


@pytest.mark.asyncio
async def test_first_alert_not_duplicate(dedup):
    result = await dedup.check("HighP95Latency", "10.0.2.30:8080", "firing")
    assert result is False


@pytest.mark.asyncio
async def test_second_alert_is_duplicate(dedup):
    await dedup.check("HighP95Latency", "10.0.2.30:8080", "firing")
    result = await dedup.check("HighP95Latency", "10.0.2.30:8080", "firing")
    assert result is True


@pytest.mark.asyncio
async def test_different_alert_not_duplicate(dedup):
    await dedup.check("HighP95Latency", "10.0.2.30:8080", "firing")
    result = await dedup.check("HighCpuUsage", "10.0.2.30:8080", "firing")
    assert result is False


@pytest.mark.asyncio
async def test_different_instance_not_duplicate(dedup):
    await dedup.check("HighP95Latency", "10.0.2.30:8080", "firing")
    result = await dedup.check("HighP95Latency", "10.0.2.31:8080", "firing")
    assert result is False


@pytest.mark.asyncio
async def test_expired_window_not_duplicate(dedup):
    await dedup.check("HighP95Latency", "10.0.2.30:8080", "firing")
    await asyncio.sleep(2.1)
    result = await dedup.check("HighP95Latency", "10.0.2.30:8080", "firing")
    assert result is False


@pytest.mark.asyncio
async def test_resolved_then_refired_reprocessed(dedup):
    await dedup.check("HighP95Latency", "10.0.2.30:8080", "firing")
    await dedup.check("HighP95Latency", "10.0.2.30:8080", "resolved")
    result = await dedup.check("HighP95Latency", "10.0.2.30:8080", "firing")
    assert result is False


@pytest.mark.asyncio
async def test_concurrent_checks_safe(dedup):
    """Multiple concurrent checks on the same alert should not race."""
    results = await asyncio.gather(
        *[dedup.check("HighP95Latency", "10.0.2.30:8080", "firing") for _ in range(10)]
    )
    # Exactly one should be non-duplicate (first one), rest should be duplicates
    assert results.count(False) == 1
    assert results.count(True) == 9
