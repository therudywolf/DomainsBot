"""
Unit тесты для cache.
"""

import pytest
import asyncio
import time
import uuid
from utils.cache import ttl_cache, _memory_cache


class TestTTLCache:
    """Тесты для TTL кэша."""

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        """Тест попадания в кэш — функция вызывается один раз."""
        call_count = 0
        tag = uuid.uuid4().hex

        @ttl_cache(ttl=3600)
        async def cached_fn(tag: str, x: int) -> int:
            nonlocal call_count
            call_count += 1
            return x * 2

        result1 = await cached_fn(tag, 5)
        assert result1 == 10
        assert call_count == 1

        result2 = await cached_fn(tag, 5)
        assert result2 == 10
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_cache_miss_different_args(self):
        """Тест промаха кэша при разных аргументах."""
        call_count = 0
        tag = uuid.uuid4().hex

        @ttl_cache(ttl=3600)
        async def cached_fn(tag: str, x: int) -> int:
            nonlocal call_count
            call_count += 1
            return x * 2

        await cached_fn(tag, 5)
        await cached_fn(tag, 10)

        assert call_count == 2

    @pytest.mark.asyncio
    async def test_cache_expiry(self):
        """Тест истечения TTL кэша."""
        call_count = 0
        tag = uuid.uuid4().hex

        @ttl_cache(ttl=0)
        async def cached_fn(tag: str, x: int) -> int:
            nonlocal call_count
            call_count += 1
            return x * 2

        await cached_fn(tag, 5)
        assert call_count == 1

        await asyncio.sleep(0.05)

        await cached_fn(tag, 5)
        assert call_count == 2
