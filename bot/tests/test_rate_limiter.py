"""
Unit тесты для rate_limiter.
"""

import pytest
import asyncio
from utils.rate_limiter import AsyncRateLimiter


class TestAsyncRateLimiter:
    """Тесты для AsyncRateLimiter."""
    
    @pytest.mark.asyncio
    async def test_rate_limit_allows_requests(self):
        """Тест разрешения запросов в пределах лимита."""
        limiter = AsyncRateLimiter(max_requests=5, window_seconds=60)
        user_id = 123
        
        for i in range(5):
            assert await limiter.is_allowed(user_id) is True
    
    @pytest.mark.asyncio
    async def test_rate_limit_blocks_excess(self):
        """Тест блокировки запросов сверх лимита."""
        limiter = AsyncRateLimiter(max_requests=3, window_seconds=60)
        user_id = 123
        
        for i in range(3):
            assert await limiter.is_allowed(user_id) is True
        
        assert await limiter.is_allowed(user_id) is False
    
    @pytest.mark.asyncio
    async def test_rate_limit_different_users(self):
        """Тест независимых лимитов для разных пользователей."""
        limiter = AsyncRateLimiter(max_requests=2, window_seconds=60)
        
        assert await limiter.is_allowed(1) is True
        assert await limiter.is_allowed(1) is True
        assert await limiter.is_allowed(1) is False
        
        assert await limiter.is_allowed(2) is True
        assert await limiter.is_allowed(2) is True
        assert await limiter.is_allowed(2) is False
    
    @pytest.mark.asyncio
    async def test_rate_limit_window_expiry(self):
        """Тест истечения окна лимита."""
        limiter = AsyncRateLimiter(max_requests=2, window_seconds=0.1)
        user_id = 123
        
        assert await limiter.is_allowed(user_id) is True
        assert await limiter.is_allowed(user_id) is True
        assert await limiter.is_allowed(user_id) is False
        
        await asyncio.sleep(0.2)
        
        assert await limiter.is_allowed(user_id) is True
    
    @pytest.mark.asyncio
    async def test_get_remaining(self):
        """Тест получения оставшихся запросов."""
        limiter = AsyncRateLimiter(max_requests=5, window_seconds=60)
        user_id = 123
        
        remaining = await limiter.get_remaining(user_id)
        assert remaining == 5
        
        await limiter.is_allowed(user_id)
        remaining = await limiter.get_remaining(user_id)
        assert remaining == 4
