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
        limiter = AsyncRateLimiter(requests=5, window=60)
        user_id = 123
        
        # Первые 5 запросов должны быть разрешены
        for i in range(5):
            assert await limiter.is_allowed(user_id) is True
    
    @pytest.mark.asyncio
    async def test_rate_limit_blocks_excess(self):
        """Тест блокировки запросов сверх лимита."""
        limiter = AsyncRateLimiter(requests=3, window=60)
        user_id = 123
        
        # Первые 3 запроса разрешены
        for i in range(3):
            assert await limiter.is_allowed(user_id) is True
        
        # 4-й запрос должен быть заблокирован
        assert await limiter.is_allowed(user_id) is False
    
    @pytest.mark.asyncio
    async def test_rate_limit_different_users(self):
        """Тест независимых лимитов для разных пользователей."""
        limiter = AsyncRateLimiter(requests=2, window=60)
        
        # Каждый пользователь имеет свой лимит
        assert await limiter.is_allowed(1) is True
        assert await limiter.is_allowed(1) is True
        assert await limiter.is_allowed(1) is False
        
        assert await limiter.is_allowed(2) is True
        assert await limiter.is_allowed(2) is True
        assert await limiter.is_allowed(2) is False
    
    @pytest.mark.asyncio
    async def test_rate_limit_window_expiry(self):
        """Тест истечения окна лимита."""
        limiter = AsyncRateLimiter(requests=2, window=0.1)  # Короткое окно для теста
        user_id = 123
        
        # Используем лимит
        assert await limiter.is_allowed(user_id) is True
        assert await limiter.is_allowed(user_id) is True
        assert await limiter.is_allowed(user_id) is False
        
        # Ждем истечения окна
        await asyncio.sleep(0.2)
        
        # После истечения окна запросы снова разрешены
        assert await limiter.is_allowed(user_id) is True
    
    @pytest.mark.asyncio
    async def test_get_remaining(self):
        """Тест получения оставшихся запросов."""
        limiter = AsyncRateLimiter(requests=5, window=60)
        user_id = 123
        
        # До использования
        remaining = await limiter.get_remaining(user_id)
        assert remaining == 5
        
        # После использования
        await limiter.is_allowed(user_id)
        remaining = await limiter.get_remaining(user_id)
        assert remaining == 4





