"""
Unit тесты для cache.
"""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
from utils.cache import ttl_cache


class TestTTLCache:
    """Тесты для TTL кэша."""
    
    @pytest.fixture
    def temp_dir(self):
        """Создает временную директорию для тестов."""
        temp_path = Path(tempfile.mkdtemp())
        yield temp_path
        shutil.rmtree(temp_path)
    
    @pytest.mark.asyncio
    async def test_cache_hit(self, temp_dir):
        """Тест попадания в кэш."""
        call_count = 0
        
        @ttl_cache(ttl=3600)
        async def test_func(x: int) -> int:
            nonlocal call_count
            call_count += 1
            return x * 2
        
        # Первый вызов - должен выполниться функция
        result1 = await test_func(5)
        assert result1 == 10
        assert call_count == 1
        
        # Второй вызов - должен вернуть из кэша
        result2 = await test_func(5)
        assert result2 == 10
        assert call_count == 1  # Функция не должна вызываться снова
    
    @pytest.mark.asyncio
    async def test_cache_miss_different_args(self, temp_dir):
        """Тест промаха кэша при разных аргументах."""
        call_count = 0
        
        @ttl_cache(ttl=3600)
        async def test_func(x: int) -> int:
            nonlocal call_count
            call_count += 1
            return x * 2
        
        await test_func(5)
        await test_func(10)  # Другой аргумент
        
        assert call_count == 2
    
    @pytest.mark.asyncio
    async def test_cache_expiry(self, temp_dir):
        """Тест истечения TTL кэша."""
        call_count = 0
        
        @ttl_cache(ttl=0.1)  # Очень короткий TTL для теста
        async def test_func(x: int) -> int:
            nonlocal call_count
            call_count += 1
            return x * 2
        
        # Первый вызов
        await test_func(5)
        assert call_count == 1
        
        # Ждем истечения TTL
        await asyncio.sleep(0.2)
        
        # Второй вызов после истечения TTL
        await test_func(5)
        assert call_count == 2

