"""
Unit тесты для dns_utils.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from utils.dns_utils import fetch_dns


class TestFetchDNS:
    """Тесты для функции fetch_dns."""
    
    @pytest.mark.asyncio
    async def test_fetch_dns_success(self):
        """Тест успешного получения DNS записей."""
        with patch('utils.dns_utils.dns.asyncresolver.Resolver') as mock_resolver_class:
            mock_resolver = AsyncMock()
            mock_resolver_class.return_value = mock_resolver
            
            # Мокаем ответы DNS
            mock_a = MagicMock()
            mock_a.to_text.return_value = "1.2.3.4"
            
            mock_mx = MagicMock()
            mock_mx.to_text.return_value = "10 mail.example.com."
            
            mock_ns = MagicMock()
            mock_ns.to_text.return_value = "ns1.example.com."
            
            mock_resolver.resolve.side_effect = [
                [mock_a],  # A запись
                [],  # AAAA запись (пусто)
                [mock_mx],  # MX запись
                [mock_ns],  # NS запись
            ]
            
            result = await fetch_dns("example.com", timeout=5)
            
            assert "A" in result
            assert result["A"] == ["1.2.3.4"]
            assert "AAAA" in result
            assert result["AAAA"] == []
            assert "MX" in result
            assert "NS" in result
    
    @pytest.mark.asyncio
    async def test_fetch_dns_timeout(self):
        """Тест таймаута при получении DNS."""
        with patch('utils.dns_utils.dns.asyncresolver.Resolver') as mock_resolver_class:
            mock_resolver = AsyncMock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve.side_effect = TimeoutError("DNS timeout")
            
            result = await fetch_dns("example.com", timeout=1)
            
            # При ошибке должен вернуться пустой словарь или словарь с пустыми списками
            assert isinstance(result, dict)
    
    @pytest.mark.asyncio
    async def test_fetch_dns_exception(self):
        """Тест обработки исключений."""
        with patch('utils.dns_utils.dns.asyncresolver.Resolver') as mock_resolver_class:
            mock_resolver = AsyncMock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve.side_effect = Exception("DNS error")
            
            result = await fetch_dns("example.com", timeout=5)
            
            # При ошибке должен вернуться пустой словарь
            assert isinstance(result, dict)





