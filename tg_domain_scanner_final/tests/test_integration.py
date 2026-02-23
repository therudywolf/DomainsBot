"""
Интеграционные тесты для бота.

Тестирует взаимодействие компонентов и обработчиков команд.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from aiogram import Bot
from aiogram.fsm.context import FSMContext
from aiogram.types import Message, User, Chat

from utils.domain_processor import validate_and_normalize_domains, check_single_domain
from utils.report_formatter import format_csv_report
import asyncio


class TestDomainProcessing:
    """Интеграционные тесты для обработки доменов."""
    
    @pytest.mark.asyncio
    async def test_validate_and_normalize_domains(self):
        """Тест валидации и нормализации доменов."""
        raw_text = "example.com, https://test.ru/path, invalid domain"
        domains, bad = validate_and_normalize_domains(raw_text)
        
        assert "example.com" in domains
        assert "test.ru" in domains
        # "invalid" and "domain" are separate tokens after split, both are bad
        assert len(bad) >= 1
    
    @pytest.mark.asyncio
    async def test_validate_urls_not_in_bad(self):
        """URLs that normalize successfully should NOT appear in bad list."""
        raw_text = "https://example.com/path?q=1 http://test.ru"
        domains, bad = validate_and_normalize_domains(raw_text)
        
        assert "example.com" in domains
        assert "test.ru" in domains
        assert len(bad) == 0
    
    @pytest.mark.asyncio
    async def test_format_csv_report(self):
        """Тест форматирования CSV отчета."""
        collected = [
            (
                "example.com",
                {"A": ["1.2.3.4"], "AAAA": [], "MX": [], "NS": []},
                {"CN": "example.com", "gost": True, "NotBefore": None, "NotAfter": None},
                True,
                "policy"
            )
        ]
        
        csv_bytes = format_csv_report(collected, brief=False)
        
        assert csv_bytes is not None
        assert len(csv_bytes) > 0
        assert b"example.com" in csv_bytes


class TestErrorHandling:
    """Тесты обработки ошибок."""
    
    @pytest.mark.asyncio
    async def test_graceful_degradation_dns_error(self):
        """Тест graceful degradation при ошибке DNS."""
        # Мокаем fetch_dns чтобы он выбрасывал исключение
        with patch('utils.domain_processor.fetch_dns', side_effect=Exception("DNS error")):
            semaphore = asyncio.Semaphore(10)
            
            # Функция должна обработать ошибку и вернуть частичный результат
            line, row = await check_single_domain("example.com", 123, semaphore, brief=False)
            
            assert line is not None
            assert row is not None
            # Домен должен быть в результате даже при ошибке
            assert row[0] == "example.com"
    
    @pytest.mark.asyncio
    async def test_graceful_degradation_ssl_error(self):
        """Тест graceful degradation при ошибке SSL."""
        with patch('utils.domain_processor.fetch_ssl', side_effect=Exception("SSL error")):
            semaphore = asyncio.Semaphore(10)
            
            line, row = await check_single_domain("example.com", 123, semaphore, brief=False)
            
            assert line is not None
            assert row is not None
            assert row[0] == "example.com"


class TestMonitoringIntegration:
    """Интеграционные тесты для мониторинга."""
    
    @pytest.mark.asyncio
    async def test_monitoring_state_management(self):
        """Тест управления состоянием мониторинга."""
        from utils.monitoring import (
            add_domain_to_monitoring,
            get_monitored_domains,
            remove_domain_from_monitoring
        )
        
        user_id = 999999
        
        result = await add_domain_to_monitoring(user_id, "test.example.com")
        assert result is True
        
        domains = await get_monitored_domains(user_id)
        assert "test.example.com" in domains
        
        result = await remove_domain_from_monitoring(user_id, "test.example.com")
        assert result is True
        
        domains = await get_monitored_domains(user_id)
        assert "test.example.com" not in domains


class TestAccessControl:
    """Тесты системы контроля доступа."""
    
    def test_has_access_admin(self):
        """Тест доступа администратора."""
        from bot import has_access, ADMIN_ID
        
        # Админ всегда имеет доступ
        assert has_access(ADMIN_ID) is True
    
    def test_has_permission_admin(self):
        """Тест разрешений администратора."""
        from bot import has_permission, ADMIN_ID
        
        # Админ имеет все разрешения
        assert has_permission(ADMIN_ID, "check_domains") is True
        assert has_permission(ADMIN_ID, "monitoring") is True
        assert has_permission(ADMIN_ID, "history") is True





