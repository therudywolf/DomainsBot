"""
Конфигурация pytest для тестов.
"""

import pytest
import asyncio
from pathlib import Path
import tempfile
import shutil


@pytest.fixture(scope="session")
def event_loop():
    """Создает event loop для всех тестов."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_data_dir():
    """Создает временную директорию для данных тестов."""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def mock_settings(monkeypatch):
    """Мокает настройки для тестов."""
    monkeypatch.setenv("TG_TOKEN", "test_token")
    monkeypatch.setenv("ADMIN_ID", "123456789")
    monkeypatch.setenv("DNS_TIMEOUT", "5")
    monkeypatch.setenv("HTTP_TIMEOUT", "6")





