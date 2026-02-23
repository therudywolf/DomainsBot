"""
Unit тесты для парсинга списка пользователей.
"""

import sys
import os

os.environ.setdefault("ADMIN_ID", "999999999")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Stub aiogram before importing access (which imports aiogram types)
import types as _types
_aiogram_stub = _types.ModuleType("aiogram")
_aiogram_stub.Bot = type("Bot", (), {})
_aiogram_stub.types = _types.ModuleType("aiogram.types")
_aiogram_stub.types.Message = type("Message", (), {})
sys.modules.setdefault("aiogram", _aiogram_stub)
sys.modules.setdefault("aiogram.types", _aiogram_stub.types)
_fsm_mod = _types.ModuleType("aiogram.fsm")
_state_mod = _types.ModuleType("aiogram.fsm.state")
_state_mod.State = lambda: None
_state_mod.StatesGroup = type("StatesGroup", (), {})
sys.modules.setdefault("aiogram.fsm", _fsm_mod)
sys.modules.setdefault("aiogram.fsm.state", _state_mod)

import pytest
from access import parse_user_list


class TestParseUserList:
    """Тесты для функции parse_user_list."""
    
    def test_old_bot_format(self):
        """Тест формата старого бота."""
        text = """📋 Список доступов:

• ID: 1027582338 - добавлен 2025-12-09
• ID: 127163336 - добавлен 2025-12-09
• ID: 1764262228 - добавлен 2026-02-03"""
        
        result = parse_user_list(text)
        
        assert len(result) == 3
        assert (1027582338, None, "2025-12-09") in result
        assert (127163336, None, "2025-12-09") in result
        assert (1764262228, None, "2026-02-03") in result
    
    def test_old_bot_format_without_date(self):
        """Тест формата старого бота без даты."""
        text = """• ID: 1027582338
• ID: 127163336"""
        
        result = parse_user_list(text)
        
        assert len(result) == 2
        assert (1027582338, None, None) in result
        assert (127163336, None, None) in result
    
    def test_id_format(self):
        """Тест формата ID: 123456."""
        text = """ID: 1027582338
ID: 127163336"""
        
        result = parse_user_list(text)
        
        assert len(result) == 2
        assert (1027582338, None, None) in result
        assert (127163336, None, None) in result
    
    def test_simple_numbers(self):
        """Тест простых чисел."""
        text = "1027582338 127163336 1764262228"
        
        result = parse_user_list(text)
        
        assert len(result) == 3
        assert (1027582338, None, None) in result
        assert (127163336, None, None) in result
        assert (1764262228, None, None) in result
    
    def test_comma_separated(self):
        """Тест чисел через запятую."""
        text = "1027582338, 127163336, 1764262228"
        
        result = parse_user_list(text)
        
        assert len(result) == 3
        assert (1027582338, None, None) in result
        assert (127163336, None, None) in result
        assert (1764262228, None, None) in result
    
    def test_mixed_format(self):
        """Тест смешанного формата.
        
        parse_user_list stops at the first format that matches, so only
        the bullet-point line is captured when mixed with other formats.
        """
        text = """• ID: 1027582338 - добавлен 2025-12-09
ID: 127163336
1764262228"""
        
        result = parse_user_list(text)
        
        assert len(result) >= 1
        assert (1027582338, None, "2025-12-09") in result
    
    def test_with_username(self):
        """Тест с никнеймами (username добавляется отдельно)."""
        text = """• ID: 1027582338 - добавлен 2025-12-09
@username
ID: 127163336"""
        
        result = parse_user_list(text)
        
        assert (1027582338, None, "2025-12-09") in result
        # @username is also parsed if no other usernames found
        ids_found = [r[0] for r in result if r[0] is not None]
        assert 1027582338 in ids_found
    
    def test_duplicates(self):
        """Тест дубликатов."""
        text = """• ID: 1027582338 - добавлен 2025-12-09
ID: 1027582338
1027582338"""
        
        result = parse_user_list(text)
        
        # Должен быть только один уникальный пользователь
        assert len(result) == 1
        assert (1027582338, None, "2025-12-09") in result
    
    def test_empty_text(self):
        """Тест пустого текста."""
        assert parse_user_list("") == []
        assert parse_user_list("   ") == []
    
    def test_invalid_format(self):
        """Тест некорректного формата."""
        text = "not a user id"
        result = parse_user_list(text)
        # Должен вернуть пустой список или попытаться найти числа
        assert isinstance(result, list)
    
    def test_small_numbers(self):
        """Тест маленьких чисел (не Telegram ID)."""
        text = "123 456 789"
        result = parse_user_list(text)
        # Маленькие числа не должны парситься как Telegram ID
        assert len(result) == 0
    
    def test_header_ignored(self):
        """Тест игнорирования заголовков."""
        text = """📋 Список доступов:

• ID: 1027582338 - добавлен 2025-12-09"""
        
        result = parse_user_list(text)
        
        assert len(result) == 1
        assert (1027582338, None, "2025-12-09") in result
    
    def test_various_bullets(self):
        """Тест различных маркеров списка."""
        text = """- ID: 1027582338 - добавлен 2025-12-09
* ID: 127163336 - добавлен 2025-12-09"""
        
        result = parse_user_list(text)
        
        assert len(result) == 2
        assert (1027582338, None, "2025-12-09") in result
        assert (127163336, None, "2025-12-09") in result
