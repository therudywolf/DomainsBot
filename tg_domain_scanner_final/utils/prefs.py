"""Простейшее хранилище пользовательских настроек.

Хранит:
- Режим вывода отчета (full/brief)
- Режим проверки WAF (policy/light)
- Таймаут для WAF проверки
"""

import shelve
import pathlib
from contextlib import contextmanager
from threading import RLock
from typing import Optional

_DB_PATH = pathlib.Path(__file__).resolve().parent.parent.joinpath("user_prefs.db")
_LOCK = RLock()


@contextmanager
def _shelf(write=False):
    """Контекстный менеджер для работы с shelve БД."""
    with _LOCK:
        with shelve.open(str(_DB_PATH)) as db:
            yield db


def _get_user_key(user_id: int, key: str) -> str:
    """Формирует ключ для хранения настройки пользователя."""
    return f"{user_id}:{key}"


# Режим вывода отчета
def get_mode(user_id: int, default: str = "full") -> str:
    """Получает режим вывода отчета для пользователя.
    
    Args:
        user_id: ID пользователя
        default: Значение по умолчанию
        
    Returns:
        Режим вывода: "full" или "brief"
    """
    with _shelf() as db:
        return db.get(_get_user_key(user_id, "mode"), default)


def set_mode(user_id: int, mode: str) -> None:
    """Устанавливает режим вывода отчета для пользователя.
    
    Args:
        user_id: ID пользователя
        mode: Режим вывода ("full" или "brief")
    """
    with _shelf(write=True) as db:
        db[_get_user_key(user_id, "mode")] = mode


# Режим проверки WAF
def get_waf_mode(user_id: int, default: str = "policy") -> str:
    """Получает режим проверки WAF для пользователя.
    
    Args:
        user_id: ID пользователя
        default: Значение по умолчанию
        
    Returns:
        Режим проверки: "policy" или "light"
    """
    with _shelf() as db:
        return db.get(_get_user_key(user_id, "waf_mode"), default)


def set_waf_mode(user_id: int, mode: str) -> None:
    """Устанавливает режим проверки WAF для пользователя.
    
    Args:
        user_id: ID пользователя
        mode: Режим проверки ("policy" или "light")
    """
    with _shelf(write=True) as db:
        db[_get_user_key(user_id, "waf_mode")] = mode


# Таймаут для WAF проверки
def get_waf_timeout(user_id: int) -> Optional[int]:
    """Получает таймаут для WAF проверки пользователя.
    
    Args:
        user_id: ID пользователя
        
    Returns:
        Таймаут в секундах или None если не установлен
    """
    with _shelf() as db:
        return db.get(_get_user_key(user_id, "waf_timeout"), None)


def set_waf_timeout(user_id: int, timeout: int) -> None:
    """Устанавливает таймаут для WAF проверки пользователя.
    
    Args:
        user_id: ID пользователя
        timeout: Таймаут в секундах
    """
    with _shelf(write=True) as db:
        db[_get_user_key(user_id, "waf_timeout")] = timeout