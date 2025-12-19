"""Постоянный асинхронный TTL кэш (по умолчанию 1 час) на диске (shelve)."""

import asyncio
import logging
import time
import shelve
import pathlib
from functools import wraps
from typing import Any

logger = logging.getLogger(__name__)

TTL_SECONDS = 3600  # 1 час по умолчанию
MAXSIZE = 20000

_DB_PATH = pathlib.Path(__file__).resolve().parent.parent.joinpath("domain_cache.db")
_LOCK = asyncio.Lock()


def _make_key(args, kwargs) -> str:
    """Создает ключ кэша из аргументов функции.
    
    Args:
        args: Позиционные аргументы
        kwargs: Именованные аргументы
        
    Returns:
        Строковое представление ключа
    """
    return repr((args, tuple(sorted(kwargs.items()))))


def ttl_cache(ttl: int = TTL_SECONDS, maxsize: int = MAXSIZE):
    """Декоратор для кэширования результатов async функций в shelve файле.
    
    Args:
        ttl: Время жизни кэша в секундах
        maxsize: Максимальный размер кэша (количество записей)
        
    Returns:
        Декоратор функции
    """

    def decorator(func):
        if not asyncio.iscoroutinefunction(func):
            raise RuntimeError("ttl_cache предназначен для async функций")

        @wraps(func)
        async def wrapper(*args, **kwargs):
            key = _make_key(args, kwargs)
            now = time.time()

            # Пытаемся получить из кэша
            try:
                async with _LOCK:
                    with shelve.open(str(_DB_PATH)) as db:
                        exp, val = db.get(key, (0, None))
                        if now < exp:
                            return val  # Свежий кэш найден
                        # Помечаем, что кто-то считает (exp=0)
                        db[key] = (0, None)
            except Exception as e:
                logger.warning(f"Ошибка при чтении кэша для {func.__name__}: {e}")

            # Выполняем реальный вызов
            try:
                result = await func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Ошибка при выполнении {func.__name__}: {e}")
                # Удаляем пометку о вычислении при ошибке
                try:
                    async with _LOCK:
                        with shelve.open(str(_DB_PATH), writeback=True) as db:
                            if key in db and db[key][0] == 0:
                                del db[key]
                except Exception:
                    pass
                raise

            # Сохраняем результат в кэш
            try:
                async with _LOCK:
                    with shelve.open(str(_DB_PATH), writeback=True) as db:
                        db[key] = (now + ttl, result)
                        # Ограничиваем размер кэша
                        if len(db) > maxsize:
                            # Удаляем самые старые записи
                            items = list(db.items())
                            items.sort(key=lambda x: x[1][0] if isinstance(x[1], tuple) and len(x[1]) == 2 else 0)
                            for k, _ in items[:len(items) - maxsize]:
                                db.pop(k, None)
            except Exception as e:
                logger.warning(f"Ошибка при сохранении кэша для {func.__name__}: {e}")
            
            return result

        return wrapper

    return decorator
