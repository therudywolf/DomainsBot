"""
Постоянный асинхронный TTL кэш (по умолчанию 1 час) на диске (shelve).

Улучшенная версия с retry механизмом, fallback на in-memory кэш
и детальным логированием ошибок.
"""

import asyncio
import logging
import time
import shelve
import pathlib
from functools import wraps
from typing import Any, Dict, Tuple, Optional
from collections import OrderedDict

logger = logging.getLogger(__name__)

TTL_SECONDS = 3600  # 1 час по умолчанию
MAXSIZE = 20000
MAX_RETRIES = 3  # Количество попыток при ошибке
RETRY_DELAY = 0.1  # Задержка между попытками (секунды)

_DB_PATH = pathlib.Path(__file__).resolve().parent.parent.joinpath("domain_cache.db")
_LOCK = asyncio.Lock()

# In-memory fallback кэш для случаев, когда shelve недоступен
_memory_cache: Dict[str, Tuple[float, Any]] = OrderedDict()
_memory_cache_maxsize = 1000  # Ограничение размера in-memory кэша

# Метрики кэша
_cache_stats = {
    "hits": 0,
    "misses": 0,
    "memory_hits": 0,
    "shelve_hits": 0,
    "errors": 0,
}


def _make_key(args, kwargs) -> str:
    """Создает ключ кэша из аргументов функции.
    
    Args:
        args: Позиционные аргументы
        kwargs: Именованные аргументы
        
    Returns:
        Строковое представление ключа
    """
    return repr((args, tuple(sorted(kwargs.items()))))


def _get_from_memory_cache(key: str, now: float) -> Optional[Any]:
    """
    Получает значение из in-memory кэша.
    
    Args:
        key: Ключ кэша
        now: Текущее время
        
    Returns:
        Значение из кэша или None если не найдено или истекло
    """
    if key in _memory_cache:
        exp, val = _memory_cache[key]
        if now < exp:
            # Перемещаем в конец (LRU)
            _memory_cache.move_to_end(key)
            return val
        else:
            # Удаляем истекший кэш
            del _memory_cache[key]
    return None


def _save_to_memory_cache(key: str, value: Any, ttl: int) -> None:
    """
    Сохраняет значение в in-memory кэш.
    
    Args:
        key: Ключ кэша
        value: Значение для сохранения
        ttl: Время жизни в секундах
    """
    now = time.time()
    _memory_cache[key] = (now + ttl, value)
    
    # Ограничиваем размер кэша (LRU)
    if len(_memory_cache) > _memory_cache_maxsize:
        _memory_cache.popitem(last=False)  # Удаляем самый старый элемент


async def _read_from_shelve(key: str, now: float) -> Tuple[bool, Optional[Any]]:
    """
    Читает значение из shelve с retry механизмом.
    
    Args:
        key: Ключ кэша
        now: Текущее время
        
    Returns:
        Кортеж (успешно, значение) - успешно=True если значение найдено и свежее
    """
    for attempt in range(MAX_RETRIES):
        try:
            async with _LOCK:
                with shelve.open(str(_DB_PATH)) as db:
                    exp, val = db.get(key, (0, None))
                    if now < exp:
                        return (True, val)
                    return (False, None)
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                logger.debug(
                    f"Ошибка при чтении кэша (попытка {attempt + 1}/{MAX_RETRIES}): {e}"
                )
                await asyncio.sleep(RETRY_DELAY * (attempt + 1))
            else:
                logger.warning(
                    f"Не удалось прочитать кэш после {MAX_RETRIES} попыток для ключа {key[:50]}: {e}",
                    exc_info=True
                )
                _cache_stats["errors"] += 1
                return (False, None)
    return (False, None)


async def _write_to_shelve(key: str, value: Any, ttl: int, maxsize: int) -> bool:
    """
    Записывает значение в shelve с retry механизмом.
    
    Args:
        key: Ключ кэша
        value: Значение для сохранения
        ttl: Время жизни в секундах
        maxsize: Максимальный размер кэша
        
    Returns:
        True если успешно записано
    """
    now = time.time()
    
    for attempt in range(MAX_RETRIES):
        try:
            async with _LOCK:
                with shelve.open(str(_DB_PATH), writeback=True) as db:
                    db[key] = (now + ttl, value)
                    # Ограничиваем размер кэша
                    if len(db) > maxsize:
                        # Удаляем самые старые записи
                        items = list(db.items())
                        items.sort(
                            key=lambda x: x[1][0] 
                            if isinstance(x[1], tuple) and len(x[1]) == 2 
                            else 0
                        )
                        for k, _ in items[:len(items) - maxsize]:
                            db.pop(k, None)
            return True
            except Exception as e:
                if attempt < MAX_RETRIES - 1:
                    logger.debug(
                        f"Ошибка при записи кэша (попытка {attempt + 1}/{MAX_RETRIES}): {e}"
                    )
                    await asyncio.sleep(RETRY_DELAY * (attempt + 1))
                else:
                    logger.warning(
                        f"Не удалось записать кэш после {MAX_RETRIES} попыток для ключа {key[:50]}: {e}",
                        exc_info=True
                    )
                    _cache_stats["errors"] += 1
                    return False
    return False


def ttl_cache(ttl: int = TTL_SECONDS, maxsize: int = MAXSIZE):
    """
    Декоратор для кэширования результатов async функций в shelve файле.
    
    Улучшенная версия с:
    - Retry механизмом для операций с shelve
    - Fallback на in-memory кэш при проблемах с файлом
    - Детальным логированием ошибок
    
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
            
            # Сначала проверяем in-memory кэш
            memory_val = _get_from_memory_cache(key, now)
            if memory_val is not None:
                _cache_stats["hits"] += 1
                _cache_stats["memory_hits"] += 1
                logger.debug(f"Кэш найден в памяти для {func.__name__}")
                return memory_val

            # Пытаемся получить из shelve
            shelve_success, shelve_val = await _read_from_shelve(key, now)
            if shelve_success and shelve_val is not None:
                _cache_stats["hits"] += 1
                _cache_stats["shelve_hits"] += 1
                logger.debug(f"Кэш найден в shelve для {func.__name__}")
                # Сохраняем в memory cache для быстрого доступа
                _save_to_memory_cache(key, shelve_val, ttl)
                return shelve_val
            
            # Кэш не найден
            _cache_stats["misses"] += 1

            # Если кэш не найден, помечаем что вычисляем
            try:
                async with _LOCK:
                    with shelve.open(str(_DB_PATH), writeback=True) as db:
                        db[key] = (0, None)  # Помечаем что вычисляем
            except Exception as e:
                logger.debug(f"Не удалось пометить вычисление в shelve: {e}")

            # Выполняем реальный вызов
            try:
                result = await func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Ошибка при выполнении {func.__name__}: {e}", exc_info=True)
                # Удаляем пометку о вычислении при ошибке
                try:
                    async with _LOCK:
                        with shelve.open(str(_DB_PATH), writeback=True) as db:
                            if key in db and db[key][0] == 0:
                                del db[key]
                except Exception:
                    pass
                raise

            # Сохраняем результат в кэш (сначала в memory, потом в shelve)
            _save_to_memory_cache(key, result, ttl)
            
            # Пытаемся сохранить в shelve
            shelve_success = await _write_to_shelve(key, result, ttl, maxsize)
            if not shelve_success:
                logger.debug(
                    f"Не удалось сохранить в shelve для {func.__name__}, "
                    f"используется только memory cache"
                )
            
            return result

        return wrapper

    return decorator


def get_cache_stats() -> Dict[str, Any]:
    """
    Возвращает статистику использования кэша.
    
    Returns:
        Словарь со статистикой: hits, misses, hit_rate, memory_hits, shelve_hits, errors
    """
    total = _cache_stats["hits"] + _cache_stats["misses"]
    hit_rate = (_cache_stats["hits"] / total * 100) if total > 0 else 0.0
    
    return {
        "hits": _cache_stats["hits"],
        "misses": _cache_stats["misses"],
        "total": total,
        "hit_rate": round(hit_rate, 2),
        "memory_hits": _cache_stats["memory_hits"],
        "shelve_hits": _cache_stats["shelve_hits"],
        "errors": _cache_stats["errors"],
        "memory_cache_size": len(_memory_cache),
    }


def reset_cache_stats() -> None:
    """Сбрасывает статистику кэша."""
    global _cache_stats
    _cache_stats = {
        "hits": 0,
        "misses": 0,
        "memory_hits": 0,
        "shelve_hits": 0,
        "errors": 0,
    }
