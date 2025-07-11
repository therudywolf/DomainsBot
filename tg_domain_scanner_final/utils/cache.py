
"""Persistent async TTL cache stored on disk (shelve).

* TTL и размер берутся из переменных окружения:
    * ``CACHE_TTL``   — время жизни результата в секундах (по‑умолчанию 6 часов)
    * ``CACHE_MAXSIZE`` — максимальное число одновременных ключей (по‑умолчанию 5000)

Реализована анти‑stampede защита: при первом обращении ключ помечается как
«в расчёте», остальные корутины ждут готовый результат вместо повтора запроса.
"""

import asyncio
import time
import shelve
import pathlib
import os
from functools import wraps
from typing import Any, Dict, Tuple

TTL_SECONDS = int(os.getenv("CACHE_TTL", 6 * 60 * 60))  # 6 часов
MAXSIZE = int(os.getenv("CACHE_MAXSIZE", 5000))

_DB_PATH = pathlib.Path(__file__).resolve().parent.parent.joinpath("domain_cache.db")
_LOCK = asyncio.Lock()
_IN_PROGRESS: Dict[str, asyncio.Event] = {}

def _make_key(args, kwargs) -> str:
    """Детерминированно сериализуем позиционные и именованные аргументы."""
    parts = [repr(a) for a in args]
    parts.extend(f"{k}={v!r}" for k, v in sorted(kwargs.items()))
    return "|".join(parts)

def ttl_cache(ttl: int = TTL_SECONDS, maxsize: int = MAXSIZE):
    """Кэширует результат async‑функции в shelve‑файле с TTL и анти‑stampede."""

    def decorator(func):
        if not asyncio.iscoroutinefunction(func):
            raise RuntimeError("ttl_cache предназначен для async‑функций")

        @wraps(func)
        async def wrapper(*args, **kwargs):
            key = _make_key(args, kwargs)
            now = time.time()

            async with _LOCK:
                with shelve.open(str(_DB_PATH)) as db:
                    exp, val = db.get(key, (0, None))
                    if exp > now:           # свежий кэш
                        return val
                    if exp == -1:            # расчёт уже выполняется
                        waiter = _IN_PROGRESS.get(key)
                    else:
                        # помечаем «в расчёте»
                        db[key] = (-1, None)
                        waiter = None

            if waiter:
                await waiter.wait()
                # повторная попытка вернёт уже готовый результат
                return await wrapper(*args, **kwargs)

            event = asyncio.Event()
            _IN_PROGRESS[key] = event
            try:
                result = await func(*args, **kwargs)
            finally:
                async with _LOCK:
                    with shelve.open(str(_DB_PATH), writeback=True) as db:
                        db[key] = (now + ttl, result)
                        # убираем лишние записи
                        if len(db) > maxsize:
                            for k in list(db.keys())[: len(db) - maxsize]:
                                db.pop(k, None)
                    _IN_PROGRESS.pop(key, None)
                    event.set()  # разбудим ожидающих
            return result

        return wrapper

    return decorator
