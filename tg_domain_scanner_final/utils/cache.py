"""Persistent async TTL cache (6 ч) stored on disk (shelve)."""

import asyncio
import time
import shelve
import pathlib
from functools import wraps
from typing import Any, Dict, Tuple

TTL_SECONDS = 1
MAXSIZE = 1

_DB_PATH = pathlib.Path(__file__).resolve().parent.parent.joinpath("domain_cache.db")
_LOCK = asyncio.Lock()

def _make_key(args, kwargs) -> str:
    # ключ представляем как строку — репрезентация аргументов
    return repr((args, tuple(sorted(kwargs.items()))))

def ttl_cache(ttl: int = TTL_SECONDS, maxsize: int = MAXSIZE):
    """Кэширует результат async‑функции в shelve‑файле."""

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
                    if now < exp:
                        return val  # свежий кэш
                    # помечаем, что кто‑то считает (exp=0)
                    db[key] = (0, None)

            # выполняем реальный вызов
            result = await func(*args, **kwargs)

            async with _LOCK:
                with shelve.open(str(_DB_PATH), writeback=True) as db:
                    db[key] = (now + ttl, result)
                    # ограничиваем размер
                    if len(db) > maxsize:
                        for k in list(db.keys())[: len(db) - maxsize]:
                            db.pop(k, None)
            return result

        return wrapper

    return decorator