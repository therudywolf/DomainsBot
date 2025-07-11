"""Простейшее хранилище пользовательских настроек (режим вывода)."""

import shelve
import pathlib
from contextlib import contextmanager
from threading import RLock

_DB_PATH = pathlib.Path(__file__).resolve().parent.parent.joinpath("user_prefs.db")
_LOCK = RLock()

@contextmanager
def _shelf(write=False):
    with _LOCK:
        with shelve.open(str(_DB_PATH)) as db:
            yield db

def get_mode(user_id: int, default: str = "full") -> str:
    with _shelf() as db:
        return db.get(str(user_id), default)

def set_mode(user_id: int, mode: str) -> None:
    with _shelf(write=True) as db:
        db[str(user_id)] = mode