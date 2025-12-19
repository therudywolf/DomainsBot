"""
Модуль для сбора и хранения статистики использования бота.

Собирает метрики:
- Количество проверенных доменов
- Количество пользователей
- Популярные домены
- Время работы бота
- Ошибки и их частота
"""

import json
import logging
import time
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Путь к файлу статистики
STATS_FILE = Path(__file__).resolve().parent.parent / "data" / "stats.json"
STATS_FILE.parent.mkdir(parents=True, exist_ok=True)

# Блокировка для потокобезопасности
_stats_lock = Lock()

# Глобальная статистика в памяти
_stats: Dict[str, Any] = {
    "start_time": time.time(),
    "total_domains_checked": 0,
    "total_users": set(),
    "domains_checked": Counter(),
    "errors": Counter(),
    "commands_used": Counter(),
    "last_reset": datetime.now().isoformat(),
}


def _load_stats() -> Dict[str, Any]:
    """Загружает статистику из файла."""
    if not STATS_FILE.exists():
        return _stats.copy()
    
    try:
        with open(STATS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Конвертируем списки обратно в set и Counter
            if "total_users" in data:
                data["total_users"] = set(data["total_users"])
            if "domains_checked" in data:
                data["domains_checked"] = Counter(data["domains_checked"])
            if "errors" in data:
                data["errors"] = Counter(data["errors"])
            if "commands_used" in data:
                data["commands_used"] = Counter(data["commands_used"])
            return data
    except Exception as e:
        logger.error(f"Ошибка при загрузке статистики: {e}")
        return _stats.copy()


def _save_stats() -> None:
    """Сохраняет статистику в файл."""
    try:
        with _stats_lock:
            # Конвертируем set и Counter в JSON-совместимые типы
            data = _stats.copy()
            data["total_users"] = list(data["total_users"])
            data["domains_checked"] = dict(data["domains_checked"])
            data["errors"] = dict(data["errors"])
            data["commands_used"] = dict(data["commands_used"])
            
            with open(STATS_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    except Exception as e:
        logger.error(f"Ошибка при сохранении статистики: {e}")


def record_domain_check(domain: str, user_id: int) -> None:
    """
    Записывает проверку домена.
    
    Args:
        domain: Проверенный домен
        user_id: ID пользователя
    """
    with _stats_lock:
        _stats["total_domains_checked"] += 1
        _stats["total_users"].add(user_id)
        _stats["domains_checked"][domain] += 1
    
    # Периодически сохраняем (каждые 10 проверок)
    if _stats["total_domains_checked"] % 10 == 0:
        _save_stats()


def record_error(error_type: str) -> None:
    """
    Записывает ошибку.
    
    Args:
        error_type: Тип ошибки
    """
    with _stats_lock:
        _stats["errors"][error_type] += 1
    
    # Сохраняем при каждой ошибке
    _save_stats()


def record_command(command: str) -> None:
    """
    Записывает использование команды.
    
    Args:
        command: Название команды
    """
    with _stats_lock:
        _stats["commands_used"][command] += 1
    
    # Периодически сохраняем
    if sum(_stats["commands_used"].values()) % 20 == 0:
        _save_stats()


def get_stats() -> Dict[str, Any]:
    """
    Получает текущую статистику.
    
    Returns:
        Словарь со статистикой
    """
    with _stats_lock:
        uptime_seconds = time.time() - _stats["start_time"]
        uptime_hours = uptime_seconds / 3600
        uptime_days = uptime_hours / 24
        
        return {
            "uptime_seconds": int(uptime_seconds),
            "uptime_hours": round(uptime_hours, 2),
            "uptime_days": round(uptime_days, 2),
            "total_domains_checked": _stats["total_domains_checked"],
            "total_users": len(_stats["total_users"]),
            "top_domains": dict(_stats["domains_checked"].most_common(10)),
            "top_errors": dict(_stats["errors"].most_common(5)),
            "top_commands": dict(_stats["commands_used"].most_common(10)),
            "last_reset": _stats["last_reset"],
        }


def reset_stats() -> None:
    """Сбрасывает статистику."""
    global _stats
    with _stats_lock:
        _stats = {
            "start_time": time.time(),
            "total_domains_checked": 0,
            "total_users": set(),
            "domains_checked": Counter(),
            "errors": Counter(),
            "commands_used": Counter(),
            "last_reset": datetime.now().isoformat(),
        }
        _save_stats()
    logger.info("Статистика сброшена")


# Загружаем статистику при импорте
_stats = _load_stats()
if "start_time" not in _stats:
    _stats["start_time"] = time.time()

