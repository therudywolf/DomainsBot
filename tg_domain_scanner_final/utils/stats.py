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
    "errors_by_type": defaultdict(int),  # Статистика по типам ошибок
    "activity_by_hour": defaultdict(int),  # Статистика по часам суток
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


def record_check_duration(duration_seconds: float) -> None:
    """
    Записывает время выполнения проверки домена.
    
    Args:
        duration_seconds: Время выполнения в секундах
    """
    with _stats_lock:
        durations = _stats.get("check_durations", [])
        durations.append(duration_seconds)
        # Храним только последние 1000 измерений
        if len(durations) > 1000:
            durations = durations[-1000:]
        _stats["check_durations"] = durations


def record_domain_check(domain: str, user_id: int) -> None:
    """
    Записывает проверку домена.
    
    Использует буферизованную запись для оптимизации производительности.
    
    Args:
        domain: Проверенный домен
        user_id: ID пользователя
    """
    with _stats_lock:
        _stats["total_domains_checked"] += 1
        _stats["total_users"].add(user_id)
        _stats["domains_checked"][domain] += 1
        # Статистика по времени суток
        current_hour = datetime.now().hour
        _stats["activity_by_hour"][current_hour] += 1
    
    # Используем буферизованную запись (сохраняется периодически)
    from utils.buffered_writer import get_buffered_writer
    
    writer = get_buffered_writer(STATS_FILE, flush_interval=30, max_buffer_size=50)
    
    def update_stats(data: Dict[str, Any]) -> None:
        """Обновляет статистику в данных."""
        data["total_domains_checked"] = _stats["total_domains_checked"]
        data["total_users"] = list(_stats["total_users"])
        data["domains_checked"] = dict(_stats["domains_checked"])
        data["errors"] = dict(_stats["errors"])
        data["commands_used"] = dict(_stats["commands_used"])
        data["last_update"] = datetime.now().isoformat()
    
    writer.add_operation(update_stats)


def record_error(error_type: str) -> None:
    """
    Записывает ошибку.
    
    Args:
        error_type: Тип ошибки
    """
    with _stats_lock:
        _stats["errors"][error_type] += 1
        _stats["errors_by_type"][error_type] += 1
    
    # Используем буферизованную запись
    from utils.buffered_writer import get_buffered_writer
    
    writer = get_buffered_writer(STATS_FILE, flush_interval=30, max_buffer_size=50)
    
    def update_stats(data: Dict[str, Any]) -> None:
        """Обновляет статистику в данных."""
        data["total_domains_checked"] = _stats["total_domains_checked"]
        data["total_users"] = list(_stats["total_users"])
        data["domains_checked"] = dict(_stats["domains_checked"])
        data["errors"] = dict(_stats["errors"])
        data["commands_used"] = dict(_stats["commands_used"])
        data["last_update"] = datetime.now().isoformat()
    
    writer.add_operation(update_stats)


def record_command(command: str) -> None:
    """
    Записывает использование команды.
    
    Args:
        command: Название команды
    """
    with _stats_lock:
        _stats["commands_used"][command] += 1
    
    # Используем буферизованную запись
    from utils.buffered_writer import get_buffered_writer
    
    writer = get_buffered_writer(STATS_FILE, flush_interval=30, max_buffer_size=50)
    
    def update_stats(data: Dict[str, Any]) -> None:
        """Обновляет статистику в данных."""
        data["total_domains_checked"] = _stats["total_domains_checked"]
        data["total_users"] = list(_stats["total_users"])
        data["domains_checked"] = dict(_stats["domains_checked"])
        data["errors"] = dict(_stats["errors"])
        data["commands_used"] = dict(_stats["commands_used"])
        data["last_update"] = datetime.now().isoformat()
    
    writer.add_operation(update_stats)


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
        
        # Вычисляем метрики производительности
        durations = _stats.get("check_durations", [])
        performance_metrics = {}
        if durations:
            sorted_durations = sorted(durations)
            n = len(sorted_durations)
            performance_metrics = {
                "avg_duration": round(sum(durations) / n, 3),
                "median_duration": round(sorted_durations[n // 2], 3),
                "p95_duration": round(sorted_durations[int(n * 0.95)] if n > 0 else 0, 3),
                "p99_duration": round(sorted_durations[int(n * 0.99)] if n > 0 else 0, 3),
                "min_duration": round(min(durations), 3),
                "max_duration": round(max(durations), 3),
            }
        
        # Получаем статистику кэша
        cache_stats = {}
        try:
            from utils.cache import get_cache_stats
            cache_stats = get_cache_stats()
        except Exception:
            pass
        
        return {
            "uptime_seconds": int(uptime_seconds),
            "uptime_hours": round(uptime_hours, 2),
            "uptime_days": round(uptime_days, 2),
            "total_domains_checked": _stats["total_domains_checked"],
            "total_users": len(_stats["total_users"]),
            "top_domains": dict(_stats["domains_checked"].most_common(10)),
            "top_errors": dict(_stats["errors"].most_common(5)),
            "top_commands": dict(_stats["commands_used"].most_common(10)),
            "errors_by_type": dict(_stats.get("errors_by_type", {})),
            "activity_by_hour": dict(_stats.get("activity_by_hour", {})),
            "performance_metrics": performance_metrics,
            "cache_stats": cache_stats,
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
            "errors_by_type": defaultdict(int),
            "activity_by_hour": defaultdict(int),
            "check_durations": [],
            "cache_stats": {},
            "last_reset": datetime.now().isoformat(),
        }
        _save_stats()
    logger.info("Статистика сброшена")


# Загружаем статистику при импорте
_stats = _load_stats()
if "start_time" not in _stats:
    _stats["start_time"] = time.time()

