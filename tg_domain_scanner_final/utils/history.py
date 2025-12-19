"""
Модуль для хранения истории проверок доменов.

Сохраняет результаты проверок для последующего анализа и сравнения.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from threading import Lock

logger = logging.getLogger(__name__)

# Путь к файлу истории
HISTORY_FILE = Path(__file__).resolve().parent.parent / "data" / "check_history.json"
HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)

# Максимальное количество записей в истории
MAX_HISTORY_ENTRIES = 10000

# Блокировка для потокобезопасности
_history_lock = Lock()


def _load_history() -> List[Dict[str, Any]]:
    """Загружает историю из файла."""
    if not HISTORY_FILE.exists():
        return []
    
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Ошибка при загрузке истории: {e}")
        return []


def _save_history(history: List[Dict[str, Any]]) -> None:
    """Сохраняет историю в файл."""
    try:
        # Ограничиваем размер истории
        if len(history) > MAX_HISTORY_ENTRIES:
            history = history[-MAX_HISTORY_ENTRIES:]
        
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False, indent=2, default=str)
    except Exception as e:
        logger.error(f"Ошибка при сохранении истории: {e}")


def add_check_result(
    domain: str,
    user_id: int,
    dns_info: Dict[str, Any],
    ssl_info: Dict[str, Any],
    waf_enabled: bool,
) -> None:
    """
    Добавляет результат проверки в историю.
    
    Args:
        domain: Проверенный домен
        user_id: ID пользователя
        dns_info: DNS информация
        ssl_info: SSL информация
        waf_enabled: Наличие WAF
    """
    entry = {
        "timestamp": datetime.now().isoformat(),
        "domain": domain,
        "user_id": user_id,
        "dns": dns_info,
        "ssl": {
            "CN": ssl_info.get("CN"),
            "gost": ssl_info.get("gost", False),
            "not_after": ssl_info.get("NotAfter").isoformat() if ssl_info.get("NotAfter") else None,
            "gost_not_after": ssl_info.get("GostNotAfter").isoformat() if ssl_info.get("GostNotAfter") else None,
        },
        "waf": waf_enabled,
    }
    
    with _history_lock:
        history = _load_history()
        history.append(entry)
        _save_history(history)


def get_domain_history(domain: str, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Получает историю проверок для домена.
    
    Args:
        domain: Домен для поиска
        limit: Максимальное количество записей
        
    Returns:
        Список записей истории
    """
    with _history_lock:
        history = _load_history()
        domain_history = [
            entry for entry in history
            if entry.get("domain", "").lower() == domain.lower()
        ]
        # Сортируем по времени (новые первые)
        domain_history.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return domain_history[:limit]


def get_user_history(user_id: int, limit: int = 20) -> List[Dict[str, Any]]:
    """
    Получает историю проверок пользователя.
    
    Args:
        user_id: ID пользователя
        limit: Максимальное количество записей
        
    Returns:
        Список записей истории
    """
    with _history_lock:
        history = _load_history()
        user_history = [
            entry for entry in history
            if entry.get("user_id") == user_id
        ]
        # Сортируем по времени (новые первые)
        user_history.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return user_history[:limit]


def cleanup_old_history(days: int = 30) -> int:
    """
    Удаляет старые записи из истории.
    
    Args:
        days: Количество дней для хранения
        
    Returns:
        Количество удаленных записей
    """
    from datetime import timedelta
    
    cutoff_date = datetime.now() - timedelta(days=days)
    cutoff_str = cutoff_date.isoformat()
    
    with _history_lock:
        history = _load_history()
        original_count = len(history)
        
        # Фильтруем старые записи
        history = [
            entry for entry in history
            if entry.get("timestamp", "") >= cutoff_str
        ]
        
        removed = original_count - len(history)
        _save_history(history)
        
        if removed > 0:
            logger.info(f"Удалено {removed} старых записей из истории (старше {days} дней)")
        
        return removed

