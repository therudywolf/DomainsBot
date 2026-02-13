"""
Модуль для управления настройками чатов для уведомлений.

Позволяет пользователям настраивать, в какие чаты бот должен отправлять уведомления мониторинга.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime

logger = logging.getLogger(__name__)

# Путь к файлу с настройками чатов
CHAT_SETTINGS_FILE = Path(__file__).resolve().parent.parent / "data" / "chat_settings.json"
CHAT_SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)

# Структура данных:
# {
#   "user_id": {
#     "notification_chat_id": chat_id (int или None),
#     "known_chats": [
#       {"chat_id": int, "title": str, "type": str, "added_at": str}
#     ]
#   }
# }


def _load_chat_settings() -> Dict:
    """Загружает настройки чатов из файла."""
    if not CHAT_SETTINGS_FILE.exists():
        return {}
    
    try:
        with open(CHAT_SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Ошибка при загрузке настроек чатов: {e}")
        return {}


def _save_chat_settings(data: Dict) -> None:
    """Сохраняет настройки чатов в файл."""
    try:
        with open(CHAT_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Ошибка при сохранении настроек чатов: {e}")


def register_chat(user_id: int, chat_id: int, chat_title: str, chat_type: str) -> None:
    """
    Регистрирует чат, в котором находится пользователь.
    
    Args:
        user_id: ID пользователя
        chat_id: ID чата
        chat_title: Название чата
        chat_type: Тип чата ("private", "group", "supergroup", "channel")
    """
    data = _load_chat_settings()
    user_key = str(user_id)
    
    if user_key not in data:
        data[user_key] = {
            "notification_chat_id": None,
            "known_chats": []
        }
    
    # Проверяем, не зарегистрирован ли уже этот чат
    known_chats = data[user_key].get("known_chats", [])
    chat_exists = any(chat.get("chat_id") == chat_id for chat in known_chats)
    
    if not chat_exists:
        known_chats.append({
            "chat_id": chat_id,
            "title": chat_title or f"Chat {chat_id}",
            "type": chat_type,
            "added_at": datetime.now().isoformat()
        })
        data[user_key]["known_chats"] = known_chats
        _save_chat_settings(data)
        logger.info(f"Зарегистрирован чат {chat_id} ({chat_title}) для пользователя {user_id}")


def get_notification_chat_id(user_id: int) -> Optional[int]:
    """
    Получает ID чата для уведомлений пользователя.
    
    Args:
        user_id: ID пользователя
        
    Returns:
        ID чата для уведомлений или None если не настроено
    """
    data = _load_chat_settings()
    user_key = str(user_id)
    
    if user_key not in data:
        return None
    
    chat_id = data[user_key].get("notification_chat_id")
    return int(chat_id) if chat_id is not None else None


def set_notification_chat_id(user_id: int, chat_id: Optional[int]) -> bool:
    """
    Устанавливает ID чата для уведомлений пользователя.
    
    Args:
        user_id: ID пользователя
        chat_id: ID чата (None для отключения уведомлений в чат)
        
    Returns:
        True если успешно
    """
    data = _load_chat_settings()
    user_key = str(user_id)
    
    if user_key not in data:
        data[user_key] = {
            "notification_chat_id": None,
            "known_chats": []
        }
    
    data[user_key]["notification_chat_id"] = chat_id
    _save_chat_settings(data)
    logger.info(f"Установлен чат уведомлений {chat_id} для пользователя {user_id}")
    return True


def get_known_chats(user_id: int) -> List[Dict]:
    """
    Получает список известных чатов пользователя.
    
    Args:
        user_id: ID пользователя
        
    Returns:
        Список словарей с информацией о чатах
    """
    data = _load_chat_settings()
    user_key = str(user_id)
    
    if user_key not in data:
        return []
    
    return data[user_key].get("known_chats", [])


def remove_known_chat(user_id: int, chat_id: int) -> bool:
    """
    Удаляет чат из списка известных.
    
    Args:
        user_id: ID пользователя
        chat_id: ID чата для удаления
        
    Returns:
        True если успешно
    """
    data = _load_chat_settings()
    user_key = str(user_id)
    
    if user_key not in data or user_key not in data:
        return False
    
    known_chats = data[user_key].get("known_chats", [])
    original_count = len(known_chats)
    data[user_key]["known_chats"] = [
        chat for chat in known_chats if chat.get("chat_id") != chat_id
    ]
    
    # Если удаляемый чат был настроен для уведомлений, сбрасываем настройку
    if data[user_key].get("notification_chat_id") == chat_id:
        data[user_key]["notification_chat_id"] = None
    
    if len(data[user_key]["known_chats"]) < original_count:
        _save_chat_settings(data)
        logger.info(f"Удален чат {chat_id} из списка известных для пользователя {user_id}")
        return True
    
    return False





