"""
Модуль управления доступом к боту.

Содержит константы, функции и FSM-состояния для авторизации,
системы разрешений и парсинга пользователей.
"""

import json
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

from aiogram import Bot, types
from aiogram.fsm.state import State, StatesGroup

logger = logging.getLogger(__name__)

# ---------- Конфигурация авторизации и доступа ----------

_admin_id = os.getenv("ADMIN_ID")
if not _admin_id:
    print("Ошибка: ADMIN_ID не задан. Установите переменную окружения ADMIN_ID.", file=sys.stderr)
    sys.exit(1)
ADMIN_ID = int(_admin_id)

REQUEST_ACCESS_URL = os.getenv("REQUEST_ACCESS_URL", "")

ACCESS_DB_FILE = Path("data/access_db.json")
ACCESS_DB_FILE.parent.mkdir(parents=True, exist_ok=True)

# ---------- Система разрешений ----------

PERMISSIONS = {
    "check_domains": "🔍 Проверка доменов",
    "monitoring": "📊 Мониторинг доменов",
    "history": "📋 История проверок",
    "settings": "⚙️ Настройки",
    "inline": "💬 Inline режим",
    "file_upload": "📄 Загрузка файлов",
}

DEFAULT_PERMISSIONS = {
    "check_domains": True,
    "monitoring": False,
    "history": False,
    "settings": True,
    "inline": True,
    "file_upload": False,
}


# ---------- Функции работы с БД доступа ----------

def load_access_db() -> dict:
    """Загружает БД доступа из JSON файла."""
    if ACCESS_DB_FILE.exists():
        try:
            with open(ACCESS_DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                for user_id, user_data in data.items():
                    if isinstance(user_data, dict) and "permissions" not in user_data:
                        user_data["permissions"] = DEFAULT_PERMISSIONS.copy()
                return data
        except Exception as e:
            logger.error(f"Ошибка при загрузке БД: {e}")
            return {}
    return {}


def save_access_db(data: dict) -> None:
    """Сохраняет БД доступа в JSON файл."""
    try:
        with open(ACCESS_DB_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Ошибка при сохранении БД: {e}")


def has_access(user_id: int) -> bool:
    """
    Проверяет, есть ли у пользователя базовый доступ к боту.
    
    Args:
        user_id: ID пользователя
        
    Returns:
        True если у пользователя есть доступ
    """
    if user_id == ADMIN_ID:
        return True
    
    db = load_access_db()
    return str(user_id) in db


def has_permission(user_id: int, permission: str) -> bool:
    """
    Проверяет, есть ли у пользователя конкретное разрешение.
    
    Args:
        user_id: ID пользователя
        permission: Название разрешения
        
    Returns:
        True если разрешение есть
    """
    if user_id == ADMIN_ID:
        return True
    
    if not has_access(user_id):
        return False
    
    db = load_access_db()
    user_data = db.get(str(user_id), {})
    permissions = user_data.get("permissions", DEFAULT_PERMISSIONS.copy())
    
    return permissions.get(permission, DEFAULT_PERMISSIONS.get(permission, False))


def get_user_permissions(user_id: int) -> dict:
    """
    Получает все разрешения пользователя.
    
    Args:
        user_id: ID пользователя
        
    Returns:
        Словарь с разрешениями
    """
    if user_id == ADMIN_ID:
        return {perm: True for perm in PERMISSIONS.keys()}
    
    db = load_access_db()
    user_data = db.get(str(user_id), {})
    return user_data.get("permissions", DEFAULT_PERMISSIONS.copy())


def set_user_permission(user_id: int, permission: str, value: bool) -> bool:
    """
    Устанавливает разрешение для пользователя.
    
    Args:
        user_id: ID пользователя
        permission: Название разрешения
        value: Значение разрешения (True/False)
        
    Returns:
        True если успешно
    """
    if permission not in PERMISSIONS:
        logger.warning(f"Попытка установить неизвестное разрешение: {permission}")
        return False
    
    db = load_access_db()
    user_key = str(user_id)
    
    if user_key not in db:
        return False
    
    if "permissions" not in db[user_key]:
        db[user_key]["permissions"] = DEFAULT_PERMISSIONS.copy()
    
    db[user_key]["permissions"][permission] = value
    save_access_db(db)
    logger.info(f"Разрешение {permission} для пользователя {user_id} установлено в {value}")
    return True


def add_access(user_id: int, username: str = "", permissions: Optional[dict] = None) -> bool:
    """
    Добавляет доступ пользователю с указанными разрешениями.
    
    Args:
        user_id: ID пользователя
        username: Имя пользователя (опционально)
        permissions: Словарь разрешений (если None, используются значения по умолчанию)
        
    Returns:
        True если успешно
    """
    db = load_access_db()
    user_key = str(user_id)
    
    if user_key in db:
        if permissions is not None:
            db[user_key]["permissions"] = {**DEFAULT_PERMISSIONS, **permissions}
        elif "permissions" not in db[user_key]:
            db[user_key]["permissions"] = DEFAULT_PERMISSIONS.copy()
        db[user_key]["username"] = username or db[user_key].get("username", "")
    else:
        db[user_key] = {
            "username": username or "",
            "added_at": str(datetime.now()),
            "permissions": permissions if permissions is not None else DEFAULT_PERMISSIONS.copy(),
        }
    
    save_access_db(db)
    logger.info(f"Доступ добавлен для пользователя {user_id} с разрешениями: {db[user_key].get('permissions', {})}")
    return True


def remove_access(user_id: int) -> bool:
    """Удаляет доступ пользователя."""
    db = load_access_db()
    if str(user_id) in db:
        del db[str(user_id)]
        save_access_db(db)
        logger.info(f"Доступ удален для пользователя {user_id}")
        return True
    return False


def get_access_list() -> dict:
    """Получает список всех доступов с разрешениями."""
    return load_access_db()


async def get_username_by_id(bot: Bot, user_id: int) -> Optional[str]:
    """
    Получает актуальный username пользователя по его ID через Telegram API.
    
    Args:
        bot: Экземпляр бота
        user_id: ID пользователя
        
    Returns:
        Username пользователя или None если не удалось получить
    """
    try:
        chat = await bot.get_chat(user_id)
        return chat.username if chat.username else None
    except Exception as e:
        logger.debug(f"Не удалось получить username для пользователя {user_id}: {e}")
        return None


async def get_id_by_username(bot: Bot, username: str) -> Optional[int]:
    """
    Получает ID пользователя по его @username через Telegram API.
    Username может быть с @ или без.
    
    Args:
        bot: Экземпляр бота
        username: Username пользователя (с @ или без)
        
    Returns:
        ID пользователя или None если не удалось получить
    """
    if not username or not username.strip():
        return None
    name = username.strip()
    if not name.startswith("@"):
        name = "@" + name
    try:
        chat = await bot.get_chat(name)
        return chat.id if chat else None
    except Exception as e:
        logger.debug(f"Не удалось получить ID для username {name}: {e}")
        return None


_bot_username_cache: Optional[str] = None


async def get_bot_username(bot: Bot) -> str:
    """Возвращает @username бота (кэшируется после первого вызова)."""
    global _bot_username_cache
    if _bot_username_cache is None:
        try:
            me = await bot.get_me()
            _bot_username_cache = me.username or "Bot"
        except Exception as e:
            logger.warning(f"Не удалось получить username бота: {e}")
            _bot_username_cache = "Bot"
    return _bot_username_cache


# ---------- Проверки доступа для хэндлеров ----------

async def check_access(message: types.Message) -> bool:
    """Проверяет доступ пользователя. Если нет доступа - отправляет сообщение."""
    if has_access(message.from_user.id):
        return True
    
    from keyboards import build_access_denied_keyboard
    await message.answer(
        "❌ У вас нет доступа к этому боту.\n\n"
        "Свяжитесь с администратором, нажав кнопку ниже.",
        reply_markup=build_access_denied_keyboard()
    )
    return False


async def check_permission(message: types.Message, permission: str) -> bool:
    """
    Проверяет разрешение пользователя на выполнение функции.
    
    Args:
        message: Сообщение от пользователя
        permission: Название разрешения
        
    Returns:
        True если разрешение есть
    """
    user_id = message.from_user.id
    
    if has_permission(user_id, permission):
        return True
    
    from keyboards import build_access_denied_keyboard
    perm_name = PERMISSIONS.get(permission, permission)
    await message.answer(
        f"❌ У вас нет доступа к функции: {perm_name}\n\n"
        "Свяжитесь с администратором для получения доступа.",
        reply_markup=build_access_denied_keyboard()
    )
    return False


# ---------- Парсинг списка пользователей ----------

def parse_user_list(text: str) -> List[Tuple[Optional[int], Optional[str], Optional[str]]]:
    """
    Парсит список пользователей из различных форматов.
    
    Поддерживаемые форматы:
    - Формат старого бота: "• ID: 1027582338 - добавлен 2025-12-09"
    - Формат с ID: "ID: 1027582338"
    - Простые числа: "1027582338"
    - @username: "@johndoe"
    - Несколько через пробел/запятую
    
    Returns:
        Список кортежей (user_id, username, date_added):
        (user_id, None, date_added) для ID, (None, username, None) для @username
    """
    users: List[Tuple[Optional[int], Optional[str], Optional[str]]] = []
    
    if not text:
        return users
    
    old_bot_format = re.compile(
        r'(?:^|\n)[•\-\*]\s*ID:\s*(\d+)\s*(?:-\s*добавлен\s+(\d{4}-\d{2}-\d{2}))?',
        re.IGNORECASE | re.MULTILINE
    )
    
    id_format = re.compile(r'ID:\s*(\d+)', re.IGNORECASE)
    
    matches = old_bot_format.findall(text)
    if matches:
        for user_id_str, date_str in matches:
            try:
                user_id = int(user_id_str)
                users.append((user_id, None, date_str if date_str else None))
            except ValueError:
                continue
    
    if not users:
        matches = id_format.findall(text)
        for user_id_str in matches:
            try:
                user_id = int(user_id_str)
                users.append((user_id, None, None))
            except ValueError:
                continue
    
    if not users:
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if not line or any(keyword in line.lower() for keyword in ['список', 'доступ', 'пользовател']):
                continue
            
            numbers = re.findall(r'\b\d{8,}\b', line)
            for num_str in numbers:
                try:
                    user_id = int(num_str)
                    users.append((user_id, None, None))
                except ValueError:
                    continue
    
    if not users:
        items = re.split(r'[\s,;]+', text.strip())
        username_re = re.compile(r'^@?([a-zA-Z][a-zA-Z0-9_]{4,31})$')
        for item in items:
            item = item.strip()
            if not item:
                continue
            if item.startswith("@"):
                m = username_re.match(item)
                if m:
                    users.append((None, m.group(1), None))
                continue
            try:
                user_id = int(item)
                if user_id >= 100000000:
                    users.append((user_id, None, None))
            except ValueError:
                pass
    
    if not any(u[1] for u in users):
        for m in re.finditer(r'@([a-zA-Z][a-zA-Z0-9_]{4,31})', text):
            users.append((None, m.group(1), None))
    
    seen: set = set()
    unique_users = []
    for uid, uname, date in users:
        key = (uid, uname)
        if key not in seen:
            seen.add(key)
            unique_users.append((uid, uname, date))
    
    return unique_users


# ---------- FSM состояния ----------

class AdminStates(StatesGroup):
    add_access_waiting = State()
    remove_access_waiting = State()
    manage_permissions_user_waiting = State()
    manage_permissions_permission_waiting = State()


class MonitoringStates(StatesGroup):
    """Состояния FSM для мониторинга доменов."""
    add_domain_waiting = State()
    remove_domain_waiting = State()
    set_interval_waiting = State()
    set_waf_timeout_waiting = State()


class ChatSettingsStates(StatesGroup):
    """Состояния FSM для настройки чатов уведомлений."""
    waiting_chat_id = State()
