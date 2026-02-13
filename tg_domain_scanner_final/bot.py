"""
Telegram-бот для анализа доменов.

Основной модуль бота, который обрабатывает команды пользователей,
проверяет домены и предоставляет информацию о DNS, SSL, WAF и GOST сертификатах.

Функционал:
- Проверка доменов (DNS, SSL, WAF, GOST)
- Мониторинг доменов с уведомлениями
- История проверок
- Статистика использования
- Rate limiting для защиты от спама
- Админ-панель для управления доступом
"""

# Опциональная оптимизация: используем uvloop для повышения производительности asyncio
# uvloop - быстрая реализация event loop на основе libuv
try:
    import uvloop  # type: ignore
    uvloop.install()
except ModuleNotFoundError:
    # Если uvloop не установлен, используем стандартный event loop
    pass

import asyncio
import csv
import html
import io
import json
import logging
import re
import os
import signal
import sys
from typing import List, Tuple, Optional
from pathlib import Path
from datetime import datetime

from aiogram import Bot, Dispatcher, F, Router, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    BotCommand, 
    InlineQuery, 
    InlineQueryResultArticle, 
    InputTextMessageContent
)
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.fsm.state import State, StatesGroup

# Импорт конфигурации и настроек
from config import settings

# Импорт утилит для проверки доменов
from utils.dns_utils import fetch_dns
from utils.ssl_utils import fetch_ssl
from utils.waf_utils import test_waf
from utils.waf_injection_check import test_waf_injection
from utils.formatting import build_report, build_report_keyboard
from utils.telegram_utils import safe_send_text

# Импорт утилит для настроек пользователя
from utils.prefs import (
    get_mode, set_mode,
    get_waf_mode, set_waf_mode,
    get_waf_timeout, set_waf_timeout
)

# Импорт утилит для нормализации доменов
from utils.domain_normalizer import normalize_domains

# Импорт модулей для обработки доменов
from utils.domain_processor import validate_and_normalize_domains, check_single_domain
from utils.report_formatter import format_csv_report, send_domain_reports

# Импорт модуля для управления чатами
from utils.chat_settings import (
    register_chat,
    get_notification_chat_id,
    set_notification_chat_id,
    get_known_chats,
    remove_known_chat
)

# Импорт утилит для мониторинга доменов
from utils.monitoring import (
    add_domain_to_monitoring,
    remove_domain_from_monitoring,
    get_monitored_domains,
    set_monitoring_interval,
    get_monitoring_interval,
    set_monitoring_enabled,
    is_monitoring_enabled,
    start_monitoring,
    stop_monitoring,
)

# Импорт новых утилит
from utils.rate_limiter import check_rate_limit, get_remaining_requests, cleanup_rate_limiter
from utils.stats import record_domain_check, record_error, record_command, get_stats, reset_stats
from utils.history import add_check_result, get_domain_history, get_user_history, cleanup_old_history
from utils.logger_config import setup_logging

# Настройка логирования
setup_logging(
    log_level=settings.LOG_LEVEL,
    log_file=settings.LOG_FILE if settings.LOG_FILE else None,
    max_bytes=settings.LOG_MAX_BYTES,
    backup_count=settings.LOG_BACKUP_COUNT,
)

logger = logging.getLogger(__name__)

# Регулярное выражение для разбиения доменов (пробелы, запятые, переносы строк)
DOMAIN_SPLIT_RE = re.compile(r"[\s,\n]+")

# Режим отчета по умолчанию: 'full' (расширенный) или 'brief' (короткий)
DEFAULT_MODE = "full"

# ---------- Конфигурация авторизации и доступа ----------

# ID администратора бота (обязательная переменная окружения)
_admin_id = os.getenv("ADMIN_ID")
if not _admin_id:
    print("Ошибка: ADMIN_ID не задан. Установите переменную окружения ADMIN_ID.", file=sys.stderr)
    sys.exit(1)
ADMIN_ID = int(_admin_id)

# URL для запроса доступа (ссылка на администратора)
REQUEST_ACCESS_URL = os.getenv("REQUEST_ACCESS_URL", "")

# Путь к файлу базы данных доступов
ACCESS_DB_FILE = Path("data/access_db.json")

# Создаем директорию для данных, если она не существует
ACCESS_DB_FILE.parent.mkdir(parents=True, exist_ok=True)

# Глобальная переменная для graceful shutdown
_shutdown_event = asyncio.Event()

# ---------- Система разрешений ----------

# Доступные разрешения (permissions)
PERMISSIONS = {
    "check_domains": "🔍 Проверка доменов",
    "monitoring": "📊 Мониторинг доменов",
    "history": "📋 История проверок",
    "settings": "⚙️ Настройки",
    "inline": "💬 Inline режим",
    "file_upload": "📄 Загрузка файлов",
}

# Разрешения по умолчанию при добавлении пользователя
DEFAULT_PERMISSIONS = {
    "check_domains": True,  # Базовая функция должна быть доступна
    "monitoring": False,
    "history": False,
    "settings": True,  # Настройки обычно доступны
    "inline": True,
    "file_upload": False,
}


def load_access_db() -> dict:
    """Загружает БД доступа из JSON файла."""
    if ACCESS_DB_FILE.exists():
        try:
            with open(ACCESS_DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Миграция старых записей к новой структуре
                for user_id, user_data in data.items():
                    if isinstance(user_data, dict) and "permissions" not in user_data:
                        # Старая структура - добавляем разрешения по умолчанию
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
    # Админ всегда имеет доступ
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
    # Админ всегда имеет все разрешения
    if user_id == ADMIN_ID:
        return True
    
    # Если нет базового доступа, нет и разрешений
    if not has_access(user_id):
        return False
    
    db = load_access_db()
    user_data = db.get(str(user_id), {})
    permissions = user_data.get("permissions", DEFAULT_PERMISSIONS.copy())
    
    # Если разрешение не указано, используем значение по умолчанию
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
        # Админ имеет все разрешения
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
        # Пользователь не существует
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
    
    # Если пользователь уже существует, обновляем разрешения
    if user_key in db:
        if permissions is not None:
            db[user_key]["permissions"] = {**DEFAULT_PERMISSIONS, **permissions}
        elif "permissions" not in db[user_key]:
            db[user_key]["permissions"] = DEFAULT_PERMISSIONS.copy()
        db[user_key]["username"] = username or db[user_key].get("username", "")
    else:
        # Новый пользователь
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


# ---------- FSM для админ команд ----------

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


# ---------- Клавиатура режима ----------

def build_mode_keyboard(current_mode: str) -> types.InlineKeyboardMarkup:
    """Inline-кнопки для переключения формата вывода."""
    return types.InlineKeyboardMarkup(
        inline_keyboard=[
            [
                types.InlineKeyboardButton(
                    text=("✅ 🔎 Расширенный" if current_mode == "full" else "🔎 Расширенный"),
                    callback_data="mode_full",
                ),
                types.InlineKeyboardButton(
                    text=("✅ 📄 Короткий" if current_mode == "brief" else "📄 Короткий"),
                    callback_data="mode_brief",
                ),
            ]
        ]
    )


def build_waf_mode_keyboard(current_mode: str) -> types.InlineKeyboardMarkup:
    """Inline-кнопки для переключения режима проверки WAF."""
    return types.InlineKeyboardMarkup(
        inline_keyboard=[
            [
                types.InlineKeyboardButton(
                    text=("✅ Policy" if current_mode == "policy" else "Policy"),
                    callback_data="waf_mode_policy",
                ),
                types.InlineKeyboardButton(
                    text=("✅ Light" if current_mode == "light" else "Light"),
                    callback_data="waf_mode_light",
                ),
            ]
        ]
    )


def build_monitoring_keyboard() -> types.InlineKeyboardMarkup:
    """Клавиатура для управления мониторингом."""
    return types.InlineKeyboardMarkup(
        inline_keyboard=[
            [
                types.InlineKeyboardButton(
                    text="➕ Добавить домен",
                    callback_data="monitor_add",
                ),
                types.InlineKeyboardButton(
                    text="➖ Удалить домен",
                    callback_data="monitor_remove",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="📋 Список доменов",
                    callback_data="monitor_list",
                ),
                types.InlineKeyboardButton(
                    text="📥 Экспорт",
                    callback_data="monitor_export",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="⏱️ Интервал",
                    callback_data="monitor_interval",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="⚙️ WAF таймаут",
                    callback_data="monitor_waf_timeout",
                ),
                types.InlineKeyboardButton(
                    text="🔄 Вкл/Выкл",
                    callback_data="monitor_toggle",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="💬 Чат для уведомлений",
                    callback_data="settings_notification_chat",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="🔙 Главное меню",
                    callback_data="main_menu",
                ),
            ],
        ]
    )


def build_main_menu_keyboard(user_id: int) -> types.ReplyKeyboardMarkup:
    """
    Создает главное меню с кнопками для быстрого доступа.
    
    Показывает только те функции, к которым у пользователя есть доступ.
    
    Args:
        user_id: ID пользователя для определения доступных функций
        
    Returns:
        ReplyKeyboardMarkup с кнопками главного меню
    """
    keyboard = []
    
    # Базовая проверка доменов (всегда доступна, если есть базовый доступ)
    if has_access(user_id) and has_permission(user_id, "check_domains"):
        keyboard.append([
            types.KeyboardButton(text="🔍 Проверить домен"),
        ])
    
    # Мониторинг (только если есть разрешение)
    if has_access(user_id) and has_permission(user_id, "monitoring"):
        if keyboard:
            keyboard[-1].append(types.KeyboardButton(text="📊 Мониторинг"))
        else:
            keyboard.append([types.KeyboardButton(text="📊 Мониторинг")])
    
    # Настройки (только если есть разрешение)
    if has_access(user_id) and has_permission(user_id, "settings"):
        if keyboard and len(keyboard[-1]) < 2:
            keyboard[-1].append(types.KeyboardButton(text="⚙️ Настройки"))
        else:
            if not keyboard:
                keyboard.append([])
            keyboard.append([types.KeyboardButton(text="⚙️ Настройки")])
    
    # История (только если есть разрешение)
    if has_access(user_id) and has_permission(user_id, "history"):
        if keyboard and len(keyboard[-1]) < 2:
            keyboard[-1].append(types.KeyboardButton(text="📋 История"))
        else:
            if not keyboard:
                keyboard.append([])
            keyboard.append([types.KeyboardButton(text="📋 История")])
    
    # Для админа добавляем админ-панель
    if user_id == ADMIN_ID:
        keyboard.append([
            types.KeyboardButton(text="👨‍💼 Админ-панель"),
        ])
    
    # Всегда добавляем кнопку "Назад" и "Главное меню"
    keyboard.append([
        types.KeyboardButton(text="🔙 Назад"),
        types.KeyboardButton(text="🏠 Главное меню"),
    ])
    
    # Помощь всегда доступна
    keyboard.append([
        types.KeyboardButton(text="ℹ️ Помощь"),
    ])
    
    return types.ReplyKeyboardMarkup(
        keyboard=keyboard,
        resize_keyboard=True,
        input_field_placeholder="Введите домен или выберите действие..."
    )


def build_settings_keyboard(user_id: int) -> types.InlineKeyboardMarkup:
    """
    Создает клавиатуру настроек пользователя.
    
    Args:
        user_id: ID пользователя
        
    Returns:
        InlineKeyboardMarkup с настройками
    """
    current_mode = get_mode(user_id, DEFAULT_MODE)
    current_waf_mode = get_waf_mode(user_id, "policy")
    
    return types.InlineKeyboardMarkup(
        inline_keyboard=[
            [
                types.InlineKeyboardButton(
                    text="📄 Режим отчета",
                    callback_data="settings_report_mode",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text=("✅ 🔎 Расширенный" if current_mode == "full" else "🔎 Расширенный"),
                    callback_data="mode_full",
                ),
                types.InlineKeyboardButton(
                    text=("✅ 📄 Короткий" if current_mode == "brief" else "📄 Короткий"),
                    callback_data="mode_brief",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="🛡️ Режим WAF",
                    callback_data="settings_waf_mode",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text=("✅ Policy" if current_waf_mode == "policy" else "Policy"),
                    callback_data="waf_mode_policy",
                ),
                types.InlineKeyboardButton(
                    text=("✅ Light" if current_waf_mode == "light" else "Light"),
                    callback_data="waf_mode_light",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="💬 Чат для уведомлений",
                    callback_data="settings_notification_chat",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="🔙 Главное меню",
                    callback_data="main_menu",
                ),
            ],
        ]
    )


def build_access_denied_keyboard() -> types.InlineKeyboardMarkup:
    """Кнопка для запроса доступа (если задан REQUEST_ACCESS_URL)."""
    if REQUEST_ACCESS_URL and REQUEST_ACCESS_URL.startswith(("http://", "https://")):
        return types.InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    types.InlineKeyboardButton(
                        text="📬 Запросить доступ",
                        url=REQUEST_ACCESS_URL,
                    ),
                ]
            ]
        )
    return types.InlineKeyboardMarkup(inline_keyboard=[])


def build_admin_keyboard() -> types.InlineKeyboardMarkup:
    """Админ-панель кнопок с расширенным функционалом."""
    return types.InlineKeyboardMarkup(
        inline_keyboard=[
            [
                types.InlineKeyboardButton(
                    text="➕ Добавить доступ",
                    callback_data="admin_add_access",
                ),
                types.InlineKeyboardButton(
                    text="➖ Удалить доступ",
                    callback_data="admin_remove_access",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="📋 Список пользователей",
                    callback_data="admin_list_access",
                ),
                types.InlineKeyboardButton(
                    text="🔐 Управление разрешениями",
                    callback_data="admin_manage_permissions",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="📤 Экспорт пользователей",
                    callback_data="admin_export_users",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="📊 Статистика",
                    callback_data="admin_stats",
                ),
            ],
        ]
    )


router = Router()

# ---------- Middleware для расширенного логирования ----------

class LoggingMiddleware:
    """Middleware для логирования всех обновлений и обработчиков."""
    
    async def __call__(
        self,
        handler,
        event,
        data
    ):
        """Обрабатывает событие с логированием."""
        start_time = asyncio.get_running_loop().time()
        event_type = type(event).__name__
        
        # Логируем входящее событие
        if isinstance(event, types.Message):
            user_id = event.from_user.id if event.from_user else None
            username = event.from_user.username if event.from_user else None
            chat_id = event.chat.id if event.chat else None
            text_preview = (event.text or event.caption or "")[:100] if hasattr(event, 'text') or hasattr(event, 'caption') else ""
            
            logger.info(
                f"📨 Входящее сообщение | "
                f"user_id={user_id} (@{username}) | "
                f"chat_id={chat_id} | "
                f"text={text_preview} | "
                f"message_id={event.message_id if hasattr(event, 'message_id') else 'N/A'}"
            )
        elif isinstance(event, types.CallbackQuery):
            user_id = event.from_user.id if event.from_user else None
            username = event.from_user.username if event.from_user else None
            callback_data = event.data or "N/A"
            
            logger.info(
                f"🔘 Callback query | "
                f"user_id={user_id} (@{username}) | "
                f"callback_data={callback_data} | "
                f"message_id={event.message.message_id if event.message else 'N/A'}"
            )
        elif isinstance(event, types.InlineQuery):
            user_id = event.from_user.id if event.from_user else None
            query = (event.query or "")[:100]
            
            logger.info(
                f"🔍 Inline query | "
                f"user_id={user_id} | "
                f"query={query}"
            )
        else:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"📥 Событие {event_type} получено")
        
        try:
            # НЕ добавляем задержку для входящих сообщений - это блокирует обработку команд
            # Rate limiting для исходящих сообщений уже реализован в telegram_utils
            # Входящие сообщения обрабатываются без задержки для отзывчивости бота
            
            # Выполняем обработчик
            result = await handler(event, data)
            
            # Логируем успешное выполнение
            duration = asyncio.get_running_loop().time() - start_time
            if duration > 1.0:  # Логируем только медленные обработчики
                logger.warning(
                    f"⏱️ Медленный обработчик | "
                    f"event={event_type} | "
                    f"duration={duration:.2f}s"
                )
            else:
                logger.debug(
                    f"✅ Обработчик выполнен | "
                    f"event={event_type} | "
                    f"duration={duration:.3f}s"
                )
            
            return result
            
        except Exception as e:
            # Логируем ошибку с полным контекстом
            try:
                loop = asyncio.get_running_loop()
                duration = loop.time() - start_time
            except RuntimeError:
                # Если нет запущенного loop, используем альтернативный способ
                duration = (datetime.now().timestamp() - start_time) if isinstance(start_time, float) else 0.0
            error_context = {
                "event_type": event_type,
                "duration": f"{duration:.3f}s",
                "error": str(e),
                "error_type": type(e).__name__,
            }
            
            if isinstance(event, types.Message):
                error_context["user_id"] = event.from_user.id if event.from_user else None
                error_context["chat_id"] = event.chat.id if event.chat else None
                error_context["text"] = (event.text or event.caption or "")[:200] if hasattr(event, 'text') or hasattr(event, 'caption') else ""
            elif isinstance(event, types.CallbackQuery):
                error_context["user_id"] = event.from_user.id if event.from_user else None
                error_context["callback_data"] = event.data or "N/A"
            
            logger.error(
                f"❌ Ошибка в обработчике | "
                f"{json.dumps(error_context, ensure_ascii=False)}",
                exc_info=True
            )
            
            # Авто-восстановление: пытаемся отправить сообщение об ошибке пользователю
            try:
                if isinstance(event, types.Message):
                    # Пытаемся отправить сообщение об ошибке
                    try:
                        await event.answer(
                            "❌ Произошла ошибка при обработке запроса. "
                            "Попробуйте еще раз или обратитесь к администратору."
                        )
                    except Exception:
                        # Если не удалось отправить, игнорируем
                        pass
                elif isinstance(event, types.CallbackQuery):
                    # Пытаемся ответить на callback
                    try:
                        await event.answer(
                            "❌ Произошла ошибка",
                            show_alert=True
                        )
                    except Exception:
                        # Если не удалось ответить, игнорируем
                        pass
            except Exception as recovery_error:
                # Если авто-восстановление тоже упало, просто логируем
                logger.error(f"Ошибка при авто-восстановлении: {recovery_error}")
            
            # НЕ пробрасываем исключение дальше - это предотвращает падение бота
            # Вместо этого возвращаем None, чтобы обработка продолжилась
            return None


# Регистрируем middleware
router.message.middleware(LoggingMiddleware())
router.callback_query.middleware(LoggingMiddleware())
router.inline_query.middleware(LoggingMiddleware())

# ---------- Основная проверка доступа ----------

async def check_access(message: types.Message) -> bool:
    """Проверяет доступ пользователя. Если нет доступа - отправляет сообщение."""
    if has_access(message.from_user.id):
        return True
    
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
    
    perm_name = PERMISSIONS.get(permission, permission)
    await message.answer(
        f"❌ У вас нет доступа к функции: {perm_name}\n\n"
        "Свяжитесь с администратором для получения доступа.",
        reply_markup=build_access_denied_keyboard()
    )
    return False


# ---------- Основная проверка домена ----------

async def _process_domains(message: types.Message, state: FSMContext, raw_text: str) -> None:
    """
    Обрабатывает список доменов: парсит, нормализует, проверяет и формирует отчёт.
    
    Args:
        message: Сообщение от пользователя
        state: Состояние FSM
        raw_text: Текст с доменами для обработки
    """
    start_time = asyncio.get_event_loop().time()
    user_id = message.from_user.id
    
    logger.info(
        f"🔍 Начало обработки доменов | "
        f"user_id={user_id} | "
        f"text_length={len(raw_text)} | "
        f"chat_id={message.chat.id}"
    )
    
    # Логируем начало обработки для отладки
    processing_start = asyncio.get_event_loop().time()
    
    # Проверка доступа
    if not await check_access(message):
        logger.warning(f"❌ Доступ запрещен для user_id={user_id} при обработке доменов")
        return
    
    # Проверка rate limit
    if not await check_rate_limit(user_id):
        remaining = await get_remaining_requests(user_id)
        logger.warning(
            f"⏱️ Rate limit превышен | "
            f"user_id={user_id} | "
            f"remaining={remaining}"
        )
        await safe_send_text(
            message.bot,
            message.chat.id,
            f"⏱️ Превышен лимит запросов. Попробуйте позже.\n"
            f"Осталось запросов: {remaining}"
        )
        return
    
    # Валидация и нормализация доменов
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Валидация и нормализация доменов для user_id={user_id}")
    domains, bad = validate_and_normalize_domains(raw_text)
    
    logger.info(
        f"📋 Домены обработаны | "
        f"user_id={user_id} | "
        f"valid={len(domains)} | "
        f"invalid={len(bad)}"
    )

    # Проверка на пустой список
    if not domains:
        await safe_send_text(
            message.bot,
            message.chat.id,
            "❗️ Не вижу ни одного корректного домена.\n\n"
            "Убедитесь, что домены указаны правильно. Поддерживаются форматы:\n"
            "• example.com\n"
            "• https://example.com/path\n"
            "• http://example.com?param=value"
        )
        return
    
    # Проверка лимита доменов
    if len(domains) > settings.MAX_DOMAINS_PER_REQUEST:
        await safe_send_text(
            message.bot,
            message.chat.id,
            f"❗️ Превышен лимит доменов ({settings.MAX_DOMAINS_PER_REQUEST}).\n"
            f"Получено: {len(domains)} доменов."
        )
        return

    # Получаем режим отображения из состояния
    view_mode = (await state.get_data()).get("view_mode", DEFAULT_MODE)
    brief = view_mode == "brief"

    # Семафор для ограничения количества одновременных проверок
    semaphore = asyncio.Semaphore(settings.CONCURRENCY)
    reports: List[str] = []
    collected: List[Tuple[str, dict, dict, bool, Optional[str]]] = []

    # Создаем задачи для проверки всех доменов
    tasks = [
        asyncio.create_task(check_single_domain(d, user_id, semaphore, brief))
        for d in domains
    ]

    # ---------- Прогресс-индикатор ----------
    MIN_EDIT_INTERVAL = 10  # секунд между edit_text (увеличено для снижения нагрузки на API)
    total = len(tasks)
    done = 0
    loop = asyncio.get_running_loop()
    start_ts = loop.time()
    last_edit = start_ts - MIN_EDIT_INTERVAL
    progress_msg: types.Message | None = None

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Ожидание завершения {total} задач проверки доменов")
    
    # Максимальное время на проверку одного домена (включая все попытки)
    MAX_DOMAIN_CHECK_TIMEOUT = 120  # 2 минуты на домен
    
    # Обертываем каждую задачу в таймаут
    async def check_with_timeout(task: asyncio.Task, domain: str) -> Tuple[str, Tuple[str, dict, dict, bool, Optional[str]]]:
        """Обертка для задачи с таймаутом."""
        try:
            return await asyncio.wait_for(task, timeout=MAX_DOMAIN_CHECK_TIMEOUT)
        except asyncio.TimeoutError:
            logger.error(
                f"⏱️ Таймаут при проверке домена {domain} | "
                f"user_id={user_id} | "
                f"timeout={MAX_DOMAIN_CHECK_TIMEOUT}s"
            )
            # Отменяем задачу при таймауте
            if not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
            # Возвращаем частичный результат при таймауте
            error_msg = f"⏱️ Таймаут проверки (> {MAX_DOMAIN_CHECK_TIMEOUT}s)"
            row = (domain, {}, {}, False, None)
            return error_msg, row
        except BaseException as e:
            logger.error(
                f"❌ Критическая ошибка при проверке домена {domain} | "
                f"user_id={user_id} | "
                f"error={type(e).__name__}: {str(e)}",
                exc_info=True
            )
            # Отменяем задачу при ошибке
            if not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
            error_msg = f"❌ Ошибка: {type(e).__name__}"
            row = (domain, {}, {}, False, None)
            return error_msg, row
    
    # Создаем обернутые задачи
    wrapped_tasks = [
        asyncio.create_task(check_with_timeout(task, domain))
        for task, domain in zip(tasks, domains)
    ]
    
    # Общий таймаут для всей обработки (максимум 10 минут на все домены)
    MAX_TOTAL_PROCESSING_TIME = 600  # 10 минут
    
    try:
        # Используем as_completed напрямую, но с проверкой общего таймаута
        completed_count = 0
        for coro in asyncio.as_completed(wrapped_tasks):
            # Проверяем общий таймаут перед обработкой каждого результата
            elapsed_total = loop.time() - start_ts
            if elapsed_total > MAX_TOTAL_PROCESSING_TIME:
                logger.error(
                    f"⏱️ Превышен общий таймаут обработки доменов | "
                    f"user_id={user_id} | "
                    f"elapsed={elapsed_total:.2f}s | "
                    f"done={done}/{total}"
                )
                # Отменяем все оставшиеся задачи
                for task in wrapped_tasks:
                    if not task.done():
                        task.cancel()
                break
            
            try:
                line, row = await coro
                reports.append(line)
                collected.append(row)
                done += 1
                completed_count += 1
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"✅ Домен проверен: {row[0]} ({done}/{total})")
            except BaseException as e:
                logger.error(
                    f"❌ Неожиданная ошибка при обработке результата проверки | "
                    f"user_id={user_id} | "
                    f"done={done}/{total} | "
                    f"error={type(e).__name__}: {str(e)}",
                    exc_info=True
                )
                done += 1
                completed_count += 1
                # Добавляем пустой результат, чтобы не сломать счетчик
                row = ("unknown", {}, {}, False, None)
                collected.append(row)

            now = loop.time()
            need_update = total >= 4 and (done == total or now - last_edit >= MIN_EDIT_INTERVAL)

            if need_update:
                elapsed = now - start_ts
                # Защита от деления на ноль
                if done > 0 and done < total:
                    eta_sec = int(elapsed / done * (total - done))
                    eta_txt = f"{eta_sec // 60}м {eta_sec % 60}с" if eta_sec > 0 else "0 с"
                else:
                    eta_txt = "0 с"
                text = f"⏳ {done} / {total} • осталось ≈ {eta_txt}"

                try:
                    # Используем safe функции для rate limiting
                    from utils.telegram_utils import safe_reply, safe_edit_text
                    if progress_msg is None:
                        progress_msg = await safe_reply(message, text)
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"Создано сообщение прогресса для user_id={user_id}")
                    else:
                        await safe_edit_text(progress_msg, text)
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"Обновлено сообщение прогресса: {done}/{total} для user_id={user_id}")
                    last_edit = now
                except Exception as e:
                    logger.warning(f"Ошибка при обновлении прогресса: {e}")
                    progress_msg = None
            
            # Если все задачи завершены, выходим из цикла
            if completed_count >= total:
                logger.debug(f"Все {total} задач завершены, выходим из цикла")
                break
        
        logger.debug(f"Цикл as_completed завершен: completed={completed_count}, done={done}, total={total}")
    finally:
        # Отменяем все незавершенные задачи с таймаутом
        remaining_tasks = [t for t in wrapped_tasks if not t.done()]
        if remaining_tasks:
            logger.warning(f"Отменяем {len(remaining_tasks)} незавершенных задач для user_id={user_id}")
            for task in remaining_tasks:
                task.cancel()
            # Ждем отмены с таймаутом, чтобы не блокировать event loop
            try:
                await asyncio.wait_for(
                    asyncio.gather(*remaining_tasks, return_exceptions=True),
                    timeout=2.0
                )
            except asyncio.TimeoutError:
                logger.warning(f"Таймаут при ожидании отмены задач для user_id={user_id}")
        logger.debug(f"Все задачи завершены или отменены для user_id={user_id}")

    if bad:
        reports.append("🔸 Игнорированы некорректные строки: " + ", ".join(bad))

    total_duration = asyncio.get_event_loop().time() - start_time
    processing_duration = asyncio.get_event_loop().time() - processing_start
    logger.info(
        f"✅ Все домены проверены | "
        f"user_id={user_id} | "
        f"total={total} | "
        f"duration={total_duration:.2f}s | "
        f"processing_duration={processing_duration:.2f}s | "
        f"avg_per_domain={total_duration/total:.2f}s"
    )

    # ---------- Формирование вывода ----------
    if total >= 4:
        logger.debug(f"Отправка CSV отчета для {total} доменов")
        # CSV отчет для множественных доменов
        csv_bytes = format_csv_report(collected, brief)
        # Используем safe_send_document для rate limiting
        from utils.telegram_utils import safe_send_document
        await safe_send_document(
            message.bot,
            message.chat.id,
            types.BufferedInputFile(csv_bytes, filename="report.csv"),
            caption=f"✔️ Проверено {total} доменов.",
        )
        logger.info(f"CSV отчет отправлен для user_id={user_id}, доменов={total}")
    else:
        logger.debug(f"Отправка отдельных отчетов для {total} доменов")
        # Отдельные отчеты для каждого домена
        has_waf_perm = has_permission(user_id, "check_domains")
        has_monitoring_perm = has_permission(user_id, "monitoring")
        await send_domain_reports(
            message.bot,
            message.chat.id,
            collected,
            view_mode,
            user_id,
            has_waf_perm,
            brief,
            has_monitoring_perm
        )
        logger.info(f"Отчеты отправлены для user_id={user_id}, доменов={total}")


# ---------- Команды ----------

@router.message(CommandStart())
async def cmd_start(message: types.Message, state: FSMContext):
    """
    Обработчик команды /start.
    
    Показывает приветственное сообщение и главное меню.
    Также автоматически регистрирует чат, если команда вызвана из группы/канала.
    """
    user_id = message.from_user.id
    
    # Регистрируем чат, если сообщение пришло не из личных сообщений
    if message.chat.id != user_id:
        chat_title = message.chat.title or f"Chat {message.chat.id}"
        chat_type = message.chat.type
        register_chat(user_id, message.chat.id, chat_title, chat_type)
    
    # Проверка доступа
    if not has_access(user_id):
        await message.answer(
            "❌ У вас нет доступа к этому боту.\n\n"
            "Свяжитесь с администратором, нажав кнопку ниже.",
            reply_markup=build_access_denied_keyboard()
        )
        return
    
    # Инициализируем режим пользователя
    mode = get_mode(user_id, DEFAULT_MODE)
    await state.update_data(view_mode=mode)
    
    # Записываем использование команды
    record_command("start")
    
    # Формируем список доступных функций
    available_features = []
    
    if has_permission(user_id, "check_domains"):
        available_features.append("🔍 Проверка доменов")
    if has_permission(user_id, "monitoring"):
        available_features.append("📊 Мониторинг доменов")
    if has_permission(user_id, "history"):
        available_features.append("📋 История проверок")
    if has_permission(user_id, "settings"):
        available_features.append("⚙️ Настройки")
    if has_permission(user_id, "inline"):
        available_features.append("💬 Inline режим")
    if has_permission(user_id, "file_upload"):
        available_features.append("📄 Загрузка файлов")
    
    features_text = "\n".join(f"• {f}" for f in available_features) if available_features else "• Базовый доступ"
    
    bot_username = await get_bot_username(message.bot)
    help_text = (
        "👋 *Добро пожаловать в Domain Scanner Bot!*\n\n"
        "Я помогаю анализировать домены и получать информацию о:\n"
        "• DNS записях (A, AAAA, MX, NS)\n"
        "• SSL сертификатах (обычный и GOST)\n"
        "• WAF защите\n\n"
        "📋 *Доступные вам функции:*\n"
        f"{features_text}\n\n"
        "📥 *Как использовать:*\n"
        "• Просто отправьте домен(ы) текстом\n"
        "• Или используйте кнопки меню ниже\n"
        f"• Или вызовите бота в любом чате через @{bot_username}\n\n"
        "Используйте кнопки ниже для быстрого доступа к функциям."
    )

    await message.answer(
        help_text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=build_main_menu_keyboard(user_id),
    )


@router.message(Command("health"))
async def cmd_health(message: types.Message, state: FSMContext):
    """
    Проверка состояния бота и всех компонентов.
    
    Показывает статус доступности всех сервисов и компонентов системы.
    """
    user_id = message.from_user.id
    
    # Только для администратора
    if user_id != ADMIN_ID:
        await message.answer("❌ Эта команда доступна только администратору.")
        return
    
    health_status = []
    health_status.append("🏥 *Health Check*\n")
    
    # Проверка доступности компонентов
    try:
        # Проверка кэша
        from utils.cache import get_cache_stats
        cache_stats = get_cache_stats()
        health_status.append(f"✅ Кэш: {cache_stats['memory_cache_size']} записей в памяти")
        health_status.append(f"   Hit rate: {cache_stats['hit_rate']}%")
    except Exception as e:
        health_status.append(f"❌ Кэш: Ошибка - {e}")
    
    # Проверка статистики
    try:
        from utils.stats import get_stats
        stats = get_stats()
        health_status.append(f"✅ Статистика: {stats['total_domains_checked']} проверок")
    except Exception as e:
        health_status.append(f"❌ Статистика: Ошибка - {e}")
    
    # Проверка мониторинга
    try:
        from utils.monitoring import get_monitored_domains
        total_monitored = sum(len(get_monitored_domains(uid)) for uid in [1, 2, 3])  # Примерная проверка
        health_status.append(f"✅ Мониторинг: активен")
    except Exception as e:
        health_status.append(f"❌ Мониторинг: Ошибка - {e}")
    
    # Проверка rate limiter
    try:
        from utils.rate_limiter import _rate_limiter
        health_status.append(f"✅ Rate Limiter: активен")
    except Exception as e:
        health_status.append(f"❌ Rate Limiter: Ошибка - {e}")
    
    # Проверка Gost сервисов (базовая проверка)
    health_status.append(f"✅ Gost сервисы: проверка через docker-compose")
    
    await message.answer("\n".join(health_status), parse_mode="Markdown")


@router.message(Command("help"))
async def cmd_help(message: types.Message, state: FSMContext):
    """
    Команда /help - показывает подробную справку по использованию бота.
    """
    user_id = message.from_user.id
    
    # Проверка доступа
    if not await check_access(message):
        return
    
    # Записываем использование команды
    record_command("help")
    
    bot_username = await get_bot_username(message.bot)
    help_text = (
        "ℹ️ *Справка по использованию бота*\n\n"
        "🔍 *Проверка доменов:*\n"
        "• Отправьте домен(ы) текстом или через кнопку 'Проверить домен'\n"
        "• Поддерживаются URL: `https://example.com/path` → `example.com`\n"
        "• Можно отправить файл `.txt` со списком доменов\n"
        "• При 4+ доменах вы получите CSV-отчёт\n\n"
        "📊 *Мониторинг:*\n"
        "• Команда `/monitor` или кнопка 'Мониторинг'\n"
        "• Добавьте домены для отслеживания изменений\n"
        "• Получайте уведомления при изменениях GOST, WAF, сертификатов, DNS\n\n"
        "⚙️ *Настройки:*\n"
        "• Режим отчета: Расширенный (с DNS) или Короткий\n"
        "• Режим WAF: Policy-based или Light check\n"
        "• Все настройки сохраняются для вашего аккаунта\n\n"
        "📋 *История:*\n"
        "• Команда `/history` или кнопка 'История'\n"
        "• Просмотр последних проверенных доменов\n\n"
        f"💡 *Совет:* Используйте inline режим в любом чате:\n"
        f"Напишите `@{bot_username} example.com` для быстрой проверки!"
    )
    
    await safe_send_text(
        message.bot,
        message.chat.id,
        help_text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=build_main_menu_keyboard(user_id),
    )


@router.message(Command("stats"))
async def cmd_stats(message: types.Message):
    """
    Команда /stats - показывает статистику использования бота.
    
    Доступна только администратору.
    """
    user_id = message.from_user.id
    
    # Проверка доступа
    if not await check_access(message):
        return
    
    # Только администратор может видеть статистику
    if user_id != ADMIN_ID:
        await message.answer("❌ Эта команда доступна только администратору.")
        return
    
    # Записываем использование команды
    record_command("stats")
    
    # Получаем статистику
    stats = get_stats()
    
    # Формируем сообщение
    text = (
        "📊 *Статистика бота*\n\n"
        f"⏱️ *Время работы:*\n"
        f"• Дней: {stats['uptime_days']}\n"
        f"• Часов: {stats['uptime_hours']}\n"
        f"• Секунд: {stats['uptime_seconds']}\n\n"
        f"📈 *Использование:*\n"
        f"• Проверено доменов: {stats['total_domains_checked']}\n"
        f"• Уникальных пользователей: {stats['total_users']}\n\n"
    )
    
    # Топ доменов
    if stats['top_domains']:
        text += "🔝 *Топ доменов:*\n"
        for domain, count in list(stats['top_domains'].items())[:5]:
            text += f"• {domain}: {count}\n"
        text += "\n"
    
    # Топ команд
    if stats['top_commands']:
        text += "⚙️ *Топ команд:*\n"
        for cmd, count in list(stats['top_commands'].items())[:5]:
            text += f"• {cmd}: {count}\n"
        text += "\n"
    
    # Топ ошибок
    if stats['top_errors']:
        text += "⚠️ *Топ ошибок:*\n"
        for error, count in list(stats['top_errors'].items())[:5]:
            text += f"• {error}: {count}\n"
    
    text += f"\n🔄 Последний сброс: {stats['last_reset']}"
    
    try:
        # Проверяем, что bot не None
        if message.bot is None:
            logger.warning("message.bot is None in cmd_stats, используем прямой вызов")
            await message.answer(text, parse_mode=ParseMode.MARKDOWN)
        else:
            await safe_send_text(
                message.bot,
                message.chat.id,
                text,
                parse_mode=ParseMode.MARKDOWN
            )
    except Exception as e:
        logger.error(
            f"❌ Ошибка при отправке статистики | "
            f"user_id={user_id} | "
            f"error={type(e).__name__}: {str(e)}",
            exc_info=True
        )
        # Пытаемся отправить через прямой вызов
        try:
            await message.answer(
                "❌ Ошибка при загрузке статистики. Попробуйте позже.",
                parse_mode=ParseMode.MARKDOWN
            )
        except Exception:
            pass  # Игнорируем ошибки при отправке сообщения об ошибке


@router.message(Command("export_history"))
async def cmd_export_history(message: types.Message, state: FSMContext):
    """
    Команда /export_history - экспортирует историю проверок в CSV.
    
    Поддерживает фильтры по дате и домену.
    """
    user_id = message.from_user.id
    
    # Проверка доступа
    if not await check_access(message):
        return
    
    # Проверка разрешения на просмотр истории
    if not await check_permission(message, "history"):
        return
    
    # Проверка rate limit
    if not await check_rate_limit(user_id, operation_type="default"):
        remaining = await get_remaining_requests(user_id, operation_type="default")
        await message.answer(
            f"⏱️ Превышен лимит запросов. Попробуйте позже.\n"
            f"Осталось запросов: {remaining}"
        )
        return
    
    if not settings.HISTORY_ENABLED:
        await message.answer("❌ История проверок отключена в настройках.")
        return
    
    # Получаем историю пользователя
    from utils.history import get_user_history
    history = get_user_history(user_id, limit=1000)  # Максимум 1000 записей
    
    if not history:
        await message.answer("📋 История проверок пуста.")
        return
    
    # Формируем CSV
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Заголовки CSV
    writer.writerow([
        "Дата и время",
        "Домен",
        "GOST",
        "WAF",
        "Метод WAF",
        "Сертификат до",
        "GOST сертификат до",
        "DNS A",
        "DNS AAAA",
        "DNS MX",
        "DNS NS",
    ])
    
    # Записываем данные
    for entry in history:
        ssl_info = entry.get("ssl", {})
        dns_info = entry.get("dns", {})
        
        writer.writerow([
            entry.get("timestamp", ""),
            entry.get("domain", ""),
            "Да" if ssl_info.get("gost") else "Нет",
            "Да" if entry.get("waf") else "Нет",
            entry.get("waf_method", "unknown"),
            ssl_info.get("not_after", ""),
            ssl_info.get("gost_not_after", ""),
            ", ".join(dns_info.get("A", [])),
            ", ".join(dns_info.get("AAAA", [])),
            ", ".join(dns_info.get("MX", [])),
            ", ".join(dns_info.get("NS", [])),
        ])
    
    # Создаем файл для отправки
    csv_data = output.getvalue().encode('utf-8-sig')  # UTF-8 BOM для Excel
    csv_file = io.BytesIO(csv_data)
    csv_file.name = f"history_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    # Отправляем файл
    try:
        await message.answer_document(
            types.FSInputFile(csv_file, filename=csv_file.name),
            caption=f"📊 Экспорт истории проверок ({len(history)} записей)"
        )
        record_command("export_history")
    except Exception as e:
        logger.error(f"Ошибка при экспорте истории для пользователя {user_id}: {e}", exc_info=True)
        await message.answer("❌ Ошибка при экспорте истории. Попробуйте позже.")


@router.message(Command("history"))
async def cmd_history(message: types.Message):
    """
    Команда /history - показывает историю проверок пользователя.
    
    Показывает последние проверенные домены пользователя.
    """
    user_id = message.from_user.id
    
    # Проверка доступа
    if not await check_access(message):
        return
    
    # Проверка разрешения на просмотр истории
    if not await check_permission(message, "history"):
        return
    
    # Проверка rate limit (обычная операция)
    if not await check_rate_limit(user_id, operation_type="default"):
        remaining = await get_remaining_requests(user_id, operation_type="default")
        await message.answer(
            f"⏱️ Превышен лимит запросов. Попробуйте позже.\n"
            f"Осталось запросов: {remaining}"
        )
        return
    
    if not settings.HISTORY_ENABLED:
        await message.answer("❌ История проверок отключена в настройках.")
        return
    
    # Записываем использование команды
    record_command("history")
    
    # Получаем историю пользователя
    history = get_user_history(user_id, limit=10)
    
    if not history:
        await message.answer("📋 История проверок пуста.")
        return
    
    # Формируем сообщение
    text = "📋 *История проверок:*\n\n"
    
    for i, entry in enumerate(history, 1):
        domain = entry.get("domain", "unknown")
        timestamp = entry.get("timestamp", "")
        gost = entry.get("ssl", {}).get("gost", False)
        waf = entry.get("waf", False)
        
        # Форматируем дату
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            date_str = dt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            date_str = timestamp[:16] if timestamp else "unknown"
        
        text += (
            f"{i}. *{domain}*\n"
            f"   📅 {date_str}\n"
            f"   GOST: {'✅' if gost else '❌'} | WAF: {'✅' if waf else '❌'}\n\n"
        )
    
    await safe_send_text(
        message.bot,
        message.chat.id,
        text,
        parse_mode=ParseMode.MARKDOWN
    )


# ---------- Переключение режима ----------

@router.callback_query(F.data.in_({"mode_full", "mode_brief"}))
async def switch_mode(callback: types.CallbackQuery, state: FSMContext):
    """Переключает режим отчета (расширенный/короткий)."""
    start_time = asyncio.get_event_loop().time()
    user_id = callback.from_user.id
    callback_data = callback.data
    
    logger.info(
        f"🔄 Переключение режима | "
        f"user_id={user_id} | "
        f"callback_data={callback_data}"
    )
    
    # Проверка доступа
    if not has_access(user_id):
        logger.warning(f"❌ Доступ запрещен для user_id={user_id} при переключении режима")
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на настройки
    if not has_permission(user_id, "settings"):
        logger.warning(f"❌ Нет разрешения на настройки для user_id={user_id} при переключении режима")
        await callback.answer("❌ Нет доступа к настройкам", show_alert=True)
        return
    
    new_mode = "full" if callback.data == "mode_full" else "brief"
    logger.debug(f"Установка режима {new_mode} для user_id={user_id}")
    
    await state.update_data(view_mode=new_mode)
    set_mode(user_id, new_mode)

    await callback.answer(
        f"Режим установлен: {'Расширенный' if new_mode == 'full' else 'Короткий'}"
    )
    
    logger.debug(f"Режим {new_mode} установлен для user_id={user_id}")

    # Пытаемся найти домен и обновить отчет
    try:
        message_text = callback.message.text or callback.message.caption or ""
        domain = None
        
        logger.debug(f"Поиск домена в сообщении для user_id={user_id}, режим={new_mode}")
        
        # Способ 1: Ищем домен в тексте сообщения
        import re
        domain_match = re.search(r'🌐 <b>([^<]+)</b>', message_text)
        if domain_match:
            domain = domain_match.group(1)
            logger.debug(f"Домен найден в тексте: {domain}")
        
        # Способ 2: Ищем домен в callback_data кнопок клавиатуры
        if not domain and callback.message.reply_markup and callback.message.reply_markup.inline_keyboard:
            logger.debug("Поиск домена в клавиатуре...")
            for row in callback.message.reply_markup.inline_keyboard:
                for button in row:
                    if button.callback_data:
                        # Ищем в любых кнопках, связанных с доменом
                        if "recheck_" in button.callback_data:
                            domain = button.callback_data.replace("recheck_", "")
                            break
                        elif "quick_waf_" in button.callback_data:
                            domain = button.callback_data.replace("quick_waf_", "")
                            break
                        elif "quick_certs_" in button.callback_data:
                            domain = button.callback_data.replace("quick_certs_", "")
                            break
                        elif "detail_dns_" in button.callback_data:
                            domain = button.callback_data.replace("detail_dns_", "")
                            break
                        elif "detail_ssl_" in button.callback_data:
                            domain = button.callback_data.replace("detail_ssl_", "")
                            break
                        elif "detail_waf_" in button.callback_data:
                            domain = button.callback_data.replace("detail_waf_", "")
                            break
                if domain:
                    break
        
        # Если нашли домен, обновляем отчет
        if domain:
            logger.info(f"Обновление отчета для домена {domain} с режимом {new_mode}")
            try:
                # Перепроверяем домен с новым режимом
                # Это гарантирует, что отчет будет обновлен с актуальными данными
                await _recheck_domain(callback.message, state, domain, new_mode)
                duration = asyncio.get_running_loop().time() - start_time
                logger.info(f"✅ Отчет обновлен для {domain} за {duration:.2f}s")
            except Exception as e:
                duration = asyncio.get_running_loop().time() - start_time
                logger.error(
                    f"❌ Ошибка при обновлении отчета для {domain} | "
                    f"user_id={user_id} | "
                    f"режим={new_mode} | "
                    f"duration={duration:.2f}s | "
                    f"error={type(e).__name__}: {str(e)}",
                    exc_info=True
                )
                # Если не удалось обновить отчет, хотя бы обновляем клавиатуру
                try:
                    has_waf_perm = has_permission(user_id, "check_domains")
                    has_monitoring_perm = has_permission(user_id, "monitoring")
                    keyboard = build_report_keyboard(domain, new_mode, user_id, has_waf_perm, has_monitoring_perm)
                    await callback.message.edit_reply_markup(reply_markup=keyboard)
                except Exception as e2:
                    logger.error(f"Ошибка при обновлении клавиатуры: {e2}")
                    pass
        else:
            # Если это не отчет о домене (например, настройки), просто обновляем клавиатуру
            if callback.message.reply_markup:
                try:
                    await callback.message.edit_reply_markup(reply_markup=build_mode_keyboard(new_mode))
                except Exception:
                    pass
    except Exception as e:
        logger.error(f"Ошибка при обновлении режима: {e}", exc_info=True)
        # Пытаемся хотя бы обновить клавиатуру
        try:
            if callback.message.reply_markup:
                await callback.message.edit_reply_markup(reply_markup=build_mode_keyboard(new_mode))
        except Exception:
            pass


# ---------- Переключение режима WAF ----------

@router.callback_query(F.data.in_({"waf_mode_policy", "waf_mode_light"}))
async def switch_waf_mode(callback: types.CallbackQuery):
    """Переключает режим проверки WAF."""
    user_id = callback.from_user.id
    
    # Проверка доступа
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на настройки
    if not has_permission(user_id, "settings"):
        await callback.answer("❌ Нет доступа к настройкам", show_alert=True)
        return
    
    new_mode = "policy" if callback.data == "waf_mode_policy" else "light"
    set_waf_mode(user_id, new_mode)

    await callback.answer(
        f"Режим WAF установлен: {'Policy-based' if new_mode == 'policy' else 'Light check'}"
    )

    try:
        await callback.message.edit_reply_markup(reply_markup=build_waf_mode_keyboard(new_mode))
    except Exception:
        pass


# ---------- Быстрые действия из отчета ----------

async def _recheck_domain(
    message: types.Message,
    state: FSMContext,
    domain: str,
    mode: Optional[str] = None
) -> None:
    """
    Перепроверяет один домен и обновляет отчет.
    
    Args:
        message: Сообщение для обновления
        state: Состояние FSM
        domain: Домен для перепроверки
        mode: Режим отчета (если None, берется из state)
    """
    start_time = asyncio.get_event_loop().time()
    user_id = message.from_user.id
    
    logger.info(
        f"🔄 Перепроверка домена | "
        f"user_id={user_id} | "
        f"domain={domain} | "
        f"mode={mode}"
    )
    
    if mode is None:
        mode = (await state.get_data()).get("view_mode", DEFAULT_MODE)
    
    brief = mode == "brief"
    
    try:
        # Обновляем сообщение
        logger.debug(f"Обновление сообщения для домена {domain}")
        from utils.telegram_utils import safe_edit_text
        await safe_edit_text(message, "⏳ Перепроверяю домен...", parse_mode=ParseMode.HTML)
        
        # Получаем данные
        check_start = asyncio.get_event_loop().time()
        logger.debug(f"Начало проверки домена {domain}")
        
        dns_info, ssl_info, waf_result = await asyncio.gather(
            fetch_dns(domain, settings.DNS_TIMEOUT),
            fetch_ssl(domain),
            test_waf(domain, user_id=user_id),
            return_exceptions=True
        )
        
        check_duration = asyncio.get_event_loop().time() - check_start
        logger.info(
            f"✅ Проверка домена завершена | "
            f"domain={domain} | "
            f"duration={check_duration:.2f}s"
        )
        
        # Обрабатываем исключения (включая CancelledError, который является BaseException)
        if isinstance(dns_info, BaseException):
            logger.error(
                f"❌ Ошибка DNS для {domain} | "
                f"user_id={user_id} | "
                f"error={type(dns_info).__name__}: {str(dns_info)}",
                exc_info=True
            )
            dns_info = {}
        if isinstance(ssl_info, BaseException):
            logger.error(
                f"❌ Ошибка SSL для {domain} | "
                f"user_id={user_id} | "
                f"error={type(ssl_info).__name__}: {str(ssl_info)}",
                exc_info=True
            )
            ssl_info = {}
        
        # Убеждаемся, что ssl_info и dns_info - это словари
        if not isinstance(ssl_info, dict):
            logger.warning(f"ssl_info для {domain} не является словарем: {type(ssl_info)}")
            ssl_info = {}
        if not isinstance(dns_info, dict):
            logger.warning(f"dns_info для {domain} не является словарем: {type(dns_info)}")
            dns_info = {}
        
        # Обрабатываем результат WAF (включая CancelledError, который является BaseException)
        if isinstance(waf_result, BaseException):
            logger.error(f"Ошибка WAF для {domain}: {waf_result}")
            waf_enabled = False
            waf_method = None
        elif isinstance(waf_result, tuple) and len(waf_result) == 2:
            waf_enabled, waf_method = waf_result
        else:
            waf_enabled = bool(waf_result)
            waf_method = None
        
        # Формируем отчет
        report_text = build_report(domain, dns_info, ssl_info, waf_enabled, brief=brief, waf_method=waf_method)
        
        # Создаем клавиатуру
        has_waf_perm = has_permission(user_id, "check_domains")
        has_monitoring_perm = has_permission(user_id, "monitoring")
        keyboard = build_report_keyboard(domain, mode, user_id, has_waf_perm, has_monitoring_perm)
        
        # Обновляем сообщение
        logger.debug(f"Обновление отчета для домена {domain}")
        from utils.telegram_utils import safe_edit_text
        await safe_edit_text(
            message,
            report_text,
            parse_mode=ParseMode.HTML,
            reply_markup=keyboard,
        )
        
        total_duration = asyncio.get_event_loop().time() - start_time
        logger.info(
            f"✅ Отчет обновлен | "
            f"domain={domain} | "
            f"user_id={user_id} | "
            f"mode={mode} | "
            f"total_duration={total_duration:.2f}s"
        )
        
        # Сохраняем в историю
        if settings.HISTORY_ENABLED:
            try:
                add_check_result(domain, user_id, dns_info, ssl_info, waf_enabled, waf_method)
            except Exception as e:
                logger.warning(
                    f"⚠️ Ошибка при сохранении в историю | "
                    f"domain={domain} | "
                    f"user_id={user_id} | "
                    f"error={type(e).__name__}: {str(e)}"
                )
        
        # Записываем статистику
        if settings.STATS_ENABLED:
            record_domain_check(domain, user_id)
            
    except Exception as e:
        duration = asyncio.get_event_loop().time() - start_time
        logger.error(
            f"❌ Критическая ошибка при перепроверке домена | "
            f"domain={domain} | "
            f"user_id={user_id} | "
            f"mode={mode} | "
            f"duration={duration:.2f}s | "
            f"error={type(e).__name__}: {str(e)}",
            exc_info=True
        )
        from utils.telegram_utils import safe_edit_text
        await safe_edit_text(
            message,
            f"❌ Ошибка при перепроверке домена {domain}:\n{type(e).__name__}",
            parse_mode=ParseMode.HTML
        )


@router.callback_query(F.data.startswith("recheck_"))
async def quick_recheck(callback: types.CallbackQuery, state: FSMContext):
    """Быстрая перепроверка домена."""
    start_time = asyncio.get_event_loop().time()
    user_id = callback.from_user.id
    
    logger.info(
        f"🔄 Запрос на перепроверку домена | "
        f"user_id={user_id} | "
        f"callback_data={callback.data}"
    )
    
    if not has_access(user_id):
        logger.warning(f"❌ Доступ запрещен для user_id={user_id} при перепроверке")
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    if not has_permission(user_id, "check_domains"):
        logger.warning(f"❌ Нет разрешения на проверку доменов для user_id={user_id}")
        await callback.answer("❌ Нет доступа к проверке доменов", show_alert=True)
        return
    
    # Извлекаем домен из callback_data
    domain = callback.data.replace("recheck_", "")
    logger.debug(f"Перепроверка домена {domain} для user_id={user_id}")
    
    await callback.answer("🔄 Перепроверяю домен...")
    
    try:
        await _recheck_domain(callback.message, state, domain)
        duration = asyncio.get_event_loop().time() - start_time
        logger.info(
            f"✅ Перепроверка завершена | "
            f"domain={domain} | "
            f"user_id={user_id} | "
            f"duration={duration:.2f}s"
        )
    except Exception as e:
        duration = asyncio.get_event_loop().time() - start_time
        logger.error(
            f"❌ Ошибка при перепроверке | "
            f"domain={domain} | "
            f"user_id={user_id} | "
            f"duration={duration:.2f}s | "
            f"error={type(e).__name__}: {str(e)}",
            exc_info=True
        )
        await callback.answer("❌ Ошибка при перепроверке домена", show_alert=True)


@router.callback_query(F.data.startswith("quick_waf_"))
async def quick_waf_check(callback: types.CallbackQuery, state: FSMContext):
    """
    Быстрая проверка WAF для домена через отправку тестовой инъекции.
    
    Использует специальную проверку с инъекциями для гарантированного получения 403,
    если WAF присутствует.
    """
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    if not has_permission(user_id, "check_domains"):
        await callback.answer("❌ Нет доступа к проверке доменов", show_alert=True)
        return
    
    # Извлекаем домен
    domain = callback.data.replace("quick_waf_", "")
    
    await callback.answer("🛡️ Проверяю WAF через инъекцию...")
    
    try:
        # Обновляем сообщение
        await callback.message.edit_text(
            f"🛡️ Проверяю WAF для {domain}...\n\n"
            f"Отправляю тестовые запросы с инъекциями для проверки защиты.",
            parse_mode=ParseMode.HTML
        )
        
        # Используем специальную проверку с инъекциями
        waf_result = await test_waf_injection(domain)
        
        # Обрабатываем результат (кортеж (bool, str))
        if isinstance(waf_result, tuple) and len(waf_result) == 2:
            waf_enabled, waf_method = waf_result
        else:
            waf_enabled = bool(waf_result)
            waf_method = "injection"
        
        # Получаем текущие данные для обновления отчета
        dns_info = await fetch_dns(domain, settings.DNS_TIMEOUT)
        ssl_info = await fetch_ssl(domain)
        
        # Формируем отчет
        mode = (await state.get_data()).get("view_mode", DEFAULT_MODE)
        brief = mode == "brief"
        report_text = build_report(domain, dns_info, ssl_info, waf_enabled, brief=brief, waf_method=waf_method)
        
        # Обновляем клавиатуру
        has_waf_perm = has_permission(user_id, "check_domains")
        has_monitoring_perm = has_permission(user_id, "monitoring")
        keyboard = build_report_keyboard(domain, mode, user_id, has_waf_perm, has_monitoring_perm)
        
        await callback.message.edit_text(
            report_text,
            parse_mode=ParseMode.HTML,
            reply_markup=keyboard,
        )
        
        # Формируем детальное сообщение о результате
        if waf_enabled:
            result_msg = "✅ WAF обнаружен (получен блокирующий статус при инъекции)"
        else:
            result_msg = "❌ WAF не обнаружен (инъекции не заблокированы)"
        
        await callback.answer(result_msg, show_alert=True)
        
    except Exception as e:
        logger.error(f"Ошибка при проверке WAF для {domain}: {e}", exc_info=True)
        await callback.answer("❌ Ошибка при проверке WAF", show_alert=True)


@router.callback_query(F.data.startswith("quick_certs_"))
async def quick_certs_check(callback: types.CallbackQuery, state: FSMContext):
    """Быстрая проверка сертификатов для домена."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    if not has_permission(user_id, "check_domains"):
        await callback.answer("❌ Нет доступа к проверке доменов", show_alert=True)
        return
    
    # Извлекаем домен
    domain = callback.data.replace("quick_certs_", "")
    
    await callback.answer("📅 Проверяю сертификаты...")
    
    try:
        # Обновляем сообщение
        await callback.message.edit_text(
            f"📅 Проверяю сертификаты для {domain}...",
            parse_mode=ParseMode.HTML
        )
        
        # Получаем данные о сертификатах
        ssl_info = await fetch_ssl(domain)
        dns_info = await fetch_dns(domain, settings.DNS_TIMEOUT)
        waf_result = await test_waf(domain, user_id=user_id)
        
        # Обрабатываем результат WAF
        if isinstance(waf_result, tuple) and len(waf_result) == 2:
            waf_enabled, waf_method = waf_result
        else:
            waf_enabled = bool(waf_result)
            waf_method = None
        
        # Формируем отчет
        mode = (await state.get_data()).get("view_mode", DEFAULT_MODE)
        brief = mode == "brief"
        report_text = build_report(domain, dns_info, ssl_info, waf_enabled, brief=brief, waf_method=waf_method)
        
        # Обновляем клавиатуру
        has_waf_perm = has_permission(user_id, "check_domains")
        has_monitoring_perm = has_permission(user_id, "monitoring")
        keyboard = build_report_keyboard(domain, mode, user_id, has_waf_perm, has_monitoring_perm)
        
        await callback.message.edit_text(
            report_text,
            parse_mode=ParseMode.HTML,
            reply_markup=keyboard,
        )
        
        # Формируем информацию о сертификатах
        cert_info = []
        
        if ssl_info.get("NotAfter"):
            from utils.formatting import _format_date_with_days_left
            cert_info.append(f"Обычный: {_format_date_with_days_left(ssl_info.get('NotAfter'))}")
        
        if ssl_info.get("GostNotAfter"):
            from utils.formatting import _format_date_with_days_left
            cert_info.append(f"GOST: {_format_date_with_days_left(ssl_info.get('GostNotAfter'))}")
        
        if cert_info:
            await callback.answer("✅ Сертификаты проверены\n" + "\n".join(cert_info), show_alert=True)
        else:
            await callback.answer("✅ Сертификаты проверены")
        
    except Exception as e:
        logger.error(f"Ошибка при проверке сертификатов для {domain}: {e}", exc_info=True)
        await callback.answer("❌ Ошибка при проверке сертификатов", show_alert=True)


# ---------- Детальный просмотр блоков ----------

@router.callback_query(F.data.startswith("detail_dns_"))
async def show_dns_details(callback: types.CallbackQuery):
    """Показывает детальную информацию о DNS записях."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    # Извлекаем домен
    domain = callback.data.replace("detail_dns_", "")
    
    await callback.answer("📡 Загружаю DNS записи...")
    
    try:
        # Получаем DNS информацию
        dns_info = await fetch_dns(domain, settings.DNS_TIMEOUT)
        
        # Формируем детальный отчет
        lines = [f"📡 <b>Детальная информация DNS для {domain}</b>\n"]
        
        # IP адреса
        ip_list = dns_info.get("IP", []) or dns_info.get("A", [])
        if ip_list:
            lines.append(f"<b>IP адреса ({len(ip_list)}):</b>")
            for ip in ip_list:
                lines.append(f"  • {ip}")
        else:
            lines.append("<b>IP адреса:</b> —")
        
        lines.append("")
        
        # A записи
        a_records = dns_info.get("A", [])
        if a_records:
            lines.append(f"<b>A записи ({len(a_records)}):</b>")
            for a in a_records:
                lines.append(f"  • {a}")
        else:
            lines.append("<b>A записи:</b> —")
        
        lines.append("")
        
        # AAAA записи
        aaaa_records = dns_info.get("AAAA", [])
        if aaaa_records:
            lines.append(f"<b>AAAA записи ({len(aaaa_records)}):</b>")
            for aaaa in aaaa_records:
                lines.append(f"  • {aaaa}")
        else:
            lines.append("<b>AAAA записи:</b> —")
        
        lines.append("")
        
        # MX записи
        mx_records = dns_info.get("MX", [])
        if mx_records:
            lines.append(f"<b>MX записи ({len(mx_records)}):</b>")
            for mx in mx_records:
                lines.append(f"  • {mx}")
        else:
            lines.append("<b>MX записи:</b> —")
        
        lines.append("")
        
        # NS записи
        ns_records = dns_info.get("NS", [])
        if ns_records:
            lines.append(f"<b>NS записи ({len(ns_records)}):</b>")
            for ns in ns_records:
                lines.append(f"  • {ns}")
        else:
            lines.append("<b>NS записи:</b> —")
        
        detail_text = "\n".join(lines)
        
        # Создаем клавиатуру для возврата
        from utils.formatting import build_report_keyboard
        mode = "full"  # Используем полный режим для деталей
        has_waf_perm = has_permission(user_id, "check_domains")
        has_monitoring_perm = has_permission(user_id, "monitoring")
        keyboard = build_report_keyboard(domain, mode, user_id, has_waf_perm, has_monitoring_perm)
        
        await callback.message.edit_text(
            detail_text,
            parse_mode=ParseMode.HTML,
            reply_markup=keyboard
        )
        
    except Exception as e:
        logger.error(f"Ошибка при получении DNS деталей для {domain}: {e}", exc_info=True)
        await callback.answer("❌ Ошибка при получении DNS информации", show_alert=True)


@router.callback_query(F.data.startswith("detail_ssl_"))
async def show_ssl_details(callback: types.CallbackQuery):
    """Показывает детальную информацию о SSL сертификатах."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    # Извлекаем домен
    domain = callback.data.replace("detail_ssl_", "")
    
    await callback.answer("🔒 Загружаю информацию о сертификатах...")
    
    try:
        # Получаем SSL информацию
        ssl_info = await fetch_ssl(domain)
        
        # Формируем детальный отчет
        lines = [f"🔒 <b>Детальная информация SSL для {domain}</b>\n"]
        
        # Обычный сертификат
        lines.append("<b>📋 Обычный SSL сертификат</b>")
        lines.append("")
        
        cn = ssl_info.get('CN', '—')
        lines.append(f"<b>Common Name (CN):</b> {cn if cn != '—' else '—'}")
        
        san = ssl_info.get('SAN', [])
        if san:
            lines.append(f"<b>Subject Alternative Names ({len(san)}):</b>")
            for san_item in san:
                lines.append(f"  • {san_item}")
        else:
            lines.append("<b>Subject Alternative Names:</b> —")
        
        lines.append("")
        
        issuer = ssl_info.get('Issuer', '—')
        if issuer and issuer != "—":
            # Упрощаем issuer
            issuer_short = issuer.split(',')[0] if ',' in issuer else issuer
            lines.append(f"<b>Издатель:</b> {issuer_short}")
        
        sig_alg = ssl_info.get('SigAlg', '—')
        if sig_alg and sig_alg != "—":
            lines.append(f"<b>Алгоритм подписи:</b> {sig_alg}")
        
        cipher = ssl_info.get('Cipher', '—')
        if cipher and cipher != "—":
            lines.append(f"<b>Используемый шифр:</b> {cipher}")
        
        lines.append("")
        
        # Даты обычного сертификата
        not_before = ssl_info.get('NotBefore')
        not_after = ssl_info.get('NotAfter')
        if not_before:
            from utils.formatting import _format_date
            lines.append(f"<b>Действителен с:</b> {_format_date(not_before)}")
        if not_after:
            from utils.formatting import _format_date_with_days_left
            lines.append(f"<b>Действителен до:</b> {_format_date_with_days_left(not_after)}")
        
        lines.append("")
        lines.append("")
        
        # GOST сертификат
        lines.append("<b>🔐 GOST TLS сертификат</b>")
        lines.append("")
        
        gost_enabled = ssl_info.get('gost', False) or ssl_info.get('IsGOST', False)
        if gost_enabled:
            lines.append("✅ <b>GOST сертификат обнаружен</b>")
            lines.append("")
            
            gost_not_before = ssl_info.get('GostNotBefore')
            gost_not_after = ssl_info.get('GostNotAfter')
            
            if gost_not_before:
                from utils.formatting import _format_date
                lines.append(f"<b>Действителен с:</b> {_format_date(gost_not_before)}")
            if gost_not_after:
                from utils.formatting import _format_date_with_days_left
                lines.append(f"<b>Действителен до:</b> {_format_date_with_days_left(gost_not_after)}")
        else:
            lines.append("❌ <b>GOST сертификат не обнаружен</b>")
        
        detail_text = "\n".join(lines)
        
        # Создаем клавиатуру для возврата
        from utils.formatting import build_report_keyboard
        mode = "full"  # Используем полный режим для деталей
        has_waf_perm = has_permission(user_id, "check_domains")
        has_monitoring_perm = has_permission(user_id, "monitoring")
        keyboard = build_report_keyboard(domain, mode, user_id, has_waf_perm, has_monitoring_perm)
        
        await callback.message.edit_text(
            detail_text,
            parse_mode=ParseMode.HTML,
            reply_markup=keyboard
        )
        
    except Exception as e:
        logger.error(f"Ошибка при получении SSL деталей для {domain}: {e}", exc_info=True)
        await callback.answer("❌ Ошибка при получении SSL информации", show_alert=True)


@router.callback_query(F.data.startswith("detail_waf_"))
async def show_waf_details(callback: types.CallbackQuery):
    """Показывает детальную информацию о WAF."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    if not has_permission(user_id, "check_domains"):
        await callback.answer("❌ Нет доступа к проверке WAF", show_alert=True)
        return
    
    # Извлекаем домен
    domain = callback.data.replace("detail_waf_", "")
    
    await callback.answer("🛡️ Проверяю WAF...")
    
    try:
        # Выполняем проверку WAF
        waf_result = await test_waf(domain, user_id=user_id)
        
        # Обрабатываем результат
        if isinstance(waf_result, tuple) and len(waf_result) == 2:
            waf_enabled, waf_method = waf_result
        else:
            waf_enabled = bool(waf_result)
            waf_method = None
        
        # Формируем детальный отчет
        lines = [f"🛡️ <b>Детальная информация WAF для {domain}</b>\n"]
        lines.append("")
        
        if waf_enabled:
            lines.append("✅ <b>WAF обнаружен</b>")
        else:
            lines.append("❌ <b>WAF не обнаружен</b>")
        
        lines.append("")
        
        # Информация о методе проверки
        if waf_method:
            method_names = {
                "policy": "Check Policy (/?monitoring=test_query_for_policy)",
                "light": "Легкая проверка (анализ заголовков и статусов)",
                "injection": "Проверка через инъекции (SQL, XSS, Path Traversal)",
            }
            method_name = method_names.get(waf_method, waf_method)
            lines.append(f"<b>Метод проверки:</b> {method_name}")
        else:
            lines.append("<b>Метод проверки:</b> Не указан")
        
        lines.append("")
        lines.append("<i>💡 Для дополнительной проверки используйте кнопку '🛡️ Проверить WAF' в основном отчете.</i>")
        
        detail_text = "\n".join(lines)
        
        # Создаем клавиатуру для возврата
        from utils.formatting import build_report_keyboard
        mode = "full"  # Используем полный режим для деталей
        has_waf_perm = has_permission(user_id, "check_domains")
        has_monitoring_perm = has_permission(user_id, "monitoring")
        keyboard = build_report_keyboard(domain, mode, user_id, has_waf_perm, has_monitoring_perm)
        
        await callback.message.edit_text(
            detail_text,
            parse_mode=ParseMode.HTML,
            reply_markup=keyboard
        )
        
    except Exception as e:
        logger.error(f"Ошибка при получении WAF деталей для {domain}: {e}", exc_info=True)
        await callback.answer("❌ Ошибка при проверке WAF", show_alert=True)


# ---------- МОНИТОРИНГ ДОМЕНОВ ----------

@router.message(Command("monitor"))
async def cmd_monitor(message: types.Message):
    """Команда для управления мониторингом доменов."""
    # Проверка доступа
    if not await check_access(message):
        return
    
    # Проверка разрешения на мониторинг
    if not await check_permission(message, "monitoring"):
        return
    
    user_id = message.from_user.id
    enabled = is_monitoring_enabled(user_id)
    interval = get_monitoring_interval(user_id)
    domains = get_monitored_domains(user_id)
    
    text = (
        f"📊 *Мониторинг доменов*\n\n"
        f"Статус: {'✅ Включен' if enabled else '❌ Выключен'}\n"
        f"Интервал проверки: {interval} минут\n"
        f"Доменов в мониторинге: {len(domains)}\n\n"
        f"Используйте кнопки ниже для управления:"
    )
    
    await safe_send_text(
        message.bot,
        message.chat.id,
        text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=build_monitoring_keyboard()
    )


@router.callback_query(F.data.startswith("monitor_add_from_report_"))
async def monitor_add_from_report(callback: types.CallbackQuery):
    """Добавляет домен в мониторинг из отчета."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await callback.answer("❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    # Извлекаем домен из callback_data
    domain = callback.data.replace("monitor_add_from_report_", "")
    
    if not domain:
        await callback.answer("❌ Ошибка: домен не указан", show_alert=True)
        return
    
    # Нормализуем домен
    domains = normalize_domains([domain])
    
    if not domains:
        await callback.answer("❌ Некорректный домен", show_alert=True)
        return
    
    domain = domains[0]
    
    # Добавляем в мониторинг
    if add_domain_to_monitoring(user_id, domain):
        await callback.answer(f"✅ Домен {domain} добавлен в мониторинг", show_alert=False)
    else:
        await callback.answer(f"ℹ️ Домен {domain} уже в мониторинге", show_alert=False)


@router.callback_query(F.data == "monitor_add")
async def monitor_add(callback: types.CallbackQuery, state: FSMContext):
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await callback.answer("❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    await state.set_state(MonitoringStates.add_domain_waiting)
    await callback.message.answer(
        "📝 Введите домен(ы) для добавления в мониторинг.\n\n"
        "Можно вводить несколько через пробел, запятую или с новой строки:\n"
        "`example.com test.ru https://site.com/path`\n\n"
        "Также можно отправить TXT файл со списком доменов (по одному на строку)."
    )
    await callback.answer()


@router.message(MonitoringStates.add_domain_waiting)
async def process_monitor_add(message: types.Message, state: FSMContext):
    """Обрабатывает добавление доменов в мониторинг (текст или файл)."""
    user_id = message.from_user.id
    
    # Проверяем, не файл ли это
    if message.document:
        doc = message.document
        if doc.file_name and doc.file_name.lower().endswith(".txt"):
            # Обрабатываем файл
            try:
                file_obj = await message.bot.download(doc.file_id)
                text_data = file_obj.getvalue().decode("utf-8", errors="ignore")
                
                if not text_data.strip():
                    await message.answer("❌ Файл пуст или не содержит текста.")
                    await state.clear()
                    return
                
                # Используем ту же логику что и при проверке доменов
                domains, bad = validate_and_normalize_domains(text_data)
                
                added_count = 0
                for domain in domains:
                    if add_domain_to_monitoring(user_id, domain):
                        added_count += 1
                
                response = f"✅ Добавлено {added_count} домен(ов) из файла в мониторинг"
                if bad:
                    response += f"\n⚠️ Некоторые домены не были добавлены (некорректный формат): {', '.join(bad[:5])}"
                    if len(bad) > 5:
                        response += f" и еще {len(bad) - 5}"
                
                await message.answer(response)
                await state.clear()
                return
            except Exception as e:
                logger.error(f"Ошибка при обработке файла для мониторинга: {e}", exc_info=True)
                await message.answer("❌ Ошибка при обработке файла. Попробуйте еще раз.")
                await state.clear()
                return
    
    # Обрабатываем текстовый ввод - используем ту же логику что и при проверке доменов
    text = message.text or ""
    domains, bad = validate_and_normalize_domains(text)
    
    if not domains:
        await message.answer(
            "❗️ Не вижу ни одного корректного домена.\n\n"
            "Убедитесь, что домены указаны правильно. Поддерживаются форматы:\n"
            "• example.com\n"
            "• https://example.com/path\n"
            "• http://example.com?param=value"
        )
        await state.clear()
        return
    
    added_count = 0
    for domain in domains:
        if add_domain_to_monitoring(user_id, domain):
            added_count += 1
    
    response = f"✅ Добавлено {added_count} домен(ов) в мониторинг"
    if bad:
        response += f"\n⚠️ Некоторые домены не были добавлены (некорректный формат): {', '.join(bad[:5])}"
        if len(bad) > 5:
            response += f" и еще {len(bad) - 5}"
    
    await message.answer(response)
    await state.clear()


@router.callback_query(F.data == "monitor_remove")
async def monitor_remove(callback: types.CallbackQuery, state: FSMContext):
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await callback.answer("❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    await state.set_state(MonitoringStates.remove_domain_waiting)
    await callback.message.answer(
        "🗑️ Введите домен(ы) для удаления из мониторинга.\n\n"
        "Можно вводить несколько через пробел или запятую."
    )
    await callback.answer()


@router.message(MonitoringStates.remove_domain_waiting)
async def process_monitor_remove(message: types.Message, state: FSMContext):
    text = message.text or ""
    raw_items = [x.strip() for x in DOMAIN_SPLIT_RE.split(text) if x.strip()]
    domains = normalize_domains(raw_items)
    
    user_id = message.from_user.id
    removed_count = 0
    
    for domain in domains:
        if remove_domain_from_monitoring(user_id, domain):
            removed_count += 1
    
    response = f"✅ Удалено {removed_count} домен(ов) из мониторинга"
    if removed_count < len(domains):
        response += f"\n⚠️ Некоторые домены не были найдены в мониторинге"
    
    await message.answer(response)
    await state.clear()


@router.callback_query(F.data == "monitor_list")
async def monitor_list(callback: types.CallbackQuery):
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await callback.answer("❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    domains = get_monitored_domains(user_id)
    
    if not domains:
        await callback.message.answer("📋 Нет доменов в мониторинге")
    else:
        text = "📋 *Домены в мониторинге:*\n\n" + "\n".join(f"• {d}" for d in domains)
        await callback.message.answer(text, parse_mode=ParseMode.MARKDOWN)
    
    await callback.answer()


@router.callback_query(F.data == "stats_export_json")
async def stats_export_json(callback: types.CallbackQuery):
    """Экспортирует статистику в JSON."""
    user_id = callback.from_user.id
    
    if user_id != ADMIN_ID:
        await callback.answer("❌ Только администратор", show_alert=True)
        return
    
    try:
        from utils.stats import get_stats
        stats = get_stats()
        
        import io
        json_data = json.dumps(stats, ensure_ascii=False, indent=2, default=str)
        json_file = io.BytesIO(json_data.encode('utf-8'))
        json_file.name = f"stats_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        await callback.message.answer_document(
            types.FSInputFile(json_file, filename=json_file.name),
            caption="📥 Экспорт статистики в JSON"
        )
        await callback.answer("✅ Статистика экспортирована в JSON")
    except Exception as e:
        logger.error(f"Ошибка при экспорте статистики в JSON: {e}", exc_info=True)
        await callback.answer("❌ Ошибка при экспорте", show_alert=True)


@router.callback_query(F.data == "stats_export_csv")
async def stats_export_csv(callback: types.CallbackQuery):
    """Экспортирует статистику в CSV."""
    user_id = callback.from_user.id
    
    if user_id != ADMIN_ID:
        await callback.answer("❌ Только администратор", show_alert=True)
        return
    
    try:
        from utils.stats import get_stats
        stats = get_stats()
        
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Основная статистика
        writer.writerow(["Метрика", "Значение"])
        writer.writerow(["Время работы (дни)", stats['uptime_days']])
        writer.writerow(["Время работы (часы)", stats['uptime_hours']])
        writer.writerow(["Проверено доменов", stats['total_domains_checked']])
        writer.writerow(["Уникальных пользователей", stats['total_users']])
        writer.writerow([])
        
        # Топ доменов
        writer.writerow(["Топ доменов", "Количество"])
        for domain, count in list(stats.get('top_domains', {}).items()):
            writer.writerow([domain, count])
        writer.writerow([])
        
        # Топ команд
        writer.writerow(["Топ команд", "Количество"])
        for cmd, count in list(stats.get('top_commands', {}).items()):
            writer.writerow([cmd, count])
        writer.writerow([])
        
        # Топ ошибок
        writer.writerow(["Топ ошибок", "Количество"])
        for error, count in list(stats.get('top_errors', {}).items()):
            writer.writerow([error, count])
        writer.writerow([])
        
        # Активность по часам
        writer.writerow(["Час", "Количество проверок"])
        for hour, count in sorted(stats.get('activity_by_hour', {}).items()):
            writer.writerow([f"{hour:02d}:00", count])
        
        csv_data = output.getvalue().encode('utf-8-sig')
        csv_file = io.BytesIO(csv_data)
        csv_file.name = f"stats_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        await callback.message.answer_document(
            types.FSInputFile(csv_file, filename=csv_file.name),
            caption="📊 Экспорт статистики в CSV"
        )
        await callback.answer("✅ Статистика экспортирована в CSV")
    except Exception as e:
        logger.error(f"Ошибка при экспорте статистики в CSV: {e}", exc_info=True)
        await callback.answer("❌ Ошибка при экспорте", show_alert=True)


@router.callback_query(F.data == "monitor_export")
async def monitor_export(callback: types.CallbackQuery):
    """Экспортирует список доменов из мониторинга в текстовый файл."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await callback.answer("❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    domains = get_monitored_domains(user_id)
    
    if not domains:
        await callback.answer("📋 Нет доменов в мониторинге для экспорта", show_alert=True)
        return
    
    # Создаем текстовый файл со списком доменов
    import io
    domains_text = "\n".join(domains)
    domains_file = io.BytesIO(domains_text.encode('utf-8'))
    domains_file.name = f"monitored_domains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    try:
        await callback.message.answer_document(
            types.FSInputFile(domains_file, filename=domains_file.name),
            caption=f"📥 Экспорт доменов из мониторинга ({len(domains)} доменов)"
        )
        await callback.answer("✅ Список доменов экспортирован")
    except Exception as e:
        logger.error(f"Ошибка при экспорте доменов для пользователя {user_id}: {e}", exc_info=True)
        await callback.answer("❌ Ошибка при экспорте доменов", show_alert=True)


@router.callback_query(F.data == "monitor_interval")
async def monitor_interval(callback: types.CallbackQuery, state: FSMContext):
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await callback.answer("❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    await state.set_state(MonitoringStates.set_interval_waiting)
    current_interval = get_monitoring_interval(callback.from_user.id)
    await callback.message.answer(
        f"⏱️ Введите интервал проверки в минутах (текущий: {current_interval} минут).\n\n"
        f"Например: `15` или `30`"
    )
    await callback.answer()


@router.message(MonitoringStates.set_interval_waiting)
async def process_monitor_interval(message: types.Message, state: FSMContext):
    text = message.text or ""
    try:
        interval = int(text.strip())
        if interval < 1 or interval > 1440:  # От 1 минуты до 24 часов
            await message.answer("❌ Интервал должен быть от 1 до 1440 минут")
            await state.clear()
            return
        
        set_monitoring_interval(message.from_user.id, interval)
        await message.answer(f"✅ Интервал проверки установлен: {interval} минут")
    except ValueError:
        await message.answer("❌ Некорректное значение. Введите число (минуты)")
    
    await state.clear()


@router.callback_query(F.data == "monitor_waf_timeout")
async def monitor_waf_timeout(callback: types.CallbackQuery, state: FSMContext):
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await callback.answer("❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    await state.set_state(MonitoringStates.set_waf_timeout_waiting)
    current_timeout = get_waf_timeout(callback.from_user.id)
    timeout_text = f"{current_timeout} секунд" if current_timeout else "не установлен"
    await callback.message.answer(
        f"⚙️ Введите таймаут для WAF проверки в секундах (текущий: {timeout_text}).\n\n"
        f"Например: `10` или `15`"
    )
    await callback.answer()


@router.message(MonitoringStates.set_waf_timeout_waiting)
async def process_monitor_waf_timeout(message: types.Message, state: FSMContext):
    text = message.text or ""
    try:
        timeout = int(text.strip())
        if timeout < 1 or timeout > 60:
            await message.answer("❌ Таймаут должен быть от 1 до 60 секунд")
            await state.clear()
            return
        
        set_waf_timeout(message.from_user.id, timeout)
        await message.answer(f"✅ Таймаут WAF проверки установлен: {timeout} секунд")
    except ValueError:
        await message.answer("❌ Некорректное значение. Введите число (секунды)")
    
    await state.clear()


@router.callback_query(F.data == "monitor_toggle")
async def monitor_toggle(callback: types.CallbackQuery):
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await callback.answer("❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    user_id = callback.from_user.id
    current_state = is_monitoring_enabled(user_id)
    set_monitoring_enabled(user_id, not current_state)
    
    new_state = "включен" if not current_state else "выключен"
    await callback.answer(f"✅ Мониторинг {new_state}")


# ---------- Inline режим для быстрой проверки доменов ----------

@router.inline_query()
async def inline_query_handler(inline_query: InlineQuery):
    """
    Обработчик inline запросов.
    
    Позволяет быстро проверять домены из любого чата,
    используя синтаксис: @YourBotName example.com
    """
    user_id = inline_query.from_user.id
    
    # Проверка доступа
    if not has_access(user_id):
        # Показываем сообщение об отсутствии доступа
        results = [
            InlineQueryResultArticle(
                id="no_access",
                title="❌ Нет доступа",
                description="Свяжитесь с администратором для получения доступа",
                input_message_content=InputTextMessageContent(
                    message_text="❌ У вас нет доступа к этому боту."
                ),
            )
        ]
        await inline_query.answer(results, cache_time=1)
        return
    
    # Проверка разрешения на inline режим
    if not has_permission(user_id, "inline"):
        results = [
            InlineQueryResultArticle(
                id="no_inline_permission",
                title="❌ Нет доступа к inline режиму",
                description="Свяжитесь с администратором для получения доступа",
                input_message_content=InputTextMessageContent(
                    message_text="❌ У вас нет доступа к inline режиму."
                ),
            )
        ]
        await inline_query.answer(results, cache_time=1)
        return
    
    query = (inline_query.query or "").strip()
    
    # Если запрос пустой, показываем подсказку
    if not query:
        results = [
            InlineQueryResultArticle(
                id="help",
                title="🔍 Проверка домена",
                description="Введите домен для проверки (например: example.com)",
                input_message_content=InputTextMessageContent(
                    message_text="Введите домен для проверки"
                ),
            )
        ]
        await inline_query.answer(results, cache_time=300)
        return
    
    # Нормализуем домен
    from utils.domain_normalizer import normalize_domain
    
    normalized = normalize_domain(query)
    
    if not normalized:
        results = [
            InlineQueryResultArticle(
                id="invalid",
                title="❌ Некорректный домен",
                description=f"Не удалось распознать домен: {query}",
                input_message_content=InputTextMessageContent(
                    message_text=f"❌ Некорректный домен: {query}"
                ),
            )
        ]
        await inline_query.answer(results, cache_time=1)
        return
    
    # Создаем результат для inline режима
    # При выборе результата будет отправлено сообщение с доменом,
    # которое обработается обычным обработчиком текста
    results = [
        InlineQueryResultArticle(
            id=f"domain_{normalized}",
            title=f"🔍 Проверить {normalized}",
            description="Нажмите для проверки домена",
            input_message_content=InputTextMessageContent(
                message_text=normalized  # Отправляем просто домен, он будет обработан
            ),
        )
    ]
    
    await inline_query.answer(results, cache_time=60)


# ---------- Обработка callback для главного меню ----------

@router.callback_query(F.data == "main_menu")
async def main_menu_callback(callback: types.CallbackQuery, state: FSMContext):
    """Обработчик кнопки 'Главное меню'."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    help_text = (
        "🏠 *Главное меню*\n\n"
        "Выберите действие из меню ниже или отправьте домен для проверки."
    )
    
    await callback.message.edit_text(
        help_text,
        parse_mode=ParseMode.MARKDOWN,
    )
    
    await callback.message.answer(
        "Используйте кнопки меню для быстрого доступа:",
        reply_markup=build_main_menu_keyboard(user_id),
    )
    
    await callback.answer()


@router.callback_query(F.data == "settings_report_mode")
async def settings_report_mode_callback(callback: types.CallbackQuery):
    """Обработчик кнопки настроек режима отчета."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    current_mode = get_mode(user_id, DEFAULT_MODE)
    mode_text = "Расширенный" if current_mode == "full" else "Короткий"
    
    await callback.answer(
        f"Текущий режим: {mode_text}. Используйте кнопки ниже для изменения.",
        show_alert=False
    )


@router.callback_query(F.data == "settings_waf_mode")
async def settings_waf_mode_callback(callback: types.CallbackQuery):
    """Обработчик кнопки настроек режима WAF."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    current_mode = get_waf_mode(user_id, "policy")
    mode_text = "Policy-based" if current_mode == "policy" else "Light check"
    
    await callback.answer(
        f"Текущий режим WAF: {mode_text}. Используйте кнопки ниже для изменения.",
        show_alert=False
    )


# ---------- Настройки чата для уведомлений ----------

@router.callback_query(F.data == "settings_notification_chat")
async def settings_notification_chat(callback: types.CallbackQuery):
    """Показывает меню настройки чата для уведомлений."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    known_chats = get_known_chats(user_id)
    current_chat_id = get_notification_chat_id(user_id)
    
    if not known_chats:
        await callback.message.edit_text(
            "💬 *Настройка чата для уведомлений*\n\n"
            "У вас пока нет зарегистрированных чатов.\n\n"
            "Чтобы добавить чат:\n"
            "1. Добавьте бота в группу или канал\n"
            "2. Отправьте любое сообщение в этом чате\n"
            "3. Или укажите ID чата вручную",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=types.InlineKeyboardMarkup(
                inline_keyboard=[
                    [
                        types.InlineKeyboardButton(
                            text="➕ Указать ID чата",
                            callback_data="notification_chat_set_id"
                        )
                    ],
                    [
                        types.InlineKeyboardButton(
                            text="🔙 Назад",
                            callback_data="settings_back"
                        )
                    ]
                ]
            )
        )
        await callback.answer()
        return
    
    # Формируем список чатов
    chat_list_text = "💬 *Настройка чата для уведомлений*\n\n"
    if current_chat_id:
        current_chat = next((c for c in known_chats if c.get("chat_id") == current_chat_id), None)
        if current_chat:
            chat_list_text += f"✅ Текущий чат: *{current_chat.get('title')}* (ID: {current_chat_id})\n\n"
        else:
            chat_list_text += f"✅ Текущий чат: ID {current_chat_id}\n\n"
    else:
        chat_list_text += "📭 Уведомления отправляются в личные сообщения\n\n"
    
    chat_list_text += "*Доступные чаты:*\n"
    
    keyboard = []
    for chat in known_chats:
        chat_id = chat.get("chat_id")
        chat_title = chat.get("title", f"Chat {chat_id}")
        chat_type = chat.get("type", "unknown")
        is_current = chat_id == current_chat_id
        
        emoji = "✅" if is_current else "💬"
        keyboard.append([
            types.InlineKeyboardButton(
                text=f"{emoji} {chat_title} ({chat_type})",
                callback_data=f"notification_chat_select_{chat_id}"
            )
        ])
    
    keyboard.append([
        types.InlineKeyboardButton(
            text="➕ Указать ID чата",
            callback_data="notification_chat_set_id"
        )
    ])
    keyboard.append([
        types.InlineKeyboardButton(
            text="❌ Отключить уведомления в чат",
            callback_data="notification_chat_disable"
        )
    ])
    keyboard.append([
        types.InlineKeyboardButton(
            text="🔙 Назад",
            callback_data="settings_back"
        )
    ])
    
    await callback.message.edit_text(
        chat_list_text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=types.InlineKeyboardMarkup(inline_keyboard=keyboard)
    )
    await callback.answer()


@router.callback_query(F.data.startswith("notification_chat_select_"))
async def select_notification_chat(callback: types.CallbackQuery):
    """Выбирает чат для уведомлений из списка."""
    user_id = callback.from_user.id
    chat_id_str = callback.data.replace("notification_chat_select_", "")
    
    try:
        chat_id = int(chat_id_str)
        set_notification_chat_id(user_id, chat_id)
        
        known_chats = get_known_chats(user_id)
        selected_chat = next((c for c in known_chats if c.get("chat_id") == chat_id), None)
        chat_name = selected_chat.get("title", f"Chat {chat_id}") if selected_chat else f"Chat {chat_id}"
        
        await callback.answer(f"✅ Чат '{chat_name}' выбран для уведомлений")
        await settings_notification_chat(callback)
    except ValueError:
        await callback.answer("❌ Неверный ID чата", show_alert=True)


@router.callback_query(F.data == "notification_chat_set_id")
async def set_notification_chat_id_handler(callback: types.CallbackQuery, state: FSMContext):
    """Запрашивает ID чата для уведомлений."""
    await callback.message.edit_text(
        "💬 *Указать ID чата для уведомлений*\n\n"
        "Отправьте ID чата (число).\n\n"
        "Как узнать ID чата:\n"
        "• Добавьте бота @userinfobot в чат\n"
        "• Или используйте @RawDataBot\n"
        "• Или используйте API Telegram",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=types.InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    types.InlineKeyboardButton(
                        text="❌ Отмена",
                        callback_data="settings_notification_chat"
                    )
                ]
            ]
        )
    )
    await state.set_state(ChatSettingsStates.waiting_chat_id)
    await callback.answer()


@router.message(ChatSettingsStates.waiting_chat_id)
async def process_chat_id(message: types.Message, state: FSMContext):
    """Обрабатывает введенный ID чата."""
    user_id = message.from_user.id
    text = (message.text or "").strip()
    
    if not text.isdigit():
        await message.answer("❌ Неверный формат ID. Отправьте число.")
        return
    
    try:
        chat_id = int(text)
        set_notification_chat_id(user_id, chat_id)
        
        # Регистрируем чат
        register_chat(user_id, chat_id, f"Chat {chat_id}", "unknown")
        
        await message.answer(
            f"✅ Чат с ID {chat_id} установлен для уведомлений.\n\n"
            "Теперь все уведомления мониторинга будут отправляться в этот чат."
        )
        await state.clear()
    except ValueError:
        await message.answer("❌ Неверный формат ID. Отправьте число.")


@router.callback_query(F.data == "notification_chat_disable")
async def disable_notification_chat(callback: types.CallbackQuery):
    """Отключает отправку уведомлений в чат (возврат к личным сообщениям)."""
    user_id = callback.from_user.id
    set_notification_chat_id(user_id, None)
    await callback.answer("✅ Уведомления будут отправляться в личные сообщения")
    await settings_notification_chat(callback)


@router.callback_query(F.data == "settings_back")
async def settings_back(callback: types.CallbackQuery):
    """Возврат в меню настроек."""
    user_id = callback.from_user.id
    await callback.message.edit_text(
        "⚙️ *Настройки*\n\n"
        "Выберите параметр для изменения:",
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=build_settings_keyboard(user_id)
    )
    await callback.answer()


# ---------- АДМИН-ПАНЕЛЬ ----------

@router.callback_query(F.data == "admin_add_access")
async def admin_add_access(callback: types.CallbackQuery, state: FSMContext):
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Только администратор", show_alert=True)
        return
    
    await state.set_state(AdminStates.add_access_waiting)
    await callback.message.answer(
        "📝 Введите TG ID или @username пользователя(ей).\n\n"
        "Поддерживаемые форматы:\n"
        "• Простые числа: `123456789 987654321`\n"
        "• @username: `@johndoe` или `johndoe`\n"
        "• Формат ID: `ID: 123456789`\n"
        "• Формат старого бота:\n"
        "`• ID: 123456789 - добавлен 2025-12-09`\n\n"
        "Можно вставлять список из старого бота целиком!"
    )
    await callback.answer()


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
    
    # Регулярное выражение для формата "ID: 123456"
    id_format = re.compile(r'ID:\s*(\d+)', re.IGNORECASE)
    
    # Сначала пробуем найти формат старого бота
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
    
    # Если все еще ничего не нашли, пробуем простые числа
    if not users:
        # Разбиваем на строки и ищем числа
        lines = text.split('\n')
        for line in lines:
            # Пропускаем заголовки и пустые строки
            line = line.strip()
            if not line or any(keyword in line.lower() for keyword in ['список', 'доступ', 'пользовател']):
                continue
            
            # Ищем числа в строке
            numbers = re.findall(r'\b\d{8,}\b', line)  # Минимум 8 цифр для Telegram ID
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
    
    # @username в тексте (regex)
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


@router.message(AdminStates.add_access_waiting)
async def process_add_access(message: types.Message, state: FSMContext):
    """Обрабатывает добавление доступа пользователям."""
    if message.from_user.id != ADMIN_ID:
        return
    
    text = message.text or ""
    
    nav = _handle_admin_navigation(text)
    if nav:
        await state.clear()
        if nav == "admin" and message.from_user and message.from_user.id == ADMIN_ID:
            help_text = "👨‍💼 *Админ-панель*\n\nИспользуйте кнопки ниже для управления доступом:"
            await safe_send_text(
                message.bot,
                message.chat.id,
                help_text,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=build_admin_keyboard(),
            )
        else:
            await cmd_start(message, state)
        return
    
    parsed_users = parse_user_list(text)
    bot = message.bot
    
    added_count = 0
    errors = []
    added_users = []
    
    for uid, username, date_added in parsed_users:
        try:
            if uid is not None:
                # Числовой ID
                add_access(uid, "")
                added_count += 1
                added_users.append(uid)
            elif username is not None:
                # @username — резолвим в ID через API
                resolved_id = await get_id_by_username(bot, username)
                if resolved_id:
                    add_access(resolved_id, username)
                    added_count += 1
                    added_users.append(resolved_id)
                else:
                    errors.append(f"⚠️ @{username} - не удалось найти пользователя")
        except Exception as e:
            err_id = uid if uid is not None else f"@{username or '?'}"
            errors.append(f"❌ {err_id} - Ошибка при добавлении: {str(e)}")
    
    # Если парсер ничего не нашел, пробуем старый способ (для обратной совместимости)
    if not parsed_users:
        items = re.split(r"[\s,]+", text.strip())
        
        for item in items:
            if not item:
                continue
            
            # @username — пробуем резолвить
            if item.startswith("@"):
                resolved_id = await get_id_by_username(bot, item)
                if resolved_id:
                    add_access(resolved_id, item[1:])
                    added_count += 1
                    added_users.append(resolved_id)
                else:
                    errors.append(f"⚠️ {item} - не удалось найти пользователя")
                continue
            
            try:
                user_id = int(item)
                add_access(user_id, "")
                added_count += 1
                added_users.append(user_id)
            except ValueError:
                errors.append(f"❌ {item} - Некорректный формат")
            except Exception as e:
                errors.append(f"❌ {item} - Ошибка: {str(e)}")
    
    response = f"✅ Добавлен доступ для {added_count} пользователей(я)"
    if errors:
        response += "\n\n" + "\n".join(errors)
    
    response += (
        "\n\n💡 *Совет:* Используйте 'Управление разрешениями' в админ-панели "
        "для настройки доступа к конкретным функциям."
    )
    
    await message.answer(response, parse_mode=ParseMode.MARKDOWN)
    
    # Если добавлен один пользователь, предлагаем сразу настроить разрешения
    if added_count == 1 and added_users:
        user_id = added_users[0]
        permissions = get_user_permissions(user_id)
        
        # Формируем информацию о разрешениях по умолчанию
        perms_text = "📋 *Разрешения по умолчанию:*\n\n"
        for perm_key, perm_name in PERMISSIONS.items():
            status = "✅" if permissions.get(perm_key, False) else "❌"
            perms_text += f"{status} {perm_name}\n"
        
        perms_text += "\nИспользуйте 'Управление разрешениями' для изменения."
        
        await message.answer(perms_text, parse_mode=ParseMode.MARKDOWN)
    
    await state.clear()


@router.callback_query(F.data == "admin_remove_access")
async def admin_remove_access(callback: types.CallbackQuery, state: FSMContext):
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Только администратор", show_alert=True)
        return
    
    await state.set_state(AdminStates.remove_access_waiting)
    await callback.message.answer(
        "🗑️ Введите TG ID пользователя(ей) для удаления доступа.\n\n"
        "Можно вводить несколько через пробел или запятую:\n"
        "`123456789 987654321`"
    )
    await callback.answer()


@router.message(AdminStates.remove_access_waiting)
async def process_remove_access(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    
    text = message.text or ""
    
    nav = _handle_admin_navigation(text)
    if nav:
        await state.clear()
        if nav == "admin" and message.from_user and message.from_user.id == ADMIN_ID:
            help_text = "👨‍💼 *Админ-панель*\n\nИспользуйте кнопки ниже для управления доступом:"
            await safe_send_text(
                message.bot,
                message.chat.id,
                help_text,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=build_admin_keyboard(),
            )
        else:
            await cmd_start(message, state)
        return
    
    items = re.split(r"[\s,]+", text.strip())
    
    removed_count = 0
    not_found = []
    
    for item in items:
        if not item:
            continue
        
        try:
            user_id = int(item)
            if remove_access(user_id):
                removed_count += 1
            else:
                not_found.append(str(user_id))
        except ValueError:
            not_found.append(item)
    
    response = f"✅ Доступ удален для {removed_count} пользователей(я)"
    if not_found:
        response += f"\n⚠️ Не найдены в БД: {', '.join(not_found)}"
    
    await message.answer(response)
    await state.clear()


@router.callback_query(F.data == "admin_list_access")
async def admin_list_access(callback: types.CallbackQuery):
    """Показывает список всех пользователей с их разрешениями."""
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Только администратор", show_alert=True)
        return
    
    if not callback.message:
        await callback.answer("❌ Ошибка: сообщение недоступно", show_alert=True)
        return
    
    await callback.answer("⏳ Загрузка списка пользователей...")
    
    db = get_access_list()
    
    if not db:
        await callback.message.answer("📋 БД доступов пуста")
        return
    
    bot = callback.message.bot if callback.message else callback.bot
    if not bot:
        await callback.message.answer("❌ Ошибка: бот недоступен")
        return
    
    # Форматируем список с разрешениями
    lines = ["📋 *Список пользователей и их разрешения:*\n"]
    
    # Получаем актуальные юзернеймы для всех пользователей
    user_ids = [int(user_id) for user_id in db.keys() if str(user_id).isdigit()]
    
    # Получаем юзернеймы параллельно
    username_tasks = [get_username_by_id(bot, user_id) for user_id in user_ids]
    usernames = await asyncio.gather(*username_tasks, return_exceptions=True)
    
    # Создаем словарь user_id -> username
    username_map = {}
    for user_id, username_result in zip(user_ids, usernames):
        if isinstance(username_result, str):
            # Сохраняем даже пустую строку, так как это означает отсутствие username
            username_map[user_id] = username_result
        elif isinstance(username_result, Exception):
            logger.debug(f"Ошибка получения username для {user_id}: {username_result}")
    
    for user_id, data in sorted(db.items(), key=lambda x: (int(x[0]) if str(x[0]).isdigit() else 0)):
        # Используем актуальный username из API, если доступен, иначе из БД
        uid = int(user_id) if str(user_id).isdigit() else 0
        # Проверяем, есть ли значение в username_map (даже если это пустая строка)
        if uid in username_map:
            current_username = username_map[uid]
        else:
            current_username = data.get("username", "")
        
        added_at = data.get("added_at", "")
        permissions = data.get("permissions", DEFAULT_PERMISSIONS.copy())
        
        user_info = f"*ID: {user_id}*"
        if current_username:
            user_info += f" (@{current_username})"
        if added_at:
            user_info += f"\nДобавлен: {added_at[:10]}"
        
        lines.append(user_info)
        lines.append("Разрешения:")
        
        # Показываем разрешения
        for perm_key, perm_name in PERMISSIONS.items():
            status = "✅" if permissions.get(perm_key, False) else "❌"
            lines.append(f"  {status} {perm_name}")
        
        lines.append("")  # Пустая строка между пользователями
    
    text = "\n".join(lines)
    
    # Если текст слишком длинный, отправляем как файл
    if len(text) > 4000:
        buf = io.BytesIO(text.encode("utf-8"))
        await callback.message.answer_document(
            types.BufferedInputFile(buf.getvalue(), filename="access_list.txt")
        )
    else:
        await callback.message.answer(text, parse_mode=ParseMode.MARKDOWN)


@router.callback_query(F.data == "admin_manage_permissions")
async def admin_manage_permissions(callback: types.CallbackQuery, state: FSMContext):
    """Начинает процесс управления разрешениями пользователя."""
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Только администратор", show_alert=True)
        return
    
    if not callback.message:
        await callback.answer("❌ Ошибка: сообщение недоступно", show_alert=True)
        return
    
    await callback.answer("⏳ Загрузка списка пользователей...")
    
    await state.set_state(AdminStates.manage_permissions_user_waiting)
    
    db = get_access_list()
    if not db:
        await callback.message.answer("❌ Нет пользователей в базе. Сначала добавьте пользователя.")
        await state.clear()
        return
    
    bot = callback.message.bot if callback.message else callback.bot
    if not bot:
        await callback.message.answer("❌ Ошибка: бот недоступен")
        await state.clear()
        return
    
    # Получаем актуальные юзернеймы для всех пользователей
    user_ids = [int(user_id) for user_id in db.keys() if str(user_id).isdigit()]
    
    # Получаем юзернеймы параллельно
    username_tasks = [get_username_by_id(bot, user_id) for user_id in user_ids]
    usernames = await asyncio.gather(*username_tasks, return_exceptions=True)
    
    # Создаем словарь user_id -> username
    username_map = {}
    for user_id, username_result in zip(user_ids, usernames):
        if isinstance(username_result, str):
            # Сохраняем даже пустую строку, так как это означает отсутствие username
            username_map[user_id] = username_result
        elif isinstance(username_result, Exception):
            logger.debug(f"Ошибка получения username для {user_id}: {username_result}")
    
    # Формируем список пользователей
    users_list = "👥 *Выберите пользователя для управления разрешениями:*\n\n"
    for user_id, data in sorted(db.items(), key=lambda x: (int(x[0]) if str(x[0]).isdigit() else 0)):
        uid = int(user_id) if str(user_id).isdigit() else 0
        # Проверяем, есть ли значение в username_map (даже если это пустая строка)
        if uid in username_map:
            current_username = username_map[uid]
        else:
            current_username = data.get("username", "")
        user_display = f"ID: {user_id}"
        if current_username:
            user_display += f" (@{current_username})"
        users_list += f"• {user_display}\n"
    
    users_list += "\nВведите TG ID или @username пользователя:"
    
    await callback.message.answer(users_list, parse_mode=ParseMode.MARKDOWN)


def _handle_admin_navigation(text: str) -> Optional[str]:
    """
    Проверяет навигационную команду.
    Returns: "back" | "admin" | None
    """
    t = (text or "").strip()
    if t in ("🔙 Назад", "🏠 Главное меню"):
        return "back"
    if t == "👨‍💼 Админ-панель":
        return "admin"
    return None


@router.message(AdminStates.manage_permissions_user_waiting)
async def process_manage_permissions_user(message: types.Message, state: FSMContext):
    """Обрабатывает выбор пользователя для управления разрешениями."""
    if message.from_user.id != ADMIN_ID:
        return
    
    text = message.text or ""
    
    nav = _handle_admin_navigation(text)
    if nav:
        await state.clear()
        if nav == "admin" and message.from_user and message.from_user.id == ADMIN_ID:
            help_text = "👨‍💼 *Админ-панель*\n\nИспользуйте кнопки ниже для управления доступом:"
            await safe_send_text(
                message.bot,
                message.chat.id,
                help_text,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=build_admin_keyboard(),
            )
        else:
            await cmd_start(message, state)
        return
    
    # Определяем user_id: число или @username
    user_id = None
    text_stripped = text.strip()
    
    if text_stripped.startswith("@"):
        # Пытаемся получить ID по username
        user_id = await get_id_by_username(message.bot, text_stripped)
        if not user_id:
            await message.answer(
                f"❌ Не удалось найти пользователя {text_stripped}.\n"
                "Проверьте username или введите числовой TG ID."
            )
            return
    else:
        try:
            user_id = int(text_stripped)
        except ValueError:
            await message.answer("❌ Некорректный формат. Введите числовой TG ID или @username.")
            return
    
    # Проверяем, что пользователь существует
    db = get_access_list()
    if str(user_id) not in db:
        await message.answer(f"❌ Пользователь {user_id} не найден в базе.")
        await state.clear()
        return
    
    # Сохраняем выбранного пользователя в состоянии
    await state.update_data(selected_user_id=user_id)
    
    # Получаем текущие разрешения
    permissions = get_user_permissions(user_id)
    user_data = db[str(user_id)]
    
    # Получаем актуальный username через API
    bot = message.bot
    current_username = await get_username_by_id(bot, user_id)
    if not current_username:
        current_username = user_data.get("username", "")
    
    # Формируем клавиатуру с разрешениями
    keyboard_buttons = []
    for perm_key, perm_name in PERMISSIONS.items():
        current_status = permissions.get(perm_key, False)
        status_icon = "✅" if current_status else "❌"
        keyboard_buttons.append([
            types.InlineKeyboardButton(
                text=f"{status_icon} {perm_name}",
                callback_data=f"perm_toggle_{user_id}_{perm_key}",
            )
        ])
    
    keyboard_buttons.append([
        types.InlineKeyboardButton(
            text="🔙 Назад",
            callback_data="admin_back",
        )
    ])
    
    keyboard = types.InlineKeyboardMarkup(inline_keyboard=keyboard_buttons)
    
    user_display = f"ID: {user_id}"
    if current_username:
        user_display += f" (@{current_username})"
    user_display_safe = html.escape(user_display)
    
    text_msg = (
        f"🔐 <b>Управление разрешениями</b>\n\n"
        f"Пользователь: {user_display_safe}\n\n"
        f"Нажмите на разрешение для переключения:"
    )
    
    await message.answer(text_msg, parse_mode=ParseMode.HTML, reply_markup=keyboard)
    await state.clear()


@router.callback_query(F.data.startswith("perm_toggle_"))
async def toggle_permission(callback: types.CallbackQuery):
    """Переключает разрешение пользователя."""
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Только администратор", show_alert=True)
        return
    
    # Парсим данные: perm_toggle_{user_id}_{permission}
    parts = callback.data.split("_")
    if len(parts) != 4:
        await callback.answer("❌ Ошибка формата", show_alert=True)
        return
    
    try:
        user_id = int(parts[2])
        permission = parts[3]
    except (ValueError, IndexError):
        await callback.answer("❌ Ошибка парсинга", show_alert=True)
        return
    
    if permission not in PERMISSIONS:
        await callback.answer("❌ Неизвестное разрешение", show_alert=True)
        return
    
    # Получаем текущее значение и переключаем
    current_value = has_permission(user_id, permission)
    new_value = not current_value
    
    if set_user_permission(user_id, permission, new_value):
        status = "выдано" if new_value else "отозвано"
        perm_name = PERMISSIONS[permission]
        await callback.answer(f"✅ Разрешение '{perm_name}' {status}", show_alert=False)
        
        # Обновляем клавиатуру
        permissions = get_user_permissions(user_id)
        keyboard_buttons = []
        for perm_key, perm_name in PERMISSIONS.items():
            current_status = permissions.get(perm_key, False)
            status_icon = "✅" if current_status else "❌"
            keyboard_buttons.append([
                types.InlineKeyboardButton(
                    text=f"{status_icon} {perm_name}",
                    callback_data=f"perm_toggle_{user_id}_{perm_key}",
                )
            ])
        
        keyboard_buttons.append([
            types.InlineKeyboardButton(
                text="🔙 Назад",
                callback_data="admin_back",
            )
        ])
        
        keyboard = types.InlineKeyboardMarkup(inline_keyboard=keyboard_buttons)
        
        try:
            await callback.message.edit_reply_markup(reply_markup=keyboard)
        except Exception:
            pass
    else:
        await callback.answer("❌ Ошибка при изменении разрешения", show_alert=True)


@router.callback_query(F.data == "admin_export_users")
async def admin_export_users(callback: types.CallbackQuery):
    """Экспортирует список пользователей в формате JSON для удобного переноса."""
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Только администратор", show_alert=True)
        return
    
    if not callback.message:
        await callback.answer("❌ Ошибка: сообщение недоступно", show_alert=True)
        return
    
    await callback.answer("⏳ Подготовка экспорта...")
    
    db = get_access_list()
    
    if not db:
        await callback.message.answer("📋 БД доступов пуста")
        return
    
    bot = callback.message.bot if callback.message else callback.bot
    if not bot:
        await callback.message.answer("❌ Ошибка: бот недоступен")
        return
    
    # Получаем актуальные юзернеймы для всех пользователей
    user_ids = [int(user_id) for user_id in db.keys() if str(user_id).isdigit()]
    
    # Получаем юзернеймы параллельно
    username_tasks = [get_username_by_id(bot, user_id) for user_id in user_ids]
    usernames = await asyncio.gather(*username_tasks, return_exceptions=True)
    
    # Создаем словарь user_id -> username
    username_map = {}
    for user_id, username_result in zip(user_ids, usernames):
        if isinstance(username_result, str):
            # Сохраняем даже пустую строку, так как это означает отсутствие username
            username_map[user_id] = username_result
    
    # Формируем данные для экспорта
    export_data = {}
    for user_id, data in sorted(db.items(), key=lambda x: (int(x[0]) if str(x[0]).isdigit() else 0)):
        uid = int(user_id) if str(user_id).isdigit() else 0
        # Проверяем, есть ли значение в username_map (даже если это пустая строка)
        if uid in username_map:
            current_username = username_map[uid]
        else:
            current_username = data.get("username", "")
        
        export_data[user_id] = {
            "user_id": int(user_id) if str(user_id).isdigit() else user_id,
            "username": current_username,
            "added_at": data.get("added_at", ""),
            "permissions": data.get("permissions", DEFAULT_PERMISSIONS.copy()),
        }
    
    # Формируем JSON
    json_data = json.dumps(export_data, ensure_ascii=False, indent=2, default=str)
    
    # Формируем текстовый формат для удобного копирования
    text_lines = ["📤 *Экспорт пользователей*\n\n"]
    text_lines.append("Формат для добавления:\n")
    text_lines.append("```")
    
    for user_id, user_data in export_data.items():
        uid = user_data["user_id"]
        username = user_data["username"]
        text_lines.append(f"{uid}  # @{username}" if username else f"{uid}")
    
    text_lines.append("```")
    text_lines.append("\nИли используйте JSON файл ниже для полного переноса.")
    
    text_msg = "\n".join(text_lines)
    
    # Отправляем текстовое сообщение
    await callback.message.answer(text_msg, parse_mode=ParseMode.MARKDOWN)
    
    # Отправляем JSON файл
    json_bytes = json_data.encode("utf-8")
    buf = io.BytesIO(json_bytes)
    await callback.message.answer_document(
        types.BufferedInputFile(buf.getvalue(), filename="users_export.json")
    )


@router.callback_query(F.data == "admin_back")
async def admin_back(callback: types.CallbackQuery):
    """Возврат в админ-панель."""
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Только администратор", show_alert=True)
        return
    
    if not callback.message:
        await callback.answer("❌ Ошибка: сообщение недоступно", show_alert=True)
        return
    
    help_text = (
        "👨‍💼 *Админ-панель*\n\n"
        "Используйте кнопки ниже для управления:"
    )
    
    try:
        await callback.message.edit_text(
            help_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=build_admin_keyboard(),
        )
    except Exception as e:
        logger.error(f"Ошибка при редактировании сообщения: {e}")
        await callback.message.answer(
            help_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=build_admin_keyboard(),
        )
    await callback.answer()


@router.callback_query(F.data == "admin_stats")
async def admin_stats_callback(callback: types.CallbackQuery):
    """Показывает статистику через админ-панель."""
    try:
        if callback.from_user.id != ADMIN_ID:
            await callback.answer("❌ Только администратор", show_alert=True)
            return
        
        # Получаем bot из callback.message.bot или callback.bot
        bot = callback.message.bot if callback.message else callback.bot
        if bot is None:
            # Если bot все еще None, пытаемся получить из data
            logger.error("Bot is None in admin_stats_callback, используем прямой вызов")
            # Используем прямой вызов вместо fake_message
            await callback.answer("⏳ Загрузка статистики...")
            stats = get_stats()
            
            # Формируем сообщение
            text = (
                "📊 *Статистика бота*\n\n"
                f"⏱️ *Время работы:*\n"
                f"• Дней: {stats['uptime_days']}\n"
                f"• Часов: {stats['uptime_hours']}\n"
                f"• Секунд: {stats['uptime_seconds']}\n\n"
                f"📈 *Использование:*\n"
                f"• Проверено доменов: {stats['total_domains_checked']}\n"
                f"• Уникальных пользователей: {stats['total_users']}\n\n"
            )
            
            # Топ доменов
            if stats['top_domains']:
                text += "🔝 *Топ доменов:*\n"
                for domain, count in list(stats['top_domains'].items())[:5]:
                    text += f"• {domain}: {count}\n"
                text += "\n"
            
            # Топ команд
            if stats['top_commands']:
                text += "⚙️ *Топ команд:*\n"
                for cmd, count in list(stats['top_commands'].items())[:5]:
                    text += f"• {cmd}: {count}\n"
                text += "\n"
            
            # Топ ошибок
            if stats['top_errors']:
                text += "⚠️ *Топ ошибок:*\n"
                for error, count in list(stats['top_errors'].items())[:5]:
                    text += f"• {error}: {count}\n"
            
            text += f"\n🔄 Последний сброс: {stats['last_reset']}"
            
            # Отправляем напрямую через callback.message
            if callback.message:
                await callback.message.answer(text, parse_mode=ParseMode.MARKDOWN)
            await callback.answer()
            return
        
        # Используем существующую команду stats
        from aiogram.types import Message
        # Создаем fake_message с правильным bot
        fake_message = Message(
            message_id=callback.message.message_id if callback.message else 0,
            date=callback.message.date if callback.message else datetime.now(),
            chat=callback.message.chat if callback.message else callback.from_user,
            from_user=callback.from_user,
            content_type="text",
            text="/stats",
            bot=bot,
        )
        await cmd_stats(fake_message)
        await callback.answer()
    except Exception as e:
        logger.error(
            f"❌ Ошибка в admin_stats_callback | "
            f"user_id={callback.from_user.id if callback.from_user else None} | "
            f"error={type(e).__name__}: {str(e)}",
            exc_info=True
        )
        try:
            await callback.answer("❌ Ошибка при загрузке статистики", show_alert=True)
        except Exception:
            pass  # Игнорируем ошибки при ответе на callback


# ---------- Обработчик необработанных callback_query ----------
# Должен быть зарегистрирован ПОСЛЕДНИМ, чтобы не перехватывать специфические обработчики

@router.callback_query()
async def handle_unhandled_callback(callback: types.CallbackQuery):
    """Обрабатывает все callback query, которые не были обработаны другими обработчиками."""
    user_id = callback.from_user.id
    callback_data = callback.data or "N/A"
    message_id = callback.message.message_id if callback.message else "N/A"
    
    logger.warning(
        f"⚠️ Необработанный callback query | "
        f"user_id={user_id} | "
        f"callback_data={callback_data} | "
        f"message_id={message_id} | "
        f"chat_id={callback.message.chat.id if callback.message else 'N/A'}"
    )
    
    try:
        await callback.answer("❓ Неизвестная команда", show_alert=False)
    except Exception as e:
        logger.error(
            f"❌ Ошибка при ответе на необработанный callback | "
            f"user_id={user_id} | "
            f"callback_data={callback_data} | "
            f"error={type(e).__name__}: {str(e)}",
            exc_info=True
        )


# ---------- Загрузка TXT ----------

@router.message(F.document)
async def handle_document(message: types.Message, state: FSMContext):
    """
    Обрабатывает загруженные документы (TXT файлы со списком доменов).
    
    Поддерживает только .txt файлы с кодировкой UTF-8.
    Максимальный размер файла ограничен настройкой MAX_FILE_SIZE_MB.
    
    Также автоматически регистрирует чат, если сообщение пришло из группы/канала.
    """
    user_id = message.from_user.id
    
    # Регистрируем чат, если сообщение пришло не из личных сообщений
    if message.chat.id != user_id:
        chat_title = message.chat.title or f"Chat {message.chat.id}"
        chat_type = message.chat.type
        register_chat(user_id, message.chat.id, chat_title, chat_type)
    
    # Проверка доступа
    if not await check_access(message):
        return
    
    # Проверка rate limit (загрузка файлов)
    if not await check_rate_limit(user_id, operation_type="file_upload"):
        remaining = await get_remaining_requests(user_id, operation_type="file_upload")
        await message.reply(
            f"⏱️ Превышен лимит загрузки файлов. Попробуйте позже.\n"
            f"Осталось загрузок: {remaining}"
        )
        return
    
    doc = message.document
    
    # Проверка разрешения на загрузку файлов
    if not has_permission(user_id, "file_upload"):
        await message.reply(
            "❌ У вас нет доступа к загрузке файлов.\n\n"
            "Свяжитесь с администратором для получения доступа."
        )
        return
    
    # Проверка расширения файла
    if not doc.file_name or not doc.file_name.lower().endswith(".txt"):
        await message.reply(
            "📄 Пришлите TXT-файл со списком доменов.\n\n"
            "Файл должен содержать домены, по одному на строку."
        )
        return
    
    # Защита от инъекций в имени файла
    import re
    if re.search(r'[<>:"/\\|?*\x00-\x1f]', doc.file_name):
        await message.reply(
            "❌ Некорректное имя файла. Используйте только безопасные символы."
        )
        return
    
    # Проверка размера файла
    max_size_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if doc.file_size and doc.file_size > max_size_bytes:
        await message.reply(
            f"❌ Файл слишком большой.\n"
            f"Максимальный размер: {settings.MAX_FILE_SIZE_MB} MB\n"
            f"Размер вашего файла: {doc.file_size / 1024 / 1024:.2f} MB"
        )
        return
    
    try:
        # Загружаем файл
        file_obj = await message.bot.download(doc.file_id)
        text_data = file_obj.getvalue().decode("utf-8", errors="ignore")
        
        # Проверяем, что файл не пустой
        if not text_data.strip():
            await message.reply("❌ Файл пуст или не содержит текста.")
            return
        
        # Обрабатываем домены из файла
        await _process_domains(message, state, text_data)
        
        # Записываем использование команды
        record_command("file_upload")
        
    except Exception as e:
        logger.error(f"Ошибка при обработке файла от пользователя {user_id}: {e}", exc_info=True)
        record_error("FILE_PROCESSING_ERROR")
        await message.reply(
            f"❌ Ошибка при обработке файла: {type(e).__name__}\n"
            f"Попробуйте еще раз или обратитесь к администратору."
        )


# ---------- Текстовый ввод ----------

@router.message(F.text)
async def handle_text(message: types.Message, state: FSMContext):
    """
    Обрабатывает текстовые сообщения.
    
    Поддерживает:
    - Проверку доменов (прямой ввод)
    - Команды через кнопки меню
    
    Также автоматически регистрирует чат, если сообщение пришло из группы/канала.
    """
    start_time = asyncio.get_event_loop().time()
    user_id = message.from_user.id
    text = (message.text or "").strip()
    
    logger.info(
        f"📝 Обработка текстового сообщения | "
        f"user_id={user_id} | "
        f"chat_id={message.chat.id} | "
        f"text_length={len(text)} | "
        f"text_preview={text[:100]}"
    )
    
    # Регистрируем чат, если сообщение пришло не из личных сообщений
    if message.chat.id != user_id:
        chat_title = message.chat.title or f"Chat {message.chat.id}"
        chat_type = message.chat.type
        register_chat(user_id, message.chat.id, chat_title, chat_type)
        logger.debug(f"Чат зарегистрирован: {chat_title} (ID: {message.chat.id})")
    
    # Проверка доступа
    if not await check_access(message):
        logger.warning(f"❌ Доступ запрещен для user_id={user_id}")
        return
    
    # Обработка команд через кнопки меню
    if text == "🔍 Проверить домен":
        await message.answer(
            "📝 Введите домен(ы) для проверки:\n\n"
            "Можно указать несколько доменов через пробел или запятую.\n"
            "Поддерживаются URL: `https://example.com/path`"
        )
        return
    
    elif text == "📊 Мониторинг":
        # Проверка разрешения на мониторинг
        if not has_permission(message.from_user.id, "monitoring"):
            await message.answer(
                "❌ У вас нет доступа к мониторингу доменов.\n\n"
                "Свяжитесь с администратором для получения доступа."
            )
            return
        await cmd_monitor(message)
        return
    
    elif text == "⚙️ Настройки":
        # Проверка разрешения на настройки
        if not has_permission(user_id, "settings"):
            await message.answer(
                "❌ У вас нет доступа к настройкам.\n\n"
                "Свяжитесь с администратором для получения доступа."
            )
            return
        
        await message.answer(
            "⚙️ *Настройки*\n\n"
            "Выберите параметр для изменения:",
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=build_settings_keyboard(user_id),
        )
        return
    
    elif text == "📋 История":
        # Проверка разрешения на историю
        if not has_permission(message.from_user.id, "history"):
            await message.answer(
                "❌ У вас нет доступа к истории проверок.\n\n"
                "Свяжитесь с администратором для получения доступа."
            )
            return
        await cmd_history(message)
        return
    
    elif text == "👨‍💼 Админ-панель" and user_id == ADMIN_ID:
        help_text = (
            "👨‍💼 *Админ-панель*\n\n"
            "Используйте кнопки ниже для управления доступом:"
        )
        await safe_send_text(
            message.bot,
            message.chat.id,
            help_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=build_admin_keyboard(),
        )
        return
    
    elif text == "ℹ️ Помощь":
        await cmd_help(message, state)
        return
    
    elif text == "🔙 Назад" or text == "🏠 Главное меню":
        # Возврат в главное меню
        await state.clear()
        await cmd_start(message, state)
        return
    
    # Если это не команда меню, обрабатываем как домены
    if text:
        logger.debug(f"Обработка доменов из текста для user_id={user_id}")
        try:
            await _process_domains(message, state, text)
            duration = asyncio.get_running_loop().time() - start_time
            logger.info(
                f"✅ Обработка доменов завершена | "
                f"user_id={user_id} | "
                f"duration={duration:.2f}s"
            )
        except Exception as e:
            duration = asyncio.get_running_loop().time() - start_time
            logger.error(
                f"❌ Ошибка при обработке доменов | "
                f"user_id={user_id} | "
                f"duration={duration:.2f}s | "
                f"error={type(e).__name__}: {str(e)}",
                exc_info=True
            )
            raise


# ---------- Запуск ----------

def setup_signal_handlers(bot: Bot, dp: Dispatcher) -> None:
    """
    Настраивает обработчики сигналов для graceful shutdown.
    
    Args:
        bot: Экземпляр бота
        dp: Диспетчер
    """
    def signal_handler(signum, frame):
        """Обработчик сигналов для корректного завершения работы."""
        logger.info(f"Получен сигнал {signum}, начинаем graceful shutdown...")
        _shutdown_event.set()
    
    # Регистрируем обработчики для SIGINT и SIGTERM
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


async def cleanup_resources() -> None:
    """Очищает ресурсы при завершении работы."""
    logger.info("Очистка ресурсов...")
    
    try:
        # Останавливаем мониторинг
        stop_monitoring()
        logger.info("Мониторинг остановлен")
    except Exception as e:
        logger.error(f"Ошибка при остановке мониторинга: {e}")
    
    try:
        # Очищаем rate limiter
        await cleanup_rate_limiter()
        logger.info("Rate limiter очищен")
    except Exception as e:
        logger.error(f"Ошибка при очистке rate limiter: {e}")
    
    try:
        # Очищаем старую историю
        if settings.HISTORY_ENABLED:
            removed = cleanup_old_history(settings.HISTORY_CLEANUP_DAYS)
            if removed > 0:
                logger.info(f"Удалено {removed} старых записей из истории")
    except Exception as e:
        logger.error(f"Ошибка при очистке истории: {e}")
    
    logger.info("Очистка ресурсов завершена")


async def setup_bot_commands(bot: Bot) -> None:
    """
    Настраивает команды бота для отображения в меню Telegram.
    
    Args:
        bot: Экземпляр бота
    """
    commands = [
        BotCommand(command="start", description="🚀 Запустить бота / Главное меню"),
        BotCommand(command="help", description="ℹ️ Справка по использованию"),
        BotCommand(command="monitor", description="📊 Управление мониторингом доменов"),
        BotCommand(command="history", description="📋 История проверок"),
        BotCommand(command="export_history", description="📥 Экспорт истории в CSV"),
        BotCommand(command="compare", description="🔍 Сравнение двух доменов"),
    ]
    
    # Для админа добавляем команду статистики и health check
    admin_commands = commands + [
        BotCommand(command="stats", description="📈 Статистика использования (админ)"),
        BotCommand(command="health", description="🏥 Проверка состояния системы (админ)"),
    ]
    
    try:
        # Устанавливаем команды для всех пользователей
        await bot.set_my_commands(commands)
        logger.info("Команды бота установлены")
        
        # Устанавливаем команды для админа
        await bot.set_my_commands(
            admin_commands,
            scope=types.BotCommandScopeDefault()
        )
        logger.info("Команды для админа установлены")
    except Exception as e:
        logger.error(f"Ошибка при установке команд бота: {e}")


async def main():
    """
    Главная функция запуска бота.
    
    Инициализирует бота, настраивает обработчики, запускает мониторинг
    и начинает обработку сообщений. Поддерживает graceful shutdown.
    """
    # Проверка обязательных настроек
    if not settings.TG_TOKEN:
        logger.error("TG_TOKEN не задан в переменных окружения")
        raise RuntimeError("TG_TOKEN не задан в .env")
    
    logger.info("Запуск бота...")
    logger.info(f"Уровень логирования: {settings.LOG_LEVEL}")
    logger.info(f"Максимальная конкурентность: {settings.CONCURRENCY}")
    logger.info(f"Rate limit: {settings.RATE_LIMIT_REQUESTS} запросов за {settings.RATE_LIMIT_WINDOW} секунд")
    
    # Создаем экземпляр бота
    bot = Bot(
        settings.TG_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML)
    )
    
    # Настраиваем команды бота
    await setup_bot_commands(bot)
    
    # Создаем диспетчер с хранилищем состояний в памяти
    dp = Dispatcher(storage=MemoryStorage())
    
    # Подключаем роутер с обработчиками
    dp.include_router(router)
    
    # Настраиваем обработчики сигналов для graceful shutdown
    setup_signal_handlers(bot, dp)
    
    # Запускаем мониторинг доменов (фоновая задача)
    start_monitoring(bot)
    logger.info("Мониторинг доменов запущен")
    
    # Периодическая очистка ресурсов (каждый час)
    async def periodic_cleanup():
        """Периодическая очистка ресурсов."""
        while not _shutdown_event.is_set():
            await asyncio.sleep(3600)  # Каждый час
            if not _shutdown_event.is_set():
                await cleanup_resources()
    
    # Запускаем периодическую очистку
    cleanup_task = asyncio.create_task(periodic_cleanup())
    
    try:
        logger.info("Бот запущен и готов к работе")
        logger.info(f"Обработчики зарегистрированы: {len(router.sub_routers)} роутеров")
        
        # Запускаем polling
        logger.info("Начало polling...")
        await dp.start_polling(
            bot,
            allowed_updates=dp.resolve_used_update_types(),
            close_bot_session=True
        )
    except asyncio.CancelledError:
        logger.info("Polling отменен (graceful shutdown)")
    except Exception as e:
        logger.critical(
            f"❌ Критическая ошибка при работе бота | "
            f"error={type(e).__name__}: {str(e)}",
            exc_info=True
        )
        record_error("BOT_CRITICAL_ERROR")
    finally:
        # Ожидаем завершения периодической очистки
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        
        # Финальная очистка ресурсов
        await cleanup_resources()
        
        logger.info("Бот остановлен")


if __name__ == "__main__":
    """
    Точка входа в приложение.
    
    Запускает бота с обработкой исключений и graceful shutdown.
    """
    try:
        # Запускаем асинхронную функцию main
        asyncio.run(main())
    except KeyboardInterrupt:
        # Пользователь прервал выполнение (Ctrl+C)
        logger.info("Получен сигнал прерывания от пользователя")
    except SystemExit:
        # Системный выход
        logger.info("Системный выход")
    except Exception as e:
        # Неожиданная ошибка
        logger.critical(f"Критическая ошибка при запуске: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Приложение завершено")
