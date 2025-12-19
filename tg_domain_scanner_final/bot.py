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
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.fsm.state import State, StatesGroup

# Импорт конфигурации и настроек
from config import settings

# Импорт утилит для проверки доменов
from utils.dns_utils import fetch_dns
from utils.ssl_utils import fetch_ssl
from utils.waf_utils import test_waf
from utils.formatting import build_report
from utils.telegram_utils import safe_send_text

# Импорт утилит для настроек пользователя
from utils.prefs import (
    get_mode, set_mode,
    get_waf_mode, set_waf_mode,
    get_waf_timeout, set_waf_timeout
)

# Импорт утилит для нормализации доменов
from utils.domain_normalizer import normalize_domains

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

# ID администратора бота (может быть переопределен через переменную окружения)
ADMIN_ID = int(os.getenv("ADMIN_ID", "6323277521"))

# URL для запроса доступа (ссылка на администратора)
REQUEST_ACCESS_URL = os.getenv("REQUEST_ACCESS_URL", "https://t.me/tyoma_platonov")

# Путь к файлу базы данных доступов
ACCESS_DB_FILE = Path("data/access_db.json")

# Создаем директорию для данных, если она не существует
ACCESS_DB_FILE.parent.mkdir(parents=True, exist_ok=True)

# Глобальная переменная для graceful shutdown
_shutdown_event = asyncio.Event()

# ---------- БД доступов ----------

def load_access_db() -> dict:
    """Загружает БД доступа из JSON файла."""
    if ACCESS_DB_FILE.exists():
        try:
            with open(ACCESS_DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
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
    """Проверяет, есть ли у пользователя доступ."""
    # Админ всегда имеет доступ
    if user_id == ADMIN_ID:
        return True
    
    db = load_access_db()
    return str(user_id) in db


def add_access(user_id: int, username: str = "") -> bool:
    """Добавляет доступ пользователю."""
    db = load_access_db()
    db[str(user_id)] = {
        "username": username or "",
        "added_at": str(__import__('datetime').datetime.now())
    }
    save_access_db(db)
    return True


def remove_access(user_id: int) -> bool:
    """Удаляет доступ пользователя."""
    db = load_access_db()
    if str(user_id) in db:
        del db[str(user_id)]
        save_access_db(db)
        return True
    return False


def get_access_list() -> dict:
    """Получает список всех доступов."""
    return load_access_db()


# ---------- FSM для админ команд ----------

class AdminStates(StatesGroup):
    add_access_waiting = State()
    remove_access_waiting = State()


class MonitoringStates(StatesGroup):
    add_domain_waiting = State()
    remove_domain_waiting = State()
    set_interval_waiting = State()
    set_waf_timeout_waiting = State()


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
        ]
    )


def build_access_denied_keyboard() -> types.InlineKeyboardMarkup:
    """Кнопка для запроса доступа."""
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


def build_admin_keyboard() -> types.InlineKeyboardMarkup:
    """Админ-панель кнопок."""
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
                    text="📋 Список доступов",
                    callback_data="admin_list_access",
                ),
            ]
        ]
    )


router = Router()

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


# ---------- Основная проверка домена ----------

async def _process_domains(message: types.Message, state: FSMContext, raw_text: str) -> None:
    """
    Обрабатывает список доменов: парсит, нормализует, проверяет и формирует отчёт.
    
    Args:
        message: Сообщение от пользователя
        state: Состояние FSM
        raw_text: Текст с доменами для обработки
    """
    user_id = message.from_user.id
    
    # Проверка доступа
    if not await check_access(message):
        return
    
    # Проверка rate limit
    if not check_rate_limit(user_id):
        remaining = get_remaining_requests(user_id)
        await safe_send_text(
            message.bot,
            message.chat.id,
            f"⏱️ Превышен лимит запросов. Попробуйте позже.\n"
            f"Осталось запросов: {remaining}"
        )
        return
    
    # Разбиваем на отдельные строки
    raw_items = [x.strip() for x in DOMAIN_SPLIT_RE.split(raw_text or "") if x.strip()]
    
    # Нормализуем домены (обрабатывает https://, пути, параметры и т.д.)
    domains = normalize_domains(raw_items)
    bad = [item for item in raw_items if item not in domains]

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
    collected: List[Tuple[str, dict, dict, bool]] = []

    async def process(domain: str):
        """
        Обрабатывает один домен: получает DNS, SSL и WAF информацию.
        
        Args:
            domain: Домен для проверки
            
        Returns:
            Кортеж (строка отчета, данные для CSV)
        """
        async with semaphore:
            try:
                # Параллельно получаем информацию о домене
                dns_info, ssl_info, waf_enabled = await asyncio.gather(
                    fetch_dns(domain, settings.DNS_TIMEOUT),
                    fetch_ssl(domain),
                    test_waf(domain, user_id=user_id),
                    return_exceptions=True
                )
                
                # Обрабатываем исключения
                if isinstance(dns_info, Exception):
                    logger.error(f"Ошибка DNS для {domain}: {dns_info}")
                    dns_info = {}
                    record_error("DNS_ERROR")
                
                if isinstance(ssl_info, Exception):
                    logger.error(f"Ошибка SSL для {domain}: {ssl_info}")
                    ssl_info = {}
                    record_error("SSL_ERROR")
                
                if isinstance(waf_enabled, Exception):
                    logger.error(f"Ошибка WAF для {domain}: {waf_enabled}")
                    waf_enabled = False
                    record_error("WAF_ERROR")
                
                # Формируем данные для отчета
                row = (domain, dns_info, ssl_info, waf_enabled)
                line = build_report(domain, dns_info, ssl_info, waf_enabled, brief=brief)
                
                # Сохраняем в историю (если включено)
                if settings.HISTORY_ENABLED:
                    try:
                        add_check_result(domain, user_id, dns_info, ssl_info, waf_enabled)
                    except Exception as e:
                        logger.warning(f"Ошибка при сохранении в историю: {e}")
                
                # Записываем статистику
                if settings.STATS_ENABLED:
                    record_domain_check(domain, user_id)
                
            except Exception as exc:  # noqa: BLE001
                logger.exception(f"Критическая ошибка при обработке {domain}")
                record_error("PROCESSING_ERROR")
                row = (domain, {}, {}, False)
                line = f"❌ {domain}: ошибка ({type(exc).__name__})"
            
            return line, row

    tasks = [asyncio.create_task(process(d)) for d in domains]

    # ---------- Прогресс-индикатор ----------

    MIN_EDIT_INTERVAL = 4  # секунд между edit_text
    total = len(tasks)
    done = 0
    loop = asyncio.get_event_loop()
    start_ts = loop.time()
    last_edit = start_ts - MIN_EDIT_INTERVAL
    progress_msg: types.Message | None = None

    for coro in asyncio.as_completed(tasks):
        line, row = await coro
        reports.append(line)
        collected.append(row)
        done += 1

        now = loop.time()
        need_update = total >= 4 and (done == total or now - last_edit >= MIN_EDIT_INTERVAL)

        if need_update:
            elapsed = now - start_ts
            eta_sec = int(elapsed / done * (total - done)) if done < total else 0
            eta_txt = f"{eta_sec // 60}м {eta_sec % 60}с" if eta_sec else "0 с"
            text = f"⏳ {done} / {total} • осталось ≈ {eta_txt}"

            try:
                if progress_msg is None:
                    progress_msg = await message.reply(text)
                else:
                    await progress_msg.edit_text(text)
                last_edit = now
            except Exception:
                progress_msg = None

    if bad:
        reports.append("🔸 Игнорированы некорректные строки: " + ", ".join(bad))

    # ---------- Формирование вывода ----------

    if total >= 4:
        buf = io.StringIO(newline="")
        writer = csv.writer(buf, delimiter=";")
        if brief:
            writer.writerow([
                "Domain", "CN", "Valid From", "Valid To", 
                "GOST Cert From", "GOST Cert To", "WAF", "GOST"
            ])
        else:
            writer.writerow(
                [
                    "Domain",
                    "A",
                    "AAAA",
                    "MX",
                    "NS",
                    "CN",
                    "Valid From",
                    "Valid To",
                    "GOST Cert From",
                    "GOST Cert To",
                    "WAF",
                    "GOST",
                ]
            )

        for domain, dns_info, ssl_info, waf_enabled in collected:
            gost_val = "Да" if ssl_info.get("gost") else "Нет"
            waf_val = "Да" if waf_enabled else "Нет"
            
            # Форматируем даты
            def format_date(dt):
                if dt is None:
                    return ""
                if hasattr(dt, 'date'):
                    return dt.date().isoformat()
                return str(dt)
            
            row_base = [
                domain,
                ssl_info.get("CN") or "",
                format_date(ssl_info.get("NotBefore")),
                format_date(ssl_info.get("NotAfter")),
                format_date(ssl_info.get("GostNotBefore")),
                format_date(ssl_info.get("GostNotAfter")),
                waf_val,
                gost_val,
            ]

            if brief:
                writer.writerow(row_base)
            else:
                writer.writerow(
                    [
                        domain,
                        ",".join(dns_info.get("A", [])),
                        ",".join(dns_info.get("AAAA", [])),
                        ",".join(dns_info.get("MX", [])),
                        ",".join(dns_info.get("NS", [])),
                        *row_base[1:],
                    ]
                )

        csv_bytes = buf.getvalue().encode("utf-8-sig")
        await message.answer_document(
            types.BufferedInputFile(csv_bytes, filename="report.csv"),
            caption=f"✔️ Проверено {total} доменов.",
        )

    else:
        await safe_send_text(
            message.bot,
            message.chat.id,
            "\n".join(reports),
            reply_markup=build_mode_keyboard(view_mode),
        )


# ---------- Команды ----------

@router.message(CommandStart())
async def cmd_start(message: types.Message, state: FSMContext):
    user_id = message.from_user.id
    
    # Проверка доступа
    if not has_access(user_id):
        await message.answer(
            "❌ У вас нет доступа к этому боту.\n\n"
            "Свяжитесь с администратором, нажав кнопку ниже.",
            reply_markup=build_access_denied_keyboard()
        )
        return
    
    # Если админ - показать админ-панель
    if user_id == ADMIN_ID:
        help_text = (
            "👨‍💼 *Админ-панель*\n\n"
            "Используйте кнопки ниже для управления доступом:"
        )
        await safe_send_text(
            message.bot,
            message.chat.id,
            help_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=build_admin_keyboard()
        )
        return
    
    # Обычный пользователь
    mode = get_mode(user_id, DEFAULT_MODE)
    await state.update_data(view_mode=mode)

    help_text = (
        "👋 Я сканирую домены и показываю DNS-, SSL-, WAF-информацию.\n\n"
        "📥 *Как пользоваться*:\n"
        "1. *Текст*: перечислите домены через пробел, запятую или с новой строки.\n"
        "   Поддерживаются URL: `https://example.com/path` → `example.com`\n"
        "2. *Файл*: пришлите `.txt` (UTF-8), по одному домену в строке (до 1000).\n"
        "3. 4+ доменов — получаете CSV-отчёт.\n\n"
        "📄 *Короткий режим* — колонки: CN, даты сертификатов (обычный + GOST), WAF, GOST.\n"
        "🔎 *Расширенный* — те же колонки + DNS-записи A, AAAA, MX, NS.\n\n"
        "⚙️ *Дополнительно*:\n"
        "• `/monitor` — мониторинг доменов с уведомлениями об изменениях\n"
        "• Режим проверки WAF настраивается в настройках\n\n"
        "Режимы запоминаются для вашего аккаунта."
    )

    await safe_send_text(
        message.bot,
        message.chat.id,
        help_text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=build_mode_keyboard(mode),
    )


@router.message(Command("help"))
async def cmd_help(message: types.Message, state: FSMContext):
    """Команда /help - показывает справку по использованию бота."""
    await cmd_start(message, state)


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
    
    await safe_send_text(
        message.bot,
        message.chat.id,
        text,
        parse_mode=ParseMode.MARKDOWN
    )


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
    
    # Проверка rate limit
    if not check_rate_limit(user_id):
        remaining = get_remaining_requests(user_id)
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
    # Проверка доступа
    if not has_access(callback.from_user.id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    new_mode = "full" if callback.data == "mode_full" else "brief"
    await state.update_data(view_mode=new_mode)
    set_mode(callback.from_user.id, new_mode)

    await callback.answer(
        f"Режим установлен: {'Расширенный' if new_mode == 'full' else 'Короткий'}"
    )

    try:
        await callback.message.edit_reply_markup(reply_markup=build_mode_keyboard(new_mode))
    except Exception:
        pass


# ---------- Переключение режима WAF ----------

@router.callback_query(F.data.in_({"waf_mode_policy", "waf_mode_light"}))
async def switch_waf_mode(callback: types.CallbackQuery):
    # Проверка доступа
    if not has_access(callback.from_user.id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    new_mode = "policy" if callback.data == "waf_mode_policy" else "light"
    set_waf_mode(callback.from_user.id, new_mode)

    await callback.answer(
        f"Режим WAF установлен: {'Policy-based' if new_mode == 'policy' else 'Light check'}"
    )

    try:
        await callback.message.edit_reply_markup(reply_markup=build_waf_mode_keyboard(new_mode))
    except Exception:
        pass


# ---------- МОНИТОРИНГ ДОМЕНОВ ----------

@router.message(Command("monitor"))
async def cmd_monitor(message: types.Message):
    """Команда для управления мониторингом доменов."""
    # Проверка доступа
    if not await check_access(message):
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


@router.callback_query(F.data == "monitor_add")
async def monitor_add(callback: types.CallbackQuery, state: FSMContext):
    if not has_access(callback.from_user.id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    await state.set_state(MonitoringStates.add_domain_waiting)
    await callback.message.answer(
        "📝 Введите домен(ы) для добавления в мониторинг.\n\n"
        "Можно вводить несколько через пробел, запятую или с новой строки:\n"
        "`example.com test.ru https://site.com/path`"
    )
    await callback.answer()


@router.message(MonitoringStates.add_domain_waiting)
async def process_monitor_add(message: types.Message, state: FSMContext):
    text = message.text or ""
    raw_items = [x.strip() for x in DOMAIN_SPLIT_RE.split(text) if x.strip()]
    domains = normalize_domains(raw_items)
    
    user_id = message.from_user.id
    added_count = 0
    
    for domain in domains:
        if add_domain_to_monitoring(user_id, domain):
            added_count += 1
    
    response = f"✅ Добавлено {added_count} домен(ов) в мониторинг"
    if len(domains) < len(raw_items):
        response += f"\n⚠️ Некоторые домены не были добавлены (некорректный формат)"
    
    await message.answer(response)
    await state.clear()


@router.callback_query(F.data == "monitor_remove")
async def monitor_remove(callback: types.CallbackQuery, state: FSMContext):
    if not has_access(callback.from_user.id):
        await callback.answer("❌ Нет доступа", show_alert=True)
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
    if not has_access(callback.from_user.id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    user_id = callback.from_user.id
    domains = get_monitored_domains(user_id)
    
    if not domains:
        await callback.message.answer("📋 Нет доменов в мониторинге")
    else:
        text = "📋 *Домены в мониторинге:*\n\n" + "\n".join(f"• {d}" for d in domains)
        await callback.message.answer(text, parse_mode=ParseMode.MARKDOWN)
    
    await callback.answer()


@router.callback_query(F.data == "monitor_interval")
async def monitor_interval(callback: types.CallbackQuery, state: FSMContext):
    if not has_access(callback.from_user.id):
        await callback.answer("❌ Нет доступа", show_alert=True)
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
    if not has_access(callback.from_user.id):
        await callback.answer("❌ Нет доступа", show_alert=True)
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
    if not has_access(callback.from_user.id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    user_id = callback.from_user.id
    current_state = is_monitoring_enabled(user_id)
    set_monitoring_enabled(user_id, not current_state)
    
    new_state = "включен" if not current_state else "выключен"
    await callback.answer(f"✅ Мониторинг {new_state}")


# ---------- АДМИН-ПАНЕЛЬ ----------

@router.callback_query(F.data == "admin_add_access")
async def admin_add_access(callback: types.CallbackQuery, state: FSMContext):
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Только администратор", show_alert=True)
        return
    
    await state.set_state(AdminStates.add_access_waiting)
    await callback.message.answer(
        "📝 Введите TG ID пользователя(ей).\n\n"
        "Можно вводить несколько через пробел или запятую:\n"
        "`123456789 987654321 444555666`"
    )
    await callback.answer()


@router.message(AdminStates.add_access_waiting)
async def process_add_access(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    
    text = message.text or ""
    # Парсим TG ID
    items = re.split(r"[\s,]+", text.strip())
    
    added_count = 0
    errors = []
    
    for item in items:
        if not item:
            continue
        
        # Если начинается с @, то это никнейм - пропускаем (нужен ID)
        if item.startswith("@"):
            errors.append(f"⚠️ {item} - Требуется TG ID, не никнейм")
            continue
        
        # Пытаемся распарсить как число
        try:
            user_id = int(item)
            username = ""
            add_access(user_id, username)
            added_count += 1
        except ValueError:
            errors.append(f"❌ {item} - Некорректный формат")
    
    response = f"✅ Добавлен доступ для {added_count} пользователей(я)"
    if errors:
        response += "\n\n" + "\n".join(errors)
    
    await message.answer(response)
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
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Только администратор", show_alert=True)
        return
    
    db = get_access_list()
    
    if not db:
        await callback.message.answer("📋 БД доступов пуста")
        await callback.answer()
        return
    
    # Форматируем список
    lines = ["📋 *Список доступов:*\n"]
    for user_id, data in sorted(db.items()):
        username = data.get("username", "")
        added_at = data.get("added_at", "")
        
        user_info = f"ID: {user_id}"
        if username:
            user_info += f" (@{username})"
        if added_at:
            user_info += f" - добавлен {added_at[:10]}"
        
        lines.append(f"• {user_info}")
    
    text = "\n".join(lines)
    
    # Если текст слишком длинный, отправляем как файл
    if len(text) > 4000:
        buf = io.BytesIO(text.encode("utf-8"))
        await callback.message.answer_document(
            types.BufferedInputFile(buf.getvalue(), filename="access_list.txt")
        )
    else:
        await callback.message.answer(text, parse_mode=ParseMode.MARKDOWN)
    
    await callback.answer()


# ---------- Загрузка TXT ----------

@router.message(F.document)
async def handle_document(message: types.Message, state: FSMContext):
    """
    Обрабатывает загруженные документы (TXT файлы со списком доменов).
    
    Поддерживает только .txt файлы с кодировкой UTF-8.
    Максимальный размер файла ограничен настройкой MAX_FILE_SIZE_MB.
    """
    user_id = message.from_user.id
    
    # Проверка доступа
    if not await check_access(message):
        return
    
    # Проверка rate limit
    if not check_rate_limit(user_id):
        remaining = get_remaining_requests(user_id)
        await message.reply(
            f"⏱️ Превышен лимит запросов. Попробуйте позже.\n"
            f"Осталось запросов: {remaining}"
        )
        return
    
    doc = message.document
    
    # Проверка расширения файла
    if not doc.file_name or not doc.file_name.lower().endswith(".txt"):
        await message.reply(
            "📄 Пришлите TXT-файл со списком доменов.\n\n"
            "Файл должен содержать домены, по одному на строку."
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
    await _process_domains(message, state, message.text or "")


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
        cleanup_rate_limiter()
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
        
        # Запускаем polling
        await dp.start_polling(
            bot,
            allowed_updates=dp.resolve_used_update_types(),
            close_bot_session=True
        )
    except Exception as e:
        logger.error(f"Критическая ошибка при работе бота: {e}", exc_info=True)
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
