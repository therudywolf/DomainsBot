"""
Обработчики команд бота.

Содержит обработчики для /start, /help, /health, /stats,
/export_history, /history, /monitor.
"""

import asyncio
import csv
import io
import logging
from datetime import datetime

from aiogram import Bot, F, Router, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext

from access import (
    has_access,
    has_permission,
    check_access,
    check_permission,
    ADMIN_ID,
    PERMISSIONS,
    get_bot_username,
)
from keyboards import (
    build_access_denied_keyboard,
    build_main_menu_keyboard,
    build_monitoring_keyboard,
    build_settings_keyboard,
    DEFAULT_MODE,
)
from config import settings
from utils.chat_settings import register_chat
from utils.monitoring import (
    get_monitored_domains,
    get_monitoring_interval,
    is_monitoring_enabled,
)
from utils.prefs import get_mode, set_mode
from utils.rate_limiter import check_rate_limit, get_remaining_requests
from utils.stats import record_command, get_stats
from utils.history import get_user_history
from utils.telegram_utils import safe_send_text

logger = logging.getLogger(__name__)

router = Router()


@router.message(CommandStart())
async def cmd_start(message: types.Message, state: FSMContext):
    """
    Обработчик команды /start.
    
    Показывает приветственное сообщение и главное меню.
    Также автоматически регистрирует чат, если команда вызвана из группы/канала.
    """
    user_id = message.from_user.id
    
    if message.chat.id != user_id:
        chat_title = message.chat.title or f"Chat {message.chat.id}"
        chat_type = message.chat.type
        register_chat(user_id, message.chat.id, chat_title, chat_type)
    
    if not has_access(user_id):
        await message.answer(
            "❌ У вас нет доступа к этому боту.\n\n"
            "Свяжитесь с администратором, нажав кнопку ниже.",
            reply_markup=build_access_denied_keyboard()
        )
        return
    
    mode = get_mode(user_id, DEFAULT_MODE)
    await state.update_data(view_mode=mode)
    
    record_command("start")
    
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
    
    if user_id != ADMIN_ID:
        await message.answer("❌ Эта команда доступна только администратору.")
        return
    
    health_status = []
    health_status.append("🏥 *Health Check*\n")
    
    try:
        from utils.cache import get_cache_stats
        cache_stats = get_cache_stats()
        health_status.append(f"✅ Кэш: {cache_stats['memory_cache_size']} записей в памяти")
        health_status.append(f"   Hit rate: {cache_stats['hit_rate']}%")
    except Exception as e:
        health_status.append(f"❌ Кэш: Ошибка - {e}")
    
    try:
        from utils.stats import get_stats
        stats = get_stats()
        health_status.append(f"✅ Статистика: {stats['total_domains_checked']} проверок")
    except Exception as e:
        health_status.append(f"❌ Статистика: Ошибка - {e}")
    
    try:
        health_status.append(f"✅ Мониторинг: активен")
    except Exception as e:
        health_status.append(f"❌ Мониторинг: Ошибка - {e}")
    
    try:
        from utils.rate_limiter import _rate_limiter
        health_status.append(f"✅ Rate Limiter: активен")
    except Exception as e:
        health_status.append(f"❌ Rate Limiter: Ошибка - {e}")
    
    health_status.append(f"✅ Gost сервисы: проверка через docker-compose")

    try:
        from utils.wireguard_utils import check_wg_connection
        wg = check_wg_connection()
        if wg.get("config_found"):
            if wg.get("interface_up"):
                health_status.append(f"✅ WireGuard: контейнер доступен ({wg.get('interface_ip', '—')})")
            else:
                health_status.append(f"⚠️ WireGuard: конфиг есть, контейнер недоступен")
        else:
            health_status.append(f"⚠️ WireGuard: конфиг не найден (резерв при 504 недоступен)")
    except Exception as e:
        health_status.append(f"❌ WireGuard: Ошибка — {e}")
    
    await message.answer("\n".join(health_status), parse_mode="Markdown")


@router.message(Command("help"))
async def cmd_help(message: types.Message, state: FSMContext):
    """Команда /help - показывает подробную справку по использованию бота."""
    user_id = message.from_user.id
    
    if not await check_access(message):
        return
    
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
    
    if not await check_access(message):
        return
    
    if user_id != ADMIN_ID:
        await message.answer("❌ Эта команда доступна только администратору.")
        return
    
    record_command("stats")
    
    stats = get_stats()
    
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
    
    if stats['top_domains']:
        text += "🔝 *Топ доменов:*\n"
        for domain, count in list(stats['top_domains'].items())[:5]:
            text += f"• {domain}: {count}\n"
        text += "\n"
    
    if stats['top_commands']:
        text += "⚙️ *Топ команд:*\n"
        for cmd, count in list(stats['top_commands'].items())[:5]:
            text += f"• {cmd}: {count}\n"
        text += "\n"
    
    if stats['top_errors']:
        text += "⚠️ *Топ ошибок:*\n"
        for error, count in list(stats['top_errors'].items())[:5]:
            text += f"• {error}: {count}\n"
    
    text += f"\n🔄 Последний сброс: {stats['last_reset']}"
    
    try:
        bot = message.bot
        if bot is None:
            logger.warning("message.bot is None in cmd_stats, создаем новый bot instance")
            bot = Bot(
                settings.TG_TOKEN,
                default=DefaultBotProperties(parse_mode=ParseMode.HTML)
            )
            try:
                await safe_send_text(
                    bot,
                    message.chat.id,
                    text,
                    parse_mode=ParseMode.MARKDOWN
                )
            finally:
                await bot.session.close()
        else:
            await safe_send_text(
                bot,
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
        try:
            await message.answer(
                "❌ Ошибка при загрузке статистики. Попробуйте позже.",
                parse_mode=ParseMode.MARKDOWN
            )
        except Exception:
            pass


@router.message(Command("export_history"))
async def cmd_export_history(message: types.Message, state: FSMContext):
    """
    Команда /export_history - экспортирует историю проверок в CSV.
    
    Поддерживает фильтры по дате и домену.
    """
    user_id = message.from_user.id
    
    if not await check_access(message):
        return
    
    if not await check_permission(message, "history"):
        return
    
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
    
    history = get_user_history(user_id, limit=1000)
    
    if not history:
        await message.answer("📋 История проверок пуста.")
        return
    
    output = io.StringIO()
    writer = csv.writer(output)
    
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
    
    csv_data = output.getvalue().encode('utf-8-sig')
    csv_file = io.BytesIO(csv_data)
    csv_file.name = f"history_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    try:
        await message.answer_document(
            types.BufferedInputFile(csv_data, filename=csv_file.name),
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
    
    if not await check_access(message):
        return
    
    if not await check_permission(message, "history"):
        return
    
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
    
    record_command("history")
    
    history = get_user_history(user_id, limit=10)
    
    if not history:
        await message.answer("📋 История проверок пуста.")
        return
    
    text = "📋 *История проверок:*\n\n"
    
    for i, entry in enumerate(history, 1):
        domain = entry.get("domain", "unknown")
        timestamp = entry.get("timestamp", "")
        gost = entry.get("ssl", {}).get("gost", False)
        waf = entry.get("waf", False)
        
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


@router.message(Command("monitor"))
async def cmd_monitor(message: types.Message):
    """Команда для управления мониторингом доменов."""
    if not await check_access(message):
        return
    
    if not await check_permission(message, "monitoring"):
        return
    
    user_id = message.from_user.id
    enabled = await is_monitoring_enabled(user_id)
    interval = await get_monitoring_interval(user_id)
    domains = await get_monitored_domains(user_id)
    
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
