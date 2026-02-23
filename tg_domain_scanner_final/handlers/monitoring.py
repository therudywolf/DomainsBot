"""Handlers for domain monitoring management."""

import io
import logging
from datetime import datetime

from aiogram import F, Router, types
from aiogram.enums import ParseMode
from aiogram.fsm.context import FSMContext

from access import has_access, has_permission, check_access, ADMIN_ID, MonitoringStates
from keyboards import build_monitoring_keyboard
from utils.monitoring import (
    add_domain_to_monitoring,
    remove_domain_from_monitoring,
    get_monitored_domains,
    set_monitoring_interval,
    get_monitoring_interval,
    set_monitoring_enabled,
    is_monitoring_enabled,
)
from utils.domain_processor import validate_and_normalize_domains, DOMAIN_SPLIT_RE
from utils.domain_normalizer import normalize_domains
from utils.prefs import get_waf_timeout, set_waf_timeout
from handlers.callbacks import safe_callback_answer
from utils.telegram_utils import safe_send_text

logger = logging.getLogger(__name__)

router = Router()


@router.callback_query(F.data.startswith("monitor_add_from_report_"))
async def monitor_add_from_report(callback: types.CallbackQuery):
    """Добавляет домен в мониторинг из отчета."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await safe_callback_answer(callback, "❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    # Извлекаем домен из callback_data
    domain = callback.data.replace("monitor_add_from_report_", "")
    
    if not domain:
        await safe_callback_answer(callback, "❌ Ошибка: домен не указан", show_alert=True)
        return
    
    # Нормализуем домен
    domains = normalize_domains([domain])
    
    if not domains:
        await safe_callback_answer(callback, "❌ Некорректный домен", show_alert=True)
        return
    
    domain = domains[0]
    
    # Добавляем в мониторинг
    if await add_domain_to_monitoring(user_id, domain):
        await safe_callback_answer(callback, f"✅ Домен {domain} добавлен в мониторинг", show_alert=False)
    else:
        await safe_callback_answer(callback, f"ℹ️ Домен {domain} уже в мониторинге", show_alert=False)


@router.callback_query(F.data == "monitor_add")
async def monitor_add(callback: types.CallbackQuery, state: FSMContext):
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await safe_callback_answer(callback, "❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    await state.set_state(MonitoringStates.add_domain_waiting)
    await callback.message.answer(
        "📝 Введите домен(ы) для добавления в мониторинг.\n\n"
        "Можно вводить несколько через пробел, запятую или с новой строки:\n"
        "`example.com test.ru https://site.com/path`\n\n"
        "Также можно отправить TXT файл со списком доменов (по одному на строку)."
    )
    await safe_callback_answer(callback, "")


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
                    if await add_domain_to_monitoring(user_id, domain):
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
        if await add_domain_to_monitoring(user_id, domain):
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
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await safe_callback_answer(callback, "❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    await state.set_state(MonitoringStates.remove_domain_waiting)
    await callback.message.answer(
        "🗑️ Введите домен(ы) для удаления из мониторинга.\n\n"
        "Можно вводить несколько через пробел или запятую."
    )
    await safe_callback_answer(callback, "")


@router.message(MonitoringStates.remove_domain_waiting)
async def process_monitor_remove(message: types.Message, state: FSMContext):
    text = message.text or ""
    raw_items = [x.strip() for x in DOMAIN_SPLIT_RE.split(text) if x.strip()]
    domains = normalize_domains(raw_items)
    
    user_id = message.from_user.id
    removed_count = 0
    
    for domain in domains:
        if await remove_domain_from_monitoring(user_id, domain):
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
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await safe_callback_answer(callback, "❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    domains = await get_monitored_domains(user_id)
    
    if not domains:
        await callback.message.answer("📋 Нет доменов в мониторинге")
    else:
        text = "📋 *Домены в мониторинге:*\n\n" + "\n".join(f"• {d}" for d in domains)
        await callback.message.answer(text, parse_mode=ParseMode.MARKDOWN)
    
    await safe_callback_answer(callback, "")


@router.callback_query(F.data == "monitor_export")
async def monitor_export(callback: types.CallbackQuery):
    """Экспортирует список доменов из мониторинга в текстовый файл."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await safe_callback_answer(callback, "❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    domains = await get_monitored_domains(user_id)
    
    if not domains:
        await safe_callback_answer(callback, "📋 Нет доменов в мониторинге для экспорта", show_alert=True)
        return
    
    # Создаем текстовый файл со списком доменов
    domains_text = "\n".join(domains)
    domains_file = io.BytesIO(domains_text.encode('utf-8'))
    domains_file.name = f"monitored_domains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    try:
        await callback.message.answer_document(
            types.FSInputFile(domains_file, filename=domains_file.name),
            caption=f"📥 Экспорт доменов из мониторинга ({len(domains)} доменов)"
        )
        await safe_callback_answer(callback, "✅ Список доменов экспортирован")
    except Exception as e:
        logger.error(f"Ошибка при экспорте доменов для пользователя {user_id}: {e}", exc_info=True)
        await safe_callback_answer(callback, "❌ Ошибка при экспорте доменов", show_alert=True)


@router.callback_query(F.data == "monitor_interval")
async def monitor_interval(callback: types.CallbackQuery, state: FSMContext):
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await safe_callback_answer(callback, "❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    await state.set_state(MonitoringStates.set_interval_waiting)
    current_interval = await get_monitoring_interval(callback.from_user.id)
    await callback.message.answer(
        f"⏱️ Введите интервал проверки в минутах (текущий: {current_interval} минут).\n\n"
        f"Например: `15` или `30`"
    )
    await safe_callback_answer(callback, "")


@router.message(MonitoringStates.set_interval_waiting)
async def process_monitor_interval(message: types.Message, state: FSMContext):
    text = message.text or ""
    try:
        interval = int(text.strip())
        if interval < 1 or interval > 1440:  # От 1 минуты до 24 часов
            await message.answer("❌ Интервал должен быть от 1 до 1440 минут")
            await state.clear()
            return
        
        await set_monitoring_interval(message.from_user.id, interval)
        await message.answer(f"✅ Интервал проверки установлен: {interval} минут")
    except ValueError:
        await message.answer("❌ Некорректное значение. Введите число (минуты)")
    
    await state.clear()


@router.callback_query(F.data == "monitor_waf_timeout")
async def monitor_waf_timeout(callback: types.CallbackQuery, state: FSMContext):
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await safe_callback_answer(callback, "❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    await state.set_state(MonitoringStates.set_waf_timeout_waiting)
    current_timeout = get_waf_timeout(callback.from_user.id)
    timeout_text = f"{current_timeout} секунд" if current_timeout else "не установлен"
    await callback.message.answer(
        f"⚙️ Введите таймаут для WAF проверки в секундах (текущий: {timeout_text}).\n\n"
        f"Например: `10` или `15`"
    )
    await safe_callback_answer(callback, "")


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
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на мониторинг
    if not has_permission(user_id, "monitoring"):
        await safe_callback_answer(callback, "❌ Нет доступа к мониторингу", show_alert=True)
        return
    
    user_id = callback.from_user.id
    current_state = await is_monitoring_enabled(user_id)
    await set_monitoring_enabled(user_id, not current_state)
    
    new_state = "включен" if not current_state else "выключен"
    await safe_callback_answer(callback, f"✅ Мониторинг {new_state}")
