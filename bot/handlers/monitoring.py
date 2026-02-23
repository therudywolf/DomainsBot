"""Handlers for domain monitoring management."""

import asyncio
import io
import logging
from datetime import datetime

from aiogram import F, Router, types
from aiogram.fsm.context import FSMContext

from access import has_access, has_permission, check_access, check_access_callback, ADMIN_ID, MonitoringStates, is_admin_user
from keyboards import (
    build_monitoring_keyboard,
    build_monitoring_global_keyboard,
    build_monitoring_admin_panel_keyboard,
)
from utils.monitoring import (
    add_domain_to_monitoring,
    remove_domain_from_monitoring,
    get_monitored_domains,
    set_monitoring_interval,
    get_monitoring_interval,
    set_monitoring_enabled,
    is_monitoring_enabled,
    run_checks_now,
    get_monitoring_owner_keys,
)
from utils.chat_settings import get_notification_chat_id_global, set_notification_chat_id_global
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


def _resolve_monitor_scope(state_data: dict, user_id: int) -> tuple[int, str]:
    """По данным FSM возвращает (user_id, scope) для вызовов API мониторинга."""
    scope = (state_data or {}).get("monitor_scope", "user")
    owner = (state_data or {}).get("monitor_owner_key")
    if scope == "global":
        return 0, "global"
    if scope == "admin" and owner:
        try:
            return int(owner), "user"
        except ValueError:
            pass
    return user_id, "user"


@router.message(MonitoringStates.add_domain_waiting)
async def process_monitor_add(message: types.Message, state: FSMContext):
    """Обрабатывает добавление доменов в мониторинг (текст или файл)."""
    user_id = message.from_user.id
    data = await state.get_data()
    api_user_id, scope = _resolve_monitor_scope(data, user_id)
    
    if message.document:
        doc = message.document
        if doc.file_name and doc.file_name.lower().endswith(".txt"):
            try:
                file_obj = await message.bot.download(doc.file_id)
                text_data = file_obj.getvalue().decode("utf-8", errors="ignore")
                if not text_data.strip():
                    await message.answer("❌ Файл пуст или не содержит текста.")
                    await state.clear()
                    return
                domains, bad = validate_and_normalize_domains(text_data)
                added_count = 0
                for domain in domains:
                    if await add_domain_to_monitoring(api_user_id, domain, scope=scope):
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
        if await add_domain_to_monitoring(api_user_id, domain, scope=scope):
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
    data = await state.get_data()
    api_user_id, scope = _resolve_monitor_scope(data, message.from_user.id)
    removed_count = 0
    for domain in domains:
        if await remove_domain_from_monitoring(api_user_id, domain, scope=scope):
            removed_count += 1
    response = f"✅ Удалено {removed_count} домен(ов) из мониторинга"
    if removed_count < len(domains):
        response += f"\n⚠️ Некоторые домены не были найдены в мониторинге"
    await message.answer(response)
    await state.clear()


@router.callback_query(F.data == "monitor_list")
async def monitor_list(callback: types.CallbackQuery):
    user_id = callback.from_user.id
    
    if not await check_access_callback(callback, "monitoring"):
        return
    
    domains = await get_monitored_domains(user_id)
    
    if not domains:
        await callback.message.answer("📋 Нет доменов в мониторинге")
    else:
        text = "📋 <b>Домены в мониторинге:</b>\n\n" + "\n".join(f"• {d}" for d in domains)
        await callback.message.answer(text)
    
    await safe_callback_answer(callback, "")


@router.callback_query(F.data == "monitor_export")
async def monitor_export(callback: types.CallbackQuery):
    """Экспортирует список доменов из мониторинга в текстовый файл."""
    user_id = callback.from_user.id
    
    if not await check_access_callback(callback, "monitoring"):
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
            types.BufferedInputFile(domains_text.encode('utf-8'), filename=domains_file.name),
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
    data = await state.get_data()
    api_user_id, scope = _resolve_monitor_scope(data, message.from_user.id)
    try:
        interval = int(text.strip())
        if interval < 1 or interval > 1440:
            await message.answer("❌ Интервал должен быть от 1 до 1440 минут")
            await state.clear()
            return
        await set_monitoring_interval(api_user_id, interval, scope=scope)
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
    data = await state.get_data()
    api_user_id, _ = _resolve_monitor_scope(data, message.from_user.id)
    try:
        timeout = int(text.strip())
        if timeout < 1 or timeout > 60:
            await message.answer("❌ Таймаут должен быть от 1 до 60 секунд")
            await state.clear()
            return
        set_waf_timeout(api_user_id, timeout)
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


@router.callback_query(F.data == "monitor_run_now")
async def monitor_run_now(callback: types.CallbackQuery):
    """Запускает проверку всех доменов мониторинга без ожидания таймера."""
    user_id = callback.from_user.id

    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    if not has_permission(user_id, "monitoring"):
        await safe_callback_answer(callback, "❌ Нет доступа к мониторингу", show_alert=True)
        return

    domains = await get_monitored_domains(user_id)
    if not domains:
        await safe_callback_answer(callback, "📋 Нет доменов в мониторинге для проверки", show_alert=True)
        return

    bot = callback.bot or (callback.message.bot if callback.message else None)
    if not bot:
        await safe_callback_answer(callback, "❌ Ошибка: бот недоступен", show_alert=True)
        return

    asyncio.create_task(run_checks_now(bot, str(user_id)))
    await safe_callback_answer(callback, "▶️ Запущена проверка доменов мониторинга; уведомления придут при изменениях.", show_alert=False)
    if callback.message:
        await callback.message.answer("▶️ Запущена проверка всех доменов. Уведомления придут при обнаружении изменений.")


# --- Back to main monitoring ---
@router.callback_query(F.data == "monitor_back")
async def monitor_back(callback: types.CallbackQuery):
    """Возврат к главному экрану мониторинга."""
    user_id = callback.from_user.id
    if not has_access(user_id) or not has_permission(user_id, "monitoring"):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    enabled = await is_monitoring_enabled(user_id)
    interval = await get_monitoring_interval(user_id)
    domains = await get_monitored_domains(user_id)
    text = (
        f"📊 <b>Мониторинг доменов</b>\n\n"
        f"Статус: {'✅ Включен' if enabled else '❌ Выключен'}\n"
        f"Интервал проверки: {interval} минут\n"
        f"Доменов в мониторинге: {len(domains)}\n\n"
        f"Используйте кнопки ниже для управления:"
    )
    try:
        await callback.message.edit_text(text, reply_markup=build_monitoring_keyboard(user_id))
    except Exception:
        await callback.message.answer(text, reply_markup=build_monitoring_keyboard(user_id))
    await safe_callback_answer(callback, "")


# --- Global panel (admin only) ---
@router.callback_query(F.data == "monitor_switch_global")
async def monitor_switch_global(callback: types.CallbackQuery):
    """Открывает глобальную панель мониторинга (только админ)."""
    user_id = callback.from_user.id
    if not is_admin_user(user_id):
        await safe_callback_answer(callback, "❌ Только для администратора", show_alert=True)
        return
    enabled = await is_monitoring_enabled(0, scope="global")
    interval = await get_monitoring_interval(0, scope="global")
    domains = await get_monitored_domains(0, scope="global")
    chat_id = get_notification_chat_id_global()
    text = (
        f"🌐 <b>Глобальная панель мониторинга</b>\n\n"
        f"Статус: {'✅ Включен' if enabled else '❌ Выключен'}\n"
        f"Интервал: {interval} мин\n"
        f"Доменов: {len(domains)}\n"
        f"Чат уведомлений: {f'ID {chat_id}' if chat_id else 'не задан'}\n\n"
        f"Управление кнопками ниже:"
    )
    try:
        await callback.message.edit_text(text, reply_markup=build_monitoring_global_keyboard())
    except Exception:
        await callback.message.answer(text, reply_markup=build_monitoring_global_keyboard())
    await safe_callback_answer(callback, "")


@router.callback_query(F.data == "monitor_global_add")
async def monitor_global_add(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin_user(callback.from_user.id):
        await safe_callback_answer(callback, "❌ Только для администратора", show_alert=True)
        return
    await state.set_state(MonitoringStates.add_domain_waiting)
    await state.update_data(monitor_scope="global")
    await callback.message.answer(
        "📝 Введите домен(ы) для добавления в <b>глобальную</b> панель мониторинга.\n\n"
        "Можно несколько через пробел, запятую или с новой строки."
    )
    await safe_callback_answer(callback, "")


@router.callback_query(F.data == "monitor_global_remove")
async def monitor_global_remove(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin_user(callback.from_user.id):
        await safe_callback_answer(callback, "❌ Только для администратора", show_alert=True)
        return
    await state.set_state(MonitoringStates.remove_domain_waiting)
    await state.update_data(monitor_scope="global")
    await callback.message.answer("🗑️ Введите домен(ы) для удаления из <b>глобальной</b> панели мониторинга.")
    await safe_callback_answer(callback, "")


@router.callback_query(F.data == "monitor_global_list")
async def monitor_global_list(callback: types.CallbackQuery):
    if not is_admin_user(callback.from_user.id):
        await safe_callback_answer(callback, "❌ Только для администратора", show_alert=True)
        return
    domains = await get_monitored_domains(0, scope="global")
    if not domains:
        await callback.message.answer("📋 В глобальной панели нет доменов")
    else:
        await callback.message.answer("📋 <b>Глобальная панель — домены:</b>\n\n" + "\n".join(f"• {d}" for d in domains))
    await safe_callback_answer(callback, "")


@router.callback_query(F.data == "monitor_global_export")
async def monitor_global_export(callback: types.CallbackQuery):
    if not is_admin_user(callback.from_user.id):
        await safe_callback_answer(callback, "❌ Только для администратора", show_alert=True)
        return
    domains = await get_monitored_domains(0, scope="global")
    if not domains:
        await safe_callback_answer(callback, "📋 Нет доменов для экспорта", show_alert=True)
        return
    domains_text = "\n".join(domains)
    fname = f"global_monitored_domains_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        await callback.message.answer_document(
            types.BufferedInputFile(domains_text.encode("utf-8"), filename=fname),
            caption=f"📥 Экспорт глобальной панели ({len(domains)} доменов)",
        )
        await safe_callback_answer(callback, "✅ Экспорт выполнен")
    except Exception as e:
        logger.error(f"Ошибка экспорта глобальной панели: {e}", exc_info=True)
        await safe_callback_answer(callback, "❌ Ошибка экспорта", show_alert=True)


@router.callback_query(F.data == "monitor_global_interval")
async def monitor_global_interval(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin_user(callback.from_user.id):
        await safe_callback_answer(callback, "❌ Только для администратора", show_alert=True)
        return
    await state.set_state(MonitoringStates.set_interval_waiting)
    await state.update_data(monitor_scope="global")
    current = await get_monitoring_interval(0, scope="global")
    await callback.message.answer(f"⏱️ Введите интервал в минутах для глобальной панели (текущий: {current} мин).")
    await safe_callback_answer(callback, "")


@router.callback_query(F.data == "monitor_global_waf_timeout")
async def monitor_global_waf_timeout(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin_user(callback.from_user.id):
        await safe_callback_answer(callback, "❌ Только для администратора", show_alert=True)
        return
    await state.set_state(MonitoringStates.set_waf_timeout_waiting)
    await state.update_data(monitor_scope="global")
    current = get_waf_timeout(0)
    txt = f"{current} сек" if current else "не установлен"
    await callback.message.answer(f"⚙️ Введите таймаут WAF в секундах для глобальной панели (текущий: {txt}).")
    await safe_callback_answer(callback, "")


@router.callback_query(F.data == "monitor_global_toggle")
async def monitor_global_toggle(callback: types.CallbackQuery):
    if not is_admin_user(callback.from_user.id):
        await safe_callback_answer(callback, "❌ Только для администратора", show_alert=True)
        return
    current = await is_monitoring_enabled(0, scope="global")
    await set_monitoring_enabled(0, not current, scope="global")
    new_state = "включен" if not current else "выключен"
    await safe_callback_answer(callback, f"✅ Глобальный мониторинг {new_state}")


@router.callback_query(F.data == "monitor_run_now_global")
async def monitor_run_now_global(callback: types.CallbackQuery):
    if not is_admin_user(callback.from_user.id):
        await safe_callback_answer(callback, "❌ Только для администратора", show_alert=True)
        return
    domains = await get_monitored_domains(0, scope="global")
    if not domains:
        await safe_callback_answer(callback, "📋 Нет доменов в глобальной панели для проверки", show_alert=True)
        return
    bot = callback.bot or (callback.message.bot if callback.message else None)
    if not bot:
        await safe_callback_answer(callback, "❌ Бот недоступен", show_alert=True)
        return
    asyncio.create_task(run_checks_now(bot, "global"))
    await safe_callback_answer(callback, "▶️ Запущена проверка глобальной панели.", show_alert=False)
    if callback.message:
        await callback.message.answer("▶️ Запущена проверка глобальной панели. Уведомления придут при изменениях.")


@router.callback_query(F.data == "monitor_global_chat")
async def monitor_global_chat(callback: types.CallbackQuery, state: FSMContext):
    if not is_admin_user(callback.from_user.id):
        await safe_callback_answer(callback, "❌ Только для администратора", show_alert=True)
        return
    await state.set_state(MonitoringStates.set_global_chat_waiting)
    current = get_notification_chat_id_global()
    await callback.message.answer(
        f"💬 Введите ID чата для уведомлений глобальной панели (число).\n"
        f"Текущий: {current if current is not None else 'не задан'}.\n"
        f"Для супергруппы — отрицательный ID (например -100…)."
    )
    await safe_callback_answer(callback, "")


@router.message(MonitoringStates.set_global_chat_waiting)
async def process_global_chat_id(message: types.Message, state: FSMContext):
    if not is_admin_user(message.from_user.id):
        await state.clear()
        return
    text = (message.text or "").strip()
    try:
        chat_id = int(text)
        set_notification_chat_id_global(chat_id)
        await message.answer(f"✅ Чат для уведомлений глобальной панели установлен: {chat_id}")
    except ValueError:
        await message.answer("❌ Введите число (ID чата). Для супергруппы — отрицательное число.")
    await state.clear()


# --- Admin: list and view other users' panels ---
@router.callback_query(F.data == "monitor_admin_panels")
async def monitor_admin_panels(callback: types.CallbackQuery):
    """Список панелей мониторинга (владельцы + глобальная) для админа."""
    user_id = callback.from_user.id
    if not is_admin_user(user_id):
        await safe_callback_answer(callback, "❌ Только для администратора", show_alert=True)
        return
    keys = await get_monitoring_owner_keys()
    if not keys:
        await safe_callback_answer(callback, "Нет ни одной панели в мониторинге", show_alert=True)
        return
    keyboard = []
    for k in sorted(keys, key=lambda x: (x == "global", x)):
        label = "🌐 Общая панель" if k == "global" else f"👤 {k}"
        keyboard.append([types.InlineKeyboardButton(text=label, callback_data=f"monitor_admin_select_{k}")])
    markup = types.InlineKeyboardMarkup(inline_keyboard=keyboard)
    text = "👥 Выберите панель для просмотра/редактирования:"
    try:
        await callback.message.edit_text(text, reply_markup=markup)
    except Exception:
        await callback.message.answer(text, reply_markup=markup)
    await safe_callback_answer(callback, "")


@router.callback_query(F.data.startswith("monitor_admin_select_"))
async def monitor_admin_select(callback: types.CallbackQuery):
    """Открывает выбранную панель (пользователь или глобальная) для админа."""
    user_id = callback.from_user.id
    if not is_admin_user(user_id):
        await safe_callback_answer(callback, "❌ Только для администратора", show_alert=True)
        return
    owner_key = callback.data.replace("monitor_admin_select_", "", 1)
    if not owner_key:
        await safe_callback_answer(callback, "❌ Ошибка", show_alert=True)
        return
    scope = "global" if owner_key == "global" else "user"
    try:
        uid = 0 if scope == "global" else int(owner_key)
    except ValueError:
        await safe_callback_answer(callback, "❌ Неверный ключ панели", show_alert=True)
        return
    enabled = await is_monitoring_enabled(uid, scope=scope)
    interval = await get_monitoring_interval(uid, scope=scope)
    domains = await get_monitored_domains(uid, scope=scope)
    title = "🌐 Глобальная панель" if owner_key == "global" else f"👤 Панель {owner_key}"
    text = (
        f"{title}\n\n"
        f"Статус: {'✅ Включен' if enabled else '❌ Выключен'}\n"
        f"Интервал: {interval} мин\n"
        f"Доменов: {len(domains)}\n\n"
        f"Управление кнопками ниже:"
    )
    try:
        await callback.message.edit_text(text, reply_markup=build_monitoring_admin_panel_keyboard(owner_key))
    except Exception:
        await callback.message.answer(text, reply_markup=build_monitoring_admin_panel_keyboard(owner_key))
    await safe_callback_answer(callback, "")


def _parse_admin_panel_action(data: str) -> tuple[str, str] | None:
    """Разбирает callback_data вида monitor_admin_<owner_key>_<action>. Возвращает (owner_key, action) или None."""
    if not data.startswith("monitor_admin_") or data == "monitor_admin_panels":
        return None
    rest = data[len("monitor_admin_"):]
    if rest.endswith("_run_now"):
        owner_key = rest[:-len("_run_now")]
        return (owner_key, "run_now")
    parts = rest.rsplit("_", 1)
    if len(parts) != 2:
        return None
    return (parts[0], parts[1])


@router.callback_query(F.data.startswith("monitor_admin_"))
async def monitor_admin_panel_action(callback: types.CallbackQuery, state: FSMContext):
    """Обработка действий админа над выбранной панелью: add, remove, list, export, interval, waf_timeout, toggle, run_now."""
    user_id = callback.from_user.id
    if not is_admin_user(user_id):
        await safe_callback_answer(callback, "❌ Только для администратора", show_alert=True)
        return
    parsed = _parse_admin_panel_action(callback.data)
    if not parsed:
        return
    owner_key, action = parsed
    scope = "global" if owner_key == "global" else "user"
    try:
        uid = 0 if scope == "global" else int(owner_key)
    except ValueError:
        await safe_callback_answer(callback, "❌ Неверный ключ панели", show_alert=True)
        return
    bot = callback.bot or (callback.message.bot if callback.message else None)

    if action == "add":
        await state.set_state(MonitoringStates.add_domain_waiting)
        await state.update_data(monitor_scope="admin", monitor_owner_key=owner_key)
        await callback.message.answer(f"📝 Введите домен(ы) для добавления в панель {owner_key}.")
        await safe_callback_answer(callback, "")
        return
    if action == "remove":
        await state.set_state(MonitoringStates.remove_domain_waiting)
        await state.update_data(monitor_scope="admin", monitor_owner_key=owner_key)
        await callback.message.answer(f"🗑️ Введите домен(ы) для удаления из панели {owner_key}.")
        await safe_callback_answer(callback, "")
        return
    if action == "list":
        domains = await get_monitored_domains(uid, scope=scope)
        if not domains:
            await callback.message.answer(f"📋 В панели {owner_key} нет доменов")
        else:
            await callback.message.answer("📋 <b>Домены:</b>\n\n" + "\n".join(f"• {d}" for d in domains))
        await safe_callback_answer(callback, "")
        return
    if action == "export":
        domains = await get_monitored_domains(uid, scope=scope)
        if not domains:
            await safe_callback_answer(callback, "Нет доменов для экспорта", show_alert=True)
            return
        fname = f"monitored_{owner_key}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            await callback.message.answer_document(
                types.BufferedInputFile("\n".join(domains).encode("utf-8"), filename=fname),
                caption=f"📥 Экспорт панели {owner_key} ({len(domains)} доменов)",
            )
            await safe_callback_answer(callback, "✅ Экспорт выполнен")
        except Exception as e:
            logger.error(f"Ошибка экспорта панели {owner_key}: {e}", exc_info=True)
            await safe_callback_answer(callback, "❌ Ошибка экспорта", show_alert=True)
        return
    if action == "interval":
        await state.set_state(MonitoringStates.set_interval_waiting)
        await state.update_data(monitor_scope="admin", monitor_owner_key=owner_key)
        current = await get_monitoring_interval(uid, scope=scope)
        await callback.message.answer(f"⏱️ Введите интервал в минутах для панели {owner_key} (текущий: {current} мин).")
        await safe_callback_answer(callback, "")
        return
    if action == "waf_timeout":
        await state.set_state(MonitoringStates.set_waf_timeout_waiting)
        await state.update_data(monitor_scope="admin", monitor_owner_key=owner_key)
        current = get_waf_timeout(uid)
        txt = f"{current} сек" if current else "не установлен"
        await callback.message.answer(f"⚙️ Введите таймаут WAF в секундах для панели {owner_key} (текущий: {txt}).")
        await safe_callback_answer(callback, "")
        return
    if action == "toggle":
        current = await is_monitoring_enabled(uid, scope=scope)
        await set_monitoring_enabled(uid, not current, scope=scope)
        new_state = "включен" if not current else "выключен"
        await safe_callback_answer(callback, f"✅ Мониторинг панели {owner_key} {new_state}")
        return
    if action == "run_now":
        domains = await get_monitored_domains(uid, scope=scope)
        if not domains:
            await safe_callback_answer(callback, "Нет доменов для проверки", show_alert=True)
            return
        if not bot:
            await safe_callback_answer(callback, "❌ Бот недоступен", show_alert=True)
            return
        asyncio.create_task(run_checks_now(bot, owner_key))
        await safe_callback_answer(callback, f"▶️ Запущена проверка панели {owner_key}.", show_alert=False)
        if callback.message:
            await callback.message.answer(f"▶️ Запущена проверка панели {owner_key}. Уведомления придут при изменениях.")
        return
