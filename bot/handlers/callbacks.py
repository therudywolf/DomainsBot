"""
Обработчики callback query для бота.

Содержит все обработчики inline-кнопок: переключение режимов,
быстрые проверки, детальные просмотры, экспорт статистики,
настройки и catch-all для необработанных callback.
"""

import asyncio
import csv
import io
import json
import logging
import re
from datetime import datetime
from typing import Optional

from aiogram import F, Router, types
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.fsm.context import FSMContext

from config import settings

from access import (
    has_access,
    has_permission,
    check_access,
    ADMIN_ID,
    PERMISSIONS,
    get_bot_username,
    AdminStates,
    MonitoringStates,
    ChatSettingsStates,
)

from keyboards import (
    build_mode_keyboard,
    build_waf_mode_keyboard,
    build_settings_keyboard,
    build_main_menu_keyboard,
    build_access_denied_keyboard,
    DEFAULT_MODE,
)

from utils.dns_utils import fetch_dns
from utils.ssl_utils import fetch_ssl
from utils.waf_utils import test_waf
from utils.waf_injection_check import test_waf_injection
from utils.formatting import build_report, build_report_keyboard
from utils.prefs import get_mode, set_mode, get_waf_mode, set_waf_mode
from utils.stats import record_domain_check
from utils.history import add_check_result
from utils.chat_settings import (
    register_chat,
    get_notification_chat_id,
    set_notification_chat_id,
    get_known_chats,
)

logger = logging.getLogger(__name__)

router = Router()


# ---------- Вспомогательные функции ----------

async def safe_callback_answer(
    callback: types.CallbackQuery,
    text: str,
    show_alert: bool = False
) -> bool:
    """
    Безопасно отвечает на callback query, обрабатывая ошибки устаревших запросов.
    
    Args:
        callback: Callback query объект
        text: Текст ответа
        show_alert: Показывать ли alert вместо уведомления
        
    Returns:
        True если ответ успешно отправлен, False если callback устарел или произошла ошибка
    """
    try:
        await callback.answer(text, show_alert=show_alert)
        return True
    except TelegramBadRequest as e:
        error_message = str(e).lower()
        if "query is too old" in error_message or "timeout expired" in error_message or "query id is invalid" in error_message:
            logger.debug(
                f"⚠️ Callback query устарел (это нормально) | "
                f"user_id={callback.from_user.id if callback.from_user else None} | "
                f"callback_data={callback.data or 'N/A'}"
            )
            return False
        else:
            logger.warning(
                f"⚠️ Ошибка при ответе на callback query | "
                f"user_id={callback.from_user.id if callback.from_user else None} | "
                f"callback_data={callback.data or 'N/A'} | "
                f"error={type(e).__name__}: {str(e)}"
            )
            return False
    except Exception as e:
        logger.warning(
            f"⚠️ Неожиданная ошибка при ответе на callback query | "
            f"user_id={callback.from_user.id if callback.from_user else None} | "
            f"callback_data={callback.data or 'N/A'} | "
            f"error={type(e).__name__}: {str(e)}"
        )
        return False


# ---------- Переключение режима отчета ----------

@router.callback_query(F.data.in_({"mode_full", "mode_brief"}))
async def switch_mode(callback: types.CallbackQuery, state: FSMContext):
    """Переключает режим отчета (расширенный/короткий)."""
    start_time = asyncio.get_running_loop().time()
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
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на настройки
    if not has_permission(user_id, "settings"):
        logger.warning(f"❌ Нет разрешения на настройки для user_id={user_id} при переключении режима")
        await safe_callback_answer(callback, "❌ Нет доступа к настройкам", show_alert=True)
        return
    
    new_mode = "full" if callback.data == "mode_full" else "brief"
    logger.debug(f"Установка режима {new_mode} для user_id={user_id}")
    
    await state.update_data(view_mode=new_mode)
    set_mode(user_id, new_mode)

    await safe_callback_answer(
        callback,
        f"Режим установлен: {'Расширенный' if new_mode == 'full' else 'Короткий'}"
    )
    
    logger.debug(f"Режим {new_mode} установлен для user_id={user_id}")

    # Пытаемся найти домен и обновить отчет
    try:
        message_text = callback.message.text or callback.message.caption or ""
        domain = None
        
        logger.debug(f"Поиск домена в сообщении для user_id={user_id}, режим={new_mode}")
        
        # Способ 1: Ищем домен в тексте сообщения
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
                await _recheck_domain(callback.message, state, domain, new_mode, requester_id=user_id)
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
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    # Проверка разрешения на настройки
    if not has_permission(user_id, "settings"):
        await safe_callback_answer(callback, "❌ Нет доступа к настройкам", show_alert=True)
        return
    
    new_mode = "policy" if callback.data == "waf_mode_policy" else "light"
    set_waf_mode(user_id, new_mode)

    await safe_callback_answer(
        callback,
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
    mode: Optional[str] = None,
    requester_id: Optional[int] = None,
) -> None:
    """
    Перепроверяет один домен и обновляет отчет.
    
    Args:
        message: Сообщение для обновления
        state: Состояние FSM
        domain: Домен для перепроверки
        mode: Режим отчета (если None, берется из state)
        requester_id: ID пользователя, запросившего перепроверку
    """
    start_time = asyncio.get_running_loop().time()
    user_id = requester_id or (message.from_user.id if message.from_user else 0)
    
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
        check_start = asyncio.get_running_loop().time()
        logger.debug(f"Начало проверки домена {domain}")
        
        dns_info, ssl_info, waf_result = await asyncio.gather(
            fetch_dns(domain, settings.DNS_TIMEOUT),
            fetch_ssl(domain),
            test_waf(domain, user_id=user_id),
            return_exceptions=True
        )
        
        check_duration = asyncio.get_running_loop().time() - check_start
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
        
        total_duration = asyncio.get_running_loop().time() - start_time
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
        duration = asyncio.get_running_loop().time() - start_time
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
    start_time = asyncio.get_running_loop().time()
    user_id = callback.from_user.id
    
    logger.info(
        f"🔄 Запрос на перепроверку домена | "
        f"user_id={user_id} | "
        f"callback_data={callback.data}"
    )
    
    if not has_access(user_id):
        logger.warning(f"❌ Доступ запрещен для user_id={user_id} при перепроверке")
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    if not has_permission(user_id, "check_domains"):
        logger.warning(f"❌ Нет разрешения на проверку доменов для user_id={user_id}")
        await safe_callback_answer(callback, "❌ Нет доступа к проверке доменов", show_alert=True)
        return
    
    # Извлекаем домен из callback_data
    domain = callback.data.replace("recheck_", "")
    logger.debug(f"Перепроверка домена {domain} для user_id={user_id}")
    
    await safe_callback_answer(callback, "🔄 Перепроверяю домен...")
    
    try:
        await _recheck_domain(callback.message, state, domain, requester_id=user_id)
        duration = asyncio.get_running_loop().time() - start_time
        logger.info(
            f"✅ Перепроверка завершена | "
            f"domain={domain} | "
            f"user_id={user_id} | "
            f"duration={duration:.2f}s"
        )
    except Exception as e:
        duration = asyncio.get_running_loop().time() - start_time
        logger.error(
            f"❌ Ошибка при перепроверке | "
            f"domain={domain} | "
            f"user_id={user_id} | "
            f"duration={duration:.2f}s | "
            f"error={type(e).__name__}: {str(e)}",
            exc_info=True
        )
        await safe_callback_answer(callback, "❌ Ошибка при перепроверке домена", show_alert=True)


@router.callback_query(F.data.startswith("quick_waf_"))
async def quick_waf_check(callback: types.CallbackQuery, state: FSMContext):
    """
    Быстрая проверка WAF для домена через отправку тестовой инъекции.
    
    Использует специальную проверку с инъекциями для гарантированного получения 403,
    если WAF присутствует.
    """
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    if not has_permission(user_id, "check_domains"):
        await safe_callback_answer(callback, "❌ Нет доступа к проверке доменов", show_alert=True)
        return
    
    # Извлекаем домен
    domain = callback.data.replace("quick_waf_", "")
    
    await safe_callback_answer(callback, "🛡️ Проверяю WAF через инъекцию...")
    
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
        
        await safe_callback_answer(callback, result_msg, show_alert=True)
        
    except Exception as e:
        logger.error(f"Ошибка при проверке WAF для {domain}: {e}", exc_info=True)
        await safe_callback_answer(callback, "❌ Ошибка при проверке WAF", show_alert=True)


@router.callback_query(F.data.startswith("quick_certs_"))
async def quick_certs_check(callback: types.CallbackQuery, state: FSMContext):
    """Быстрая проверка сертификатов для домена."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    if not has_permission(user_id, "check_domains"):
        await safe_callback_answer(callback, "❌ Нет доступа к проверке доменов", show_alert=True)
        return
    
    # Извлекаем домен
    domain = callback.data.replace("quick_certs_", "")
    
    await safe_callback_answer(callback, "📅 Проверяю сертификаты...")
    
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
            await safe_callback_answer(callback, "✅ Сертификаты проверены\n" + "\n".join(cert_info), show_alert=True)
        else:
            await safe_callback_answer(callback, "✅ Сертификаты проверены")
        
    except Exception as e:
        logger.error(f"Ошибка при проверке сертификатов для {domain}: {e}", exc_info=True)
        await safe_callback_answer(callback, "❌ Ошибка при проверке сертификатов", show_alert=True)


# ---------- Детальный просмотр блоков ----------

@router.callback_query(F.data.startswith("detail_dns_"))
async def show_dns_details(callback: types.CallbackQuery):
    """Показывает детальную информацию о DNS записях."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    # Извлекаем домен
    domain = callback.data.replace("detail_dns_", "")
    
    await safe_callback_answer(callback, "📡 Загружаю DNS записи...")
    
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
        await safe_callback_answer(callback, "❌ Ошибка при получении DNS информации", show_alert=True)


@router.callback_query(F.data.startswith("detail_ssl_"))
async def show_ssl_details(callback: types.CallbackQuery):
    """Показывает детальную информацию о SSL сертификатах."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    # Извлекаем домен
    domain = callback.data.replace("detail_ssl_", "")
    
    await safe_callback_answer(callback, "🔒 Загружаю информацию о сертификатах...")
    
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
        await safe_callback_answer(callback, "❌ Ошибка при получении SSL информации", show_alert=True)


@router.callback_query(F.data.startswith("detail_waf_"))
async def show_waf_details(callback: types.CallbackQuery):
    """Показывает детальную информацию о WAF."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    if not has_permission(user_id, "check_domains"):
        await safe_callback_answer(callback, "❌ Нет доступа к проверке WAF", show_alert=True)
        return
    
    # Извлекаем домен
    domain = callback.data.replace("detail_waf_", "")
    
    await safe_callback_answer(callback, "🛡️ Проверяю WAF...")
    
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
        await safe_callback_answer(callback, "❌ Ошибка при проверке WAF", show_alert=True)


# ---------- Экспорт статистики ----------

@router.callback_query(F.data == "stats_export_json")
async def stats_export_json(callback: types.CallbackQuery):
    """Экспортирует статистику в JSON."""
    user_id = callback.from_user.id
    
    if user_id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return
    
    try:
        from utils.stats import get_stats
        stats = get_stats()
        
        json_data = json.dumps(stats, ensure_ascii=False, indent=2, default=str)
        json_file = io.BytesIO(json_data.encode('utf-8'))
        json_file.name = f"stats_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        await callback.message.answer_document(
            types.BufferedInputFile(json_data.encode('utf-8'), filename=json_file.name),
            caption="📥 Экспорт статистики в JSON"
        )
        await safe_callback_answer(callback, "✅ Статистика экспортирована в JSON")
    except Exception as e:
        logger.error(f"Ошибка при экспорте статистики в JSON: {e}", exc_info=True)
        await safe_callback_answer(callback, "❌ Ошибка при экспорте", show_alert=True)


@router.callback_query(F.data == "stats_export_csv")
async def stats_export_csv(callback: types.CallbackQuery):
    """Экспортирует статистику в CSV."""
    user_id = callback.from_user.id
    
    if user_id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return
    
    try:
        from utils.stats import get_stats
        stats = get_stats()
        
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
            types.BufferedInputFile(csv_data, filename=csv_file.name),
            caption="📊 Экспорт статистики в CSV"
        )
        await safe_callback_answer(callback, "✅ Статистика экспортирована в CSV")
    except Exception as e:
        logger.error(f"Ошибка при экспорте статистики в CSV: {e}", exc_info=True)
        await safe_callback_answer(callback, "❌ Ошибка при экспорте", show_alert=True)


# ---------- Главное меню и настройки ----------

@router.callback_query(F.data == "main_menu")
async def main_menu_callback(callback: types.CallbackQuery, state: FSMContext):
    """Обработчик кнопки 'Главное меню'."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
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
    
    await safe_callback_answer(callback, "")


@router.callback_query(F.data == "settings_report_mode")
async def settings_report_mode_callback(callback: types.CallbackQuery):
    """Обработчик кнопки настроек режима отчета."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    current_mode = get_mode(user_id, DEFAULT_MODE)
    mode_text = "Расширенный" if current_mode == "full" else "Короткий"
    
    await safe_callback_answer(callback, 
        f"Текущий режим: {mode_text}. Используйте кнопки ниже для изменения.",
        show_alert=False
    )


@router.callback_query(F.data == "settings_waf_mode")
async def settings_waf_mode_callback(callback: types.CallbackQuery):
    """Обработчик кнопки настроек режима WAF."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
        return
    
    current_mode = get_waf_mode(user_id, "policy")
    mode_text = "Policy-based" if current_mode == "policy" else "Light check"
    
    await safe_callback_answer(callback, 
        f"Текущий режим WAF: {mode_text}. Используйте кнопки ниже для изменения.",
        show_alert=False
    )


# ---------- Настройки чата для уведомлений ----------

@router.callback_query(F.data == "settings_notification_chat")
async def settings_notification_chat(callback: types.CallbackQuery):
    """Показывает меню настройки чата для уведомлений."""
    user_id = callback.from_user.id
    
    if not has_access(user_id):
        await safe_callback_answer(callback, "❌ Нет доступа", show_alert=True)
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
        await safe_callback_answer(callback, "")
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
    await safe_callback_answer(callback, "")


@router.callback_query(F.data.startswith("notification_chat_select_"))
async def select_notification_chat(callback: types.CallbackQuery):
    """Выбирает чат для уведомлений из списка."""
    user_id = callback.from_user.id
    chat_id_str = callback.data.replace("notification_chat_select_", "")
    
    try:
        chat_id = int(chat_id_str)
        
        # Проверяем, что чат существует в списке известных чатов
        known_chats = get_known_chats(user_id)
        selected_chat = next((c for c in known_chats if c.get("chat_id") == chat_id), None)
        
        if not selected_chat:
            await safe_callback_answer(callback, "❌ Чат не найден в списке. Попробуйте добавить бота в чат и отправить сообщение.", show_alert=True)
            return
        
        # Проверяем доступность чата через API Telegram
        bot = callback.message.bot if callback.message else callback.bot
        if bot:
            try:
                chat_info = await bot.get_chat(chat_id)
                set_notification_chat_id(user_id, chat_id)
                chat_name = chat_info.title if hasattr(chat_info, 'title') and chat_info.title else selected_chat.get("title", f"Chat {chat_id}")
                await safe_callback_answer(callback, f"✅ Чат '{chat_name}' выбран для уведомлений")
                await settings_notification_chat(callback)
            except Exception as e:
                logger.warning(f"Не удалось получить информацию о чате {chat_id}: {e}")
                set_notification_chat_id(user_id, chat_id)
                chat_name = selected_chat.get("title", f"Chat {chat_id}")
                await safe_callback_answer(callback, f"✅ Чат '{chat_name}' выбран для уведомлений (проверка через API не удалась)")
                await settings_notification_chat(callback)
        else:
            set_notification_chat_id(user_id, chat_id)
            chat_name = selected_chat.get("title", f"Chat {chat_id}")
            await safe_callback_answer(callback, f"✅ Чат '{chat_name}' выбран для уведомлений")
            await settings_notification_chat(callback)
    except ValueError:
        await safe_callback_answer(callback, "❌ Неверный ID чата", show_alert=True)


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
    await safe_callback_answer(callback, "")


@router.message(ChatSettingsStates.waiting_chat_id)
async def process_chat_id(message: types.Message, state: FSMContext):
    """Обрабатывает введенный ID чата."""
    user_id = message.from_user.id
    text = (message.text or "").strip()
    
    try:
        chat_id = int(text)
    except ValueError:
        await message.answer("❌ Неверный формат ID. Отправьте число.")
        return
    
    try:
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
    await safe_callback_answer(callback, "✅ Уведомления будут отправляться в личные сообщения")
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
    await safe_callback_answer(callback, "")


# ---------- Catch-all для необработанных callback ----------

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
        await safe_callback_answer(callback, "❓ Неизвестная команда", show_alert=False)
    except Exception as e:
        logger.error(
            f"❌ Ошибка при ответе на необработанный callback | "
            f"user_id={user_id} | "
            f"callback_data={callback_data} | "
            f"error={type(e).__name__}: {str(e)}",
            exc_info=True
        )
