"""
Система мониторинга доменов.

Отслеживает изменения в:
- GOST сертификатах
- WAF статусе
- Датах сертификатов
- DNS записях

Отправляет уведомления пользователям при обнаружении изменений.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Literal

from aiogram import Bot

from utils.dns_utils import fetch_dns
from utils.ssl_utils import fetch_ssl
from utils.waf_utils import test_waf
from utils.file_utils import async_read_json, async_write_json
from utils.chat_settings import get_notification_chat_id
from config import settings

logger = logging.getLogger(__name__)

# Путь к БД мониторинга
MONITORING_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "monitoring_db.json"
MONITORING_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Единая async блокировка для всех операций с БД мониторинга
_monitoring_async_lock = asyncio.Lock()

# Глобальная переменная для фоновой задачи
_monitoring_task: Optional[asyncio.Task] = None

# Максимальное количество сохраненных состояний для каждого домена
MAX_STATE_HISTORY = 10


async def _load_monitoring_db() -> Dict[str, Any]:
    """Асинхронно загружает БД мониторинга из файла."""
    return await async_read_json(MONITORING_DB_PATH, {})


async def _save_monitoring_db(data: Dict[str, Any]) -> None:
    """Асинхронно сохраняет БД мониторинга в файл."""
    await async_write_json(MONITORING_DB_PATH, data)


def _owner_key(user_id: int, scope: Literal["user", "global"]) -> str:
    """Возвращает ключ владельца панели в БД."""
    return "global" if scope == "global" else str(user_id)


async def add_domain_to_monitoring(user_id: int, domain: str, scope: Literal["user", "global"] = "user") -> bool:
    """Добавляет домен в мониторинг для пользователя или общей панели.
    
    Args:
        user_id: ID пользователя (для scope=user)
        domain: Домен для мониторинга
        scope: "user" — личная панель, "global" — общая панель
        
    Returns:
        True если домен добавлен, False если уже был в мониторинге
    """
    async with _monitoring_async_lock:
        db = await _load_monitoring_db()
        
        user_key = _owner_key(user_id, scope)
        if user_key not in db:
            db[user_key] = {
                "domains": {},
                "enabled": True,
                "interval_minutes": 15,
            }
        
        if domain not in db[user_key]["domains"]:
            db[user_key]["domains"][domain] = {
                "added_at": datetime.now().isoformat(),
                "last_check": None,
                "last_state": None,
                "state_history": [],
            }
            await _save_monitoring_db(db)
            logger.info(f"Домен {domain} добавлен в мониторинг ({scope}: {user_key})")
            return True
        
        return False


async def remove_domain_from_monitoring(user_id: int, domain: str, scope: Literal["user", "global"] = "user") -> bool:
    """Удаляет домен из мониторинга пользователя или общей панели.
    
    Args:
        user_id: ID пользователя (для scope=user)
        domain: Домен для удаления
        scope: "user" или "global"
        
    Returns:
        True если домен был удален, False если его не было
    """
    async with _monitoring_async_lock:
        db = await _load_monitoring_db()
        
        user_key = _owner_key(user_id, scope)
        if user_key in db and domain in db[user_key]["domains"]:
            del db[user_key]["domains"][domain]
            await _save_monitoring_db(db)
            logger.info(f"Домен {domain} удален из мониторинга ({scope}: {user_key})")
            return True
        
        return False


async def get_monitored_domains(user_id: int, scope: Literal["user", "global"] = "user") -> List[str]:
    """Получает список доменов в мониторинге для пользователя или общей панели.
    
    Args:
        user_id: ID пользователя (для scope=user)
        scope: "user" или "global"
        
    Returns:
        Список доменов
    """
    async with _monitoring_async_lock:
        db = await _load_monitoring_db()
        user_key = _owner_key(user_id, scope)
        if user_key in db:
            return list(db[user_key]["domains"].keys())
        return []


async def set_monitoring_interval(user_id: int, interval_minutes: int, scope: Literal["user", "global"] = "user") -> None:
    """Устанавливает интервал проверки для пользователя или общей панели."""
    async with _monitoring_async_lock:
        db = await _load_monitoring_db()
        user_key = _owner_key(user_id, scope)
        if user_key not in db:
            db[user_key] = {
                "domains": {},
                "enabled": True,
                "interval_minutes": interval_minutes,
            }
        else:
            db[user_key]["interval_minutes"] = interval_minutes
        await _save_monitoring_db(db)


async def get_monitoring_interval(user_id: int, scope: Literal["user", "global"] = "user") -> int:
    """Получает интервал проверки для пользователя или общей панели (по умолчанию 15 мин)."""
    async with _monitoring_async_lock:
        db = await _load_monitoring_db()
        user_key = _owner_key(user_id, scope)
        if user_key in db:
            return db[user_key].get("interval_minutes", 15)
        return 15


async def set_monitoring_enabled(user_id: int, enabled: bool, scope: Literal["user", "global"] = "user") -> None:
    """Включает/выключает мониторинг для пользователя или общей панели."""
    async with _monitoring_async_lock:
        db = await _load_monitoring_db()
        user_key = _owner_key(user_id, scope)
        if user_key not in db:
            db[user_key] = {
                "domains": {},
                "enabled": enabled,
                "interval_minutes": 15,
            }
        else:
            db[user_key]["enabled"] = enabled
        await _save_monitoring_db(db)


async def is_monitoring_enabled(user_id: int, scope: Literal["user", "global"] = "user") -> bool:
    """Проверяет, включен ли мониторинг для пользователя или общей панели."""
    async with _monitoring_async_lock:
        db = await _load_monitoring_db()
        user_key = _owner_key(user_id, scope)
        if user_key in db:
            return db[user_key].get("enabled", True)
        return True


async def get_monitoring_owner_keys() -> List[str]:
    """Возвращает список ключей владельцев в БД мониторинга (для админа: список панелей)."""
    async with _monitoring_async_lock:
        db = await _load_monitoring_db()
        return list(db.keys())


async def _get_domain_state(domain: str, user_id: int) -> Dict[str, Any]:
    """Получает текущее состояние домена.
    
    Args:
        domain: Домен для проверки
        user_id: ID пользователя (для настроек WAF)
        
    Returns:
        Словарь с текущим состоянием домена
    """
    try:
        # Запускаем проверки параллельно
        dns_info, ssl_info, waf_result = await asyncio.gather(
            fetch_dns(domain, settings.DNS_TIMEOUT),
            fetch_ssl(domain),
            test_waf(domain, user_id=user_id),
            return_exceptions=True
        )
        
        # Обрабатываем исключения (включая CancelledError, который является BaseException)
        if isinstance(dns_info, BaseException):
            logger.error(f"Ошибка DNS для {domain}: {dns_info}")
            dns_info = {}
        if isinstance(ssl_info, BaseException):
            logger.error(f"Ошибка SSL для {domain}: {ssl_info}")
            ssl_info = {}
        
        # Распаковка результата WAF: test_waf возвращает tuple[bool, str]
        if isinstance(waf_result, BaseException):
            logger.error(f"Ошибка WAF для {domain}: {waf_result}")
            waf_enabled = False
        elif isinstance(waf_result, tuple) and len(waf_result) == 2:
            waf_enabled, _ = waf_result
        else:
            waf_enabled = bool(waf_result)
        
        # Убеждаемся, что данные правильного типа
        if not isinstance(ssl_info, dict):
            ssl_info = {}
        if not isinstance(dns_info, dict):
            dns_info = {}
        
        return {
            "gost": ssl_info.get("gost", False) if isinstance(ssl_info, dict) else False,
            "waf": bool(waf_enabled),
            "cert_not_after": (
                ssl_info.get("NotAfter").isoformat() 
                if isinstance(ssl_info, dict) and ssl_info.get("NotAfter") 
                else None
            ),
            "gost_cert_not_after": (
                ssl_info.get("GostNotAfter").isoformat() 
                if isinstance(ssl_info, dict) and ssl_info.get("GostNotAfter") 
                else None
            ),
            "dns_a": sorted(dns_info.get("A", [])) if isinstance(dns_info, dict) else [],
            "dns_aaaa": sorted(dns_info.get("AAAA", [])) if isinstance(dns_info, dict) else [],
            "dns_mx": sorted(dns_info.get("MX", [])) if isinstance(dns_info, dict) else [],
            "dns_ns": sorted(dns_info.get("NS", [])) if isinstance(dns_info, dict) else [],
        }
    except Exception as e:
        logger.error(f"Ошибка при получении состояния домена {domain}: {e}", exc_info=True)
        return {}


def _compare_states(old_state: Optional[Dict[str, Any]], new_state: Dict[str, Any]) -> List[str]:
    """Сравнивает два состояния и возвращает список изменений.
    
    Args:
        old_state: Предыдущее состояние
        new_state: Новое состояние
        
    Returns:
        Список строк с описанием изменений
    """
    if old_state is None:
        return ["Домен добавлен в мониторинг"]
    
    changes = []
    
    # Проверка GOST
    old_gost = old_state.get("gost", False)
    new_gost = new_state.get("gost", False)
    if old_gost != new_gost:
        changes.append(f"GOST: {'Да' if old_gost else 'Нет'} → {'Да' if new_gost else 'Нет'}")
    
    # Проверка WAF
    old_waf = old_state.get("waf", False)
    new_waf = new_state.get("waf", False)
    if old_waf != new_waf:
        changes.append(f"WAF: {'Да' if old_waf else 'Нет'} → {'Да' if new_waf else 'Нет'}")
    
    # Проверка дат сертификатов с уведомлениями о приближающемся истечении
    old_cert_date = old_state.get("cert_not_after")
    new_cert_date = new_state.get("cert_not_after")
    if old_cert_date != new_cert_date:
        if new_cert_date:
            try:
                cert_date = datetime.fromisoformat(new_cert_date.replace('Z', '+00:00'))
                days_left = (cert_date - datetime.now(cert_date.tzinfo)).days
                # Уведомления за 30, 14, 7 дней до истечения
                if days_left <= 30 and days_left > 0:
                    if days_left <= 7:
                        changes.append(f"⚠️ СРОЧНО: Сертификат истекает через {days_left} дней!")
                    elif days_left <= 14:
                        changes.append(f"⚠️ ВНИМАНИЕ: Сертификат истекает через {days_left} дней")
                    else:
                        changes.append(f"📅 Сертификат истекает через {days_left} дней")
                elif days_left <= 0:
                    changes.append(f"❌ Сертификат истек!")
            except Exception:
                pass
    
    old_gost_cert_date = old_state.get("gost_cert_not_after")
    new_gost_cert_date = new_state.get("gost_cert_not_after")
    if old_gost_cert_date != new_gost_cert_date:
        if new_gost_cert_date:
            try:
                gost_cert_date = datetime.fromisoformat(new_gost_cert_date.replace('Z', '+00:00'))
                days_left = (gost_cert_date - datetime.now(gost_cert_date.tzinfo)).days
                # Уведомления за 30, 14, 7 дней до истечения
                if days_left <= 30 and days_left > 0:
                    if days_left <= 7:
                        changes.append(f"⚠️ СРОЧНО: GOST сертификат истекает через {days_left} дней!")
                    elif days_left <= 14:
                        changes.append(f"⚠️ ВНИМАНИЕ: GOST сертификат истекает через {days_left} дней")
                    else:
                        changes.append(f"📅 GOST сертификат истекает через {days_left} дней")
                elif days_left <= 0:
                    changes.append(f"❌ GOST сертификат истек!")
            except Exception:
                pass
    
    # Проверяем приближающееся истечение даже если дата не изменилась
    # (для периодических напоминаний)
    if new_cert_date:
        try:
            cert_date = datetime.fromisoformat(new_cert_date.replace('Z', '+00:00'))
            days_left = (cert_date - datetime.now(cert_date.tzinfo)).days
            # Отправляем напоминание если до истечения осталось 30, 14 или 7 дней
            if days_left in [30, 14, 7] and days_left > 0:
                if days_left <= 7:
                    changes.append(f"⚠️ НАПОМИНАНИЕ: Сертификат истекает через {days_left} дней!")
                elif days_left <= 14:
                    changes.append(f"⚠️ НАПОМИНАНИЕ: Сертификат истекает через {days_left} дней")
                else:
                    changes.append(f"📅 НАПОМИНАНИЕ: Сертификат истекает через {days_left} дней")
        except Exception:
            pass
    
    if new_gost_cert_date:
        try:
            gost_cert_date = datetime.fromisoformat(new_gost_cert_date.replace('Z', '+00:00'))
            days_left = (gost_cert_date - datetime.now(gost_cert_date.tzinfo)).days
            # Отправляем напоминание если до истечения осталось 30, 14 или 7 дней
            if days_left in [30, 14, 7] and days_left > 0:
                if days_left <= 7:
                    changes.append(f"⚠️ НАПОМИНАНИЕ: GOST сертификат истекает через {days_left} дней!")
                elif days_left <= 14:
                    changes.append(f"⚠️ НАПОМИНАНИЕ: GOST сертификат истекает через {days_left} дней")
                else:
                    changes.append(f"📅 НАПОМИНАНИЕ: GOST сертификат истекает через {days_left} дней")
        except Exception:
            pass
    
    # Проверка DNS
    for dns_type in ["dns_a", "dns_aaaa", "dns_mx", "dns_ns"]:
        old_dns = old_state.get(dns_type, [])
        new_dns = new_state.get(dns_type, [])
        if old_dns != new_dns:
            dns_name = dns_type.replace("dns_", "").upper()
            changes.append(f"DNS {dns_name} изменился")
    
    return changes


async def _check_domain(bot: Bot, owner_key: str, domain: str, notification_chat_id: Optional[int] = None) -> None:
    """Проверяет один домен и отправляет уведомления при изменениях.
    
    Args:
        bot: Экземпляр бота для отправки уведомлений
        owner_key: Ключ владельца панели в БД (str(user_id) или "global")
        domain: Домен для проверки
        notification_chat_id: Чат для уведомлений (если None, берётся из настроек)
    """
    user_id_for_prefs = int(owner_key) if owner_key != "global" else 0
    try:
        # Получаем текущее состояние
        new_state = await _get_domain_state(domain, user_id_for_prefs)
        
        if not new_state:
            logger.warning(f"Не удалось получить состояние для {domain}")
            return
        
        # Загружаем БД и сравниваем с предыдущим состоянием (async-safe)
        async with _monitoring_async_lock:
            db = await _load_monitoring_db()
            user_key = owner_key
            
            if user_key not in db or domain not in db[user_key]["domains"]:
                return
            
            domain_data = db[user_key]["domains"][domain]
            old_state = domain_data.get("last_state")
            changes = _compare_states(old_state, new_state)
            
            # Обновляем состояние
            domain_data["last_state"] = new_state
            domain_data["last_check"] = datetime.now().isoformat()
            
            # Добавляем в историю состояний
            state_history = domain_data.get("state_history", [])
            state_history.append({
                "timestamp": datetime.now().isoformat(),
                "state": new_state
            })
            
            # Ограничиваем размер истории (предотвращение утечек памяти)
            if len(state_history) > MAX_STATE_HISTORY:
                state_history = state_history[-MAX_STATE_HISTORY:]
            
            domain_data["state_history"] = state_history
            
            # Сохраняем БД (async-safe)
            await _save_monitoring_db(db)
        
        # Отправляем уведомления если есть изменения
        if changes:
            notification_text = f"🔔 Изменение для {domain}:\n" + "\n".join(f"• {c}" for c in changes)
            
            # Определяем чат для отправки уведомления
            target_chat_id = notification_chat_id
            if target_chat_id is None:
                try:
                    if owner_key == "global":
                        from utils.chat_settings import get_notification_chat_id_global
                        target_chat_id = get_notification_chat_id_global()
                    else:
                        target_chat_id = get_notification_chat_id(int(owner_key))
                except Exception:
                    target_chat_id = None
            
            # Если чат не настроен: для пользователя — в ЛС, для global — не отправляем
            dm_fallback_id = int(owner_key) if owner_key != "global" else None
            if target_chat_id is None and dm_fallback_id is not None:
                target_chat_id = dm_fallback_id
            
            if target_chat_id is None:
                logger.debug(f"Нет чата для уведомлений (панель {owner_key}), пропуск отправки")
                return
            
            try:
                await bot.send_message(target_chat_id, notification_text)
                logger.info(f"Отправлено уведомление в чат {target_chat_id} для панели {owner_key} (домен: {domain})")
            except Exception as e:
                error_msg = str(e).lower()
                # Проверяем, является ли ошибка связанной с недоступностью чата или правами бота
                is_chat_not_found = (
                    "chat not found" in error_msg or
                    "чат не найден" in error_msg or
                    "chat_id is empty" in error_msg or
                    "bad request: chat not found" in error_msg
                )
                is_forbidden_or_no_rights = (
                    "forbidden" in error_msg or
                    "bot is not a member" in error_msg or
                    "not a member of" in error_msg or
                    "not enough rights" in error_msg or
                    "have no rights" in error_msg or
                    "can't send" in error_msg or
                    "нет прав" in error_msg or
                    "недоступен" in error_msg
                )
                is_chat_unavailable = is_chat_not_found or is_forbidden_or_no_rights

                if is_chat_unavailable and (dm_fallback_id is None or target_chat_id != dm_fallback_id):
                    logger.warning(f"Чат {target_chat_id} недоступен для панели {owner_key}, удаляем из настроек")
                    try:
                        if owner_key == "global":
                            from utils.chat_settings import set_notification_chat_id_global
                            set_notification_chat_id_global(None)
                        else:
                            from utils.chat_settings import set_notification_chat_id, remove_known_chat
                            set_notification_chat_id(int(owner_key), None)
                            remove_known_chat(int(owner_key), target_chat_id)
                            try:
                                await bot.send_message(
                                    int(owner_key),
                                    f"⚠️ Чат с ID {target_chat_id} недоступен. "
                                    f"Уведомления переключены на личные сообщения.\n\n"
                                    f"Чтобы настроить другой чат, используйте настройки мониторинга."
                                )
                            except Exception:
                                pass
                    except Exception as cleanup_error:
                        logger.error(f"Ошибка при очистке настроек чата: {cleanup_error}")
                
                logger.warning(f"Не удалось отправить уведомление в чат {target_chat_id} для панели {owner_key}: {e}")
                if dm_fallback_id is not None and target_chat_id != dm_fallback_id:
                    try:
                        await bot.send_message(dm_fallback_id, notification_text)
                        logger.info(f"Отправлено уведомление в ЛС пользователю {dm_fallback_id} (домен: {domain})")
                    except Exception as e2:
                        logger.error(f"Не удалось отправить уведомление пользователю {dm_fallback_id}: {e2}")
    
    except Exception as e:
        logger.error(f"Ошибка при проверке домена {domain}: {e}", exc_info=True)


async def run_checks_now(bot: Bot, owner_key: str) -> None:
    """Запускает проверку всех доменов панели мониторинга без ожидания таймера.

    Args:
        bot: Экземпляр бота для отправки уведомлений
        owner_key: Ключ владельца панели — str(user_id) или "global"
    """
    semaphore = asyncio.Semaphore(settings.CONCURRENCY)

    async with _monitoring_async_lock:
        db = await _load_monitoring_db()

    if owner_key not in db:
        logger.warning(f"run_checks_now: панель {owner_key} не найдена")
        return

    user_data = db[owner_key]
    domains = list(user_data.get("domains", {}).keys())
    if not domains:
        logger.debug(f"run_checks_now: нет доменов для панели {owner_key}")
        return

    notification_chat_id = None
    try:
        if owner_key == "global":
            from utils.chat_settings import get_notification_chat_id_global
            notification_chat_id = get_notification_chat_id_global()
        else:
            notification_chat_id = get_notification_chat_id(int(owner_key))
    except Exception:
        pass

    async def check_with_semaphore(domain: str, key: str, chat_id: Optional[int]):
        async with semaphore:
            await _check_domain(bot, key, domain, notification_chat_id=chat_id)

    tasks = [check_with_semaphore(d, owner_key, notification_chat_id) for d in domains]
    await asyncio.gather(*tasks, return_exceptions=True)
    logger.info(f"run_checks_now: проверка панели {owner_key} завершена ({len(domains)} доменов)")


async def _monitoring_loop(bot: Bot) -> None:
    """Основной цикл мониторинга.
    
    Args:
        bot: Экземпляр бота для отправки уведомлений
    """
    logger.info("Запущен цикл мониторинга доменов")
    
    # Семафор для контроля параллельных проверок
    semaphore = asyncio.Semaphore(settings.CONCURRENCY)
    
    while True:
        try:
            # Загружаем БД (async-safe)
            async with _monitoring_async_lock:
                db = await _load_monitoring_db()
            
            # Собираем задачи для параллельного выполнения
            tasks = []
            
            # Проверяем каждую панель (пользователь или global)
            for owner_key, user_data in db.items():
                if not user_data.get("enabled", True):
                    continue

                interval_minutes = user_data.get("interval_minutes", 15)

                # Получаем ID чата для уведомлений
                notification_chat_id = None
                try:
                    if owner_key == "global":
                        from utils.chat_settings import get_notification_chat_id_global
                        notification_chat_id = get_notification_chat_id_global()
                    else:
                        notification_chat_id = get_notification_chat_id(int(owner_key))
                except (ValueError, Exception):
                    pass

                # Проверяем каждый домен панели
                for domain, domain_data in user_data.get("domains", {}).items():
                    last_check = domain_data.get("last_check")

                    should_check = True
                    if last_check:
                        try:
                            last_check_dt = datetime.fromisoformat(last_check.replace('Z', '+00:00'))
                            next_check = last_check_dt + timedelta(minutes=interval_minutes)
                            should_check = datetime.now(last_check_dt.tzinfo) >= next_check
                        except Exception:
                            pass

                    if should_check:
                        async def check_with_semaphore(d: str, key: str, chat_id: Optional[int]):
                            async with semaphore:
                                await _check_domain(bot, key, d, notification_chat_id=chat_id)

                        tasks.append(check_with_semaphore(domain, owner_key, notification_chat_id))
            
            # Выполняем все проверки параллельно
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            # Периодическая очистка неактивных пользователей и старых данных
            await _cleanup_monitoring_data()
            
            # Ждем перед следующей итерацией
            await asyncio.sleep(60)  # Проверяем каждую минуту
            
        except Exception as e:
            logger.error(f"Ошибка в цикле мониторинга: {e}", exc_info=True)
            await asyncio.sleep(60)


async def _cleanup_monitoring_data() -> None:
    """Очищает неактивных пользователей и старые данные из мониторинга."""
    try:
        async with _monitoring_async_lock:
            db = await _load_monitoring_db()
        
        now = datetime.now()
        max_idle_days = 90
        
        users_to_remove = []
        modified = False
        
        for user_key, user_data in db.items():
            domains = user_data.get("domains", {})
            
            for domain, domain_data in domains.items():
                state_history = domain_data.get("state_history", [])
                if len(state_history) > MAX_STATE_HISTORY:
                    domain_data["state_history"] = state_history[-MAX_STATE_HISTORY:]
                    modified = True
            
            has_recent_activity = False
            for domain_data in domains.values():
                last_check = domain_data.get("last_check")
                if last_check:
                    try:
                        last_check_dt = datetime.fromisoformat(last_check.replace('Z', '+00:00'))
                        if (now - last_check_dt.replace(tzinfo=None)).days < max_idle_days:
                            has_recent_activity = True
                            break
                    except Exception:
                        pass
            
            if not has_recent_activity and not domains and user_key != "global":
                users_to_remove.append(user_key)

        for user_key in users_to_remove:
            del db[user_key]
            logger.debug(f"Удален неактивный пользователь {user_key} из мониторинга")
        
        if users_to_remove or modified:
            async with _monitoring_async_lock:
                await _save_monitoring_db(db)
                
    except Exception as e:
        logger.error(f"Ошибка при очистке данных мониторинга: {e}", exc_info=True)


def start_monitoring(bot: Bot) -> None:
    """Запускает фоновую задачу мониторинга.
    
    Args:
        bot: Экземпляр бота
    """
    global _monitoring_task
    
    if _monitoring_task is None or _monitoring_task.done():
        _monitoring_task = asyncio.create_task(_monitoring_loop(bot))
        logger.info("Мониторинг доменов запущен")


def stop_monitoring() -> None:
    """Останавливает фоновую задачу мониторинга."""
    global _monitoring_task
    
    if _monitoring_task and not _monitoring_task.done():
        _monitoring_task.cancel()
        logger.info("Мониторинг доменов остановлен")

