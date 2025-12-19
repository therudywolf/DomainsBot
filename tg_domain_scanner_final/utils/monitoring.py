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
from typing import Dict, List, Optional, Any, Set
from threading import RLock

from aiogram import Bot

from utils.dns_utils import fetch_dns
from utils.ssl_utils import fetch_ssl
from utils.waf_utils import test_waf
from config import settings

logger = logging.getLogger(__name__)

# Путь к БД мониторинга
MONITORING_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "monitoring_db.json"
MONITORING_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Блокировка для потокобезопасности
_monitoring_lock = RLock()

# Глобальная переменная для фоновой задачи
_monitoring_task: Optional[asyncio.Task] = None


def _load_monitoring_db() -> Dict[str, Any]:
    """Загружает БД мониторинга из файла."""
    if not MONITORING_DB_PATH.exists():
        return {}
    
    try:
        with open(MONITORING_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Ошибка при загрузке БД мониторинга: {e}")
        return {}


def _save_monitoring_db(data: Dict[str, Any]) -> None:
    """Сохраняет БД мониторинга в файл."""
    try:
        with open(MONITORING_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    except Exception as e:
        logger.error(f"Ошибка при сохранении БД мониторинга: {e}")


def add_domain_to_monitoring(user_id: int, domain: str) -> bool:
    """Добавляет домен в мониторинг для пользователя.
    
    Args:
        user_id: ID пользователя
        domain: Домен для мониторинга
        
    Returns:
        True если домен добавлен, False если уже был в мониторинге
    """
    with _monitoring_lock:
        db = _load_monitoring_db()
        
        user_key = str(user_id)
        if user_key not in db:
            db[user_key] = {
                "domains": {},
                "enabled": True,
                "interval_minutes": 15,  # По умолчанию 15 минут
            }
        
        if domain not in db[user_key]["domains"]:
            db[user_key]["domains"][domain] = {
                "added_at": datetime.now().isoformat(),
                "last_check": None,
                "last_state": None,
            }
            _save_monitoring_db(db)
            logger.info(f"Домен {domain} добавлен в мониторинг для пользователя {user_id}")
            return True
        
        return False


def remove_domain_from_monitoring(user_id: int, domain: str) -> bool:
    """Удаляет домен из мониторинга пользователя.
    
    Args:
        user_id: ID пользователя
        domain: Домен для удаления
        
    Returns:
        True если домен был удален, False если его не было
    """
    with _monitoring_lock:
        db = _load_monitoring_db()
        
        user_key = str(user_id)
        if user_key in db and domain in db[user_key]["domains"]:
            del db[user_key]["domains"][domain]
            _save_monitoring_db(db)
            logger.info(f"Домен {domain} удален из мониторинга для пользователя {user_id}")
            return True
        
        return False


def get_monitored_domains(user_id: int) -> List[str]:
    """Получает список доменов в мониторинге для пользователя.
    
    Args:
        user_id: ID пользователя
        
    Returns:
        Список доменов
    """
    with _monitoring_lock:
        db = _load_monitoring_db()
        user_key = str(user_id)
        if user_key in db:
            return list(db[user_key]["domains"].keys())
        return []


def set_monitoring_interval(user_id: int, interval_minutes: int) -> None:
    """Устанавливает интервал проверки для пользователя.
    
    Args:
        user_id: ID пользователя
        interval_minutes: Интервал в минутах
    """
    with _monitoring_lock:
        db = _load_monitoring_db()
        user_key = str(user_id)
        if user_key not in db:
            db[user_key] = {
                "domains": {},
                "enabled": True,
                "interval_minutes": interval_minutes,
            }
        else:
            db[user_key]["interval_minutes"] = interval_minutes
        _save_monitoring_db(db)


def get_monitoring_interval(user_id: int) -> int:
    """Получает интервал проверки для пользователя.
    
    Args:
        user_id: ID пользователя
        
    Returns:
        Интервал в минутах (по умолчанию 15)
    """
    with _monitoring_lock:
        db = _load_monitoring_db()
        user_key = str(user_id)
        if user_key in db:
            return db[user_key].get("interval_minutes", 15)
        return 15


def set_monitoring_enabled(user_id: int, enabled: bool) -> None:
    """Включает/выключает мониторинг для пользователя.
    
    Args:
        user_id: ID пользователя
        enabled: Включен ли мониторинг
    """
    with _monitoring_lock:
        db = _load_monitoring_db()
        user_key = str(user_id)
        if user_key not in db:
            db[user_key] = {
                "domains": {},
                "enabled": enabled,
                "interval_minutes": 15,
            }
        else:
            db[user_key]["enabled"] = enabled
        _save_monitoring_db(db)


def is_monitoring_enabled(user_id: int) -> bool:
    """Проверяет, включен ли мониторинг для пользователя.
    
    Args:
        user_id: ID пользователя
        
    Returns:
        True если мониторинг включен
    """
    with _monitoring_lock:
        db = _load_monitoring_db()
        user_key = str(user_id)
        if user_key in db:
            return db[user_key].get("enabled", True)
        return True


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
        if isinstance(ssl_info, Exception):
            logger.error(f"Ошибка SSL для {domain}: {ssl_info}")
            ssl_info = {}
        if isinstance(waf_enabled, Exception):
            logger.error(f"Ошибка WAF для {domain}: {waf_enabled}")
            waf_enabled = False
        
        return {
            "gost": ssl_info.get("gost", False) if isinstance(ssl_info, dict) else False,
            "waf": waf_enabled if isinstance(waf_enabled, bool) else False,
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
    
    # Проверка дат сертификатов
    old_cert_date = old_state.get("cert_not_after")
    new_cert_date = new_state.get("cert_not_after")
    if old_cert_date != new_cert_date:
        if new_cert_date:
            try:
                cert_date = datetime.fromisoformat(new_cert_date.replace('Z', '+00:00'))
                days_left = (cert_date - datetime.now(cert_date.tzinfo)).days
                if days_left < 30:
                    changes.append(f"Сертификат истекает через {days_left} дней")
            except Exception:
                pass
    
    old_gost_cert_date = old_state.get("gost_cert_not_after")
    new_gost_cert_date = new_state.get("gost_cert_not_after")
    if old_gost_cert_date != new_gost_cert_date:
        if new_gost_cert_date:
            try:
                gost_cert_date = datetime.fromisoformat(new_gost_cert_date.replace('Z', '+00:00'))
                days_left = (gost_cert_date - datetime.now(gost_cert_date.tzinfo)).days
                if days_left < 30:
                    changes.append(f"GOST сертификат истекает через {days_left} дней")
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


async def _check_domain(bot: Bot, user_id: int, domain: str) -> None:
    """Проверяет один домен и отправляет уведомления при изменениях.
    
    Args:
        bot: Экземпляр бота для отправки уведомлений
        user_id: ID пользователя
        domain: Домен для проверки
    """
    try:
        # Получаем текущее состояние
        new_state = await _get_domain_state(domain, user_id)
        
        if not new_state:
            logger.warning(f"Не удалось получить состояние для {domain}")
            return
        
        # Загружаем БД и сравниваем с предыдущим состоянием
        with _monitoring_lock:
            db = _load_monitoring_db()
            user_key = str(user_id)
            
            if user_key not in db or domain not in db[user_key]["domains"]:
                return
            
            old_state = db[user_key]["domains"][domain].get("last_state")
            changes = _compare_states(old_state, new_state)
            
            # Обновляем состояние
            db[user_key]["domains"][domain]["last_state"] = new_state
            db[user_key]["domains"][domain]["last_check"] = datetime.now().isoformat()
            _save_monitoring_db(db)
        
        # Отправляем уведомления если есть изменения
        if changes:
            message = f"🔔 Изменение для {domain}:\n" + "\n".join(f"• {c}" for c in changes)
            try:
                await bot.send_message(user_id, message)
                logger.info(f"Отправлено уведомление пользователю {user_id} для {domain}")
            except Exception as e:
                logger.error(f"Ошибка при отправке уведомления пользователю {user_id}: {e}")
    
    except Exception as e:
        logger.error(f"Ошибка при проверке домена {domain}: {e}", exc_info=True)


async def _monitoring_loop(bot: Bot) -> None:
    """Основной цикл мониторинга.
    
    Args:
        bot: Экземпляр бота для отправки уведомлений
    """
    logger.info("Запущен цикл мониторинга доменов")
    
    while True:
        try:
            # Загружаем БД
            with _monitoring_lock:
                db = _load_monitoring_db()
            
            # Проверяем каждого пользователя
            for user_key, user_data in db.items():
                if not user_data.get("enabled", True):
                    continue
                
                user_id = int(user_key)
                interval_minutes = user_data.get("interval_minutes", 15)
                
                # Проверяем каждый домен пользователя
                for domain, domain_data in user_data.get("domains", {}).items():
                    last_check = domain_data.get("last_check")
                    
                    # Проверяем, нужно ли проверять сейчас
                    should_check = True
                    if last_check:
                        try:
                            last_check_dt = datetime.fromisoformat(last_check.replace('Z', '+00:00'))
                            next_check = last_check_dt + timedelta(minutes=interval_minutes)
                            should_check = datetime.now(last_check_dt.tzinfo) >= next_check
                        except Exception:
                            pass
                    
                    if should_check:
                        await _check_domain(bot, user_id, domain)
                        # Небольшая задержка между проверками
                        await asyncio.sleep(1)
            
            # Ждем перед следующей итерацией
            await asyncio.sleep(60)  # Проверяем каждую минуту
            
        except Exception as e:
            logger.error(f"Ошибка в цикле мониторинга: {e}", exc_info=True)
            await asyncio.sleep(60)


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

