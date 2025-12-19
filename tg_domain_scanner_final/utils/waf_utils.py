"""
Утилиты для проверки WAF (Web Application Firewall).

Поддерживает два режима проверки:
- Policy-based: отправка запроса с параметром monitoring
- Light: простая проверка через GET запрос (см. waf_light_check.py)
"""

import logging
from typing import Sequence, Optional
import aiohttp

from utils.cache import ttl_cache
from utils.waf_light_check import test_waf_light
from utils.prefs import get_waf_mode, get_waf_timeout
from config import settings

logger = logging.getLogger(__name__)

# Разрешён только один «безобидный» мониторинговый запрос
PAYLOADS: Sequence[str] = (
    "/?monitoring=test_query_for_policy",
)

BLOCK_CODES = {403, 406, 429, 501, 502, 503}


async def _fetch(session: aiohttp.ClientSession, url: str, timeout: int):
    """Выполняет GET запрос и возвращает статус и длину тела.
    
    Args:
        session: HTTP сессия
        url: URL для запроса
        timeout: Таймаут запроса
        
    Returns:
        Кортеж (статус, длина_тела)
    """
    async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
        try:
            body = await resp.text()
        except Exception:
            body = ""
        return resp.status, len(body)


async def _test_waf_policy(domain: str, timeout: int = 6) -> bool:
    """Policy-based проверка WAF через отправку запроса с параметром monitoring.
    
    Args:
        domain: Домен для проверки
        timeout: Таймаут запроса
        
    Returns:
        True если WAF обнаружен
    """
    base_url = f"https://{domain}"
    connector = aiohttp.TCPConnector(limit=20, force_close=True)
    
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                base_status, base_len = await _fetch(session, base_url, timeout)
            except Exception as e:
                logger.debug(f"Не удалось подключиться к {domain} для WAF проверки: {e}")
                # При ошибке соединения не предполагаем WAF автоматически
                return False

            for p in PAYLOADS:
                try:
                    status, length = await _fetch(session, base_url + p, timeout)
                    if status in BLOCK_CODES or status != base_status:
                        logger.debug(f"WAF обнаружен для {domain}: статус изменился {base_status} -> {status}")
                        return True
                    if abs(length - base_len) > base_len * 0.5:
                        logger.debug(f"WAF обнаружен для {domain}: размер ответа изменился значительно")
                        return True
                except Exception as e:
                    logger.debug(f"Ошибка при проверке WAF для {domain} с payload {p}: {e}")
                    # Продолжаем проверку других payloads
                    continue
    except Exception as e:
        logger.warning(f"Неожиданная ошибка при проверке WAF для {domain}: {e}")
        return False
    
    return False


@ttl_cache()
async def test_waf(domain: str, timeout: Optional[int] = None, user_id: Optional[int] = None) -> bool:
    """Проверяет наличие WAF на домене.
    
    Использует режим проверки из настроек пользователя или по умолчанию policy-based.
    
    Args:
        domain: Домен для проверки
        timeout: Таймаут запроса (если None, берется из настроек пользователя или config)
        user_id: ID пользователя для получения настроек режима проверки
        
    Returns:
        True если WAF обнаружен, False если нет
    """
    # Определяем режим проверки
    if user_id is not None:
        waf_mode = get_waf_mode(user_id, "policy")
        user_timeout = get_waf_timeout(user_id)
        if user_timeout is not None:
            timeout = user_timeout
    else:
        waf_mode = "policy"
    
    timeout = timeout or settings.HTTP_TIMEOUT
    
    # Выбираем метод проверки
    if waf_mode == "light":
        logger.debug(f"Используется легкая проверка WAF для {domain}")
        return await test_waf_light(domain, timeout)
    else:
        logger.debug(f"Используется policy-based проверка WAF для {domain}")
        return await _test_waf_policy(domain, timeout)
