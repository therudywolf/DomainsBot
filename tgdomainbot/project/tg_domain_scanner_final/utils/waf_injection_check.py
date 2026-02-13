"""
Проверка WAF через отправку тестовой инъекции.

Использует легкую безобидную SQL/XSS инъекцию для гарантированного получения 403,
если WAF присутствует на домене.
"""

import logging
from typing import Optional
import aiohttp

from utils.cache import ttl_cache
from config import settings

logger = logging.getLogger(__name__)

# Легкие безобидные инъекции для проверки WAF
# Эти инъекции должны быть заблокированы WAF, но не навредят серверу
INJECTION_PAYLOADS = [
    # SQL инъекция
    "' OR '1'='1",
    # XSS инъекция
    "<script>alert(1)</script>",
    # Path traversal
    "../../etc/passwd",
    # Command injection
    "; cat /etc/passwd",
]

# Статусы, которые указывают на блокировку WAF
BLOCK_STATUSES = {403, 406, 429, 501, 502, 503}


@ttl_cache(ttl=300)  # Кэш на 5 минут для быстрой проверки
async def test_waf_injection(domain: str, timeout: Optional[int] = None) -> tuple[bool, str]:
    """
    Проверяет наличие WAF через отправку тестовой инъекции.
    
    Отправляет запросы с легкими безобидными инъекциями и проверяет,
    возвращает ли сервер статус 403 (или другой блокирующий статус).
    
    Args:
        domain: Домен для проверки
        timeout: Таймаут запроса (по умолчанию из settings)
        
    Returns:
        Кортеж (результат, метод_проверки):
        - результат: True если WAF обнаружен (получен 403 или другой блокирующий статус),
          False если WAF не обнаружен
        - метод_проверки: всегда "injection" (проверка через инъекции)
    """
    timeout = timeout or settings.HTTP_TIMEOUT
    base_url = f"https://{domain}"
    
    connector = aiohttp.TCPConnector(limit=20, force_close=True)
    
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            # Сначала делаем обычный запрос для получения базового статуса
            try:
                async with session.get(
                    base_url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=True
                ) as base_resp:
                    base_status = base_resp.status
                    logger.debug(f"Базовый статус для {domain}: {base_status}")
            except Exception as e:
                logger.debug(f"Не удалось получить базовый статус для {domain}: {e}")
                base_status = None
            
            # Пробуем каждый payload
            for payload in INJECTION_PAYLOADS:
                try:
                    # Пробуем в URL параметре
                    import urllib.parse
                    test_url = f"{base_url}/?test={urllib.parse.quote(payload)}"
                    
                    async with session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        allow_redirects=True
                    ) as resp:
                        status = resp.status
                        
                        # Если получили блокирующий статус - WAF обнаружен
                        if status in BLOCK_STATUSES:
                            logger.info(f"WAF обнаружен для {domain} через инъекцию '{payload}': статус {status}")
                            return (True, "injection")
                        
                        # Если статус изменился с базового - возможно WAF
                        if base_status and status != base_status and status in {400, 404, 500}:
                            logger.debug(f"Статус изменился для {domain} с {base_status} на {status} при инъекции '{payload}'")
                            # Не считаем это гарантированным признаком WAF, но логируем
                        
                except aiohttp.ClientError as e:
                    logger.debug(f"Ошибка клиента при проверке WAF для {domain} с payload '{payload}': {e}")
                    continue
                except Exception as e:
                    logger.debug(f"Ошибка при проверке WAF для {domain} с payload '{payload}': {e}")
                    continue
            
            # Если ни одна инъекция не вызвала блокировку, WAF скорее всего нет
            logger.debug(f"WAF не обнаружен для {domain} через инъекции")
            return (False, "injection")
            
    except Exception as e:
        logger.warning(f"Неожиданная ошибка при проверке WAF для {domain}: {e}", exc_info=True)
        return (False, "injection")

