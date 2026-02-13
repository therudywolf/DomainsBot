"""
Легкая проверка WAF через простой GET запрос.

Определяет наличие WAF по HTTP статусу и заголовкам ответа.
"""

import logging
from typing import Optional
import aiohttp

from utils.cache import ttl_cache
from config import settings

logger = logging.getLogger(__name__)

# Характерные заголовки WAF
WAF_HEADERS = {
    'server': ['cloudflare', 'cloudfront', 'ddos-guard', 'sucuri', 'incapsula', 'akamai'],
    'x-powered-by': ['cloudflare', 'ddos-guard'],
    'cf-ray': [],  # Cloudflare всегда добавляет этот заголовок
    'x-sucuri-id': [],
    'x-cache': ['cloudflare'],
}

# Характерные статусы, которые могут указывать на WAF
WAF_STATUSES = {403, 406, 429}


@ttl_cache()
async def test_waf_light(domain: str, timeout: Optional[int] = None) -> bool:
    """Легкая проверка WAF через простой GET запрос.
    
    Проверяет наличие WAF по:
    - HTTP статусу ответа
    - Характерным заголовкам (Server, X-Powered-By, и т.д.)
    
    Args:
        domain: Домен для проверки
        timeout: Таймаут запроса (по умолчанию из settings)
        
    Returns:
        True если WAF обнаружен, False если нет
    """
    timeout = timeout or settings.HTTP_TIMEOUT
    base_url = f"https://{domain}"
    
    connector = aiohttp.TCPConnector(limit=20, force_close=True)
    
    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                base_url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                allow_redirects=True
            ) as resp:
                # Проверяем статус
                if resp.status in WAF_STATUSES:
                    logger.debug(f"WAF обнаружен для {domain} по статусу {resp.status}")
                    return True
                
                # Проверяем заголовки
                headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                
                for header_name, waf_values in WAF_HEADERS.items():
                    if header_name in headers_lower:
                        header_value = headers_lower[header_name]
                        
                        # Если список значений пустой, достаточно наличия заголовка
                        if not waf_values:
                            logger.debug(f"WAF обнаружен для {domain} по заголовку {header_name}")
                            return True
                        
                        # Проверяем значения
                        for waf_value in waf_values:
                            if waf_value in header_value:
                                logger.debug(f"WAF обнаружен для {domain} по заголовку {header_name}={header_value}")
                                return True
                
                # Если ничего не найдено
                logger.debug(f"WAF не обнаружен для {domain}")
                return False
                
    except aiohttp.ClientError as e:
        logger.debug(f"Ошибка клиента при проверке WAF для {domain}: {e}")
        # При ошибке соединения не предполагаем WAF
        return False
    except Exception as e:
        logger.warning(f"Неожиданная ошибка при проверке WAF для {domain}: {e}")
        return False





