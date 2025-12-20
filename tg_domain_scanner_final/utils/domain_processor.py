"""
Модуль для обработки доменов.

Содержит функции для валидации, нормализации и проверки доменов.
"""

import asyncio
import re
import logging
from typing import List, Tuple, Dict, Any, Optional

from utils.dns_utils import fetch_dns
from utils.ssl_utils import fetch_ssl
from utils.waf_utils import test_waf
from utils.domain_normalizer import normalize_domains
from utils.formatting import build_report
from utils.history import add_check_result
from utils.stats import record_domain_check, record_error
from utils.error_logging import log_error_with_context, format_error_for_user
from utils.types import DNSInfo, SSLInfo
from config import settings

logger = logging.getLogger(__name__)

# Регулярное выражение для разбиения доменов
DOMAIN_SPLIT_RE = re.compile(r'[\s,;]+')


def validate_and_normalize_domains(raw_text: str) -> Tuple[List[str], List[str]]:
    """
    Валидирует и нормализует домены из текста.
    
    Args:
        raw_text: Текст с доменами для обработки
        
    Returns:
        Кортеж (список валидных доменов, список некорректных строк)
    """
    import re
    # Разбиваем на отдельные строки
    raw_items = [x.strip() for x in DOMAIN_SPLIT_RE.split(raw_text or "") if x.strip()]
    
    # Нормализуем домены (обрабатывает https://, пути, параметры и т.д.)
    domains = normalize_domains(raw_items)
    bad = [item for item in raw_items if item not in domains]
    
    return domains, bad


async def check_single_domain(
    domain: str,
    user_id: int,
    semaphore: asyncio.Semaphore,
    brief: bool = False
) -> Tuple[str, Tuple[str, DNSInfo, SSLInfo, bool, Optional[str]]]:
    """
    Проверяет один домен и возвращает отчет и данные для CSV.
    
    Args:
        domain: Домен для проверки
        user_id: ID пользователя
        semaphore: Семафор для ограничения параллельных запросов
        brief: Использовать краткий режим отчета
        
    Returns:
        Кортеж (строка отчета, данные для CSV: (domain, dns_info, ssl_info, waf_enabled, waf_method))
    """
    async with semaphore:
        try:
            # Параллельно получаем информацию о домене
            dns_info, ssl_info, waf_result = await asyncio.gather(
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
            
            # Обрабатываем результат WAF (может быть кортеж или исключение)
            if isinstance(waf_result, Exception):
                logger.error(f"Ошибка WAF для {domain}: {waf_result}")
                waf_enabled = False
                waf_method = None
                record_error("WAF_ERROR")
            elif isinstance(waf_result, tuple) and len(waf_result) == 2:
                waf_enabled, waf_method = waf_result
            else:
                # Обратная совместимость: если вернулся просто bool
                waf_enabled = bool(waf_result)
                waf_method = None
            
            # Формируем данные для отчета
            row = (domain, dns_info, ssl_info, waf_enabled, waf_method)
            line = build_report(domain, dns_info, ssl_info, waf_enabled, brief=brief, waf_method=waf_method)
            
            # Сохраняем в историю (если включено)
            if settings.HISTORY_ENABLED:
                try:
                    add_check_result(domain, user_id, dns_info, ssl_info, waf_enabled, waf_method)
                except Exception as e:
                    logger.warning(f"Ошибка при сохранении в историю: {e}")
            
            # Записываем статистику
            if settings.STATS_ENABLED:
                record_domain_check(domain, user_id)
            
            return line, row
            
        except Exception as exc:  # noqa: BLE001
            error_id = log_error_with_context(
                exc,
                user_id=user_id,
                context={"domain": domain, "operation": "DOMAIN_PROCESSING"},
                level="CRITICAL",
                send_alert=True
            )
            record_error("PROCESSING_ERROR")
            # Graceful degradation: показываем частичный результат даже при ошибке
            row = (domain, {}, {}, False, None)
            error_msg = format_error_for_user(error_id, exc)
            line = f"❌ {domain}: {error_msg}"
            
            return line, row

