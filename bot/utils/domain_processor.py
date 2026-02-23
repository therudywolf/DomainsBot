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
from utils.http_utils import fetch_http_info
from utils.email_security import fetch_email_security
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
    from utils.domain_normalizer import normalize_domain
    
    raw_items = [x.strip() for x in DOMAIN_SPLIT_RE.split(raw_text or "") if x.strip()]
    
    domains: List[str] = []
    bad: List[str] = []
    seen: set = set()
    
    for item in raw_items:
        norm = normalize_domain(item)
        if norm and norm not in seen:
            domains.append(norm)
            seen.add(norm)
        elif norm is None:
            bad.append(item)
    
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
            dns_info, ssl_info, waf_result, http_info, email_sec = await asyncio.gather(
                fetch_dns(domain, settings.DNS_TIMEOUT),
                fetch_ssl(domain),
                test_waf(domain, user_id=user_id),
                fetch_http_info(domain),
                fetch_email_security(domain),
                return_exceptions=True,
            )
            
            if isinstance(dns_info, BaseException):
                logger.error(f"Ошибка DNS для {domain}: {type(dns_info).__name__}: {dns_info}")
                dns_info = {}
                record_error("DNS_ERROR")
            
            if isinstance(ssl_info, BaseException):
                logger.error(f"Ошибка SSL для {domain}: {type(ssl_info).__name__}: {ssl_info}")
                ssl_info = {}
                record_error("SSL_ERROR")
            
            if not isinstance(ssl_info, dict):
                ssl_info = {}
            if not isinstance(dns_info, dict):
                dns_info = {}
            
            if isinstance(waf_result, BaseException):
                logger.error(f"Ошибка WAF для {domain}: {waf_result}")
                waf_enabled = False
                waf_method = None
                record_error("WAF_ERROR")
            elif isinstance(waf_result, tuple) and len(waf_result) == 2:
                waf_enabled, waf_method = waf_result
            else:
                waf_enabled = bool(waf_result)
                waf_method = None
            
            if isinstance(http_info, BaseException):
                logger.error(f"Ошибка HTTP для {domain}: {http_info}")
                http_info = {}
            if not isinstance(http_info, dict):
                http_info = {}
            
            if isinstance(email_sec, BaseException):
                logger.error(f"Ошибка Email Security для {domain}: {email_sec}")
                email_sec = {}
            if not isinstance(email_sec, dict):
                email_sec = {}
            
            row = (domain, dns_info, ssl_info, waf_enabled, waf_method)
            line = build_report(
                domain, dns_info, ssl_info, waf_enabled,
                brief=brief, waf_method=waf_method,
                http_info=http_info, email_security=email_sec,
            )
            
            if settings.HISTORY_ENABLED:
                try:
                    add_check_result(domain, user_id, dns_info, ssl_info, waf_enabled, waf_method)
                except Exception as e:
                    logger.warning(f"Ошибка при сохранении в историю: {e}")
            
            if settings.STATS_ENABLED:
                record_domain_check(domain, user_id)
            
            return line, row
            
        except Exception as exc:  # noqa: BLE001
            error_id = log_error_with_context(
                exc,
                user_id=user_id,
                context={"domain": domain, "operation": "DOMAIN_PROCESSING"},
                level="CRITICAL",
                send_alert=True,
            )
            record_error("PROCESSING_ERROR")
            row = (domain, {}, {}, False, None)
            error_msg = format_error_for_user(error_id, "PROCESSING_ERROR")
            line = f"❌ {domain}: {error_msg}"
            
            return line, row

