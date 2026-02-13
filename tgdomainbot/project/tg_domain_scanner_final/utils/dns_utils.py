"""Утилиты для получения DNS записей доменов."""

from __future__ import annotations

import logging
from utils.cache import ttl_cache
import dns.asyncresolver
import socket
from typing import Dict, List

from utils.types import DNSInfo

logger = logging.getLogger(__name__)


async def _query(resolver: dns.asyncresolver.Resolver, domain: str, rdtype: str) -> List[str]:
    """Выполняет DNS запрос определенного типа.
    
    Args:
        resolver: DNS резолвер
        domain: Домен для запроса
        rdtype: Тип записи (A, AAAA, MX, NS)
        
    Returns:
        Список значений DNS записей
    """
    try:
        return [rr.to_text() for rr in await resolver.resolve(domain, rdtype)]
    except Exception as e:
        logger.debug(f"Ошибка при запросе {rdtype} для {domain}: {e}")
        return []


@ttl_cache()
async def fetch_dns(domain: str, timeout: int = 5) -> Dict[str, List[str]]:
    """Получает DNS записи для домена.
    
    Args:
        domain: Домен для проверки
        timeout: Таймаут запроса в секундах
        
    Returns:
        Словарь с DNS записями:
        - A: IPv4 адреса
        - AAAA: IPv6 адреса
        - MX: Mail exchange записи
        - NS: Name server записи
        - IP: IPv4 адреса (дубликат A для совместимости)
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    
    res: Dict[str, List[str]] = {k: [] for k in ("A", "AAAA", "MX", "NS", "IP")}
    
    # Получаем записи разных типов
    for rt in ("A", "AAAA", "MX", "NS"):
        res[rt] = await _query(resolver, domain, rt)
    
    # IP - это дубликат A для совместимости со старым кодом
    res["IP"] = res["A"].copy()
    
    # Дополнительно пытаемся получить IP через socket (может дать другие результаты)
    try:
        socket_ips = socket.gethostbyname_ex(domain)[2]
        # Объединяем с уже полученными
        for ip in socket_ips:
            if ip not in res["IP"]:
                res["IP"].append(ip)
    except socket.gaierror:
        pass
    
    return res
