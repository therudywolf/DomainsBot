"""Утилиты для получения DNS записей доменов."""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Dict, List

import dns.asyncresolver

from utils.cache import ttl_cache
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


def _blocking_gethostbyname(domain: str) -> List[str]:
    """Обёртка для socket.gethostbyname_ex — вызывается в executor."""
    try:
        return socket.gethostbyname_ex(domain)[2]
    except socket.gaierror:
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
    
    res: Dict[str, List[str]] = {k: [] for k in ("A", "AAAA", "MX", "NS", "IP", "TXT", "CAA", "SOA")}
    
    for rt in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        res[rt] = await _query(resolver, domain, rt)
    
    # SOA — single record, still stored as list for uniformity
    try:
        soa_answer = await resolver.resolve(domain, "SOA")
        for rr in soa_answer:
            res["SOA"].append(rr.to_text())
    except Exception as e:
        logger.debug(f"Ошибка при запросе SOA для {domain}: {e}")
    
    res["IP"] = res["A"].copy()
    
    loop = asyncio.get_running_loop()
    try:
        socket_ips = await asyncio.wait_for(
            loop.run_in_executor(None, _blocking_gethostbyname, domain),
            timeout=timeout,
        )
        for ip in socket_ips:
            if ip not in res["IP"]:
                res["IP"].append(ip)
    except (asyncio.TimeoutError, Exception) as e:
        logger.debug(f"socket.gethostbyname_ex для {domain} не удался: {e}")
    
    return res
