"""
Утилиты для проверки SSL сертификатов и определения GOST шифрования.

Модуль содержит функции для:
- Проверки SSL сертификатов доменов
- Определения наличия GOST шифрования (через удаленные контейнеры)
- Получения информации о сертификатах (обычный и GOST TLS)
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import os
import random
from typing import Dict, Any, Optional, List
from datetime import timezone

from utils.types import SSLInfo

import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from utils.cache import ttl_cache
from config import settings
from utils.wireguard_utils import ensure_wg_interface_up, get_wg_interface_ip

logger = logging.getLogger(__name__)

# ----------------------------
#  GOST detection helpers
# ----------------------------
GOST_OID_PREFIX = "1.2.643."
GOST_CIPHERS = "GOST2012-GOST8912-GOST89"


def _cert_is_gost(cert: x509.Certificate) -> bool:
    """Проверяет, является ли сертификат GOST по OID алгоритма подписи.
    
    Args:
        cert: Сертификат для проверки
        
    Returns:
        True если сертификат использует GOST алгоритм
    """
    return cert.signature_algorithm_oid.dotted_string.startswith(GOST_OID_PREFIX)


def _cipher_is_gost(cipher_name: str) -> bool:
    """Проверяет, используется ли GOST шифр по имени.
    
    Args:
        cipher_name: Название шифра
        
    Returns:
        True если шифр является GOST
    """
    return any(c in cipher_name for c in GOST_CIPHERS.split("-"))


# ----------------------------
#  Remote GOST check
# ----------------------------
# 1) Если задан GOST_CHECK_URL - используем только его
# 2) Иначе - список hostnames контейнеров из GOSTSSL_HOSTS (через запятую)
#    По умолчанию "gostsslcheck"
if os.getenv("GOST_CHECK_URL"):
    _endpoints: List[str] = [os.getenv("GOST_CHECK_URL")]
else:
    _hosts: List[str] = [h.strip() for h in os.getenv("GOSTSSL_HOSTS", "gostsslcheck").split(',') if h.strip()]
    _endpoints: List[str] = [f"http://{h}:8080/check" for h in _hosts]

# Резервный вариант при массовых 504 - WireGuard подключение

# Глобальный connector для переиспользования соединений
_gost_connector: Optional[aiohttp.TCPConnector] = None


def _get_gost_connector() -> aiohttp.TCPConnector:
    """Получает или создает глобальный connector для Gost запросов.
    
    Returns:
        TCPConnector для переиспользования соединений
    """
    global _gost_connector
    try:
        # Проверяем, что connector существует и не закрыт
        # У TCPConnector есть только атрибут `closed`, не `is_closed`
        if _gost_connector is None or _gost_connector.closed:
            _gost_connector = None  # Сбрасываем перед созданием нового
            _gost_connector = aiohttp.TCPConnector(
                limit=20,
                limit_per_host=5,
                force_close=False,  # Переиспользование соединений
                ttl_dns_cache=300,
            )
    except Exception as e:
        logger.warning(f"Ошибка при проверке connector: {e}, создаем новый")
        _gost_connector = None
        _gost_connector = aiohttp.TCPConnector(
            limit=20,
            limit_per_host=5,
            force_close=False,
            ttl_dns_cache=300,
        )
    return _gost_connector


async def _check_single_endpoint(url: str, domain: str, timeout: int) -> tuple[Optional[bool], Optional[Exception], bool]:
    """
    Проверяет один GOST endpoint.
    
    Returns:
        Кортеж (результат, ошибка, is_504):
        - результат: True/False если успешно, None если ошибка
        - ошибка: объект исключения или None
        - is_504: True если это была ошибка 504
    """
    local_connector = None
    try:
        local_connector = aiohttp.TCPConnector(
            limit=10,
            limit_per_host=3,
            force_close=True,
            ttl_dns_cache=300,
        )
        
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with aiohttp.ClientSession(
            timeout=timeout_obj,
            connector=local_connector
        ) as session:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Проверка GOST для {domain} через {url}")
            
            async with session.get(url, params={"domain": domain}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    result = bool(data.get("is_gost"))
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"GOST проверка для {domain}: {result} (через {url})")
                    return result, None, False
                elif resp.status == 504:
                    logger.warning(f"GOST endpoint {url} вернул 504 (Gateway Timeout) для {domain}")
                    return None, Exception(f"HTTP 504"), True
                else:
                    logger.warning(f"GOST endpoint {url} вернул статус {resp.status} для {domain}")
                    return None, Exception(f"HTTP {resp.status}"), False
    except asyncio.TimeoutError:
        logger.warning(f"Таймаут при проверке GOST для {domain} через {url}")
        return None, asyncio.TimeoutError("Timeout"), False
    except (aiohttp.ClientError, RuntimeError) as e:
        error_msg = str(e)
        if "Session is closed" in error_msg or "Connector is closed" in error_msg:
            logger.warning(f"Соединение закрыто при проверке GOST для {domain} через {url}: {e}")
        else:
            logger.warning(f"Ошибка клиента при проверке GOST для {domain} через {url}: {e}")
        return None, e, False
    except Exception as e:
        logger.error(f"Неожиданная ошибка при проверке GOST для {domain} через {url}: {e}", exc_info=True)
        return None, e, False
    finally:
        if local_connector is not None and not local_connector.closed:
            try:
                await local_connector.close()
            except Exception as e:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Ошибка при закрытии connector: {e}")


async def _remote_is_gost(domain: str, timeout: Optional[int] = None) -> Optional[bool]:
    """Проверяет наличие GOST сертификата через удаленные контейнеры.
    
    Использует параллельные запросы ко всем endpoints с общим таймаутом.
    Если все endpoints вернули 504, пробует через WireGuard.
    
    Args:
        domain: Домен для проверки
        timeout: Таймаут запроса (по умолчанию из settings)
        
    Returns:
        True/False если сервис ответил, None если все endpoints недоступны
    """
    if not _endpoints:
        logger.warning("Нет настроенных endpoints для проверки GOST")
        return None

    timeout = timeout or settings.GOST_CHECK_TIMEOUT
    # Уменьшаем таймаут для каждого endpoint, но увеличиваем общий таймаут
    endpoint_timeout = min(timeout, 10)  # Максимум 10 секунд на endpoint
    # Общий таймаут: endpoint_timeout + небольшой запас
    total_timeout = endpoint_timeout + 2
    
    # Перемешиваем endpoints для распределения нагрузки
    endpoints = _endpoints.copy()
    random.shuffle(endpoints)
    
    # Создаем задачи для параллельных запросов
    tasks = [
        asyncio.create_task(_check_single_endpoint(url, domain, endpoint_timeout))
        for url in endpoints
    ]
    
    try:
        # Ждем первый успешный ответ или таймаут
        done, pending = await asyncio.wait(
            tasks,
            timeout=total_timeout,
            return_when=asyncio.FIRST_COMPLETED
        )
        
        # Проверяем завершенные задачи
        all_504_errors = True
        last_error: Optional[Exception] = None
        checked_endpoints = 0  # Счетчик проверенных endpoints
        
        for task in done:
            try:
                result, error, is_504 = await task
                checked_endpoints += 1
                if result is not None:
                    # Успешный ответ - отменяем остальные задачи и возвращаем результат
                    # WireGuard НЕ используется - основной путь работает
                    for t in pending:
                        t.cancel()
                    return result
                if error:
                    last_error = error
                    if not is_504:
                        all_504_errors = False  # Хотя бы один endpoint вернул не 504
            except Exception as e:
                logger.warning(f"Ошибка при обработке результата от endpoint: {e}")
                last_error = e
                all_504_errors = False
                checked_endpoints += 1
        
        # Если есть еще незавершенные задачи, ждем их с коротким таймаутом
        if pending:
            try:
                done_remaining, _ = await asyncio.wait(
                    pending,
                    timeout=2.0,
                    return_when=asyncio.ALL_COMPLETED
                )
                for task in done_remaining:
                    try:
                        result, error, is_504 = await task
                        checked_endpoints += 1
                        if result is not None:
                            # Успешный ответ - WireGuard НЕ используется
                            return result
                        if error:
                            last_error = error
                            if not is_504:
                                all_504_errors = False  # Хотя бы один endpoint вернул не 504
                    except Exception:
                        checked_endpoints += 1
                        pass
            except Exception:
                pass
            
            # Отменяем оставшиеся задачи
            for task in pending:
                if not task.done():
                    task.cancel()
                    checked_endpoints += 1
        
    except asyncio.TimeoutError:
        logger.warning(f"Общий таймаут ({total_timeout}s) при проверке GOST для {domain}")
        # Отменяем все задачи
        for task in tasks:
            if not task.done():
                task.cancel()
        # При таймауте не используем WireGuard (это не 504 ошибки)
        all_504_errors = False
        last_error = asyncio.TimeoutError("Total timeout")
        checked_endpoints = len(endpoints)  # Все задачи были отменены
    
    # WireGuard используется ТОЛЬКО если:
    # 1. Все проверенные endpoints вернули 504 (all_504_errors == True)
    # 2. Проверены ВСЕ endpoints (checked_endpoints == len(endpoints))
    # 3. Есть ошибка (last_error не None)
    # Это гарантирует что WireGuard - резерв, а не основной путь
    if all_504_errors and checked_endpoints == len(endpoints) and last_error:
        logger.info(f"Все endpoints вернули 504 для {domain}, пробуем через WireGuard подключение")
        try:
            # Проверяем доступность WireGuard контейнера
            if not ensure_wg_interface_up():
                logger.warning(f"WireGuard контейнер недоступен для {domain}")
            else:
                # WireGuard теперь работает в отдельном контейнере
                # Запросы автоматически идут через WireGuard сеть благодаря Docker network
                # Используем обычный connector без local_addr привязки
                wg_timeout = aiohttp.ClientTimeout(total=timeout)
                connector = aiohttp.TCPConnector(
                    limit=10,
                    limit_per_host=3,
                    force_close=True,
                    ttl_dns_cache=300
                )
                
                async with aiohttp.ClientSession(
                    timeout=wg_timeout,
                    connector=connector
                ) as session:
                    # Пробуем первый endpoint через WireGuard сеть
                    if _endpoints:
                        wg_url = _endpoints[0]
                        try:
                            async with session.get(
                                wg_url,
                                params={"domain": domain}
                            ) as resp:
                                if resp.status == 200:
                                    data = await resp.json()
                                    result = bool(data.get("is_gost"))
                                    logger.info(f"✅ GOST проверка для {domain} через WireGuard: {result}")
                                    return result
                                else:
                                    logger.warning(f"WireGuard подключение вернуло статус {resp.status} для {domain}")
                        except asyncio.TimeoutError:
                            logger.warning(f"Таймаут при использовании WireGuard для {domain}")
                        except (aiohttp.ClientError, RuntimeError) as wg_error:
                            logger.warning(f"Ошибка при использовании WireGuard для {domain}: {wg_error}")
                        except Exception as wg_error:
                            logger.error(f"Неожиданная ошибка при использовании WireGuard для {domain}: {wg_error}", exc_info=True)
                        finally:
                            try:
                                await connector.close()
                            except Exception:
                                pass
        except Exception as e:
            logger.warning(f"Не удалось использовать WireGuard подключение для {domain}: {e}")
    
    logger.error(f"Все GOST endpoints недоступны для {domain}. Последняя ошибка: {last_error}")
    return None


async def _get_gost_certificate_info(domain: str, port: int = 443) -> Optional[Dict[str, Any]]:
    """Получает информацию о GOST TLS сертификате.
    
    Пытается подключиться с GOST шифрами для получения GOST сертификата.
    
    Args:
        domain: Домен для проверки
        port: Порт для подключения
        
    Returns:
        Словарь с датами GOST сертификата или None если не удалось получить
    """
    try:
        # Создаем SSL контекст с поддержкой GOST
        ctx = ssl.create_default_context()
        # Пытаемся использовать GOST шифры
        ctx.set_ciphers('GOST2012-GOST8912-GOST89:!aNULL:!eNULL')
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port, ssl=ctx),
                timeout=settings.GOST_CHECK_TIMEOUT
            )
        except (ssl.SSLError, asyncio.TimeoutError, OSError):
            # Если не удалось подключиться с GOST - возможно домен не поддерживает
            return None
        
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                cert_bin = ssl_obj.getpeercert(True)
                if cert_bin:
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    # Проверяем, что это действительно GOST сертификат
                    if _cert_is_gost(cert):
                        try:
                            not_before = cert.not_valid_before_utc
                            not_after = cert.not_valid_after_utc
                        except AttributeError:
                            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
                        
                        return {
                            "GostNotBefore": not_before,
                            "GostNotAfter": not_after,
                        }
        finally:
            writer.close()
            await writer.wait_closed()
    except Exception as e:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Не удалось получить GOST сертификат для {domain}: {e}")
    
    return None


# ----------------------------
#  Main entry point
# ----------------------------
@ttl_cache(ttl=3600)  # Кэш на 1 час
async def fetch_ssl(domain: str, port: int = 443) -> Dict[str, Any]:
    """Получает информацию об SSL сертификатах домена.
    
    Проверяет как обычный сертификат, так и GOST TLS сертификат (если доступен).
    
    Args:
        domain: Домен для проверки
        port: Порт для подключения (по умолчанию 443)
        
    Returns:
        Словарь с информацией о сертификатах:
        - CN: Common Name
        - SAN: Subject Alternative Names
        - Issuer: Издатель сертификата
        - NotBefore, NotAfter: Даты действия обычного сертификата
        - GostNotBefore, GostNotAfter: Даты действия GOST сертификата (если есть)
        - SigAlg: Алгоритм подписи
        - Cipher: Используемый шифр
        - IsGOST, gost: Наличие GOST (булево)
    """
    # Шаг 1: Проверка через удаленный сервис
    is_gost_remote = await _remote_is_gost(domain)
    # Флаг, показывающий, что удаленная проверка не удалась (все endpoints недоступны)
    gost_check_failed = (is_gost_remote is None)
    
    # Шаг 2: Локальная проверка TLS соединения
    ctx = ssl.create_default_context()
    cert_info = {
        "CN": None,
        "SAN": [],
        "Issuer": None,
        "NotBefore": None,
        "NotAfter": None,
        "GostNotBefore": None,
        "GostNotAfter": None,
        "SigAlg": None,
        "Cipher": None,
        "IsGOST": is_gost_remote if is_gost_remote is not None else False,
        "gost": is_gost_remote if is_gost_remote is not None else False,
        "GostCheckFailed": gost_check_failed,  # Флаг: True если не удалось проверить через endpoints
    }
    
    try:
        # Используем более короткий таймаут для обычного SSL соединения
        ssl_timeout = min(settings.HTTP_TIMEOUT, 10)  # Не более 10 секунд
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, port, ssl=ctx),
            timeout=ssl_timeout
        )
    except asyncio.TimeoutError:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Таймаут при подключении к {domain}:{port}")
        return cert_info
    except Exception as e:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Не удалось подключиться к {domain}:{port}: {e}")
        return cert_info

    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        cert_bin = ssl_obj.getpeercert(True)
        negotiated_cipher = ssl_obj.cipher()[0] if ssl_obj.cipher() else None

        cert = x509.load_der_x509_certificate(cert_bin, default_backend())
        
        # Извлекаем CN
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cert_info["CN"] = ", ".join([attr.value for attr in cn_attrs]) if cn_attrs else None
        
        # Извлекаем SAN
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            cert_info["SAN"] = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        # Даты действия обычного сертификата
        try:
            cert_info["NotBefore"] = cert.not_valid_before_utc
            cert_info["NotAfter"] = cert.not_valid_after_utc
        except AttributeError:
            cert_info["NotBefore"] = cert.not_valid_before.replace(tzinfo=timezone.utc)
            cert_info["NotAfter"] = cert.not_valid_after.replace(tzinfo=timezone.utc)

        cert_info["Issuer"] = cert.issuer.rfc4514_string()
        cert_info["SigAlg"] = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid)
        cert_info["Cipher"] = negotiated_cipher
        
        # Определяем GOST
        if is_gost_remote is None:
            # Если удаленная проверка не сработала, используем локальную эвристику
            is_gost = _cert_is_gost(cert) or (negotiated_cipher and _cipher_is_gost(negotiated_cipher))
            # Если локальная проверка тоже не дала результата, оставляем флаг gost_check_failed
            if not is_gost:
                cert_info["GostCheckFailed"] = True
        else:
            is_gost = is_gost_remote
            # Если удаленная проверка прошла успешно, сбрасываем флаг
            cert_info["GostCheckFailed"] = False
        
        cert_info["IsGOST"] = is_gost
        cert_info["gost"] = is_gost
        
    finally:
        writer.close()
        await writer.wait_closed()
    
    # Шаг 3: Пытаемся получить информацию о GOST TLS сертификате
    if is_gost:
        gost_cert_info = await _get_gost_certificate_info(domain, port)
        if gost_cert_info:
            cert_info["GostNotBefore"] = gost_cert_info.get("GostNotBefore")
            cert_info["GostNotAfter"] = gost_cert_info.get("GostNotAfter")
    
    return cert_info
