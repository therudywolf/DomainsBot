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

# Резервные варианты при массовых 504
# Прокси Яндекса (если задан через переменную окружения)
# Формат: http://proxy.yandex.ru:3128 или socks5://proxy.yandex.ru:1080
_yandex_proxy: Optional[str] = os.getenv("YANDEX_PROXY")
# DNS Яндекса для информации (используется для логирования)
_yandex_dns: str = os.getenv("YANDEX_DNS", "77.88.8.8")

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


async def _remote_is_gost(domain: str, timeout: Optional[int] = None) -> Optional[bool]:
    """Проверяет наличие GOST сертификата через удаленные контейнеры.
    
    Использует retry логику: пробует все доступные endpoints по очереди,
    если один не отвечает, переключается на следующий.
    
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
    timeout_obj = aiohttp.ClientTimeout(total=timeout)
    
    # Перемешиваем endpoints для распределения нагрузки
    endpoints = _endpoints.copy()
    random.shuffle(endpoints)
    
    last_error: Optional[Exception] = None
    all_504_errors = True  # Флаг для отслеживания массовых 504
    
    # Пробуем каждый endpoint с ограничением времени
    max_total_time = timeout * len(endpoints)  # Максимальное время на все попытки
    start_time = asyncio.get_running_loop().time()
    
    for attempt, url in enumerate(endpoints, 1):
        # Проверяем, не превысили ли общий таймаут
        elapsed = asyncio.get_running_loop().time() - start_time
        if elapsed >= max_total_time:
            logger.warning(f"Превышен общий таймаут для проверки GOST {domain} ({elapsed:.2f}s)")
            break
            
        local_connector = None
        try:
            # Создаем новый connector для каждой попытки, чтобы избежать проблем с закрытием
            # Используем локальный connector вместо глобального для изоляции
            local_connector = aiohttp.TCPConnector(
                limit=10,
                limit_per_host=3,
                force_close=True,  # Закрываем соединения после использования
                ttl_dns_cache=300,
            )
            
            async with aiohttp.ClientSession(
                timeout=timeout_obj,
                connector=local_connector
            ) as session:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Проверка GOST для {domain} через {url} (попытка {attempt}/{len(endpoints)})")
                
                try:
                    async with session.get(url, params={"domain": domain}) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            result = bool(data.get("is_gost"))
                            if logger.isEnabledFor(logging.DEBUG):
                                logger.debug(f"GOST проверка для {domain}: {result} (через {url})")
                            all_504_errors = False  # Успешный ответ, не все 504
                            return result
                        elif resp.status == 504:
                            logger.warning(f"GOST endpoint {url} вернул 504 (Gateway Timeout) для {domain}")
                            last_error = Exception(f"HTTP 504")
                            # Продолжаем попытки, но отмечаем что это 504
                        else:
                            logger.warning(f"GOST endpoint {url} вернул статус {resp.status} для {domain}")
                            last_error = Exception(f"HTTP {resp.status}")
                            all_504_errors = False  # Другая ошибка, не все 504
                except RuntimeError as e:
                    if "Session is closed" in str(e):
                        logger.warning(f"Сессия закрыта для {domain} через {url}, пропускаем")
                        last_error = e
                    else:
                        raise
        except asyncio.TimeoutError:
            logger.warning(f"Таймаут при проверке GOST для {domain} через {url}")
            last_error = asyncio.TimeoutError("Timeout")
            all_504_errors = False  # Таймаут - не 504, не используем прокси
        except (aiohttp.ClientError, RuntimeError) as e:
            error_msg = str(e)
            if "Session is closed" in error_msg or "Connector is closed" in error_msg:
                logger.warning(f"Соединение закрыто при проверке GOST для {domain} через {url}: {e}")
            else:
                logger.warning(f"Ошибка клиента при проверке GOST для {domain} через {url}: {e}")
            last_error = e
            all_504_errors = False  # Ошибка соединения - не 504, не используем прокси
        except Exception as e:
            logger.error(f"Неожиданная ошибка при проверке GOST для {domain} через {url}: {e}", exc_info=True)
            last_error = e
        finally:
            # Закрываем connector после использования
            if local_connector is not None and not local_connector.closed:
                try:
                    await local_connector.close()
                except Exception as e:
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Ошибка при закрытии connector: {e}")
        
        # Небольшая задержка перед следующей попыткой (только если не последняя)
        if attempt < len(endpoints):
            await asyncio.sleep(settings.GOST_RETRY_DELAY)
    
    # Если все endpoints вернули 504 и есть резервный прокси - пробуем через прокси
    if all_504_errors and _yandex_proxy:
        logger.info(f"Все endpoints вернули 504 для {domain}, пробуем через резервный прокси Яндекса")
        try:
            proxy_timeout = aiohttp.ClientTimeout(total=timeout)
            connector = aiohttp.TCPConnector(
                limit=10,
                limit_per_host=3,
                force_close=True,
                ttl_dns_cache=300,
            )
            
            async with aiohttp.ClientSession(
                timeout=proxy_timeout,
                connector=connector
            ) as session:
                # Пробуем первый endpoint через прокси
                if _endpoints:
                    proxy_url = _endpoints[0]
                    try:
                        async with session.get(
                            proxy_url,
                            params={"domain": domain},
                            proxy=_yandex_proxy
                        ) as resp:
                            if resp.status == 200:
                                data = await resp.json()
                                result = bool(data.get("is_gost"))
                                logger.info(f"✅ GOST проверка для {domain} через прокси Яндекса: {result}")
                                return result
                            else:
                                logger.warning(f"Прокси Яндекса вернул статус {resp.status} для {domain}")
                    except asyncio.TimeoutError:
                        logger.warning(f"Таймаут при использовании прокси Яндекса для {domain}")
                    except (aiohttp.ClientError, RuntimeError) as proxy_error:
                        logger.warning(f"Ошибка при использовании прокси Яндекса для {domain}: {proxy_error}")
                    except Exception as proxy_error:
                        logger.error(f"Неожиданная ошибка при использовании прокси Яндекса для {domain}: {proxy_error}", exc_info=True)
                    finally:
                        try:
                            await connector.close()
                        except Exception:
                            pass
        except Exception as e:
            logger.warning(f"Не удалось использовать резервный прокси Яндекса для {domain}: {e}")
    
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
