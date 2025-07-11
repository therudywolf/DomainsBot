
"""Utilities for retrieving SSL information and detecting GOST certificates.

* Основная функция ``fetch_ssl(domain)`` возвращает структуру с данными сертификата
  и булевым полем ``IsGOST``. Сначала пробует внешний сервис, при недоступности
  включает локальные эвристики (проверка OID и попытка GOST‑handshake).

В модуле реализованы:

* анти‑stampede кэш (`ttl_cache`) сверху на 6 ч;
* семафор для ограничения одновременных обращений к внешнему сервису;
* корректное различие «сервер ответил False» vs «сервер недоступен».
"""

from utils.cache import ttl_cache
import asyncio
import ssl
import os
import logging
from typing import Dict, Any, Optional

import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

# Fallback detection constants
GOST_OID_PREFIX = "1.2.643."
GOST_CIPHERS = "GOST2012-GOST8912-GOST89"

_REMOTE_SEM = asyncio.Semaphore(int(os.getenv("REMOTE_GOST_CONCURRENCY", 5)))

# ---------------------------------------------------------------------------
# Low‑level helpers
# ---------------------------------------------------------------------------

def _cert_is_gost(cert: x509.Certificate) -> bool:
    """Heuristic: certificate signature algorithm OID starts with GOST prefix."""
    return cert.signature_algorithm_oid.dotted_string.startswith(GOST_OID_PREFIX)


async def _handshake_is_gost(domain: str, timeout: int = 5) -> bool:
    """Attempt TLS handshake with GOST ciphers only; succeeds ⇒ server speaks GOST."""
    ctx = ssl.create_default_context()
    ctx.set_ciphers(GOST_CIPHERS)
    cmd = [
        "openssl",
        "s_client",
        "-connect",
        f"{domain}:443",
        "-cipher",
        GOST_CIPHERS,
        "-brief",
        "-verify",
        "0",
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return False
    return proc.returncode == 0


async def _remote_is_gost(domain: str, timeout: int = 5) -> Optional[bool]:
    """Ask external GostSSLCheck service whether certificate is GOST.

    Returns:
        * ``True``  – сертификат ГОСТ;
        * ``False`` – сертификат НЕ ГОСТ;
        * ``None``  – сервис недоступен / ошибка / таймаут.
    """  # noqa: D401
    url = os.getenv("GOST_CHECK_URL", "http://gostsslcheck:8080/check")
    try:
        async with _REMOTE_SEM:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as session:
                async with session.get(url, params={"domain": domain}) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return bool(data.get("is_gost"))
                    logging.warning(
                        "GOST‑check service returned %s for %s", resp.status, domain
                    )
    except Exception as e:  # pylint: disable=broad-except
        logging.warning("GOST‑check service error for %s: %s", domain, e)
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@ttl_cache()  # TTL и размер управляются через переменные окружения
async def fetch_ssl(domain: str, port: int = 443) -> Dict[str, Any]:
    """Return SSL info for *domain* with GOST detection.

    Поля результата::

        {
            "CN":        <Common Name строки>,
            "SAN":       [<список SAN>],
            "Issuer":    <строка>,
            "NotBefore": datetime,
            "NotAfter":  datetime,
            "SigAlg":    <алгоритм подписи>,
            "Cipher":    <negotiated cipher>,
            "IsGOST":    bool
        }
    """
    # ---------------------------------------------------------------------
    # 1. Пробуем внешний сервис – быстрее и точнее
    # ---------------------------------------------------------------------
    is_gost_remote = await _remote_is_gost(domain)
    use_fallback = is_gost_remote is None

    # ---------------------------------------------------------------------
    # 2. Собираем данные сертификата через стандартный TLS‑handshake
    # ---------------------------------------------------------------------
    ctx = ssl.create_default_context()
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    try:
        reader, writer = await asyncio.open_connection(domain, port, ssl=ctx)
    except Exception as exc:
        logging.error("TLS connect to %s failed: %s", domain, exc)
        raise

    ssl_obj = writer.get_extra_info("ssl_object")
    cert_bin = ssl_obj.getpeercert(True) if ssl_obj else b""  # type: ignore[arg-type]
    negotiated_cipher = ssl_obj.cipher()[0] if ssl_obj else None  # type: ignore[index]

    writer.close()
    await writer.wait_closed()

    cert = x509.load_der_x509_certificate(cert_bin, backend=default_backend())

    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attr[0].value if cn_attr else ""

    san: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
        san = san_ext.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    # ---------------------------------------------------------------------
    # 3. Fallback‑эвристики – если сервис был недоступен
    # ---------------------------------------------------------------------
    if use_fallback:
        gost_cert_flag, gost_handshake_flag = await asyncio.gather(
            asyncio.to_thread(_cert_is_gost, cert),
            _handshake_is_gost(domain, timeout=5),
        )
        is_gost = gost_cert_flag or gost_handshake_flag
    else:
        is_gost = bool(is_gost_remote)

    return {
        "CN": cn,
        "SAN": san,
        "Issuer": cert.issuer.rfc4514_string(),
        "NotBefore": cert.not_valid_before,
        "NotAfter": cert.not_valid_after,
        "SigAlg": cert.signature_algorithm_oid._name,  # pylint: disable=protected-access
        "Cipher": negotiated_cipher,
        "IsGOST": is_gost,
    }
