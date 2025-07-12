
from utils.cache import ttl_cache
import asyncio, ssl, os, random, typing as t
from typing import Dict, Any, Optional, List
import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

# ----------------------------
#  GOST detection helpers
# ----------------------------
GOST_OID_PREFIX = "1.2.643."
GOST_CIPHERS = "GOST2012-GOST8912-GOST89"

def _cert_is_gost(cert: x509.Certificate) -> bool:
    """Heuristic: certificate signature algorithm OID starts with GOST prefix."""
    return cert.signature_algorithm_oid.dotted_string.startswith(GOST_OID_PREFIX)

def _cipher_is_gost(cipher_name: str) -> bool:
    return any(c in cipher_name for c in GOST_CIPHERS.split("-"))

# ----------------------------
#  Remote GOST check
# ----------------------------
# 1) If explicit GOST_CHECK_URL defined – use only it.
# 2) Else, list of container hostnames in GOSTSSL_HOSTS (comma‑separated).
#    By default single "gostsslcheck".
if os.getenv("GOST_CHECK_URL"):
    _endpoints: List[str] = [os.getenv("GOST_CHECK_URL")]
else:
    _hosts: List[str] = [h.strip() for h in os.getenv("GOSTSSL_HOSTS", "gostsslcheck").split(',') if h.strip()]
    _endpoints: List[str] = [f"http://{h}:8080/check" for h in _hosts]

async def _remote_is_gost(domain: str, timeout: int = 20) -> Optional[bool]:
    """Ask one of the GostSSLCheck instances whether certificate is GOST.
    Returns True/False if service responded, or None if unreachable/timeout.
    """
    if not _endpoints:
        return None

    url = random.choice(_endpoints)
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout),
            connector=aiohttp.TCPConnector(limit=20, force_close=True)
        ) as session:
            async with session.get(url, params={"domain": domain}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return bool(data.get("is_gost"))
    except Exception:
        return None
    return None

# ----------------------------
#  Main entry point
# ----------------------------
@ttl_cache(ttl=3600)  # cache for 1 hour
async def fetch_ssl(domain: str, port: int = 443) -> Dict[str, Any]:
    """Return SSL info for *domain*.

    Keys: CN, SAN, Issuer, NotBefore, NotAfter, SigAlg, Cipher, IsGOST, gost"""
    # Step 1: remote service
    is_gost_remote = await _remote_is_gost(domain)

    # Step 2: local TLS introspection
    ctx = ssl.create_default_context()
    try:
        reader, writer = await asyncio.open_connection(domain, port, ssl=ctx)
    except Exception:
        return {
            "CN": None, "SAN": [], "Issuer": None,
            "NotBefore": None, "NotAfter": None,
            "SigAlg": None, "Cipher": None,
            "IsGOST": is_gost_remote,
            "gost": is_gost_remote,
        }

    ssl_obj = writer.get_extra_info("ssl_object")
    cert_bin = ssl_obj.getpeercert(True)
    negotiated_cipher = ssl_obj.cipher()[0]
    writer.close()
    await writer.wait_closed()

    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
    cn = ", ".join([attr.value for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)])
    san = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    if is_gost_remote is None:
        is_gost = _cert_is_gost(cert) or _cipher_is_gost(negotiated_cipher)
    else:
        is_gost = is_gost_remote

    return {
        "CN": cn,
        "SAN": san,
        "Issuer": cert.issuer.rfc4514_string(),
        "NotBefore": cert.not_valid_before,
        "NotAfter": cert.not_valid_after,
        "SigAlg": cert.signature_algorithm_oid._name,
        "Cipher": negotiated_cipher,
        "IsGOST": is_gost,
        "gost": is_gost,
    }
