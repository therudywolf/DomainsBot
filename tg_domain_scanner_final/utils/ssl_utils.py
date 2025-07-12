from utils.cache import ttl_cache
import asyncio, ssl, os
from typing import Dict, Any
import typing as t
import aiohttp
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

# Fallback detection constants (kept but not used by default)
GOST_OID_PREFIX = "1.2.643."
GOST_CIPHERS = "GOST2012-GOST8912-GOST89"

def _cert_is_gost(cert: x509.Certificate) -> bool:
    """Heuristic: certificate signature algorithm OID starts with GOST prefix."""
    return cert.signature_algorithm_oid.dotted_string.startswith(GOST_OID_PREFIX)

async def _handshake_is_gost(domain: str, timeout: int = 5) -> bool:
    """
    Heuristic: try TLS handshake with only GOST ciphers; if succeeds – server supports GOST.
    Left as fallback when remote service unavailable.
    """
    cmd = [
        "openssl", "s_client",
        "-quiet",
        "-cipher", GOST_CIPHERS,
        "-connect", f"{domain}:443",
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

async def _remote_is_gost(domain: str, timeout: int = 20) -> t.Optional[bool]:
    """Ask external GostSSLCheck service whether certificate is GOST."""
    url = os.getenv("GOST_CHECK_URL", "http://gostsslcheck:8080/check")
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get(url, params={"domain": domain}) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return bool(data.get("is_gost"))
    except Exception:
        pass
    return None  # service unreachable

@ttl_cache()
async def fetch_ssl(domain: str, port: int = 443) -> Dict[str, Any]:
    """Return SSL info for domain; IsGOST fetched remotely."""
    # First, attempt remote GOST check
    is_gost_remote = await _remote_is_gost(domain)

    # Regardless of remote result, gather certificate info locally (for CN, SAN, etc.)
    ctx = ssl.create_default_context()
    try:
        reader, writer = await asyncio.open_connection(domain, port, ssl=ctx)
    except Exception:
        # If connection fails, return minimal info
        return {"CN": None, "SAN": [], "Issuer": None, "NotBefore": None,
                "NotAfter": None, "SigAlg": None, "Cipher": None, "IsGOST": is_gost_remote, "gost": is_gost_remote }


    ssl_obj = writer.get_extra_info("ssl_object")
    cert_bin = ssl_obj.getpeercert(True)
    negotiated_cipher = ssl_obj.cipher()[0] if ssl_obj else None
    writer.close()
    await writer.wait_closed()

    cert = x509.load_der_x509_certificate(cert_bin, backend=default_backend())

    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attr[0].value if cn_attr else ""
    san = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san = san_ext.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    # If remote not reachable, fall back to heuristics
    if is_gost_remote is None:
        gost_cert_flag, gost_handshake_flag = await asyncio.gather(
            asyncio.to_thread(_cert_is_gost, cert),
            _handshake_is_gost(domain, timeout=5),
        )
        is_gost = gost_cert_flag or gost_handshake_flag
    else:
        is_gost = is_gost_remote

    return {
        "CN": cn,
        "SAN": san,
        "Issuer": cert.issuer.rfc4514_string(),
        "NotBefore": cert.not_valid_before_utc,
        "NotAfter": cert.not_valid_after_utc,
        "SigAlg": cert.signature_algorithm_oid._name,
        "Cipher": negotiated_cipher,
        "IsGOST": is_gost,
        "gost": is_gost,
    }
