"""Async HTTP property checker for domains."""

import logging
from typing import Dict, Any, List, Optional

import aiohttp

from utils.cache import ttl_cache

logger = logging.getLogger(__name__)

_SECURITY_HEADER_MAP = {
    "strict_transport_security": "strict-transport-security",
    "x_frame_options": "x-frame-options",
    "x_content_type_options": "x-content-type-options",
    "content_security_policy": "content-security-policy",
    "permissions_policy": "permissions-policy",
    "x_xss_protection": "x-xss-protection",
}

_MAX_REDIRECTS = 10


def _empty_result() -> Dict[str, Any]:
    return {
        "redirect_chain": [],
        "final_url": None,
        "status_code": None,
        "server": None,
        "security_headers": {k: False for k in _SECURITY_HEADER_MAP},
        "https_available": False,
        "http_to_https_redirect": False,
    }


def _parse_security_headers(headers: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, header_name in _SECURITY_HEADER_MAP.items():
        value = headers.get(header_name)
        result[key] = value if value else False
    return result


async def _follow_redirects(
    session: aiohttp.ClientSession,
    url: str,
    timeout: aiohttp.ClientTimeout,
) -> tuple[List[str], Optional[aiohttp.ClientResponse]]:
    """Manually follow redirects to capture the full chain."""
    chain: List[str] = [url]
    resp: Optional[aiohttp.ClientResponse] = None

    for _ in range(_MAX_REDIRECTS):
        try:
            resp = await session.get(
                url, allow_redirects=False, timeout=timeout, ssl=False,
            )
        except Exception:
            break

        if resp.status in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            resp.close()
            if not location:
                break
            if location.startswith("/"):
                from yarl import URL as YarlURL
                base = YarlURL(url)
                location = str(base.origin()) + location
            url = location
            chain.append(url)
            resp = None
        else:
            break

    return chain, resp


@ttl_cache(ttl=3600)
async def fetch_http_info(domain: str, timeout: int = 10) -> Dict[str, Any]:
    """Fetch HTTP properties of a domain.

    Returns partial results on errors rather than raising.
    """
    result = _empty_result()
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # --- HTTPS probe ---
        https_url = f"https://{domain}"
        try:
            async with session.head(
                https_url, timeout=client_timeout, allow_redirects=False, ssl=False,
            ) as resp:
                result["https_available"] = True
        except Exception:
            result["https_available"] = False

        # --- HTTP redirect chain ---
        http_url = f"http://{domain}"
        try:
            chain, resp = await _follow_redirects(session, http_url, client_timeout)
            result["redirect_chain"] = chain
            result["final_url"] = chain[-1]

            if any(u.startswith("https://") for u in chain[1:]):
                result["http_to_https_redirect"] = True

            if resp is not None:
                result["status_code"] = resp.status
                result["server"] = resp.headers.get("Server")
                result["security_headers"] = _parse_security_headers(resp.headers)
                resp.close()
        except Exception as exc:
            logger.debug("Error following HTTP redirects for %s: %s", domain, exc)

        # --- If HTTPS available but no security headers yet, fetch from HTTPS ---
        if result["https_available"] and result["status_code"] is None:
            try:
                chain, resp = await _follow_redirects(
                    session, https_url, client_timeout,
                )
                result["redirect_chain"] = chain
                result["final_url"] = chain[-1]

                if resp is not None:
                    result["status_code"] = resp.status
                    result["server"] = resp.headers.get("Server")
                    result["security_headers"] = _parse_security_headers(resp.headers)
                    resp.close()
            except Exception as exc:
                logger.debug("Error fetching HTTPS for %s: %s", domain, exc)

    return result
