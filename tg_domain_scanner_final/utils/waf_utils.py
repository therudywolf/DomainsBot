from utils.cache import ttl_cache
from typing import Sequence
import aiohttp, asyncio

# Разрешён только один «безобидный» мониторинговый запрос
PAYLOADS: Sequence[str] = (
    "/?monitoring=test_query_for_policy",
)

BLOCK_CODES = {403, 406, 429, 501, 502, 503}


async def _fetch(session: aiohttp.ClientSession, url: str, timeout: int):
    """Return tuple(status, body_len). Guarantees connection closed."""
    async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
        try:
            body = await resp.text()
        except Exception:
            body = ""
        return resp.status, len(body)


@ttl_cache()
async def test_waf(domain: str, timeout: int = 6) -> bool:
    """Heuristically detect presence of WAF on *domain*."""
    base_url = f"https://{domain}"
    connector = aiohttp.TCPConnector(limit=20, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            base_status, base_len = await _fetch(session, base_url, timeout)
        except Exception:
            return True   # can't reach site – assume protected

        for p in PAYLOADS:
            try:
                status, length = await _fetch(session, base_url + p, timeout)
                if status in BLOCK_CODES or status != base_status:
                    return True
                if abs(length - base_len) > base_len * 0.5:
                    return True
            except Exception:
                return True
    return False
