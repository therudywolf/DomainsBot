
from utils.cache import ttl_cache
from typing import Sequence, Tuple
import aiohttp

PAYLOADS: Sequence[str] = (
    "/?<script>alert('x')</script>",
    "/etc/passwd",
    "/?id=1+union+select+1,2,3",
    "/../../../boot.ini",
)
BLOCK_CODES = {403, 406, 429, 501, 502, 503}

async def _fetch(session: aiohttp.ClientSession, url: str, timeout: int) -> Tuple[int, str]:
    """Return (status_code, body) and ensure the connection is released."""
    async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
        body = await resp.text()
        return resp.status, body

@ttl_cache()
async def test_waf(domain: str, timeout: int = 6) -> bool:
    """Very rough WAF detector: if payload requests behave differently from baseline."""
    base_url = f"https://{domain}"

    # Restrict the number of simultaneous connections & disable keep‑alive to avoid leaks
    connector = aiohttp.TCPConnector(limit=20, force_close=True)

    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            base_status, base_body = await _fetch(session, base_url, timeout)
            base_len = len(base_body)
        except Exception:
            # If even the baseline request fails, assume WAF or server misbehaving.
            return True

        for p in PAYLOADS:
            try:
                status, body = await _fetch(session, base_url + p, timeout)
                if status in BLOCK_CODES or status != base_status:
                    return True
                if abs(len(body) - base_len) > base_len * 0.5:
                    return True
            except Exception:
                return True
    return False
