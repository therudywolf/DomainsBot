from utils.cache import ttl_cache
from typing import Sequence
import aiohttp

PAYLOADS: Sequence[str] = (
    "/?<script>alert('x')</script>",
    "/etc/passwd",
    "/?id=1+union+select+1,2,3",
    "/../../../boot.ini",
)
BLOCK_CODES = {403, 406, 429, 501, 502, 503}

async def _fetch(session: aiohttp.ClientSession, url: str, timeout: int):
    return await session.get(url, timeout=timeout, allow_redirects=True)

@ttl_cache()
async def test_waf(domain: str, timeout: int = 6) -> bool:
    base_url = f"https://{domain}"
    async with aiohttp.ClientSession() as session:
        try:
            base_resp = await _fetch(session, base_url, timeout)
            base_status = base_resp.status
            base_len = len(await base_resp.text())
        except Exception:
            return True

        for p in PAYLOADS:
            try:
                r = await _fetch(session, base_url + p, timeout)
                if r.status in BLOCK_CODES or r.status != base_status:
                    return True
                body = await r.text()
                if abs(len(body) - base_len) > base_len * 0.5:
                    return True
            except Exception:
                return True
    return False
