from utils.cache import ttl_cache
import dns.asyncresolver
import socket
from typing import Dict, List

async def _query(resolver: dns.asyncresolver.Resolver, domain: str, rdtype: str):
    try:
        return [rr.to_text() for rr in await resolver.resolve(domain, rdtype)]
    except Exception:
        return []

@ttl_cache()
async def fetch_dns(domain: str, timeout: int = 5) -> Dict[str, List[str]]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    res: Dict[str, List[str]] = {k: [] for k in ("A","AAAA","MX","NS","IP")}
    for rt in ("A","AAAA","MX","NS"):
        res[rt] = await _query(resolver, domain, rt)
    try:
        res["IP"] = socket.gethostbyname_ex(domain)[2]
    except socket.gaierror:
        pass
    return res
