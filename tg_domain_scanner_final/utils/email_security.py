"""Async email-security record checker (SPF & DMARC)."""

import logging
from typing import Dict, Any, Optional

import dns.asyncresolver
import dns.exception

from utils.cache import ttl_cache

logger = logging.getLogger(__name__)


async def _query_txt(name: str, timeout: float) -> list[str]:
    """Return all TXT record strings for *name*, or an empty list on failure."""
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    try:
        answers = await resolver.resolve(name, "TXT")
        return [
            b"".join(rdata.strings).decode("utf-8", errors="replace")
            for rdata in answers
        ]
    except (dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer,
            dns.asyncresolver.NoNameservers, dns.exception.Timeout) as exc:
        logger.debug("TXT lookup failed for %s: %s", name, exc)
        return []
    except Exception as exc:
        logger.debug("Unexpected error querying TXT for %s: %s", name, exc)
        return []


def _extract_spf(txt_records: list[str]) -> Optional[str]:
    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            return record
    return None


def _extract_dmarc_policy(dmarc_record: str) -> Optional[str]:
    for part in dmarc_record.split(";"):
        part = part.strip().lower()
        if part.startswith("p="):
            return part[2:].strip()
    return None


@ttl_cache(ttl=3600)
async def fetch_email_security(domain: str, timeout: int = 5) -> Dict[str, Any]:
    """Fetch SPF and DMARC records for *domain*.

    Returns partial results on errors rather than raising.
    """
    result: Dict[str, Any] = {
        "spf": None,
        "spf_valid": False,
        "dmarc": None,
        "dmarc_policy": None,
    }

    # SPF — TXT record on the domain itself
    txt_records = await _query_txt(domain, timeout)
    spf_record = _extract_spf(txt_records)
    if spf_record:
        result["spf"] = spf_record
        result["spf_valid"] = spf_record.lower().startswith("v=spf1")

    # DMARC — TXT record on _dmarc.<domain>
    dmarc_name = f"_dmarc.{domain}"
    dmarc_records = await _query_txt(dmarc_name, timeout)
    for record in dmarc_records:
        if record.lower().startswith("v=dmarc1"):
            result["dmarc"] = record
            result["dmarc_policy"] = _extract_dmarc_policy(record)
            break

    return result
