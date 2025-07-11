
"""Utility functions to format domain scan results for Telegram."""

from typing import Dict, List, Any

def _shorten_san(san: List[str], max_items: int = 5) -> str:
    """Return nicely shortened SAN string."""
    if not san:
        return "—"
    if len(san) <= max_items:
        return ", ".join(san)
    return ", ".join(san[:max_items]) + f", … (+{len(san) - max_items})"

def build_report(
    domain: str,
    dns: Dict[str, List[str]],
    ssl: Dict[str, Any],
    waf: bool,
    *,
    brief: bool = False,
    max_san: int = 5,
) -> str:
    """Return pretty‑printed report for a single domain.

    Args:
        domain: domain name
        dns: DNS records dict
        ssl: SSL info dict
        waf: whether WAF detected
        brief: if True – only valid dates, WAF and GOST certificate lines
        max_san: how many SAN items to show before truncating
    """
    lines: List[str] = [f"🔍 <b>{domain}</b>"]

    if not brief:
        ip = ", ".join(dns.get("IP", [])) or "—"
        zone = "." + domain.split(".")[-1]
        lines += [f"IP: {ip}", f"Зона: {zone}"]

        for rt in ("A", "AAAA", "MX", "NS"):
            rec = ", ".join(dns.get(rt, []))
            lines.append(f"{rt}: {rec or '—'}")

        lines += [
            "SSL:",
            f"  CN: {ssl.get('CN', '—')}",
            f"  SAN: {_shorten_san(ssl.get('SAN', []), max_san)}",
            f"  Issuer: {ssl.get('Issuer', '—')}",
            f"  Алгоритм подписи: {ssl.get('SigAlg', '—')}",
            f"  Cipher: {ssl.get('Cipher', '—')}",
        ]

    lines.append(
        f"  Действителен: {ssl.get('NotBefore').date() if ssl.get('NotBefore') else '—'} → "
        f"{ssl.get('NotAfter').date() if ssl.get('NotAfter') else '—'}"
    )
    lines.append(f"WAF: {'Включён' if waf else 'Нет'}")
    lines.append(f"ГОСТ‑сертификат: {'✅' if ssl.get("gost") else '✖️'}")
    lines.append("──────────")
    return "\n".join(lines)
