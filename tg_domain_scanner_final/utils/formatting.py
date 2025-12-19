"""Утилиты для форматирования результатов сканирования доменов для Telegram."""

from typing import Dict, List, Any
from datetime import datetime


def _shorten_san(san: List[str], max_items: int = 5) -> str:
    """Сокращает список SAN для удобного отображения.
    
    Args:
        san: Список SAN значений
        max_items: Максимальное количество элементов для отображения
        
    Returns:
        Строка с SAN значениями
    """
    if not san:
        return "—"
    if len(san) <= max_items:
        return ", ".join(san)
    return ", ".join(san[:max_items]) + f", … (+{len(san) - max_items})"


def _format_date(date_obj: Any) -> str:
    """Форматирует дату для отображения.
    
    Args:
        date_obj: Объект даты (datetime или None)
        
    Returns:
        Отформатированная дата или "—"
    """
    if date_obj is None:
        return "—"
    if isinstance(date_obj, datetime):
        return date_obj.date().isoformat()
    if hasattr(date_obj, 'date'):
        return date_obj.date().isoformat()
    return str(date_obj)


def build_report(
    domain: str,
    dns: Dict[str, List[str]],
    ssl: Dict[str, Any],
    waf: bool,
    *,
    brief: bool = False,
    max_san: int = 5,
) -> str:
    """Формирует отчет о сканировании домена для Telegram.

    Args:
        domain: Имя домена
        dns: Словарь с DNS записями
        ssl: Словарь с информацией о SSL сертификатах
        waf: Обнаружен ли WAF
        brief: Если True - только даты, WAF и GOST сертификат
        max_san: Максимальное количество SAN элементов для отображения
        
    Returns:
        Отформатированный отчет в виде строки
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

    # Даты обычного сертификата
    lines.append(
        f"  Сертификат: {_format_date(ssl.get('NotBefore'))} → {_format_date(ssl.get('NotAfter'))}"
    )
    
    # Даты GOST сертификата (если есть)
    gost_not_before = ssl.get('GostNotBefore')
    gost_not_after = ssl.get('GostNotAfter')
    if gost_not_before or gost_not_after:
        lines.append(
            f"  GOST сертификат: {_format_date(gost_not_before)} → {_format_date(gost_not_after)}"
        )
    
    lines.append(f"WAF: {'Включён' if waf else 'Нет'}")
    lines.append(f"ГОСТ‑сертификат: {'✅' if ssl.get('gost') else '✖️'}")
    lines.append("──────────")
    return "\n".join(lines)
