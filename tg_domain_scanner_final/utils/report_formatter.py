"""
Модуль для форматирования отчетов.

Содержит функции для создания CSV отчетов и отправки отчетов пользователям.
"""

import asyncio
import csv
import io
from typing import List, Tuple, Dict, Any, Optional

from aiogram import Bot, types
from aiogram.enums import ParseMode

from utils.formatting import build_report, build_report_keyboard
from utils.types import DNSInfo, SSLInfo
from utils.telegram_utils import safe_send_text


def format_csv_report(
    collected: List[Tuple[str, DNSInfo, SSLInfo, bool, Optional[str]]],
    brief: bool = False
) -> bytes:
    """
    Форматирует данные проверок в CSV формат.
    
    Args:
        collected: Список кортежей (domain, dns_info, ssl_info, waf_enabled, waf_method)
        brief: Использовать краткий формат (без DNS записей)
        
    Returns:
        Байты CSV файла с UTF-8 BOM
    """
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, delimiter=";")
    
    if brief:
        writer.writerow([
            "Domain", "CN", "Valid From", "Valid To", 
            "GOST Cert From", "GOST Cert To", "WAF", "GOST"
        ])
    else:
        writer.writerow([
            "Domain",
            "A",
            "AAAA",
            "MX",
            "NS",
            "CN",
            "Valid From",
            "Valid To",
            "GOST Cert From",
            "GOST Cert To",
            "WAF",
            "GOST",
        ])

    for domain, dns_info, ssl_info, waf_enabled, waf_method in collected:
        gost_val = "Да" if ssl_info.get("gost") else "Нет"
        waf_val = "Да" if waf_enabled else "Нет"
        
        # Форматируем даты
        def format_date(dt):
            if dt is None:
                return ""
            if hasattr(dt, 'date'):
                return dt.date().isoformat()
            return str(dt)
        
        row_base = [
            domain,
            ssl_info.get("CN") or "",
            format_date(ssl_info.get("NotBefore")),
            format_date(ssl_info.get("NotAfter")),
            format_date(ssl_info.get("GostNotBefore")),
            format_date(ssl_info.get("GostNotAfter")),
            waf_val,
            gost_val,
        ]

        if brief:
            writer.writerow(row_base)
        else:
            writer.writerow([
                domain,
                ",".join(dns_info.get("A", [])),
                ",".join(dns_info.get("AAAA", [])),
                ",".join(dns_info.get("MX", [])),
                ",".join(dns_info.get("NS", [])),
                *row_base[1:],
            ])

    return buf.getvalue().encode("utf-8-sig")


async def send_domain_reports(
    bot: Bot,
    chat_id: int,
    collected: List[Tuple[str, DNSInfo, SSLInfo, bool, Optional[str]]],
    view_mode: str,
    user_id: int,
    has_waf_perm: bool,
    brief: bool = False
) -> None:
    """
    Отправляет отчеты о проверке доменов пользователю.
    
    Args:
        bot: Экземпляр бота
        chat_id: ID чата для отправки
        collected: Список кортежей (domain, dns_info, ssl_info, waf_enabled, waf_method)
        view_mode: Режим отображения ("full" или "brief")
        user_id: ID пользователя
        has_waf_perm: Есть ли у пользователя разрешение на проверку WAF
        brief: Использовать краткий режим отчета
    """
    # Для каждого домена создаем отдельное сообщение с кнопками
    for idx, (domain, dns_info, ssl_info, waf_enabled, waf_method) in enumerate(collected, 1):
        report_text = build_report(domain, dns_info, ssl_info, waf_enabled, brief=brief, waf_method=waf_method)
        
        # Создаем клавиатуру с кнопками для этого домена
        keyboard = build_report_keyboard(domain, view_mode, user_id, has_waf_perm)
        
        # Используем safe_send_text для rate limiting и разбиения длинных сообщений
        await safe_send_text(
            bot,
            chat_id,
            report_text,
            parse_mode=ParseMode.HTML,
            reply_markup=keyboard,
        )
        
        # Добавляем задержку между отправкой отчетов для разных доменов
        # (safe_send_text уже имеет внутреннюю задержку, но дополнительная не помешает)
        if idx < len(collected):
            await asyncio.sleep(0.3)  # 300ms задержка между отчетами

