"""
Утилиты для форматирования результатов сканирования доменов для Telegram.

Создает красивые, структурированные и читаемые отчеты с использованием
эмодзи, блоков и цветового кодирования для лучшего восприятия.
"""

from typing import Dict, List, Any, Optional, TYPE_CHECKING
from datetime import datetime, timedelta

# Импорт для создания клавиатур (ленивый импорт в функции)
if TYPE_CHECKING:
    from aiogram import types


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
        Отформатированная дата в формате ДД.ММ.ГГГГ или "—"
    """
    if date_obj is None:
        return "—"
    
    try:
        if isinstance(date_obj, datetime):
            dt = date_obj
        elif hasattr(date_obj, 'date'):
            dt = date_obj
        else:
            # Пытаемся распарсить строку
            if isinstance(date_obj, str):
                dt = datetime.fromisoformat(date_obj.replace('Z', '+00:00'))
            else:
                return str(date_obj)
        
        return dt.strftime("%d.%m.%Y")
    except Exception:
        return str(date_obj)


def _format_date_with_days_left(date_obj: Any) -> str:
    """Форматирует дату с указанием дней до истечения.
    
    Args:
        date_obj: Объект даты
        
    Returns:
        Строка с датой и количеством дней до истечения
    """
    if date_obj is None:
        return "—"
    
    try:
        if isinstance(date_obj, datetime):
            dt = date_obj
        elif hasattr(date_obj, 'date'):
            dt = date_obj
        else:
            if isinstance(date_obj, str):
                dt = datetime.fromisoformat(date_obj.replace('Z', '+00:00'))
            else:
                return _format_date(date_obj)
        
        # Вычисляем дни до истечения
        now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.now()
        days_left = (dt - now).days
        
        date_str = dt.strftime("%d.%m.%Y")
        
        if days_left < 0:
            return f"{date_str} (просрочен на {abs(days_left)} дн.)"
        elif days_left < 30:
            return f"{date_str} (осталось {days_left} дн.) ⚠️"
        elif days_left < 90:
            return f"{date_str} (осталось {days_left} дн.)"
        else:
            return f"{date_str} (осталось {days_left} дн.)"
    except Exception:
        return _format_date(date_obj)


def _format_issuer(issuer: str) -> str:
    """Форматирует информацию об издателе сертификата.
    
    Args:
        issuer: Строка с информацией об издателе
        
    Returns:
        Упрощенная и читаемая строка
    """
    if not issuer or issuer == "—":
        return "—"
    
    # Пытаемся извлечь CN из строки вида "CN=..., O=..., C=..."
    try:
        parts = issuer.split(',')
        for part in parts:
            if part.strip().startswith('CN='):
                return part.strip().replace('CN=', '')
    except Exception:
        pass
    
    # Если не удалось, возвращаем как есть, но ограничиваем длину
    if len(issuer) > 60:
        return issuer[:57] + "..."
    
    return issuer


def build_report(
    domain: str,
    dns: Dict[str, List[str]],
    ssl: Dict[str, Any],
    waf: bool,
    *,
    brief: bool = False,
    max_san: int = 5,
    waf_method: Optional[str] = None,
) -> str:
    """
    Формирует красивый и структурированный отчет о сканировании домена.
    
    Args:
        domain: Имя домена
        dns: Словарь с DNS записями
        ssl: Словарь с информацией о SSL сертификатах
        waf: Обнаружен ли WAF
        brief: Если True - только основные данные (даты, WAF, GOST)
        max_san: Максимальное количество SAN элементов для отображения
        
    Returns:
        Отформатированный отчет в виде строки с HTML разметкой
    """
    # Защита от неправильных типов данных
    if not isinstance(ssl, dict):
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"ssl должен быть словарем, получен {type(ssl)} для домена {domain}")
        ssl = {}
    if not isinstance(dns, dict):
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"dns должен быть словарем, получен {type(dns)} для домена {domain}")
        dns = {}
    
    lines: List[str] = []
    
    # Заголовок с доменом
    lines.append(f"🌐 <b>{domain}</b>")
    lines.append("")
    
    if not brief:
        # Блок DNS информации
        lines.append("📡 <b>DNS записи</b>")
        
        # IP адреса
        ip_list = dns.get("IP", []) or dns.get("A", [])
        if ip_list:
            ip_str = ", ".join(ip_list[:5])  # Показываем первые 5
            if len(ip_list) > 5:
                ip_str += f" (+{len(ip_list) - 5})"
            lines.append(f"   <b>IP:</b> {ip_str}")
        else:
            lines.append("   <b>IP:</b> —")
        
        # A записи
        a_records = dns.get("A", [])
        if a_records:
            a_str = ", ".join(a_records[:3])
            if len(a_records) > 3:
                a_str += f" (+{len(a_records) - 3})"
            lines.append(f"   <b>A:</b> {a_str}")
        
        # AAAA записи
        aaaa_records = dns.get("AAAA", [])
        if aaaa_records:
            aaaa_str = ", ".join(aaaa_records[:3])
            if len(aaaa_records) > 3:
                aaaa_str += f" (+{len(aaaa_records) - 3})"
            lines.append(f"   <b>AAAA:</b> {aaaa_str}")
        else:
            lines.append("   <b>AAAA:</b> —")
        
        # MX записи
        mx_records = dns.get("MX", [])
        if mx_records:
            mx_str = ", ".join(mx_records[:3])
            if len(mx_records) > 3:
                mx_str += f" (+{len(mx_records) - 3})"
            lines.append(f"   <b>MX:</b> {mx_str}")
        else:
            lines.append("   <b>MX:</b> —")
        
        # NS записи
        ns_records = dns.get("NS", [])
        if ns_records:
            ns_str = ", ".join(ns_records[:3])
            if len(ns_records) > 3:
                ns_str += f" (+{len(ns_records) - 3})"
            lines.append(f"   <b>NS:</b> {ns_str}")
        else:
            lines.append("   <b>NS:</b> —")
        
        lines.append("")
        
        # Блок SSL информации
        lines.append("🔒 <b>SSL сертификат (обычный)</b>")
        
        cn = ssl.get('CN', '—')
        if cn and cn != "—":
            lines.append(f"   <b>Домен:</b> {cn}")
        
        san = ssl.get('SAN', [])
        if san:
            san_str = _shorten_san(san, max_san)
            lines.append(f"   <b>Домены в сертификате:</b> {san_str}")
        
        issuer = _format_issuer(ssl.get('Issuer', '—'))
        if issuer and issuer != "—":
            lines.append(f"   <b>Издатель:</b> {issuer}")
        
        sig_alg = ssl.get('SigAlg', '—')
        if sig_alg and sig_alg != "—":
            lines.append(f"   <b>Алгоритм подписи:</b> {sig_alg}")
        
        cipher = ssl.get('Cipher', '—')
        if cipher and cipher != "—":
            # Упрощаем название шифра
            cipher_short = cipher.split('-')[0] if '-' in cipher else cipher
            lines.append(f"   <b>Шифр:</b> {cipher_short}")
        
        lines.append("")
    
    # Блок сроков действия сертификатов
    lines.append("📅 <b>Сроки действия сертификатов</b>")
    
    # Обычный сертификат - всегда показываем
    not_before = ssl.get('NotBefore')
    not_after = ssl.get('NotAfter')
    
    if not_before and not_after:
        # Оба значения есть
        date_range = f"{_format_date(not_before)} → {_format_date_with_days_left(not_after)}"
        lines.append(f"   <b>Обычный сертификат:</b> {date_range}")
    elif not_after:
        # Только дата окончания
        date_range = f"— → {_format_date_with_days_left(not_after)}"
        lines.append(f"   <b>Обычный сертификат:</b> {date_range}")
    elif not_before:
        # Только дата начала
        date_range = f"{_format_date(not_before)} → —"
        lines.append(f"   <b>Обычный сертификат:</b> {date_range}")
    else:
        # Нет данных
        lines.append("   <b>Обычный сертификат:</b> ❌ (данные недоступны)")
    
    # GOST сертификат - всегда показываем
    gost_not_before = ssl.get('GostNotBefore')
    gost_not_after = ssl.get('GostNotAfter')
    gost_enabled = ssl.get('gost', False)
    
    if gost_not_before and gost_not_after:
        # Оба значения есть
        date_range = f"{_format_date(gost_not_before)} → {_format_date_with_days_left(gost_not_after)}"
        lines.append(f"   <b>GOST сертификат:</b> {date_range} ✅")
    elif gost_not_after:
        # Только дата окончания
        date_range = f"— → {_format_date_with_days_left(gost_not_after)}"
        lines.append(f"   <b>GOST сертификат:</b> {date_range} ✅")
    elif gost_not_before:
        # Только дата начала
        date_range = f"{_format_date(gost_not_before)} → —"
        lines.append(f"   <b>GOST сертификат:</b> {date_range} ✅")
    elif gost_enabled:
        # GOST обнаружен, но даты не получены
        lines.append("   <b>GOST сертификат:</b> ✅ (обнаружен, даты не получены)")
    else:
        # GOST не обнаружен
        lines.append("   <b>GOST сертификат:</b> ❌ (не обнаружен)")
    
    lines.append("")
    
    # Блок безопасности
    lines.append("🛡️ <b>Безопасность</b>")
    
    # WAF
    waf_status = "✅ Включен" if waf else "❌ Не обнаружен"
    
    # Добавляем информацию о методе проверки
    if waf_method:
        method_names = {
            "policy": "check policy",
            "light": "легкая проверка",
            "injection": "скрипт (инъекции)",
        }
        method_name = method_names.get(waf_method, waf_method)
        waf_status += f" <i>(проверено: {method_name})</i>"
    
    lines.append(f"   <b>WAF:</b> {waf_status}")
    
    # GOST
    gost_status = "✅ Обнаружен" if gost_enabled else "❌ Не обнаружен"
    lines.append(f"   <b>GOST сертификат:</b> {gost_status}")
    
    return "\n".join(lines)


def build_report_keyboard(
    domain: str,
    current_mode: str,
    user_id: int,
    has_waf_permission: bool = True,
    has_monitoring_permission: bool = False,
):
    """
    Создает клавиатуру с кнопками для управления отчетом.
    
    Включает:
    - Переключение режима отчета (полный/краткий)
    - Быструю проверку WAF
    - Быструю проверку сертификатов
    - Повторную проверку домена
    - Детальный просмотр блоков (DNS, SSL, WAF)
    - Поделиться отчетом
    - Поставить на мониторинг (если есть право)
    
    Args:
        domain: Домен для быстрых действий
        current_mode: Текущий режим отчета (full/brief)
        user_id: ID пользователя
        has_waf_permission: Есть ли разрешение на проверку WAF
        has_monitoring_permission: Есть ли разрешение на мониторинг
        
    Returns:
        InlineKeyboardMarkup с кнопками
    """
    from aiogram import types as aiogram_types
    buttons = []
    
    # Кнопки переключения режима
    buttons.append([
        aiogram_types.InlineKeyboardButton(
            text=("✅ 🔎 Расширенный" if current_mode == "full" else "🔎 Расширенный"),
            callback_data="mode_full",
        ),
        aiogram_types.InlineKeyboardButton(
            text=("✅ 📄 Короткий" if current_mode == "brief" else "📄 Короткий"),
            callback_data="mode_brief",
        ),
    ])
    
    # Кнопки быстрых действий
    quick_actions = []
    
    # Проверка WAF (если есть разрешение)
    if has_waf_permission:
        quick_actions.append(
            aiogram_types.InlineKeyboardButton(
                text="🛡️ Проверить WAF",
                callback_data=f"quick_waf_{domain}",
            )
        )
    
    # Проверка сертификатов
    quick_actions.append(
        aiogram_types.InlineKeyboardButton(
            text="📅 Проверить сертификаты",
            callback_data=f"quick_certs_{domain}",
        )
    )
    
    if quick_actions:
        buttons.append(quick_actions)
    
    # Кнопки детального просмотра блоков
    detail_buttons = []
    detail_buttons.append(
        aiogram_types.InlineKeyboardButton(
            text="📡 Детали DNS",
            callback_data=f"detail_dns_{domain}",
        )
    )
    detail_buttons.append(
        aiogram_types.InlineKeyboardButton(
            text="🔒 Детали SSL",
            callback_data=f"detail_ssl_{domain}",
        )
    )
    if has_waf_permission:
        detail_buttons.append(
            aiogram_types.InlineKeyboardButton(
                text="🛡️ Детали WAF",
                callback_data=f"detail_waf_{domain}",
            )
        )
    
    if detail_buttons:
        buttons.append(detail_buttons)
    
    # Кнопка перепроверки домена
    buttons.append([
        aiogram_types.InlineKeyboardButton(
            text="🔄 Перепроверить домен",
            callback_data=f"recheck_{domain}",
        )
    ])
    
    # Кнопка "Поставить на мониторинг" (если есть право)
    if has_monitoring_permission:
        buttons.append([
            aiogram_types.InlineKeyboardButton(
                text="📊 Поставить на мониторинг",
                callback_data=f"monitor_add_from_report_{domain}",
            )
        ])
    
    # Кнопка "Поделиться" (через inline режим)
    buttons.append([
        aiogram_types.InlineKeyboardButton(
            text="📤 Поделиться",
            switch_inline_query=domain,
        )
    ])
    
    return aiogram_types.InlineKeyboardMarkup(inline_keyboard=buttons)
