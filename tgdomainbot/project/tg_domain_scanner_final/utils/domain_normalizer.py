"""
Утилиты для нормализации доменных имен.

Модуль содержит функции для извлечения и очистки доменов из различных форматов:
- URL с протоколами (http://, https://, ftp://, и др.)
- URL с путями и параметрами
- Простые доменные имена
- IDN домены (кириллица и другие Unicode символы)
"""

import re
from urllib.parse import urlparse
from typing import Optional, List

try:
    import idna
    IDNA_AVAILABLE = True
except ImportError:
    IDNA_AVAILABLE = False

# Максимальная длина домена (RFC 1035)
MAX_DOMAIN_LENGTH = 253

# Расширенное регулярное выражение для валидации домена
# Поддерживает более гибкую валидацию, включая поддомены и различные TLD
DOMAIN_VALID_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Альтернативное регулярное выражение для более гибкой валидации
# Разрешает домены с подчеркиваниями в некоторых случаях (нестандартные, но встречающиеся)
DOMAIN_VALID_RE_LOOSE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,}$"
)

# Запрещенные символы для защиты от инъекций
FORBIDDEN_CHARS = re.compile(r'[<>"\'\x00-\x1f\x7f-\x9f]')

# Список поддерживаемых протоколов
SUPPORTED_PROTOCOLS = [
    'http://', 'https://', 'ftp://', 'ftps://', 'ws://', 'wss://',
    'tcp://', 'udp://', 'smtp://', 'smtps://', 'pop3://', 'imap://',
    'file://', 'ssh://', 'telnet://', 'ldap://', 'ldaps://'
]


def _encode_idn(domain: str) -> str:
    """Кодирует IDN домен в ASCII (Punycode).
    
    Args:
        domain: Домен с возможными Unicode символами
        
    Returns:
        ASCII представление домена (Punycode) или исходный домен
    """
    if not IDNA_AVAILABLE:
        return domain
    
    try:
        # Разбиваем домен на части и кодируем каждую часть отдельно
        parts = domain.split('.')
        encoded_parts = []
        for part in parts:
            try:
                # Пытаемся закодировать часть домена
                encoded = idna.encode(part).decode('ascii')
                encoded_parts.append(encoded)
            except (idna.IDNAError, UnicodeError):
                # Если не удалось закодировать, оставляем как есть
                encoded_parts.append(part)
        return '.'.join(encoded_parts)
    except Exception:
        return domain


def _has_protocol(domain: str) -> bool:
    """Проверяет, начинается ли строка с известного протокола.
    
    Args:
        domain: Строка для проверки
        
    Returns:
        True если строка начинается с протокола
    """
    domain_lower = domain.lower()
    return any(domain_lower.startswith(proto) for proto in SUPPORTED_PROTOCOLS)


def normalize_domain(domain: str) -> Optional[str]:
    """Нормализует доменное имя, извлекая его из различных форматов.
    
    Обрабатывает:
    - URL с протоколами: https://example.com/path -> example.com
    - URL с параметрами: http://example.com?param=value -> example.com
    - Домены с портами: example.com:8080 -> example.com
    - Простые домены: example.com -> example.com
    - IDN домены (кириллица): пример.рф -> xn--e1afmkfd.xn--p1ai
    - Различные протоколы: tcp://, udp://, smtp:// и др.
    
    Args:
        domain: Строка с доменом или URL
        
    Returns:
        Нормализованный домен или None если не удалось извлечь валидный домен
    """
    if not domain:
        return None
    
    # Проверка максимальной длины (до нормализации)
    if len(domain) > MAX_DOMAIN_LENGTH * 3:  # Учитываем возможные протоколы, пути и IDN
        return None
    
    # Защита от инъекций: проверяем наличие запрещенных символов
    if FORBIDDEN_CHARS.search(domain):
        return None
    
    # Удаляем пробелы и специальные символы в начале/конце
    domain = domain.strip().strip('.,;:')
    
    # Если это пустая строка после очистки
    if not domain:
        return None
    
    # Сохраняем оригинальную строку для fallback
    original_domain = domain
    
    # Пытаемся распарсить как URL
    try:
        # Определяем, есть ли протокол
        has_proto = _has_protocol(domain)
        
        # Если нет протокола, добавляем http:// для корректного парсинга
        if not has_proto:
            domain_with_proto = f"http://{domain}"
        else:
            domain_with_proto = domain
        
        parsed = urlparse(domain_with_proto)
        hostname = parsed.hostname
        
        # Если hostname не извлечен, пробуем взять netloc целиком
        if not hostname and parsed.netloc:
            hostname = parsed.netloc.split(':')[0]  # Убираем порт если есть
        
        # Если все еще нет hostname, пробуем взять path (может быть домен без протокола)
        if not hostname and parsed.path:
            # Убираем слэши и параметры из path
            path_part = parsed.path.lstrip('/')
            hostname = path_part.split('/')[0].split('?')[0].split('#')[0]
        
        # Если hostname пустой, пробуем исходную строку напрямую
        if not hostname:
            # Убираем протоколы вручную
            temp = original_domain.lower()
            for proto in SUPPORTED_PROTOCOLS:
                if temp.startswith(proto):
                    temp = temp[len(proto):]
                    break
            # Берем первую часть до слэша, вопроса или решетки
            hostname = temp.split('/')[0].split('?')[0].split('#')[0]
        
        # Убираем порт если есть
        if hostname and ':' in hostname:
            hostname = hostname.split(':')[0]
        
        # Убираем пробелы и приводим к нижнему регистру
        if hostname:
            hostname = hostname.strip().lower()
            # Убираем точки в начале и конце
            hostname = hostname.strip('.')
        
        # Если hostname все еще пустой, возвращаем None
        if not hostname:
            return None
        
        # Пытаемся обработать IDN домен
        try:
            hostname_ascii = _encode_idn(hostname)
        except Exception:
            hostname_ascii = hostname
        
        # Валидация домена: проверка длины и формата
        # Сначала строгая валидация
        if hostname_ascii and len(hostname_ascii) <= MAX_DOMAIN_LENGTH:
            if DOMAIN_VALID_RE.fullmatch(hostname_ascii):
                return hostname_ascii
            # Пробуем более мягкую валидацию (для нестандартных доменов)
            if DOMAIN_VALID_RE_LOOSE.fullmatch(hostname_ascii):
                return hostname_ascii
        
    except Exception:
        # Если парсинг не удался, пробуем простую очистку
        pass
    
    # Fallback: простая очистка вручную
    cleaned = original_domain.lower().strip()
    
    # Убираем протоколы
    for proto in SUPPORTED_PROTOCOLS:
        if cleaned.startswith(proto):
            cleaned = cleaned[len(proto):]
            break
    
    # Убираем путь, параметры, якоря
    cleaned = cleaned.split('/')[0].split('?')[0].split('#')[0]
    
    # Убираем порт
    if ':' in cleaned:
        cleaned = cleaned.split(':')[0]
    
    # Убираем пробелы, точки и специальные символы
    cleaned = cleaned.strip().strip('.,;:')
    
    # Пытаемся обработать IDN
    try:
        cleaned = _encode_idn(cleaned)
    except Exception:
        pass
    
    # Финальная валидация: проверка длины и формата
    if cleaned and len(cleaned) <= MAX_DOMAIN_LENGTH:
        # Сначала строгая валидация
        if DOMAIN_VALID_RE.fullmatch(cleaned):
            return cleaned
        # Пробуем более мягкую валидацию
        if DOMAIN_VALID_RE_LOOSE.fullmatch(cleaned):
            return cleaned
    
    return None


def normalize_domains(domains: List[str]) -> List[str]:
    """Нормализует список доменов, удаляя невалидные.
    
    Args:
        domains: Список строк с доменами или URL
        
    Returns:
        Список нормализованных доменов (только валидные)
    """
    normalized = []
    seen = set()
    
    for domain in domains:
        norm = normalize_domain(domain)
        if norm and norm not in seen:
            normalized.append(norm)
            seen.add(norm)
    
    return normalized

