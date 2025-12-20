"""
Утилиты для нормализации доменных имен.

Модуль содержит функции для извлечения и очистки доменов из различных форматов:
- URL с протоколами (http://, https://)
- URL с путями и параметрами
- Простые доменные имена
"""

import re
from urllib.parse import urlparse
from typing import Optional, List

# Максимальная длина домена (RFC 1035)
MAX_DOMAIN_LENGTH = 253

# Регулярное выражение для валидации домена
DOMAIN_VALID_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# Запрещенные символы для защиты от инъекций
FORBIDDEN_CHARS = re.compile(r'[<>"\'\x00-\x1f\x7f-\x9f]')


def normalize_domain(domain: str) -> Optional[str]:
    """Нормализует доменное имя, извлекая его из различных форматов.
    
    Обрабатывает:
    - URL с протоколами: https://example.com/path -> example.com
    - URL с параметрами: http://example.com?param=value -> example.com
    - Домены с портами: example.com:8080 -> example.com
    - Простые домены: example.com -> example.com
    
    Args:
        domain: Строка с доменом или URL
        
    Returns:
        Нормализованный домен или None если не удалось извлечь валидный домен
    """
    if not domain:
        return None
    
    # Проверка максимальной длины (до нормализации)
    if len(domain) > MAX_DOMAIN_LENGTH * 2:  # Учитываем возможные протоколы и пути
        return None
    
    # Защита от инъекций: проверяем наличие запрещенных символов
    if FORBIDDEN_CHARS.search(domain):
        return None
    
    # Удаляем пробелы
    domain = domain.strip()
    
    # Если это пустая строка после очистки
    if not domain:
        return None
    
    # Пытаемся распарсить как URL
    try:
        # Если нет протокола, добавляем http:// для корректного парсинга
        if not domain.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
            domain = f"http://{domain}"
        
        parsed = urlparse(domain)
        hostname = parsed.hostname
        
        # Если hostname не извлечен, пробуем взять netloc целиком
        if not hostname:
            hostname = parsed.netloc.split(':')[0]  # Убираем порт если есть
        
        # Если все еще нет hostname, пробуем взять path (может быть домен без протокола)
        if not hostname:
            # Убираем слэши и параметры из path
            hostname = parsed.path.split('/')[0].split('?')[0].split('#')[0]
        
        # Если hostname пустой, пробуем исходную строку
        if not hostname:
            hostname = domain.split('/')[0].split('?')[0].split('#')[0]
        
        # Убираем порт если есть
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        # Убираем пробелы и приводим к нижнему регистру
        hostname = hostname.strip().lower()
        
        # Убираем точки в начале и конце
        hostname = hostname.strip('.')
        
        # Валидация домена: проверка длины и формата
        if hostname and len(hostname) <= MAX_DOMAIN_LENGTH and DOMAIN_VALID_RE.fullmatch(hostname):
            return hostname
        
    except Exception:
        # Если парсинг не удался, пробуем простую очистку
        pass
    
    # Простая очистка: убираем протоколы, пути, параметры вручную
    cleaned = domain.lower().strip()
    
    # Убираем протоколы
    for proto in ['http://', 'https://', 'ftp://', 'ftps://', 'ws://', 'wss://']:
        if cleaned.startswith(proto):
            cleaned = cleaned[len(proto):]
            break
    
    # Убираем путь, параметры, якоря
    cleaned = cleaned.split('/')[0].split('?')[0].split('#')[0]
    
    # Убираем порт
    if ':' in cleaned:
        cleaned = cleaned.split(':')[0]
    
    # Убираем пробелы и точки
    cleaned = cleaned.strip().strip('.')
    
    # Финальная валидация: проверка длины и формата
    if cleaned and len(cleaned) <= MAX_DOMAIN_LENGTH and DOMAIN_VALID_RE.fullmatch(cleaned):
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

