"""
Типы данных для проекта.

Определяет TypedDict, Protocol и другие типы для улучшения типизации.
"""

from __future__ import annotations

from typing import TypedDict, Literal, Protocol, Optional, List, Dict, Any
from datetime import datetime


# Режимы отчета
ReportMode = Literal["full", "brief"]

# Режимы проверки WAF
WAFMode = Literal["policy", "light", "injection"]

# Типы DNS записей
DNSType = Literal["A", "AAAA", "MX", "NS"]


class DNSInfo(TypedDict, total=False):
    """Информация о DNS записях домена."""
    A: List[str]
    AAAA: List[str]
    MX: List[str]
    NS: List[str]
    IP: str  # Основной IP адрес


class SSLInfo(TypedDict, total=False):
    """Информация о SSL сертификате."""
    CN: Optional[str]  # Common Name
    SAN: List[str]  # Subject Alternative Names
    Issuer: Optional[str]
    Algorithm: Optional[str]
    Cipher: Optional[str]
    NotBefore: Optional[datetime]
    NotAfter: Optional[datetime]
    GostNotBefore: Optional[datetime]
    GostNotAfter: Optional[datetime]
    gost: bool  # Наличие GOST сертификата


class WAFResult(TypedDict):
    """Результат проверки WAF."""
    enabled: bool
    method: Optional[str]  # "policy", "light", "injection"


class DomainCheckResult(TypedDict, total=False):
    """Результат полной проверки домена."""
    domain: str
    dns: DNSInfo
    ssl: SSLInfo
    waf: WAFResult
    timestamp: datetime
    user_id: int


class MonitoringState(TypedDict, total=False):
    """Состояние домена в мониторинге."""
    domain: str
    user_id: int
    interval: int  # Интервал проверки в минутах
    enabled: bool
    last_check: Optional[datetime]
    last_state: Optional[DomainCheckResult]


class UserPermissions(TypedDict):
    """Разрешения пользователя."""
    check_domains: bool
    monitoring: bool
    history: bool
    settings: bool
    inline: bool
    file_upload: bool


class UserData(TypedDict, total=False):
    """Данные пользователя в базе доступа."""
    username: str
    permissions: UserPermissions
    added_at: Optional[str]


# Protocol для проверки доменов
class DomainChecker(Protocol):
    """Протокол для проверки доменов."""
    
    async def check(self, domain: str) -> Dict[str, Any]:
        """Проверяет домен и возвращает результат."""
        ...


# Protocol для кэширования
class CacheBackend(Protocol):
    """Протокол для бэкенда кэша."""
    
    async def get(self, key: str) -> Optional[Any]:
        """Получает значение по ключу."""
        ...
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Устанавливает значение с TTL."""
        ...
    
    async def delete(self, key: str) -> None:
        """Удаляет значение по ключу."""
        ...





