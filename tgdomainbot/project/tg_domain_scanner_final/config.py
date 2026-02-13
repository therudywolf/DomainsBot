"""
Конфигурация приложения.

Содержит настройки для работы бота, таймауты, параметры подключения к Gost контейнерам,
настройки rate limiting, логирования и другие параметры.
"""
import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Settings:
    """
    Настройки приложения.
    
    Все параметры могут быть переопределены через переменные окружения.
    """
    # Обязательные параметры
    TG_TOKEN: str
    
    # Таймауты для различных операций (в секундах)
    DNS_TIMEOUT: int = 5
    HTTP_TIMEOUT: int = 6
    CONCURRENCY: int = 20  # Максимальное количество одновременных проверок
    
    # Настройки для Gost проверки
    GOST_CHECK_TIMEOUT: int = 30  # Таймаут для проверки Gost (должен совпадать с check.sh и server.py)
    GOST_RETRY_ATTEMPTS: int = 3  # Количество попыток при сбое
    GOST_RETRY_DELAY: float = 0.5  # Задержка между попытками (секунды)
    
    # Rate limiting
    RATE_LIMIT_REQUESTS: int = 30  # Максимальное количество запросов
    RATE_LIMIT_WINDOW: int = 60  # Окно времени в секундах
    
    # Логирование
    LOG_LEVEL: str = "INFO"  # DEBUG, INFO, WARNING, ERROR
    LOG_FILE: str = "data/bot.log"  # Путь к файлу логов (None для отключения)
    LOG_MAX_BYTES: int = 10 * 1024 * 1024  # 10 MB - максимальный размер файла лога
    LOG_BACKUP_COUNT: int = 5  # Количество резервных копий логов
    
    # История проверок
    HISTORY_ENABLED: bool = True  # Включить сохранение истории проверок
    HISTORY_MAX_ENTRIES: int = 10000  # Максимальное количество записей в истории
    HISTORY_CLEANUP_DAYS: int = 30  # Удалять записи старше N дней
    
    # Статистика
    STATS_ENABLED: bool = True  # Включить сбор статистики
    
    # Ограничения
    MAX_DOMAINS_PER_REQUEST: int = 1000  # Максимальное количество доменов в одном запросе
    MAX_FILE_SIZE_MB: int = 10  # Максимальный размер загружаемого файла в MB


def _get_env_int(key: str, default: int) -> int:
    """Получает целое число из переменной окружения."""
    value = os.getenv(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_env_float(key: str, default: float) -> float:
    """Получает число с плавающей точкой из переменной окружения."""
    value = os.getenv(key)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _get_env_bool(key: str, default: bool) -> bool:
    """Получает булево значение из переменной окружения."""
    value = os.getenv(key)
    if value is None:
        return default
    return value.lower() in ("true", "1", "yes", "on")


settings = Settings(
    TG_TOKEN=os.getenv("TG_TOKEN", ""),
    DNS_TIMEOUT=_get_env_int("DNS_TIMEOUT", 5),
    HTTP_TIMEOUT=_get_env_int("HTTP_TIMEOUT", 6),
    CONCURRENCY=_get_env_int("CONCURRENCY", 20),
    GOST_CHECK_TIMEOUT=_get_env_int("GOST_CHECK_TIMEOUT", 30),
    GOST_RETRY_ATTEMPTS=_get_env_int("GOST_RETRY_ATTEMPTS", 3),
    GOST_RETRY_DELAY=_get_env_float("GOST_RETRY_DELAY", 0.5),
    RATE_LIMIT_REQUESTS=_get_env_int("RATE_LIMIT_REQUESTS", 30),
    RATE_LIMIT_WINDOW=_get_env_int("RATE_LIMIT_WINDOW", 60),
    LOG_LEVEL=os.getenv("LOG_LEVEL", "INFO"),
    LOG_FILE=os.getenv("LOG_FILE", "data/bot.log"),
    LOG_MAX_BYTES=_get_env_int("LOG_MAX_BYTES", 10 * 1024 * 1024),
    LOG_BACKUP_COUNT=_get_env_int("LOG_BACKUP_COUNT", 5),
    HISTORY_ENABLED=_get_env_bool("HISTORY_ENABLED", True),
    HISTORY_MAX_ENTRIES=_get_env_int("HISTORY_MAX_ENTRIES", 10000),
    HISTORY_CLEANUP_DAYS=_get_env_int("HISTORY_CLEANUP_DAYS", 30),
    STATS_ENABLED=_get_env_bool("STATS_ENABLED", True),
    MAX_DOMAINS_PER_REQUEST=_get_env_int("MAX_DOMAINS_PER_REQUEST", 1000),
    MAX_FILE_SIZE_MB=_get_env_int("MAX_FILE_SIZE_MB", 10),
)
