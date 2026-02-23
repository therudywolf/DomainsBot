"""
Утилиты для управления WireGuard подключением.

WireGuard теперь работает в отдельном контейнере (masipcat/wireguard-go).
Используется для альтернативного подключения при массовых 504 ошибках.
"""

import os
import socket
import logging
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Имя WireGuard контейнера (из переменной окружения или по умолчанию)
_WG_CONTAINER_NAME = os.getenv("WG_CONTAINER_NAME", "wireguard")

# Путь к конфигу WireGuard (для чтения информации, не для управления)
_WG_CONFIG_PATH = os.getenv("WG_CONFIG_PATH", "wg/wg0.conf")

# Имя интерфейса из конфига (по умолчанию TGBOT)
_WG_INTERFACE_NAME = "TGBOT"

# IP адрес интерфейса (будет извлечен из конфига)
_WG_INTERFACE_IP: Optional[str] = None


def _get_wg_config_path() -> Path:
    """Получает абсолютный путь к конфигу WireGuard.
    
    Ищет конфиг в нескольких местах (для чтения информации):
    1. Абсолютный путь (если указан через переменную окружения)
    2. Относительно корня репозитория (для разработки)
    3. В текущей рабочей директории
    
    Returns:
        Path к конфигу WireGuard или Path к несуществующему файлу
    """
    config_path = Path(_WG_CONFIG_PATH)
    
    # Если абсолютный путь - возвращаем как есть
    if config_path.is_absolute():
        return config_path
    
    # Список мест для поиска конфига
    search_paths = []
    
    # 1. Относительно корня репозитория (для разработки на хосте)
    # Модуль находится в bot/utils/, корень на 2 уровня выше
    repo_root = Path(__file__).resolve().parent.parent.parent
    search_paths.append(repo_root / config_path)
    
    # 2. Относительно текущей рабочей директории
    search_paths.append(Path.cwd() / config_path)
    
    # 3. Относительно директории модуля
    search_paths.append(Path(__file__).resolve().parent.parent / config_path)
    
    # Ищем первый существующий файл
    for path in search_paths:
        if path.exists() and path.is_file():
            logger.debug(f"Конфиг WireGuard найден: {path}")
            return path
    
    # Если не найден, возвращаем первый путь (для логирования ошибок)
    logger.debug(f"Конфиг WireGuard не найден. Проверялись пути: {search_paths}")
    return search_paths[0] if search_paths else Path(_WG_CONFIG_PATH)


def _parse_wg_config() -> tuple[Optional[str], Optional[str]]:
    """Парсит конфиг WireGuard и извлекает имя интерфейса и IP адрес.
    
    Returns:
        Кортеж (имя_интерфейса, ip_адрес) или (None, None) при ошибке
    """
    config_path = _get_wg_config_path()
    
    if not config_path.exists():
        logger.debug(f"Конфиг WireGuard не найден: {config_path}")
        return None, None
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Извлекаем имя интерфейса из комментария # Name = ... или из имени файла (TGBOT.conf -> TGBOT)
        name_match = re.search(r'#\s*Name\s*=\s*(\S+)', content)
        if name_match:
            interface_name = name_match.group(1)
        else:
            # Fallback: имя из имени файла конфига
            stem = config_path.stem
            interface_name = stem if stem else _WG_INTERFACE_NAME
        
        # Извлекаем IP адрес из строки Address = ...
        address_match = re.search(r'Address\s*=\s*([\d.]+)', content)
        ip_address = address_match.group(1) if address_match else None
        
        return interface_name, ip_address
    except Exception as e:
        logger.error(f"Ошибка при парсинге конфига WireGuard {config_path}: {e}")
        return None, None


def _check_wg_container_available() -> bool:
    """Проверяет доступность WireGuard контейнера через Docker сеть.
    
    Пытается разрешить имя хоста контейнера через DNS Docker сети.
    
    Returns:
        True если контейнер доступен, False иначе
    """
    try:
        # Пытаемся разрешить имя хоста контейнера
        # В Docker сети контейнеры доступны по имени контейнера
        socket.gethostbyname(_WG_CONTAINER_NAME)
        return True
    except (socket.gaierror, OSError) as e:
        logger.debug(f"WireGuard контейнер {_WG_CONTAINER_NAME} недоступен: {e}")
        return False


def get_wg_interface_ip() -> Optional[str]:
    """Получает IP адрес WireGuard интерфейса из конфига.
    
    Returns:
        IP адрес интерфейса или None при ошибке
    """
    global _WG_INTERFACE_IP
    
    if _WG_INTERFACE_IP is None:
        _, ip = _parse_wg_config()
        _WG_INTERFACE_IP = ip
    
    return _WG_INTERFACE_IP


def is_wg_interface_up() -> bool:
    """Проверяет, доступен ли WireGuard контейнер.
    
    Теперь WireGuard работает в отдельном контейнере, поэтому проверяем
    доступность контейнера через Docker сеть.
    
    Returns:
        True если контейнер доступен, False иначе
    """
    return _check_wg_container_available()


def check_wg_connection() -> dict:
    """Проверяет состояние WireGuard подключения (для админ-панели).
    
    Returns:
        Словарь с ключами:
        - config_found: bool - найден ли конфиг
        - config_path: str - путь к конфигу
        - interface_name: str | None
        - interface_ip: str | None
        - interface_up: bool - доступен ли WireGuard контейнер
        - container_name: str - имя WireGuard контейнера
        - last_error: str | None - последняя ошибка
    """
    result = {
        "config_found": False,
        "config_path": "",
        "interface_name": None,
        "interface_ip": None,
        "interface_up": False,
        "container_name": _WG_CONTAINER_NAME,
        "last_error": None,
    }
    
    config_path = _get_wg_config_path()
    result["config_path"] = str(config_path)
    
    if not config_path.exists():
        result["last_error"] = f"Конфиг не найден: {config_path}"
        return result
    
    result["config_found"] = True
    
    interface_name, ip_address = _parse_wg_config()
    result["interface_name"] = interface_name
    result["interface_ip"] = ip_address
    
    # Проверяем доступность WireGuard контейнера
    result["interface_up"] = _check_wg_container_available()
    
    if not result["interface_up"]:
        result["last_error"] = f"WireGuard контейнер {_WG_CONTAINER_NAME} недоступен в Docker сети"
    
    return result


def ensure_wg_interface_up() -> bool:
    """Проверяет что WireGuard контейнер доступен.
    
    WireGuard теперь работает в отдельном контейнере, который управляется
    через docker-compose. Эта функция только проверяет доступность контейнера.
    
    Returns:
        True если контейнер доступен, False при ошибке
    """
    if _check_wg_container_available():
        logger.debug(f"WireGuard контейнер {_WG_CONTAINER_NAME} доступен")
        return True
    else:
        logger.warning(f"WireGuard контейнер {_WG_CONTAINER_NAME} недоступен")
        return False


def ensure_wg_interface_down() -> bool:
    """Опускает WireGuard интерфейс если он поднят.
    
    Теперь WireGuard работает в отдельном контейнере, поэтому эта функция
    не выполняет никаких действий. Контейнер управляется через docker-compose.
    
    Returns:
        True (для обратной совместимости)
    """
    logger.debug("WireGuard работает в отдельном контейнере, управление через docker-compose")
    return True
