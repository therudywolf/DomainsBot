"""
Утилиты для управления WireGuard интерфейсом.

Используется для альтернативного подключения при массовых 504 ошибках.
"""

import os
import subprocess
import logging
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Путь к конфигу WireGuard (относительно корня репозитория)
_WG_CONFIG_PATH = os.getenv("WG_CONFIG_PATH", "wg/TGBOT.conf")

# Имя интерфейса из конфига (по умолчанию TGBOT)
_WG_INTERFACE_NAME = "TGBOT"

# IP адрес интерфейса (будет извлечен из конфига)
_WG_INTERFACE_IP: Optional[str] = None


def _get_wg_config_path() -> Path:
    """Получает абсолютный путь к конфигу WireGuard.
    
    Ищет конфиг в нескольких местах:
    1. Абсолютный путь (если указан через переменную окружения)
    2. Относительно корня репозитория (для разработки)
    3. Внутри контейнера (/app/wg/TGBOT.conf)
    4. В текущей рабочей директории
    
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
    # Модуль находится в tg_domain_scanner_final/utils/, корень на 2 уровня выше
    repo_root = Path(__file__).resolve().parent.parent.parent
    search_paths.append(repo_root / config_path)
    
    # 2. Внутри Docker контейнера (если запущено в контейнере)
    # WORKDIR в Dockerfile = /app
    search_paths.append(Path("/app") / config_path)
    
    # 3. Относительно текущей рабочей директории
    search_paths.append(Path.cwd() / config_path)
    
    # 4. Относительно директории модуля
    search_paths.append(Path(__file__).resolve().parent.parent / config_path)
    
    # Ищем первый существующий файл
    for path in search_paths:
        if path.exists() and path.is_file():
            logger.debug(f"Конфиг WireGuard найден: {path}")
            return path
    
    # Если не найден, возвращаем первый путь (для логирования ошибок)
    logger.debug(f"Конфиг WireGuard не найден. Проверялись пути: {search_paths}")
    return search_paths[0]


def _parse_wg_config() -> tuple[Optional[str], Optional[str]]:
    """Парсит конфиг WireGuard и извлекает имя интерфейса и IP адрес.
    
    Returns:
        Кортеж (имя_интерфейса, ip_адрес) или (None, None) при ошибке
    """
    config_path = _get_wg_config_path()
    
    if not config_path.exists():
        logger.warning(f"Конфиг WireGuard не найден: {config_path}")
        return None, None
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Извлекаем имя интерфейса из комментария # Name = ... или из имени файла (TGBOT.conf -> TGBOT)
        name_match = re.search(r'#\s*Name\s*=\s*(\S+)', content)
        if name_match:
            interface_name = name_match.group(1)
        else:
            # Fallback: имя из имени файла конфига (wg-quick использует это)
            stem = config_path.stem
            interface_name = stem if stem else _WG_INTERFACE_NAME
        
        # Извлекаем IP адрес из строки Address = ...
        address_match = re.search(r'Address\s*=\s*([\d.]+)', content)
        ip_address = address_match.group(1) if address_match else None
        
        return interface_name, ip_address
    except Exception as e:
        logger.error(f"Ошибка при парсинге конфига WireGuard {config_path}: {e}")
        return None, None


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
    """Проверяет, поднят ли WireGuard интерфейс.
    
    Returns:
        True если интерфейс активен, False иначе
    """
    interface_name, _ = _parse_wg_config()
    if not interface_name:
        return False
    
    try:
        # Проверяем статус через wg show
        result = subprocess.run(
            ["wg", "show", interface_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.debug(f"Ошибка при проверке статуса WireGuard интерфейса {interface_name}: {e}")
        return False


def check_wg_connection() -> dict:
    """Проверяет состояние WireGuard подключения (для админ-панели).
    
    Returns:
        Словарь с ключами:
        - config_found: bool - найден ли конфиг
        - config_path: str - путь к конфигу
        - interface_name: str | None
        - interface_ip: str | None
        - interface_up: bool - поднят ли интерфейс
        - wg_available: bool - доступны ли wg/wg-quick
        - last_error: str | None - последняя ошибка
    """
    result = {
        "config_found": False,
        "config_path": "",
        "interface_name": None,
        "interface_ip": None,
        "interface_up": False,
        "wg_available": False,
        "last_error": None,
    }
    
    # Проверяем доступность wg
    try:
        subprocess.run(
            ["wg", "version"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        result["wg_available"] = True
    except FileNotFoundError:
        result["last_error"] = "wg/wg-quick не установлен (WireGuard недоступен)"
        return result
    except (subprocess.TimeoutExpired, OSError) as e:
        result["last_error"] = f"Проверка wg: {e}"
        return result
    
    config_path = _get_wg_config_path()
    result["config_path"] = str(config_path)
    
    if not config_path.exists():
        result["last_error"] = f"Конфиг не найден: {config_path}"
        return result
    
    result["config_found"] = True
    
    interface_name, ip_address = _parse_wg_config()
    result["interface_name"] = interface_name
    result["interface_ip"] = ip_address
    
    if interface_name:
        result["interface_up"] = is_wg_interface_up()
    
    return result


def ensure_wg_interface_up() -> bool:
    """Поднимает WireGuard интерфейс если он не поднят.
    
    Returns:
        True если интерфейс успешно поднят или уже был поднят, False при ошибке
    """
    # Проверяем, не поднят ли уже интерфейс
    if is_wg_interface_up():
        logger.debug("WireGuard интерфейс уже поднят")
        return True
    
    config_path = _get_wg_config_path()
    if not config_path.exists():
        logger.error(f"Конфиг WireGuard не найден: {config_path}")
        return False
    
    try:
        # Поднимаем интерфейс через wg-quick
        result = subprocess.run(
            ["wg-quick", "up", str(config_path)],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            logger.info(f"WireGuard интерфейс успешно поднят из конфига {config_path}")
            return True
        else:
            logger.warning(
                f"Не удалось поднять WireGuard интерфейс: {result.stderr}"
            )
            return False
    except FileNotFoundError:
        logger.error("Утилита wg-quick не найдена. Установите WireGuard.")
        return False
    except subprocess.TimeoutExpired:
        logger.error("Таймаут при поднятии WireGuard интерфейса")
        return False
    except Exception as e:
        logger.error(f"Ошибка при поднятии WireGuard интерфейса: {e}", exc_info=True)
        return False
