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
    
    Returns:
        Path к конфигу WireGuard
    """
    config_path = Path(_WG_CONFIG_PATH)
    if config_path.is_absolute():
        return config_path
    
    # Если путь относительный, ищем от корня репозитория
    # Предполагаем, что модуль находится в tg_domain_scanner_final/utils/
    # Корень репозитория на 2 уровня выше
    repo_root = Path(__file__).resolve().parent.parent.parent
    return repo_root / config_path


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
        
        # Извлекаем имя интерфейса из комментария # Name = ...
        name_match = re.search(r'#\s*Name\s*=\s*(\S+)', content)
        interface_name = name_match.group(1) if name_match else _WG_INTERFACE_NAME
        
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
