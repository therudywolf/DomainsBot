"""
Настройка логирования для бота.

Настраивает логирование в файл и консоль с ротацией логов.
"""

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional


def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
) -> None:
    """
    Настраивает логирование для приложения.
    
    Args:
        log_level: Уровень логирования (DEBUG, INFO, WARNING, ERROR)
        log_file: Путь к файлу логов (если None, логирование только в консоль)
        max_bytes: Максимальный размер файла лога перед ротацией
        backup_count: Количество резервных копий логов
    """
    # Создаем директорию для логов если нужно
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Получаем уровень логирования
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Настраиваем формат логов
    log_format = (
        "%(asctime)s - %(name)s - %(levelname)s - "
        "%(filename)s:%(lineno)d - %(message)s"
    )
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Настраиваем root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Удаляем существующие handlers
    root_logger.handlers.clear()
    
    # Handler для консоли
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_formatter = logging.Formatter(log_format, date_format)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # Handler для файла (если указан)
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)
        file_formatter = logging.Formatter(log_format, date_format)
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)
    
    # Настраиваем логирование для внешних библиотек
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("aiogram").setLevel(logging.INFO)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    
    # Включаем DEBUG логирование для нашего бота при необходимости
    # Можно переключить на INFO для продакшена
    bot_logger = logging.getLogger("__main__")
    bot_logger.setLevel(numeric_level)

