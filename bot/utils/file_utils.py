"""
Утилиты для async-safe работы с файлами.

Обеспечивает потокобезопасные операции с файлами в async контексте
через использование asyncio.Lock и выполнения операций в executor.
"""

import asyncio
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from threading import RLock

logger = logging.getLogger(__name__)


class AsyncFileLock:
    """
    Async-safe блокировка для файловых операций.
    
    Использует asyncio.Lock для async контекста и RLock для синхронных операций.
    """
    
    def __init__(self):
        self._async_lock = asyncio.Lock()
        self._sync_lock = RLock()
    
    async def acquire_async(self):
        """Приобретает async блокировку."""
        await self._async_lock.acquire()
    
    def release_async(self):
        """Освобождает async блокировку."""
        self._async_lock.release()
    
    def acquire_sync(self):
        """Приобретает синхронную блокировку."""
        self._sync_lock.acquire()
    
    def release_sync(self):
        """Освобождает синхронную блокировку."""
        self._sync_lock.release()
    
    async def __aenter__(self):
        await self.acquire_async()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.release_async()


async def async_read_json(file_path: Path, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Асинхронно читает JSON файл.
    
    Args:
        file_path: Путь к файлу
        default: Значение по умолчанию если файл не существует
        
    Returns:
        Словарь с данными из файла
    """
    if default is None:
        default = {}
    
    def _read():
        if not file_path.exists():
            return default
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Ошибка при чтении JSON файла {file_path}: {e}")
            return default
    
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _read)


async def async_write_json(file_path: Path, data: Dict[str, Any], indent: int = 2) -> bool:
    """
    Асинхронно записывает JSON файл.
    
    Args:
        file_path: Путь к файлу
        data: Данные для записи
        indent: Отступ для форматирования
        
    Returns:
        True если успешно записано
    """
    def _write():
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=indent, default=str)
            return True
        except Exception as e:
            logger.error(f"Ошибка при записи JSON файла {file_path}: {e}")
            return False
    
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _write)


async def async_read_text(file_path: Path, default: str = "") -> str:
    """
    Асинхронно читает текстовый файл.
    
    Args:
        file_path: Путь к файлу
        default: Значение по умолчанию если файл не существует
        
    Returns:
        Содержимое файла
    """
    def _read():
        if not file_path.exists():
            return default
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.error(f"Ошибка при чтении текстового файла {file_path}: {e}")
            return default
    
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _read)


async def async_write_text(file_path: Path, content: str) -> bool:
    """
    Асинхронно записывает текстовый файл.
    
    Args:
        file_path: Путь к файлу
        content: Содержимое для записи
        
    Returns:
        True если успешно записано
    """
    def _write():
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Ошибка при записи текстового файла {file_path}: {e}")
            return False
    
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _write)





