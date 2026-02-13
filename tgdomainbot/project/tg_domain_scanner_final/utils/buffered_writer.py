"""
Буферизованная запись в файлы для оптимизации производительности.

Обеспечивает batch writes и периодическое сохранение для уменьшения
количества операций записи на диск.
"""

import asyncio
import json
import logging
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Callable, Deque
from threading import Lock

logger = logging.getLogger(__name__)


class BufferedFileWriter:
    """
    Буферизованный писатель для файлов.
    
    Накапливает изменения в памяти и периодически сохраняет их на диск.
    """
    
    def __init__(
        self,
        file_path: Path,
        flush_interval: int = 60,  # Интервал сохранения в секундах
        max_buffer_size: int = 100,  # Максимальный размер буфера перед принудительным сохранением
        load_func: Optional[Callable[[], Dict[str, Any]]] = None,
        save_func: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ):
        """
        Инициализирует буферизованный писатель.
        
        Args:
            file_path: Путь к файлу
            flush_interval: Интервал автоматического сохранения в секундах
            max_buffer_size: Максимальный размер буфера перед принудительным сохранением
            load_func: Функция для загрузки данных (если None, используется JSON)
            save_func: Функция для сохранения данных (если None, используется JSON)
        """
        self.file_path = file_path
        self.flush_interval = flush_interval
        self.max_buffer_size = max_buffer_size
        self._load_func = load_func or self._default_load
        self._save_func = save_func or self._default_save
        
        self._buffer: Deque[Callable[[Dict[str, Any]], None]] = deque()
        self._lock = Lock()
        self._last_flush = datetime.now()
        self._flush_task: Optional[asyncio.Task] = None
        
    def _default_load(self) -> Dict[str, Any]:
        """Загружает данные из JSON файла."""
        if not self.file_path.exists():
            return {}
        
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                # Убеждаемся, что данные - это словарь
                if not isinstance(data, dict):
                    logger.warning(f"Данные в {self.file_path} не являются словарем, возвращаем пустой словарь")
                    return {}
                return data
        except Exception as e:
            logger.error(f"Ошибка при загрузке {self.file_path}: {e}")
            return {}
    
    def _default_save(self, data: Dict[str, Any]) -> bool:
        """Сохраняет данные в JSON файл."""
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            return True
        except Exception as e:
            logger.error(f"Ошибка при сохранении {self.file_path}: {e}")
            return False
    
    def add_operation(self, operation: Callable[[Dict[str, Any]], None]) -> None:
        """
        Добавляет операцию в буфер.
        
        Args:
            operation: Функция, которая модифицирует данные
        """
        with self._lock:
            self._buffer.append(operation)
            
            # Принудительное сохранение при достижении лимита
            # Используем синхронное сохранение для надежности
            if len(self._buffer) >= self.max_buffer_size:
                # Всегда используем синхронное сохранение для надежности
                # Асинхронное сохранение будет выполнено периодически
                self._sync_flush()
    
    async def flush(self) -> bool:
        """
        Принудительно сохраняет все накопленные изменения.
        
        Returns:
            True если успешно сохранено
        """
        with self._lock:
            if not self._buffer:
                return True
            
            # Загружаем текущие данные
            loop = asyncio.get_running_loop()
            data = await loop.run_in_executor(
                None, self._load_func
            )
            
            # Применяем все операции из буфера
            while self._buffer:
                operation = self._buffer.popleft()
                try:
                    operation(data)
                except Exception as e:
                    logger.error(f"Ошибка при применении операции: {e}")
            
            # Сохраняем данные
            success = await loop.run_in_executor(
                None, self._save_func, data
            )
            
            if success:
                self._last_flush = datetime.now()
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Буфер сохранен в {self.file_path}")
            
            return success
    
    def _sync_flush(self) -> bool:
        """
        Синхронно сохраняет все накопленные изменения.
        Используется когда event loop недоступен.
        
        Returns:
            True если успешно сохранено
        """
        with self._lock:
            if not self._buffer:
                return True
            
            # Загружаем текущие данные
            data = self._load_func()
            
            # Применяем все операции из буфера
            while self._buffer:
                operation = self._buffer.popleft()
                try:
                    operation(data)
                except Exception as e:
                    logger.error(f"Ошибка при применении операции: {e}")
            
            # Сохраняем данные
            success = self._save_func(data)
            
            if success:
                self._last_flush = datetime.now()
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Буфер синхронно сохранен в {self.file_path}")
            
            return success
    
    async def _periodic_flush(self) -> None:
        """Периодически сохраняет буфер."""
        while True:
            await asyncio.sleep(self.flush_interval)
            
            with self._lock:
                time_since_flush = (datetime.now() - self._last_flush).total_seconds()
                if time_since_flush >= self.flush_interval and self._buffer:
                    await self.flush()
    
    def start_periodic_flush(self) -> None:
        """Запускает периодическое сохранение."""
        try:
            loop = asyncio.get_running_loop()
            if self._flush_task is None or self._flush_task.done():
                self._flush_task = asyncio.create_task(self._periodic_flush())
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Запущено периодическое сохранение для {self.file_path}")
        except RuntimeError:
            # Если нет запущенного event loop, периодическое сохранение будет недоступно
            # Это нормально для синхронных контекстов - будет использоваться только синхронное сохранение
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Event loop не запущен, периодическое сохранение недоступно для {self.file_path}")
    
    def stop_periodic_flush(self) -> None:
        """Останавливает периодическое сохранение."""
        if self._flush_task and not self._flush_task.done():
            self._flush_task.cancel()
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Остановлено периодическое сохранение для {self.file_path}")


# Глобальные буферизованные писатели для разных файлов
_buffered_writers: Dict[Path, BufferedFileWriter] = {}


def get_buffered_writer(
    file_path: Path,
    flush_interval: int = 60,
    max_buffer_size: int = 100,
) -> BufferedFileWriter:
    """
    Получает или создает буферизованный писатель для файла.
    
    Args:
        file_path: Путь к файлу
        flush_interval: Интервал сохранения в секундах
        max_buffer_size: Максимальный размер буфера
        
    Returns:
        Буферизованный писатель
    """
    if file_path not in _buffered_writers:
        _buffered_writers[file_path] = BufferedFileWriter(
            file_path, flush_interval, max_buffer_size
        )
        _buffered_writers[file_path].start_periodic_flush()
    
    return _buffered_writers[file_path]


async def flush_all_buffers() -> None:
    """Принудительно сохраняет все буферы."""
    for writer in _buffered_writers.values():
        await writer.flush()

