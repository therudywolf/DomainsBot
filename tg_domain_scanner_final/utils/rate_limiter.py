"""
Rate limiter для защиты от спама и злоупотреблений.

Реализует sliding window алгоритм для ограничения количества запросов
от одного пользователя за определенный период времени.

Использует asyncio.Lock для async-safe операций.
"""

import asyncio
import time
import logging
from collections import defaultdict, deque
from typing import Dict, Deque

logger = logging.getLogger(__name__)


class AsyncRateLimiter:
    """
    Async rate limiter с sliding window алгоритмом.
    
    Ограничивает количество запросов от пользователя за определенный период.
    Использует sliding window для более точного контроля.
    Все операции async-safe с использованием asyncio.Lock.
    """
    
    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        """
        Инициализирует rate limiter.
        
        Args:
            max_requests: Максимальное количество запросов за период
            window_seconds: Период времени в секундах
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Хранилище временных меток запросов для каждого пользователя
        self._requests: Dict[int, Deque[float]] = defaultdict(lambda: deque())
        self._lock = asyncio.Lock()
    
    async def is_allowed(self, user_id: int) -> bool:
        """
        Проверяет, разрешен ли запрос от пользователя.
        
        Args:
            user_id: ID пользователя
            
        Returns:
            True если запрос разрешен, False если превышен лимит
        """
        now = time.time()
        window_start = now - self.window_seconds
        
        async with self._lock:
            # Получаем очередь запросов пользователя
            user_requests = self._requests[user_id]
            
            # Удаляем устаревшие запросы (старше окна)
            while user_requests and user_requests[0] < window_start:
                user_requests.popleft()
            
            # Проверяем лимит
            if len(user_requests) >= self.max_requests:
                logger.warning(
                    f"Rate limit превышен для пользователя {user_id}: "
                    f"{len(user_requests)}/{self.max_requests} запросов за {self.window_seconds}с"
                )
                return False
            
            # Добавляем текущий запрос
            user_requests.append(now)
            return True
    
    async def get_remaining(self, user_id: int) -> int:
        """
        Получает количество оставшихся запросов для пользователя.
        
        Args:
            user_id: ID пользователя
            
        Returns:
            Количество оставшихся запросов
        """
        now = time.time()
        window_start = now - self.window_seconds
        
        async with self._lock:
            user_requests = self._requests[user_id]
            
            # Удаляем устаревшие запросы
            while user_requests and user_requests[0] < window_start:
                user_requests.popleft()
            
            return max(0, self.max_requests - len(user_requests))
    
    async def reset(self, user_id: int) -> None:
        """
        Сбрасывает счетчик запросов для пользователя.
        
        Args:
            user_id: ID пользователя
        """
        async with self._lock:
            if user_id in self._requests:
                self._requests[user_id].clear()
    
    async def cleanup_old_users(self, max_idle_seconds: int = 3600) -> int:
        """
        Удаляет данные о неактивных пользователях.
        
        Args:
            max_idle_seconds: Максимальное время неактивности в секундах
            
        Returns:
            Количество удаленных пользователей
        """
        now = time.time()
        removed = 0
        
        async with self._lock:
            users_to_remove = []
            
            for user_id, requests in self._requests.items():
                if not requests:
                    users_to_remove.append(user_id)
                    continue
                
                # Проверяем последний запрос
                last_request = requests[-1]
                if now - last_request > max_idle_seconds:
                    users_to_remove.append(user_id)
            
            for user_id in users_to_remove:
                del self._requests[user_id]
                removed += 1
        
        if removed > 0:
            logger.debug(f"Очищено {removed} неактивных пользователей из rate limiter")
        
        return removed


# Глобальные экземпляры async rate limiter для разных типов операций
# Значительно увеличены лимиты для предотвращения блокировки пользователей
# По умолчанию: 200 запросов в минуту для обычных операций (было 30)
_rate_limiter = AsyncRateLimiter(max_requests=200, window_seconds=60)

# Более строгий лимит для тяжелых операций (проверка доменов)
# Увеличено до 50 запросов в минуту (было 10)
_heavy_operation_limiter = AsyncRateLimiter(max_requests=50, window_seconds=60)

# Лимит для загрузки файлов
# Увеличено до 20 файлов в 5 минут (было 5)
_file_upload_limiter = AsyncRateLimiter(max_requests=20, window_seconds=300)

# Временная блокировка пользователей при превышении лимита
# Уменьшено до 30 секунд (было 5 минут) для более мягкой защиты
_blocked_users: Dict[int, float] = {}  # {user_id: unblock_timestamp}
_block_lock = asyncio.Lock()
BLOCK_DURATION = 30  # 30 секунд блокировки (было 300)


async def check_rate_limit(user_id: int, operation_type: str = "default") -> bool:
    """
    Проверяет rate limit для пользователя (async версия).
    
    Args:
        user_id: ID пользователя
        operation_type: Тип операции ("default", "heavy", "file_upload")
        
    Returns:
        True если запрос разрешен, False если превышен лимит
    """
    # Проверяем временную блокировку
    async with _block_lock:
        if user_id in _blocked_users:
            unblock_time = _blocked_users[user_id]
            if time.time() < unblock_time:
                return False
            else:
                # Блокировка истекла, удаляем
                del _blocked_users[user_id]
    
    # Выбираем соответствующий лимитер
    if operation_type == "heavy":
        limiter = _heavy_operation_limiter
    elif operation_type == "file_upload":
        limiter = _file_upload_limiter
    else:
        limiter = _rate_limiter
    
    # Проверяем лимит
    is_allowed = await limiter.is_allowed(user_id)
    
    # Если лимит превышен, блокируем пользователя на короткое время
    if not is_allowed:
        async with _block_lock:
            _blocked_users[user_id] = time.time() + BLOCK_DURATION
    
    return is_allowed


async def get_remaining_requests(user_id: int, operation_type: str = "default") -> int:
    """
    Получает количество оставшихся запросов (async версия).
    
    Args:
        user_id: ID пользователя
        operation_type: Тип операции ("default", "heavy", "file_upload")
        
    Returns:
        Количество оставшихся запросов
    """
    # Проверяем блокировку
    async with _block_lock:
        if user_id in _blocked_users:
            unblock_time = _blocked_users[user_id]
            if time.time() < unblock_time:
                return 0
    
    # Выбираем соответствующий лимитер
    if operation_type == "heavy":
        limiter = _heavy_operation_limiter
    elif operation_type == "file_upload":
        limiter = _file_upload_limiter
    else:
        limiter = _rate_limiter
    
    return await limiter.get_remaining(user_id)


async def cleanup_rate_limiter() -> None:
    """Очищает неактивных пользователей из rate limiter (async версия)."""
    await _rate_limiter.cleanup_old_users()
    await _heavy_operation_limiter.cleanup_old_users()
    await _file_upload_limiter.cleanup_old_users()
    
    # Очищаем истекшие блокировки
    async with _block_lock:
        now = time.time()
        expired_users = [
            user_id for user_id, unblock_time in _blocked_users.items()
            if now >= unblock_time
        ]
        for user_id in expired_users:
            del _blocked_users[user_id]
