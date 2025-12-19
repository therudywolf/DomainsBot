"""
Rate limiter для защиты от спама и злоупотреблений.

Реализует sliding window алгоритм для ограничения количества запросов
от одного пользователя за определенный период времени.
"""

import time
import logging
from collections import defaultdict, deque
from typing import Dict, Deque
from threading import Lock

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Rate limiter с sliding window алгоритмом.
    
    Ограничивает количество запросов от пользователя за определенный период.
    Использует sliding window для более точного контроля.
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
        self._lock = Lock()
    
    def is_allowed(self, user_id: int) -> bool:
        """
        Проверяет, разрешен ли запрос от пользователя.
        
        Args:
            user_id: ID пользователя
            
        Returns:
            True если запрос разрешен, False если превышен лимит
        """
        now = time.time()
        window_start = now - self.window_seconds
        
        with self._lock:
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
    
    def get_remaining(self, user_id: int) -> int:
        """
        Получает количество оставшихся запросов для пользователя.
        
        Args:
            user_id: ID пользователя
            
        Returns:
            Количество оставшихся запросов
        """
        now = time.time()
        window_start = now - self.window_seconds
        
        with self._lock:
            user_requests = self._requests[user_id]
            
            # Удаляем устаревшие запросы
            while user_requests and user_requests[0] < window_start:
                user_requests.popleft()
            
            return max(0, self.max_requests - len(user_requests))
    
    def reset(self, user_id: int) -> None:
        """
        Сбрасывает счетчик запросов для пользователя.
        
        Args:
            user_id: ID пользователя
        """
        with self._lock:
            if user_id in self._requests:
                self._requests[user_id].clear()
    
    def cleanup_old_users(self, max_idle_seconds: int = 3600) -> int:
        """
        Удаляет данные о неактивных пользователях.
        
        Args:
            max_idle_seconds: Максимальное время неактивности в секундах
            
        Returns:
            Количество удаленных пользователей
        """
        now = time.time()
        removed = 0
        
        with self._lock:
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


# Глобальный экземпляр rate limiter
# По умолчанию: 30 запросов в минуту
_rate_limiter = RateLimiter(max_requests=30, window_seconds=60)


def check_rate_limit(user_id: int) -> bool:
    """
    Проверяет rate limit для пользователя.
    
    Args:
        user_id: ID пользователя
        
    Returns:
        True если запрос разрешен
    """
    return _rate_limiter.is_allowed(user_id)


def get_remaining_requests(user_id: int) -> int:
    """
    Получает количество оставшихся запросов.
    
    Args:
        user_id: ID пользователя
        
    Returns:
        Количество оставшихся запросов
    """
    return _rate_limiter.get_remaining(user_id)


def cleanup_rate_limiter() -> None:
    """Очищает неактивных пользователей из rate limiter."""
    _rate_limiter.cleanup_old_users()

