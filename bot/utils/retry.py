import asyncio
import functools
import logging
from typing import Type, Tuple

logger = logging.getLogger(__name__)


def async_retry(
    max_retries: int = 2,
    base_delay: float = 1.0,
    backoff_factor: float = 2.0,
    exceptions: Tuple[Type[BaseException], ...] = (Exception,),
):
    """Decorator that retries an async function with exponential backoff."""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exc = e
                    if attempt < max_retries:
                        delay = base_delay * (backoff_factor ** attempt)
                        logger.debug(
                            f"Retry {attempt + 1}/{max_retries} for {func.__name__} "
                            f"after {delay:.1f}s: {e}"
                        )
                        await asyncio.sleep(delay)
            raise last_exc
        return wrapper
    return decorator
