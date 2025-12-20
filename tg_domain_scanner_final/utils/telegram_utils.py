"""
Утилиты для безопасной отправки сообщений в Telegram.

Модуль содержит функции для отправки длинных сообщений с автоматическим
разбиением на части (лимит Telegram - 4096 символов на сообщение).
"""

import asyncio
import logging
import time
from typing import Sequence, Union
from aiogram import Bot

logger = logging.getLogger(__name__)

# Максимальная длина сообщения в Telegram (в символах)
MAX_LEN = 4096

# Rate limiting для Telegram API
# Telegram позволяет ~30 сообщений в секунду, но для безопасности используем более консервативный лимит
# Используем 0.2 секунды между сообщениями (5 сообщений/сек) для избежания банов
_MIN_DELAY_BETWEEN_MESSAGES = 0.2  # Минимальная задержка между сообщениями (200ms = 5 сообщений/сек)
_last_message_time: float = 0
_message_lock = asyncio.Lock()


async def safe_send_text(
    bot: Bot,
    chat_id: Union[int, str],
    text: Union[str, Sequence[str]],
    **kwargs
) -> None:
    """
    Безопасно отправляет сообщение(я), разбивая длинные тексты на части.
    
    Автоматически разбивает текст на части по 4096 символов (лимит Telegram)
    и отправляет их последовательно. Сохраняет все дополнительные параметры
    (parse_mode, reply_markup и т.д.) для каждого сообщения.
    
    Args:
        bot: Экземпляр бота для отправки сообщений
        chat_id: ID чата или username получателя
        text: Текст для отправки. Может быть:
            - str: отправляется как есть
            - list/tuple/iterable[str]: объединяется через перенос строки
        **kwargs: Дополнительные параметры для send_message:
            - parse_mode: режим парсинга (HTML, Markdown и т.д.)
            - reply_markup: клавиатура или кнопки
            - и другие параметры aiogram.Bot.send_message
    
    Raises:
        aiogram.exceptions.TelegramAPIError: При ошибках API Telegram
    """
    # Нормализуем текст к строке
    if isinstance(text, (list, tuple)):
        # Если передан список/кортеж, объединяем через перенос строки
        text = "\n".join(str(x) for x in text)
    elif not isinstance(text, str):
        # Если передан другой тип, конвертируем в строку
        text = str(text)
    
    # Разбиваем текст на части и отправляем с rate limiting
    global _last_message_time
    
    for offset in range(0, len(text), MAX_LEN):
        chunk = text[offset : offset + MAX_LEN]
        
        # Rate limiting: добавляем задержку между сообщениями
        async with _message_lock:
            current_time = time.time()
            time_since_last = current_time - _last_message_time
            if time_since_last < _MIN_DELAY_BETWEEN_MESSAGES:
                delay = _MIN_DELAY_BETWEEN_MESSAGES - time_since_last
                await asyncio.sleep(delay)
            _last_message_time = time.time()
        
        try:
            await bot.send_message(chat_id, chunk, **kwargs)
        except Exception as e:
            logger.error(
                f"Ошибка при отправке сообщения в чат {chat_id}: {e}",
                exc_info=True
            )
            # Пробуем отправить следующую часть, но логируем ошибку
            raise


async def safe_send_document(
    bot: Bot,
    chat_id: Union[int, str],
    document: types.BufferedInputFile,
    **kwargs
) -> None:
    """
    Безопасно отправляет документ с rate limiting.
    
    Args:
        bot: Экземпляр бота для отправки сообщений
        chat_id: ID чата или username получателя
        document: Документ для отправки
        **kwargs: Дополнительные параметры для answer_document
    """
    global _last_message_time
    
    # Rate limiting: добавляем задержку перед отправкой документа
    async with _message_lock:
        current_time = time.time()
        time_since_last = current_time - _last_message_time
        if time_since_last < _MIN_DELAY_BETWEEN_MESSAGES:
            delay = _MIN_DELAY_BETWEEN_MESSAGES - time_since_last
            await asyncio.sleep(delay)
        _last_message_time = time.time()
    
    try:
        await bot.send_document(chat_id, document, **kwargs)
    except Exception as e:
        logger.error(
            f"Ошибка при отправке документа в чат {chat_id}: {e}",
            exc_info=True
        )
        raise
