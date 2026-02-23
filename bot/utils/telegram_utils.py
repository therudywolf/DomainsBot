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
from aiogram import types

logger = logging.getLogger(__name__)

# Максимальная длина сообщения в Telegram (в символах)
MAX_LEN = 4096

# Rate limiting для Telegram API
# Telegram позволяет ~30 сообщений в секунду, но для безопасности используем более консервативный лимит
# Увеличено до 0.3 секунды между сообщениями для баланса между защитой от банов и отзывчивостью
_MIN_DELAY_BETWEEN_MESSAGES = 0.3  # Минимальная задержка между сообщениями (0.3 сек = ~3 сообщения/сек)
_last_message_time: float = 0
_message_lock = asyncio.Lock()


async def wait_for_rate_limit(delay: float = _MIN_DELAY_BETWEEN_MESSAGES) -> None:
    """
    Ожидает, если необходимо, перед выполнением операции с Telegram API.
    Используется для всех операций: send_message, edit_text, send_document и т.д.
    
    Args:
        delay: Минимальная задержка между операциями (по умолчанию _MIN_DELAY_BETWEEN_MESSAGES)
    """
    global _last_message_time
    async with _message_lock:
        current_time = time.time()
        time_since_last = current_time - _last_message_time
        if time_since_last < delay:
            sleep_time = delay - time_since_last
            await asyncio.sleep(sleep_time)
        _last_message_time = time.time()


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
    for offset in range(0, len(text), MAX_LEN):
        chunk = text[offset : offset + MAX_LEN]
        
        # Rate limiting: добавляем задержку между сообщениями
        await wait_for_rate_limit()
        
        try:
            await bot.send_message(chat_id, chunk, **kwargs)
        except Exception as e:
            logger.error(
                f"Ошибка при отправке сообщения в чат {chat_id}: {e}",
                exc_info=True
            )


async def safe_reply(
    message: types.Message,
    text: Union[str, Sequence[str]],
    delay: float = _MIN_DELAY_BETWEEN_MESSAGES,
    **kwargs
) -> types.Message:
    """
    Безопасно отвечает на сообщение с rate limiting.
    
    Args:
        message: Сообщение для ответа
        text: Текст ответа
        delay: Задержка перед отправкой (по умолчанию используется _MIN_DELAY_BETWEEN_MESSAGES)
        **kwargs: Дополнительные параметры для reply
    """
    await wait_for_rate_limit(delay)
    return await message.reply(text, **kwargs)


async def safe_edit_text(
    message: types.Message,
    text: Union[str, Sequence[str]],
    delay: float = _MIN_DELAY_BETWEEN_MESSAGES,
    **kwargs
) -> types.Message:
    """
    Безопасно редактирует сообщение с rate limiting.
    
    Args:
        message: Сообщение для редактирования
        text: Новый текст
        delay: Задержка перед редактированием (по умолчанию используется _MIN_DELAY_BETWEEN_MESSAGES)
        **kwargs: Дополнительные параметры для edit_text
    """
    await wait_for_rate_limit(delay)
    return await message.edit_text(text, **kwargs)


async def safe_send_document(
    bot: Bot,
    chat_id: Union[int, str],
    document: types.BufferedInputFile,
    delay: float = _MIN_DELAY_BETWEEN_MESSAGES,
    **kwargs
) -> None:
    """
    Безопасно отправляет документ с rate limiting.
    
    Args:
        bot: Экземпляр бота для отправки сообщений
        chat_id: ID чата или username получателя
        document: Документ для отправки
        delay: Задержка перед отправкой (по умолчанию используется _MIN_DELAY_BETWEEN_MESSAGES)
        **kwargs: Дополнительные параметры для send_document
    """
    await wait_for_rate_limit(delay)
    
    try:
        await bot.send_document(chat_id, document, **kwargs)
    except Exception as e:
        logger.error(
            f"Ошибка при отправке документа в чат {chat_id}: {e}",
            exc_info=True
        )
        raise
