"""Inline query handler that performs domain checks and returns results directly."""

import asyncio
import logging

from aiogram import Router, types
from aiogram.enums import ParseMode
from aiogram.types import (
    InlineQuery,
    InlineQueryResultArticle,
    InputTextMessageContent,
)

from access import has_access, has_permission, get_bot_username
from utils.domain_normalizer import normalize_domain
from utils.domain_processor import check_single_domain

logger = logging.getLogger(__name__)

router = Router()


@router.inline_query()
async def inline_query_handler(inline_query: InlineQuery):
    """Inline query handler that performs domain checks and returns results directly."""
    user_id = inline_query.from_user.id
    query = (inline_query.query or "").strip()

    if not has_access(user_id):
        bot_username = await get_bot_username(inline_query.bot)
        results = [
            InlineQueryResultArticle(
                id="no_access",
                title="Нет доступа",
                description="Свяжитесь с администратором для получения доступа",
                input_message_content=InputTextMessageContent(
                    message_text=f"Для использования бота запросите доступ у администратора @{bot_username}.",
                ),
            )
        ]
        await inline_query.answer(results, cache_time=10)
        return

    if not has_permission(user_id, "inline"):
        results = [
            InlineQueryResultArticle(
                id="no_permission",
                title="Нет разрешения на inline",
                description="Свяжитесь с администратором",
                input_message_content=InputTextMessageContent(
                    message_text="У вас нет разрешения на использование inline режима.",
                ),
            )
        ]
        await inline_query.answer(results, cache_time=10)
        return

    if not query:
        results = [
            InlineQueryResultArticle(
                id="empty",
                title="Введите домен",
                description="Например: example.com",
                input_message_content=InputTextMessageContent(
                    message_text="Используйте: @bot example.com",
                ),
            )
        ]
        await inline_query.answer(results, cache_time=5)
        return

    normalized = normalize_domain(query)
    if not normalized:
        results = [
            InlineQueryResultArticle(
                id="invalid",
                title="Некорректный домен",
                description=f"'{query}' не является доменом",
                input_message_content=InputTextMessageContent(
                    message_text=f"Некорректный домен: {query}",
                ),
            )
        ]
        await inline_query.answer(results, cache_time=10)
        return

    # Show a "checking..." placeholder while we work
    semaphore = asyncio.Semaphore(1)
    try:
        line, _row = await asyncio.wait_for(
            check_single_domain(normalized, user_id, semaphore, brief=True),
            timeout=12.0,
        )
    except asyncio.TimeoutError:
        line = (
            f"<b>{normalized}</b>\n"
            f"⏱ Таймаут проверки. Попробуйте /start в личных сообщениях бота."
        )
    except Exception as e:
        logger.error(f"Inline check error for {normalized}: {e}", exc_info=True)
        line = (
            f"<b>{normalized}</b>\n"
            f"❌ Ошибка при проверке. Попробуйте позже."
        )

    results = [
        InlineQueryResultArticle(
            id=f"check_{normalized}",
            title=f"Результат: {normalized}",
            description="Нажмите чтобы отправить результат проверки",
            input_message_content=InputTextMessageContent(
                message_text=line,
                parse_mode=ParseMode.HTML,
            ),
        )
    ]
    await inline_query.answer(results, cache_time=300)
