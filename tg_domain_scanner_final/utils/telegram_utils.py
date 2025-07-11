
"""Utility helpers for Telegram messages.

safe_send_text splits long messages into chunks <=4096 symbols
and safely sends them preserving kwargs like parse_mode, reply_markup etc.
"""

from typing import Sequence, Union
from aiogram import Bot

MAX_LEN = 4096

async def safe_send_text(
    bot: Bot,
    chat_id: Union[int, str],
    text: Union[str, Sequence[str]],
    **kwargs
) -> None:
    """Send message(s) splitting by 4096‑byte limit.

    *text* can be:
    • str — will be sent as is;
    • list/tuple/iterable[str] — joined with line breaks.
    Any additional **kwargs (parse_mode, reply_markup…) will be
    forwarded to :py:meth:`aiogram.Bot.send_message`.
    """
    # Normalise to string
    if isinstance(text, (list, tuple)):
        text = "\n".join(str(x) for x in text)
    elif not isinstance(text, str):
        text = str(text)

    for offset in range(0, len(text), MAX_LEN):
        chunk = text[offset : offset + MAX_LEN]
        await bot.send_message(chat_id, chunk, **kwargs)
