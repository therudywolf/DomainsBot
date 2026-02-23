"""
Telegram-бот для анализа доменов.

Тонкий модуль-точка входа: инициализация бота, сборка роутеров,
запуск polling и graceful shutdown.
"""

try:
    import uvloop  # type: ignore
    uvloop.install()
except ModuleNotFoundError:
    pass

import asyncio
import logging
import signal
import sys

from aiogram import Bot, Dispatcher, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import BotCommand

from config import settings
from access import ADMIN_ID

from utils.monitoring import start_monitoring, stop_monitoring
from utils.rate_limiter import cleanup_rate_limiter
from utils.stats import record_error
from utils.wireguard_utils import check_wg_connection
from utils.history import cleanup_old_history
from utils.logger_config import setup_logging

# ---------- Logging ----------

setup_logging(
    log_level=settings.LOG_LEVEL,
    log_file=settings.LOG_FILE if settings.LOG_FILE else None,
    max_bytes=settings.LOG_MAX_BYTES,
    backup_count=settings.LOG_BACKUP_COUNT,
)

logger = logging.getLogger(__name__)

# ---------- Shutdown event ----------

_shutdown_event = asyncio.Event()


# ---------- Logging middleware ----------

class LoggingMiddleware:
    """Middleware для логирования всех обновлений."""

    async def __call__(self, handler, event, data):
        start_time = asyncio.get_running_loop().time()
        event_type = type(event).__name__

        if isinstance(event, types.Message):
            user_id = event.from_user.id if event.from_user else None
            username = event.from_user.username if event.from_user else None
            chat_id = event.chat.id if event.chat else None
            text_preview = (event.text or event.caption or "")[:100] if hasattr(event, "text") or hasattr(event, "caption") else ""

            if user_id and chat_id and chat_id != user_id:
                try:
                    from utils.chat_settings import register_chat
                    chat_title = event.chat.title or f"Chat {chat_id}"
                    chat_type = event.chat.type
                    register_chat(user_id, chat_id, chat_title, chat_type)
                except Exception as e:
                    logger.debug(f"Ошибка при регистрации чата {chat_id}: {e}")

            logger.info(
                f"📨 Входящее сообщение | "
                f"user_id={user_id} (@{username}) | "
                f"chat_id={chat_id} | "
                f"text={text_preview} | "
                f"message_id={event.message_id if hasattr(event, 'message_id') else 'N/A'}"
            )
        elif isinstance(event, types.CallbackQuery):
            user_id = event.from_user.id if event.from_user else None
            username = event.from_user.username if event.from_user else None
            callback_data = event.data or "N/A"
            logger.info(
                f"🔘 Callback query | "
                f"user_id={user_id} (@{username}) | "
                f"callback_data={callback_data} | "
                f"message_id={event.message.message_id if event.message else 'N/A'}"
            )
        elif isinstance(event, types.InlineQuery):
            user_id = event.from_user.id if event.from_user else None
            query = (event.query or "")[:100]
            logger.info(f"🔍 Inline query | user_id={user_id} | query={query}")
        else:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"📥 Событие {event_type} получено")

        try:
            result = await handler(event, data)
            duration = asyncio.get_running_loop().time() - start_time
            if duration > 1.0:
                logger.warning(f"⏱️ Медленный обработчик | event={event_type} | duration={duration:.2f}s")
            else:
                logger.debug(f"✅ Обработчик выполнен | event={event_type} | duration={duration:.3f}s")
            return result
        except Exception as e:
            try:
                loop = asyncio.get_running_loop()
                duration = loop.time() - start_time
            except RuntimeError:
                duration = 0.0
            logger.error(
                f"❌ Ошибка в обработчике | event={event_type} | "
                f"duration={duration:.3f}s | error={type(e).__name__}: {e}",
                exc_info=True,
            )
            raise


# ---------- Bot commands menu ----------

async def setup_bot_commands(bot: Bot) -> None:
    """Настраивает команды бота для меню Telegram."""
    commands = [
        BotCommand(command="start", description="🚀 Запустить бота / Главное меню"),
        BotCommand(command="help", description="ℹ️ Справка по использованию"),
        BotCommand(command="monitor", description="📊 Управление мониторингом доменов"),
        BotCommand(command="history", description="📋 История проверок"),
        BotCommand(command="export_history", description="📥 Экспорт истории в CSV"),
    ]
    admin_commands = commands + [
        BotCommand(command="stats", description="📈 Статистика использования (админ)"),
        BotCommand(command="health", description="🏥 Проверка состояния системы (админ)"),
    ]
    try:
        await bot.set_my_commands(commands)
        from access import ADMIN_ID as _admin_id
        await bot.set_my_commands(admin_commands, scope=types.BotCommandScopeChat(chat_id=_admin_id))
        logger.info("Команды бота установлены")
    except Exception as e:
        logger.error(f"Ошибка при установке команд бота: {e}")


# ---------- Signal handlers ----------

def setup_signal_handlers(bot: Bot, dp: Dispatcher) -> None:
    """Настраивает обработчики сигналов для graceful shutdown."""
    def signal_handler(signum, frame):
        logger.info(f"Получен сигнал {signum}, начинаем graceful shutdown...")
        _shutdown_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)


# ---------- Resource cleanup ----------

async def cleanup_resources() -> None:
    """Очищает ресурсы при завершении работы."""
    logger.info("Очистка ресурсов...")
    try:
        stop_monitoring()
        logger.info("Мониторинг остановлен")
    except Exception as e:
        logger.error(f"Ошибка при остановке мониторинга: {e}")

    try:
        await cleanup_rate_limiter()
        logger.info("Rate limiter очищен")
    except Exception as e:
        logger.error(f"Ошибка при очистке rate limiter: {e}")

    try:
        if settings.HISTORY_ENABLED:
            removed = cleanup_old_history(settings.HISTORY_CLEANUP_DAYS)
            if removed > 0:
                logger.info(f"Удалено {removed} старых записей из истории")
    except Exception as e:
        logger.error(f"Ошибка при очистке истории: {e}")

    logger.info("Очистка ресурсов завершена")


# ---------- Main ----------

async def main():
    """Главная функция запуска бота."""
    if not settings.TG_TOKEN:
        logger.error("TG_TOKEN не задан в переменных окружения")
        raise RuntimeError("TG_TOKEN не задан в .env")

    logger.info("Запуск бота...")
    logger.info(f"Уровень логирования: {settings.LOG_LEVEL}")
    logger.info(f"Максимальная конкурентность: {settings.CONCURRENCY}")
    logger.info(f"Rate limit: {settings.RATE_LIMIT_REQUESTS} запросов за {settings.RATE_LIMIT_WINDOW} секунд")

    bot = Bot(
        settings.TG_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )

    await setup_bot_commands(bot)

    dp = Dispatcher(storage=MemoryStorage())
    logger.info("MemoryStorage: FSM state будет утеряно при перезапуске")

    # ---------- Register routers ----------
    from handlers.commands import router as commands_router
    from handlers.callbacks import router as callbacks_router
    from handlers.admin import router as admin_router
    from handlers.monitoring import router as monitoring_router
    from handlers.inline import router as inline_router
    from handlers.text import router as text_router

    dp.include_router(commands_router)
    dp.include_router(callbacks_router)
    dp.include_router(admin_router)
    dp.include_router(monitoring_router)
    dp.include_router(inline_router)
    dp.include_router(text_router)

    dp.message.middleware(LoggingMiddleware())
    dp.callback_query.middleware(LoggingMiddleware())

    logger.info("Все роутеры зарегистрированы")

    setup_signal_handlers(bot, dp)

    start_monitoring(bot)
    logger.info("Мониторинг доменов запущен")

    try:
        wg_status = check_wg_connection()
        if wg_status.get("config_found"):
            if wg_status.get("interface_up"):
                logger.info(f"✅ WireGuard контейнер доступен: {wg_status.get('container_name', 'wireguard')} ({wg_status.get('interface_ip', '—')})")
            else:
                logger.warning(f"⚠️ WireGuard конфиг найден, но контейнер недоступен: {wg_status.get('last_error', '—')}")
        else:
            logger.debug("ℹ️ WireGuard конфиг не найден — резерв при 504 недоступен")
    except Exception as e:
        logger.warning(f"WireGuard при старте: {e}")

    async def periodic_wg_check():
        while not _shutdown_event.is_set():
            await asyncio.sleep(300)
            if not _shutdown_event.is_set():
                try:
                    wg = check_wg_connection()
                    if wg.get("config_found") and not wg.get("interface_up"):
                        logger.warning(f"WireGuard контейнер недоступен: {wg.get('last_error', '—')}")
                except Exception as e:
                    logger.debug(f"Ошибка при периодической проверке WireGuard: {e}")

    async def periodic_cleanup():
        while not _shutdown_event.is_set():
            await asyncio.sleep(3600)
            if not _shutdown_event.is_set():
                await cleanup_resources()

    wg_check_task = asyncio.create_task(periodic_wg_check())
    cleanup_task = asyncio.create_task(periodic_cleanup())

    try:
        logger.info("Бот запущен и готов к работе")
        await dp.start_polling(
            bot,
            allowed_updates=dp.resolve_used_update_types(),
            close_bot_session=True,
        )
    except asyncio.CancelledError:
        logger.info("Polling отменен (graceful shutdown)")
    except Exception as e:
        logger.critical(f"❌ Критическая ошибка: {type(e).__name__}: {e}", exc_info=True)
        record_error("BOT_CRITICAL_ERROR")
    finally:
        wg_check_task.cancel()
        cleanup_task.cancel()
        try:
            await wg_check_task
        except asyncio.CancelledError:
            pass
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        await cleanup_resources()
        logger.info("Бот остановлен")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Получен сигнал прерывания от пользователя")
    except SystemExit:
        logger.info("Системный выход")
    except Exception as e:
        logger.critical(f"Критическая ошибка при запуске: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Приложение завершено")
