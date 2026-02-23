"""Handlers for text messages and document uploads."""

import asyncio
import logging
import re
from typing import List, Tuple, Optional

from aiogram import F, Router, types
from aiogram.fsm.context import FSMContext

from access import has_access, has_permission, check_access, check_permission, ADMIN_ID, is_admin_user
from keyboards import (
    build_main_menu_keyboard,
    build_settings_keyboard,
    build_monitoring_keyboard,
    build_admin_keyboard,
    DEFAULT_MODE,
)
from config import settings
from utils.domain_processor import validate_and_normalize_domains, check_single_domain
from utils.report_formatter import format_csv_report, send_domain_reports
from utils.telegram_utils import safe_send_text, safe_reply, safe_edit_text, safe_send_document
from utils.rate_limiter import check_rate_limit, get_remaining_requests
from utils.stats import record_domain_check, record_error, record_command
from utils.error_logging import log_error_with_context, format_error_for_user
from utils.chat_settings import register_chat
from utils.prefs import get_mode
from utils.history import add_check_result

logger = logging.getLogger(__name__)

router = Router()


async def _process_domains(message: types.Message, state: FSMContext, raw_text: str) -> None:
    """
    Обрабатывает список доменов: парсит, нормализует, проверяет и формирует отчёт.
    
    Args:
        message: Сообщение от пользователя
        state: Состояние FSM
        raw_text: Текст с доменами для обработки
    """
    start_time = asyncio.get_running_loop().time()
    user_id = message.from_user.id
    
    logger.info(
        f"🔍 Начало обработки доменов | "
        f"user_id={user_id} | "
        f"text_length={len(raw_text)} | "
        f"chat_id={message.chat.id}"
    )
    
    # Автоматически регистрируем чат, если сообщение пришло не из личных сообщений
    if message.chat.id != user_id:
        chat_title = message.chat.title or f"Chat {message.chat.id}"
        chat_type = message.chat.type
        register_chat(user_id, message.chat.id, chat_title, chat_type)
    
    # Логируем начало обработки для отладки
    processing_start = asyncio.get_running_loop().time()
    
    # Проверка доступа
    if not await check_access(message):
        logger.warning(f"❌ Доступ запрещен для user_id={user_id} при обработке доменов")
        return
    
    # Проверка rate limit
    if not await check_rate_limit(user_id):
        remaining = await get_remaining_requests(user_id)
        logger.warning(
            f"⏱️ Rate limit превышен | "
            f"user_id={user_id} | "
            f"remaining={remaining}"
        )
        await safe_send_text(
            message.bot,
            message.chat.id,
            f"⏱️ Превышен лимит запросов. Попробуйте позже.\n"
            f"Осталось запросов: {remaining}"
        )
        return
    
    # Валидация и нормализация доменов
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Валидация и нормализация доменов для user_id={user_id}")
    domains, bad = validate_and_normalize_domains(raw_text)
    
    logger.info(
        f"📋 Домены обработаны | "
        f"user_id={user_id} | "
        f"valid={len(domains)} | "
        f"invalid={len(bad)}"
    )

    # Проверка на пустой список
    if not domains:
        await safe_send_text(
            message.bot,
            message.chat.id,
            "❗️ Не вижу ни одного корректного домена.\n\n"
            "Убедитесь, что домены указаны правильно. Поддерживаются форматы:\n"
            "• example.com\n"
            "• https://example.com/path\n"
            "• http://example.com?param=value"
        )
        return
    
    # Проверка лимита доменов
    if len(domains) > settings.MAX_DOMAINS_PER_REQUEST:
        await safe_send_text(
            message.bot,
            message.chat.id,
            f"❗️ Превышен лимит доменов ({settings.MAX_DOMAINS_PER_REQUEST}).\n"
            f"Получено: {len(domains)} доменов."
        )
        return

    # Получаем режим отображения из состояния
    view_mode = (await state.get_data()).get("view_mode", DEFAULT_MODE)
    brief = view_mode == "brief"

    # Семафор для ограничения количества одновременных проверок
    semaphore = asyncio.Semaphore(settings.CONCURRENCY)
    reports: List[str] = []
    collected: List[Tuple[str, dict, dict, bool, Optional[str]]] = []

    # Создаем задачи для проверки всех доменов
    tasks = [
        asyncio.create_task(check_single_domain(d, user_id, semaphore, brief))
        for d in domains
    ]

    # ---------- Прогресс-индикатор ----------
    MIN_EDIT_INTERVAL = 6  # секунд между edit_text (баланс между отзывчивостью и лимитами Telegram API)
    total = len(tasks)
    done = 0
    loop = asyncio.get_running_loop()
    start_ts = loop.time()
    last_edit = start_ts - MIN_EDIT_INTERVAL
    progress_msg: types.Message | None = None

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Ожидание завершения {total} задач проверки доменов")
    
    # Максимальное время на проверку одного домена (включая все попытки)
    MAX_DOMAIN_CHECK_TIMEOUT = 120  # 2 минуты на домен
    
    # Обертываем каждую задачу в таймаут
    async def check_with_timeout(task: asyncio.Task, domain: str) -> Tuple[str, Tuple[str, dict, dict, bool, Optional[str]]]:
        """Обертка для задачи с таймаутом."""
        try:
            return await asyncio.wait_for(task, timeout=MAX_DOMAIN_CHECK_TIMEOUT)
        except asyncio.TimeoutError:
            logger.error(
                f"⏱️ Таймаут при проверке домена {domain} | "
                f"user_id={user_id} | "
                f"timeout={MAX_DOMAIN_CHECK_TIMEOUT}s"
            )
            # Отменяем задачу при таймауте
            if not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
            # Возвращаем частичный результат при таймауте
            error_msg = f"⏱️ Таймаут проверки (> {MAX_DOMAIN_CHECK_TIMEOUT}s)"
            row = (domain, {}, {}, False, None)
            return error_msg, row
        except BaseException as e:
            logger.error(
                f"❌ Критическая ошибка при проверке домена {domain} | "
                f"user_id={user_id} | "
                f"error={type(e).__name__}: {str(e)}",
                exc_info=True
            )
            # Отменяем задачу при ошибке
            if not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
            error_msg = f"❌ Ошибка: {type(e).__name__}"
            row = (domain, {}, {}, False, None)
            return error_msg, row
    
    # Создаем обернутые задачи
    wrapped_tasks = [
        asyncio.create_task(check_with_timeout(task, domain))
        for task, domain in zip(tasks, domains)
    ]
    
    # Общий таймаут для всей обработки (максимум 10 минут на все домены)
    MAX_TOTAL_PROCESSING_TIME = 600  # 10 минут
    
    try:
        # Используем as_completed напрямую, но с проверкой общего таймаута
        completed_count = 0
        for coro in asyncio.as_completed(wrapped_tasks):
            # Проверяем общий таймаут перед обработкой каждого результата
            elapsed_total = loop.time() - start_ts
            if elapsed_total > MAX_TOTAL_PROCESSING_TIME:
                logger.error(
                    f"⏱️ Превышен общий таймаут обработки доменов | "
                    f"user_id={user_id} | "
                    f"elapsed={elapsed_total:.2f}s | "
                    f"done={done}/{total}"
                )
                # Отменяем все оставшиеся задачи
                for task in wrapped_tasks:
                    if not task.done():
                        task.cancel()
                break
            
            try:
                line, row = await coro
                reports.append(line)
                collected.append(row)
                done += 1
                completed_count += 1
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"✅ Домен проверен: {row[0]} ({done}/{total})")
            except BaseException as e:
                logger.error(
                    f"❌ Неожиданная ошибка при обработке результата проверки | "
                    f"user_id={user_id} | "
                    f"done={done}/{total} | "
                    f"error={type(e).__name__}: {str(e)}",
                    exc_info=True
                )
                done += 1
                completed_count += 1
                # Добавляем пустой результат, чтобы не сломать счетчик
                row = ("unknown", {}, {}, False, None)
                collected.append(row)

            now = loop.time()
            need_update = total >= 4 and (done == total or now - last_edit >= MIN_EDIT_INTERVAL)

            if need_update:
                elapsed = now - start_ts
                # Защита от деления на ноль
                if done > 0 and done < total:
                    eta_sec = int(elapsed / done * (total - done))
                    eta_txt = f"{eta_sec // 60}м {eta_sec % 60}с" if eta_sec > 0 else "0 с"
                else:
                    eta_txt = "0 с"
                text = f"⏳ {done} / {total} • осталось ≈ {eta_txt}"

                try:
                    if progress_msg is None:
                        progress_msg = await safe_reply(message, text)
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"Создано сообщение прогресса для user_id={user_id}")
                    else:
                        await safe_edit_text(progress_msg, text)
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"Обновлено сообщение прогресса: {done}/{total} для user_id={user_id}")
                    last_edit = now
                except Exception as e:
                    logger.warning(f"Ошибка при обновлении прогресса: {e}")
                    progress_msg = None
            
            # Если все задачи завершены, выходим из цикла
            if completed_count >= total:
                logger.debug(f"Все {total} задач завершены, выходим из цикла")
                break
        
        logger.debug(f"Цикл as_completed завершен: completed={completed_count}, done={done}, total={total}")
    finally:
        # Отменяем все незавершенные задачи с таймаутом
        remaining_tasks = [t for t in wrapped_tasks if not t.done()]
        if remaining_tasks:
            logger.warning(f"Отменяем {len(remaining_tasks)} незавершенных задач для user_id={user_id}")
            for task in remaining_tasks:
                task.cancel()
            # Ждем отмены с таймаутом, чтобы не блокировать event loop
            try:
                await asyncio.wait_for(
                    asyncio.gather(*remaining_tasks, return_exceptions=True),
                    timeout=2.0
                )
            except asyncio.TimeoutError:
                logger.warning(f"Таймаут при ожидании отмены задач для user_id={user_id}")
        logger.debug(f"Все задачи завершены или отменены для user_id={user_id}")

    if bad:
        reports.append("🔸 Игнорированы некорректные строки: " + ", ".join(bad))

    total_duration = asyncio.get_running_loop().time() - start_time
    processing_duration = asyncio.get_running_loop().time() - processing_start
    logger.info(
        f"✅ Все домены проверены | "
        f"user_id={user_id} | "
        f"total={total} | "
        f"duration={total_duration:.2f}s | "
        f"processing_duration={processing_duration:.2f}s | "
        f"avg_per_domain={total_duration/total:.2f}s"
    )

    # ---------- Формирование вывода ----------
    if total >= 4:
        logger.debug(f"Отправка CSV отчета для {total} доменов")
        # CSV отчет для множественных доменов
        csv_bytes = format_csv_report(collected, brief)
        await safe_send_document(
            message.bot,
            message.chat.id,
            types.BufferedInputFile(csv_bytes, filename="report.csv"),
            caption=f"✔️ Проверено {total} доменов.",
        )
        logger.info(f"CSV отчет отправлен для user_id={user_id}, доменов={total}")
    else:
        logger.debug(f"Отправка отдельных отчетов для {total} доменов")
        # Отдельные отчеты для каждого домена
        has_waf_perm = has_permission(user_id, "check_domains")
        has_monitoring_perm = has_permission(user_id, "monitoring")
        await send_domain_reports(
            message.bot,
            message.chat.id,
            collected,
            view_mode,
            user_id,
            has_waf_perm,
            brief,
            has_monitoring_perm
        )
        logger.info(f"Отчеты отправлены для user_id={user_id}, доменов={total}")


@router.message(F.document)
async def handle_document(message: types.Message, state: FSMContext):
    """
    Обрабатывает загруженные документы (TXT файлы со списком доменов).
    
    Поддерживает только .txt файлы с кодировкой UTF-8.
    Максимальный размер файла ограничен настройкой MAX_FILE_SIZE_MB.
    
    Также автоматически регистрирует чат, если сообщение пришло из группы/канала.
    """
    user_id = message.from_user.id
    
    # Регистрируем чат, если сообщение пришло не из личных сообщений
    if message.chat.id != user_id:
        chat_title = message.chat.title or f"Chat {message.chat.id}"
        chat_type = message.chat.type
        register_chat(user_id, message.chat.id, chat_title, chat_type)

    # В группах: обрабатывать только при упоминании бота или ответе на его сообщение
    if settings.BOT_GROUP_MENTION_ONLY and message.chat.type in ("group", "supergroup"):
        from access import get_bot_username
        bot_username = await get_bot_username(message.bot)
        reply_to_bot = (
            message.reply_to_message
            and message.reply_to_message.from_user
            and getattr(message.reply_to_message.from_user, "is_bot", False)
        )
        caption_lower = (message.caption or "").lower()
        mentioned = f"@{bot_username}".lower() in caption_lower
        if not reply_to_bot and not mentioned:
            logger.debug(
                f"Пропуск файла в группе без упоминания/ответа | chat_id={message.chat.id}"
            )
            return

    # Проверка доступа
    if not await check_access(message):
        return

    # Проверка rate limit (загрузка файлов)
    if not await check_rate_limit(user_id, operation_type="file_upload"):
        remaining = await get_remaining_requests(user_id, operation_type="file_upload")
        await message.reply(
            f"⏱️ Превышен лимит загрузки файлов. Попробуйте позже.\n"
            f"Осталось загрузок: {remaining}"
        )
        return
    
    doc = message.document
    
    # Проверка разрешения на загрузку файлов
    if not has_permission(user_id, "file_upload"):
        await message.reply(
            "❌ У вас нет доступа к загрузке файлов.\n\n"
            "Свяжитесь с администратором для получения доступа."
        )
        return
    
    # Проверка расширения файла
    if not doc.file_name or not doc.file_name.lower().endswith(".txt"):
        await message.reply(
            "📄 Пришлите TXT-файл со списком доменов.\n\n"
            "Файл должен содержать домены, по одному на строку."
        )
        return
    
    # Защита от инъекций в имени файла
    if re.search(r'[<>:"/\\|?*\x00-\x1f]', doc.file_name):
        await message.reply(
            "❌ Некорректное имя файла. Используйте только безопасные символы."
        )
        return
    
    # Проверка размера файла
    max_size_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    if doc.file_size and doc.file_size > max_size_bytes:
        await message.reply(
            f"❌ Файл слишком большой.\n"
            f"Максимальный размер: {settings.MAX_FILE_SIZE_MB} MB\n"
            f"Размер вашего файла: {doc.file_size / 1024 / 1024:.2f} MB"
        )
        return
    
    try:
        # Загружаем файл
        file_obj = await message.bot.download(doc.file_id)
        text_data = file_obj.getvalue().decode("utf-8", errors="ignore")
        
        # Проверяем, что файл не пустой
        if not text_data.strip():
            await message.reply("❌ Файл пуст или не содержит текста.")
            return
        
        # Обрабатываем домены из файла
        await _process_domains(message, state, text_data)
        
        # Записываем использование команды
        record_command("file_upload")
        
    except Exception as e:
        error_id = log_error_with_context(
            e,
            user_id=user_id,
            context={"operation": "file_upload"},
            level="ERROR",
        )
        record_error("FILE_PROCESSING_ERROR")
        await safe_send_text(
            message.bot,
            message.chat.id,
            format_error_for_user(error_id, "FILE_PROCESSING_ERROR"),
        )


@router.message(F.text)
async def handle_text(message: types.Message, state: FSMContext):
    """
    Обрабатывает текстовые сообщения.
    
    Поддерживает:
    - Проверку доменов (прямой ввод)
    - Команды через кнопки меню
    
    Также автоматически регистрирует чат, если сообщение пришло из группы/канала.
    """
    start_time = asyncio.get_running_loop().time()
    user_id = message.from_user.id
    text = (message.text or "").strip()
    
    logger.info(
        f"📝 Обработка текстового сообщения | "
        f"user_id={user_id} | "
        f"chat_id={message.chat.id} | "
        f"text_length={len(text)} | "
        f"text_preview={text[:100]}"
    )
    
    # Регистрируем чат, если сообщение пришло не из личных сообщений
    if message.chat.id != user_id:
        chat_title = message.chat.title or f"Chat {message.chat.id}"
        chat_type = message.chat.type
        register_chat(user_id, message.chat.id, chat_title, chat_type)
        logger.debug(f"Чат зарегистрирован: {chat_title} (ID: {message.chat.id})")

    # Проверка доступа
    if not await check_access(message):
        logger.warning(f"❌ Доступ запрещен для user_id={user_id}")
        return
    
    # Обработка команд через кнопки меню
    if text == "🔍 Проверить домен":
        await message.answer(
            "📝 Введите домен(ы) для проверки:\n\n"
            "Можно указать несколько доменов через пробел или запятую.\n"
            "Поддерживаются URL: `https://example.com/path`"
        )
        return
    
    elif text == "📊 Мониторинг":
        # Проверка разрешения на мониторинг
        if not has_permission(message.from_user.id, "monitoring"):
            await message.answer(
                "❌ У вас нет доступа к мониторингу доменов.\n\n"
                "Свяжитесь с администратором для получения доступа."
            )
            return
        from handlers.commands import cmd_monitor
        await cmd_monitor(message)
        return
    
    elif text == "⚙️ Настройки":
        # Проверка разрешения на настройки
        if not has_permission(user_id, "settings"):
            await message.answer(
                "❌ У вас нет доступа к настройкам.\n\n"
                "Свяжитесь с администратором для получения доступа."
            )
            return
        
        await message.answer(
            "⚙️ <b>Настройки</b>\n\n"
            "Выберите параметр для изменения:",
            reply_markup=build_settings_keyboard(user_id),
        )
        return
    
    elif text == "📋 История":
        # Проверка разрешения на историю
        if not has_permission(message.from_user.id, "history"):
            await message.answer(
                "❌ У вас нет доступа к истории проверок.\n\n"
                "Свяжитесь с администратором для получения доступа."
            )
            return
        from handlers.commands import cmd_history
        await cmd_history(message)
        return
    
    elif text == "👨‍💼 Админ-панель" and is_admin_user(user_id):
        help_text = (
            "👨‍💼 <b>Админ-панель</b>\n\n"
            "Используйте кнопки ниже для управления доступом:"
        )
        await safe_send_text(
            message.bot,
            message.chat.id,
            help_text,
            reply_markup=build_admin_keyboard(user_id),
        )
        return
    
    elif text == "ℹ️ Помощь":
        from handlers.commands import cmd_help
        await cmd_help(message, state)
        return
    
    elif text == "🔙 Назад" or text == "🏠 Главное меню":
        # Возврат в главное меню
        await state.clear()
        from handlers.commands import cmd_start
        await cmd_start(message, state)
        return
    
    # Если это не команда меню, обрабатываем как домены
    if text:
        # В группах: обрабатывать запрос доменов только при упоминании бота или ответе на него
        if settings.BOT_GROUP_MENTION_ONLY and message.chat.type in ("group", "supergroup"):
            from access import get_bot_username
            bot_username = await get_bot_username(message.bot)
            reply_to_bot = (
                message.reply_to_message
                and message.reply_to_message.from_user
                and getattr(message.reply_to_message.from_user, "is_bot", False)
            )
            text_lower = text.lower()
            mentioned = f"@{bot_username}".lower() in text_lower
            if not reply_to_bot and not mentioned:
                logger.debug(
                    f"Пропуск доменов в группе без упоминания/ответа | chat_id={message.chat.id}"
                )
                return
        logger.debug(f"Обработка доменов из текста для user_id={user_id}")
        try:
            await _process_domains(message, state, text)
            duration = asyncio.get_running_loop().time() - start_time
            logger.info(
                f"✅ Обработка доменов завершена | "
                f"user_id={user_id} | "
                f"duration={duration:.2f}s"
            )
        except Exception as e:
            duration = asyncio.get_running_loop().time() - start_time
            error_id = log_error_with_context(
                e,
                user_id=user_id,
                context={"operation": "process_domains", "text_preview": text[:200]},
                level="ERROR",
            )
            record_error("PROCESSING_ERROR")
            await safe_send_text(
                message.bot,
                message.chat.id,
                format_error_for_user(error_id, "PROCESSING_ERROR"),
            )
            logger.info(
                f"❌ Пользователю отправлено сообщение об ошибке | "
                f"user_id={user_id} | duration={duration:.2f}s | error_id={error_id}"
            )
