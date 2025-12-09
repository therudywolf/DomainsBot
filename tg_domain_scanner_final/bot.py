# Optional uvloop for speed

try:
    import uvloop  # type: ignore
    uvloop.install()
except ModuleNotFoundError:
    pass

import asyncio
import csv
import io
import json
import logging
import re
import os
from typing import List, Tuple
from pathlib import Path

from aiogram import Bot, Dispatcher, F, Router, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.fsm.state import State, StatesGroup

from config import settings
from utils.dns_utils import fetch_dns
from utils.ssl_utils import fetch_ssl
from utils.waf_utils import test_waf
from utils.formatting import build_report
from utils.telegram_utils import safe_send_text
from utils.prefs import get_mode, set_mode

logger = logging.getLogger(__name__)

DOMAIN_SPLIT_RE = re.compile(r"[\s,]+")
DOMAIN_VALID_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")
DEFAULT_MODE = "full"  # 'full' | 'brief'

# ---------- Конфиг для авторизации ----------
ADMIN_ID = int(os.getenv("ADMIN_ID", "6323277521"))
REQUEST_ACCESS_URL = os.getenv("REQUEST_ACCESS_URL", "https://t.me/tyoma_platonov")
ACCESS_DB_FILE = Path("data/access_db.json")

# Убедимся, что директория существует
ACCESS_DB_FILE.parent.mkdir(parents=True, exist_ok=True)

# ---------- БД доступов ----------

def load_access_db() -> dict:
    """Загружает БД доступа из JSON файла."""
    if ACCESS_DB_FILE.exists():
        try:
            with open(ACCESS_DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Ошибка при загрузке БД: {e}")
            return {}
    return {}


def save_access_db(data: dict) -> None:
    """Сохраняет БД доступа в JSON файл."""
    try:
        with open(ACCESS_DB_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.error(f"Ошибка при сохранении БД: {e}")


def has_access(user_id: int) -> bool:
    """Проверяет, есть ли у пользователя доступ."""
    # Админ всегда имеет доступ
    if user_id == ADMIN_ID:
        return True
    
    db = load_access_db()
    return str(user_id) in db


def add_access(user_id: int, username: str = "") -> bool:
    """Добавляет доступ пользователю."""
    db = load_access_db()
    db[str(user_id)] = {
        "username": username or "",
        "added_at": str(__import__('datetime').datetime.now())
    }
    save_access_db(db)
    return True


def remove_access(user_id: int) -> bool:
    """Удаляет доступ пользователя."""
    db = load_access_db()
    if str(user_id) in db:
        del db[str(user_id)]
        save_access_db(db)
        return True
    return False


def get_access_list() -> dict:
    """Получает список всех доступов."""
    return load_access_db()


# ---------- FSM для админ команд ----------

class AdminStates(StatesGroup):
    add_access_waiting = State()
    remove_access_waiting = State()


# ---------- Клавиатура режима ----------

def build_mode_keyboard(current_mode: str) -> types.InlineKeyboardMarkup:
    """Inline-кнопки для переключения формата вывода."""
    return types.InlineKeyboardMarkup(
        inline_keyboard=[
            [
                types.InlineKeyboardButton(
                    text=("✅ 🔎 Расширенный" if current_mode == "full" else "🔎 Расширенный"),
                    callback_data="mode_full",
                ),
                types.InlineKeyboardButton(
                    text=("✅ 📄 Короткий" if current_mode == "brief" else "📄 Короткий"),
                    callback_data="mode_brief",
                ),
            ]
        ]
    )


def build_access_denied_keyboard() -> types.InlineKeyboardMarkup:
    """Кнопка для запроса доступа."""
    return types.InlineKeyboardMarkup(
        inline_keyboard=[
            [
                types.InlineKeyboardButton(
                    text="📬 Запросить доступ",
                    url=REQUEST_ACCESS_URL,
                ),
            ]
        ]
    )


def build_admin_keyboard() -> types.InlineKeyboardMarkup:
    """Админ-панель кнопок."""
    return types.InlineKeyboardMarkup(
        inline_keyboard=[
            [
                types.InlineKeyboardButton(
                    text="➕ Добавить доступ",
                    callback_data="admin_add_access",
                ),
                types.InlineKeyboardButton(
                    text="➖ Удалить доступ",
                    callback_data="admin_remove_access",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="📋 Список доступов",
                    callback_data="admin_list_access",
                ),
            ]
        ]
    )


router = Router()

# ---------- Основная проверка доступа ----------

async def check_access(message: types.Message) -> bool:
    """Проверяет доступ пользователя. Если нет доступа - отправляет сообщение."""
    if has_access(message.from_user.id):
        return True
    
    await message.answer(
        "❌ У вас нет доступа к этому боту.\n\n"
        "Свяжитесь с администратором, нажав кнопку ниже.",
        reply_markup=build_access_denied_keyboard()
    )
    return False


# ---------- Основная проверка домена ----------

async def _process_domains(message: types.Message, state: FSMContext, raw_text: str) -> None:
    """Парсит ввод, запускает проверки и формирует отчёт."""
    # Проверка доступа
    if not await check_access(message):
        return
    
    raw_items = [x.strip() for x in DOMAIN_SPLIT_RE.split(raw_text or "") if x.strip()]
    cleaned = [item.lower() for item in raw_items]
    domains = [d for d in cleaned if DOMAIN_VALID_RE.fullmatch(d)]
    bad = [d for d in cleaned if d not in domains]

    if not domains:
        await safe_send_text(message.bot, message.chat.id, "❗️ Не вижу ни одного корректного домена.")
        return

    view_mode = (await state.get_data()).get("view_mode", DEFAULT_MODE)
    brief = view_mode == "brief"

    semaphore = asyncio.Semaphore(settings.CONCURRENCY)
    reports: List[str] = []
    collected: List[Tuple[str, dict, dict, bool]] = []

    async def process(domain: str):
        async with semaphore:
            try:
                dns_info = await fetch_dns(domain, settings.DNS_TIMEOUT)
                ssl_info = await fetch_ssl(domain)
                waf_enabled = await test_waf(domain, settings.HTTP_TIMEOUT)
                row = (domain, dns_info, ssl_info, waf_enabled)
                line = build_report(domain, dns_info, ssl_info, waf_enabled, brief=brief)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Error processing %s", domain)
                row = (domain, {}, {}, False)
                line = f"❌ {domain}: ошибка ({exc})"
            return line, row

    tasks = [asyncio.create_task(process(d)) for d in domains]

    # ---------- Прогресс-индикатор ----------

    MIN_EDIT_INTERVAL = 4  # секунд между edit_text
    total = len(tasks)
    done = 0
    loop = asyncio.get_event_loop()
    start_ts = loop.time()
    last_edit = start_ts - MIN_EDIT_INTERVAL
    progress_msg: types.Message | None = None

    for coro in asyncio.as_completed(tasks):
        line, row = await coro
        reports.append(line)
        collected.append(row)
        done += 1

        now = loop.time()
        need_update = total >= 4 and (done == total or now - last_edit >= MIN_EDIT_INTERVAL)

        if need_update:
            elapsed = now - start_ts
            eta_sec = int(elapsed / done * (total - done)) if done < total else 0
            eta_txt = f"{eta_sec // 60}м {eta_sec % 60}с" if eta_sec else "0 с"
            text = f"⏳ {done} / {total} • осталось ≈ {eta_txt}"

            try:
                if progress_msg is None:
                    progress_msg = await message.reply(text)
                else:
                    await progress_msg.edit_text(text)
                last_edit = now
            except Exception:
                progress_msg = None

    if bad:
        reports.append("🔸 Игнорированы некорректные строки: " + ", ".join(bad))

    # ---------- Формирование вывода ----------

    if total >= 4:
        buf = io.StringIO(newline="")
        writer = csv.writer(buf, delimiter=";")
        if brief:
            writer.writerow(["Domain", "CN", "Valid From", "Valid To", "WAF", "GOST"])
        else:
            writer.writerow(
                [
                    "Domain",
                    "A",
                    "AAAA",
                    "MX",
                    "NS",
                    "CN",
                    "Valid From",
                    "Valid To",
                    "WAF",
                    "GOST",
                ]
            )

        for domain, dns_info, ssl_info, waf_enabled in collected:
            gost_val = "Да" if ssl_info.get("gost") else "Нет"
            waf_val = "Да" if waf_enabled else "Нет"
            row_base = [
                domain,
                ssl_info.get("CN") or "",
                ssl_info.get("NotBefore") or "",
                ssl_info.get("NotAfter") or "",
                waf_val,
                gost_val,
            ]

            if brief:
                writer.writerow(row_base)
            else:
                writer.writerow(
                    [
                        domain,
                        ",".join(dns_info.get("A", [])),
                        ",".join(dns_info.get("AAAA", [])),
                        ",".join(dns_info.get("MX", [])),
                        ",".join(dns_info.get("NS", [])),
                        *row_base[1:],
                    ]
                )

        csv_bytes = buf.getvalue().encode("utf-8-sig")
        await message.answer_document(
            types.BufferedInputFile(csv_bytes, filename="report.csv"),
            caption=f"✔️ Проверено {total} доменов.",
        )

    else:
        await safe_send_text(
            message.bot,
            message.chat.id,
            "\n".join(reports),
            reply_markup=build_mode_keyboard(view_mode),
        )


# ---------- Команды ----------

@router.message(CommandStart())
async def cmd_start(message: types.Message, state: FSMContext):
    user_id = message.from_user.id
    
    # Проверка доступа
    if not has_access(user_id):
        await message.answer(
            "❌ У вас нет доступа к этому боту.\n\n"
            "Свяжитесь с администратором, нажав кнопку ниже.",
            reply_markup=build_access_denied_keyboard()
        )
        return
    
    # Если админ - показать админ-панель
    if user_id == ADMIN_ID:
        help_text = (
            "👨‍💼 *Админ-панель*\n\n"
            "Используйте кнопки ниже для управления доступом:"
        )
        await safe_send_text(
            message.bot,
            message.chat.id,
            help_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=build_admin_keyboard()
        )
        return
    
    # Обычный пользователь
    mode = get_mode(user_id, DEFAULT_MODE)
    await state.update_data(view_mode=mode)

    help_text = (
        "👋 Я сканирую домены и показываю DNS-, SSL-, WAF-информацию.\n\n"
        "📥 *Как пользоваться*:\n"
        "1. *Текст*: перечислите домены через пробел, запятую или с новой строки.\n"
        "2. *Файл*: пришлите `.txt` (UTF-8), по одному домену в строке (до 1000).\n"
        "3. 4+ доменов — получаете CSV-отчёт.\n\n"
        "📄 *Короткий режим* — колонки: CN, даты сертификата, WAF, GOST.\n"
        "🔎 *Расширенный* — те же колонки + DNS-записи A, AAAA, MX, NS.\n\n"
        "Режим запоминается для вашего аккаунта; изменить можно кнопками ниже."
    )

    await safe_send_text(
        message.bot,
        message.chat.id,
        help_text,
        parse_mode=ParseMode.MARKDOWN,
        reply_markup=build_mode_keyboard(mode),
    )


@router.message(Command("help"))
async def cmd_help(message: types.Message, state: FSMContext):
    await cmd_start(message, state)


# ---------- Переключение режима ----------

@router.callback_query(F.data.in_({"mode_full", "mode_brief"}))
async def switch_mode(callback: types.CallbackQuery, state: FSMContext):
    # Проверка доступа
    if not has_access(callback.from_user.id):
        await callback.answer("❌ Нет доступа", show_alert=True)
        return
    
    new_mode = "full" if callback.data == "mode_full" else "brief"
    await state.update_data(view_mode=new_mode)
    set_mode(callback.from_user.id, new_mode)

    await callback.answer(
        f"Режим установлен: {'Расширенный' if new_mode == 'full' else 'Короткий'}"
    )

    try:
        await callback.message.edit_reply_markup(reply_markup=build_mode_keyboard(new_mode))
    except Exception:
        pass


# ---------- АДМИН-ПАНЕЛЬ ----------

@router.callback_query(F.data == "admin_add_access")
async def admin_add_access(callback: types.CallbackQuery, state: FSMContext):
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Только администратор", show_alert=True)
        return
    
    await state.set_state(AdminStates.add_access_waiting)
    await callback.message.answer(
        "📝 Введите TG ID пользователя(ей).\n\n"
        "Можно вводить несколько через пробел или запятую:\n"
        "`123456789 987654321 444555666`"
    )
    await callback.answer()


@router.message(AdminStates.add_access_waiting)
async def process_add_access(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    
    text = message.text or ""
    # Парсим TG ID
    items = re.split(r"[\s,]+", text.strip())
    
    added_count = 0
    errors = []
    
    for item in items:
        if not item:
            continue
        
        # Если начинается с @, то это никнейм - пропускаем (нужен ID)
        if item.startswith("@"):
            errors.append(f"⚠️ {item} - Требуется TG ID, не никнейм")
            continue
        
        # Пытаемся распарсить как число
        try:
            user_id = int(item)
            username = ""
            add_access(user_id, username)
            added_count += 1
        except ValueError:
            errors.append(f"❌ {item} - Некорректный формат")
    
    response = f"✅ Добавлен доступ для {added_count} пользователей(я)"
    if errors:
        response += "\n\n" + "\n".join(errors)
    
    await message.answer(response)
    await state.clear()


@router.callback_query(F.data == "admin_remove_access")
async def admin_remove_access(callback: types.CallbackQuery, state: FSMContext):
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Только администратор", show_alert=True)
        return
    
    await state.set_state(AdminStates.remove_access_waiting)
    await callback.message.answer(
        "🗑️ Введите TG ID пользователя(ей) для удаления доступа.\n\n"
        "Можно вводить несколько через пробел или запятую:\n"
        "`123456789 987654321`"
    )
    await callback.answer()


@router.message(AdminStates.remove_access_waiting)
async def process_remove_access(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    
    text = message.text or ""
    items = re.split(r"[\s,]+", text.strip())
    
    removed_count = 0
    not_found = []
    
    for item in items:
        if not item:
            continue
        
        try:
            user_id = int(item)
            if remove_access(user_id):
                removed_count += 1
            else:
                not_found.append(str(user_id))
        except ValueError:
            not_found.append(item)
    
    response = f"✅ Доступ удален для {removed_count} пользователей(я)"
    if not_found:
        response += f"\n⚠️ Не найдены в БД: {', '.join(not_found)}"
    
    await message.answer(response)
    await state.clear()


@router.callback_query(F.data == "admin_list_access")
async def admin_list_access(callback: types.CallbackQuery):
    if callback.from_user.id != ADMIN_ID:
        await callback.answer("❌ Только администратор", show_alert=True)
        return
    
    db = get_access_list()
    
    if not db:
        await callback.message.answer("📋 БД доступов пуста")
        await callback.answer()
        return
    
    # Форматируем список
    lines = ["📋 *Список доступов:*\n"]
    for user_id, data in sorted(db.items()):
        username = data.get("username", "")
        added_at = data.get("added_at", "")
        
        user_info = f"ID: {user_id}"
        if username:
            user_info += f" (@{username})"
        if added_at:
            user_info += f" - добавлен {added_at[:10]}"
        
        lines.append(f"• {user_info}")
    
    text = "\n".join(lines)
    
    # Если текст слишком длинный, отправляем как файл
    if len(text) > 4000:
        buf = io.BytesIO(text.encode("utf-8"))
        await callback.message.answer_document(
            types.BufferedInputFile(buf.getvalue(), filename="access_list.txt")
        )
    else:
        await callback.message.answer(text, parse_mode=ParseMode.MARKDOWN)
    
    await callback.answer()


# ---------- Загрузка TXT ----------

@router.message(F.document)
async def handle_document(message: types.Message, state: FSMContext):
    # Проверка доступа
    if not await check_access(message):
        return
    
    doc = message.document
    if not doc.file_name.lower().endswith(".txt"):
        await message.reply("📄 Пришлите TXT-файл со списком доменов.")
        return

    file_obj = await message.bot.download(doc.file_id)
    text_data = file_obj.getvalue().decode("utf-8", errors="ignore")

    await _process_domains(message, state, text_data)


# ---------- Текстовый ввод ----------

@router.message(F.text)
async def handle_text(message: types.Message, state: FSMContext):
    await _process_domains(message, state, message.text or "")


# ---------- Запуск ----------

async def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")

    if not settings.TG_TOKEN:
        raise RuntimeError("TG_TOKEN не задан в .env")

    bot = Bot(settings.TG_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=MemoryStorage())

    dp.include_router(router)

    await dp.start_polling(bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):  # noqa: PIE804
        print("Bot stopped.")
