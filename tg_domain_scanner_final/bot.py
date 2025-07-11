# Optional uvloop for speed
try:
    import uvloop  # type: ignore

    uvloop.install()
except ModuleNotFoundError:
    pass

import asyncio
import csv
import io
import logging
import re
from typing import List, Tuple

from aiogram import Bot, Dispatcher, F, Router, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.memory import MemoryStorage

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

# ---------- Клавиатура режима ----------
def build_mode_keyboard(current_mode: str) -> types.InlineKeyboardMarkup:  # noqa: D401
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


router = Router()

# ---------- Основная проверка ----------
async def _process_domains(message: types.Message, state: FSMContext, raw_text: str) -> None:
    """Парсит ввод, запускает проверки и формирует отчёт."""
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
    last_edit = start_ts - MIN_EDIT_INTERVAL  # чтобы первое сообщение ушло сразу
    progress_msg: types.Message | None = None

    for coro in asyncio.as_completed(tasks):
        line, row = await coro
        reports.append(line)
        collected.append(row)
        done += 1

        now = loop.time()
        need_update = total >= 4 and (
            done == total or now - last_edit >= MIN_EDIT_INTERVAL
        )

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
                progress_msg = None  # сообщение удалили или flood-лимит – игнорируем

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
            gost_val = "Да" if ssl_info.get("IsGOST") else "Нет"
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
    mode = get_mode(message.from_user.id, DEFAULT_MODE)
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


# ---------- Загрузка TXT ----------
@router.message(F.document)
async def handle_document(message: types.Message, state: FSMContext):
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
