"""
Админ-хендлеры: управление доступом, разрешениями, WireGuard, статистика.
"""

import asyncio
import html
import io
import json
import logging
import re
from typing import List, Optional, Tuple

from aiogram import Bot, F, Router, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest
from aiogram.fsm.context import FSMContext

from config import settings
from access import (
    ADMIN_ID,
    PERMISSIONS,
    DEFAULT_PERMISSIONS,
    AdminStates,
    has_access,
    has_permission,
    add_access,
    remove_access,
    get_access_list,
    get_username_by_id,
    get_id_by_username,
    load_access_db,
    save_access_db,
    set_user_permission,
    get_user_permissions,
    parse_user_list,
)
from keyboards import build_admin_keyboard, build_main_menu_keyboard
from handlers.callbacks import safe_callback_answer
from utils.telegram_utils import safe_send_text
from utils.stats import get_stats
from utils.wireguard_utils import check_wg_connection, ensure_wg_interface_up

logger = logging.getLogger(__name__)

router = Router()


# ------------------------------------------------------------------ #
#  admin_add_access
# ------------------------------------------------------------------ #

@router.callback_query(F.data == "admin_add_access")
async def admin_add_access(callback: types.CallbackQuery, state: FSMContext):
    if callback.from_user.id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return
    
    await state.set_state(AdminStates.add_access_waiting)
    await callback.message.answer(
        "📝 Введите TG ID или @username пользователя(ей).\n\n"
        "Поддерживаемые форматы:\n"
        "• Простые числа: `123456789 987654321`\n"
        "• @username: `@johndoe` или `johndoe`\n"
        "• Формат ID: `ID: 123456789`\n"
        "• Формат старого бота:\n"
        "`• ID: 123456789 - добавлен 2025-12-09`\n\n"
        "Можно вставлять список из старого бота целиком!"
    )
    await safe_callback_answer(callback, "")


# ------------------------------------------------------------------ #
#  process_add_access (FSM)
# ------------------------------------------------------------------ #

@router.message(AdminStates.add_access_waiting)
async def process_add_access(message: types.Message, state: FSMContext):
    """Обрабатывает добавление доступа пользователям."""
    if message.from_user.id != ADMIN_ID:
        return
    
    text = message.text or ""
    
    nav = _handle_admin_navigation(text)
    if nav:
        await state.clear()
        if nav == "admin" and message.from_user and message.from_user.id == ADMIN_ID:
            help_text = "👨‍💼 *Админ-панель*\n\nИспользуйте кнопки ниже для управления доступом:"
            await safe_send_text(
                message.bot,
                message.chat.id,
                help_text,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=build_admin_keyboard(),
            )
        else:
            from handlers.commands import cmd_start
            await cmd_start(message, state)
        return
    
    parsed_users = parse_user_list(text)
    bot = message.bot
    
    added_count = 0
    errors = []
    added_users = []
    
    for uid, username, date_added in parsed_users:
        try:
            if uid is not None:
                add_access(uid, "")
                added_count += 1
                added_users.append(uid)
            elif username is not None:
                resolved_id = await get_id_by_username(bot, username)
                if resolved_id:
                    add_access(resolved_id, username)
                    added_count += 1
                    added_users.append(resolved_id)
                else:
                    errors.append(f"⚠️ @{username} - не удалось найти пользователя")
        except Exception as e:
            err_id = uid if uid is not None else f"@{username or '?'}"
            errors.append(f"❌ {err_id} - Ошибка при добавлении: {str(e)}")
    
    if not parsed_users:
        items = re.split(r"[\s,]+", text.strip())
        
        for item in items:
            if not item:
                continue
            
            if item.startswith("@"):
                resolved_id = await get_id_by_username(bot, item)
                if resolved_id:
                    add_access(resolved_id, item[1:])
                    added_count += 1
                    added_users.append(resolved_id)
                else:
                    errors.append(f"⚠️ {item} - не удалось найти пользователя")
                continue
            
            try:
                user_id = int(item)
                add_access(user_id, "")
                added_count += 1
                added_users.append(user_id)
            except ValueError:
                errors.append(f"❌ {item} - Некорректный формат")
            except Exception as e:
                errors.append(f"❌ {item} - Ошибка: {str(e)}")
    
    response = f"✅ Добавлен доступ для {added_count} пользователей(я)"
    if errors:
        response += "\n\n" + "\n".join(errors)
    
    response += (
        "\n\n💡 *Совет:* Используйте 'Управление разрешениями' в админ-панели "
        "для настройки доступа к конкретным функциям."
    )
    
    await message.answer(response, parse_mode=ParseMode.MARKDOWN)
    
    if added_count == 1 and added_users:
        user_id = added_users[0]
        permissions = get_user_permissions(user_id)
        
        perms_text = "📋 *Разрешения по умолчанию:*\n\n"
        for perm_key, perm_name in PERMISSIONS.items():
            status = "✅" if permissions.get(perm_key, False) else "❌"
            perms_text += f"{status} {perm_name}\n"
        
        perms_text += "\nИспользуйте 'Управление разрешениями' для изменения."
        
        await message.answer(perms_text, parse_mode=ParseMode.MARKDOWN)
    
    await state.clear()


# ------------------------------------------------------------------ #
#  admin_remove_access
# ------------------------------------------------------------------ #

@router.callback_query(F.data == "admin_remove_access")
async def admin_remove_access(callback: types.CallbackQuery, state: FSMContext):
    if callback.from_user.id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return
    
    await state.set_state(AdminStates.remove_access_waiting)
    await callback.message.answer(
        "🗑️ Введите TG ID пользователя(ей) для удаления доступа.\n\n"
        "Можно вводить несколько через пробел или запятую:\n"
        "`123456789 987654321`"
    )
    await safe_callback_answer(callback, "")


# ------------------------------------------------------------------ #
#  process_remove_access (FSM)
# ------------------------------------------------------------------ #

@router.message(AdminStates.remove_access_waiting)
async def process_remove_access(message: types.Message, state: FSMContext):
    if message.from_user.id != ADMIN_ID:
        return
    
    text = message.text or ""
    
    nav = _handle_admin_navigation(text)
    if nav:
        await state.clear()
        if nav == "admin" and message.from_user and message.from_user.id == ADMIN_ID:
            help_text = "👨‍💼 *Админ-панель*\n\nИспользуйте кнопки ниже для управления доступом:"
            await safe_send_text(
                message.bot,
                message.chat.id,
                help_text,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=build_admin_keyboard(),
            )
        else:
            from handlers.commands import cmd_start
            await cmd_start(message, state)
        return
    
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


# ------------------------------------------------------------------ #
#  admin_list_access
# ------------------------------------------------------------------ #

@router.callback_query(F.data == "admin_list_access")
async def admin_list_access(callback: types.CallbackQuery):
    """Показывает список всех пользователей с их разрешениями."""
    if callback.from_user.id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return
    
    if not callback.message:
        await safe_callback_answer(callback, "❌ Ошибка: сообщение недоступно", show_alert=True)
        return
    
    await safe_callback_answer(callback, "⏳ Загрузка списка пользователей...")
    
    db = get_access_list()
    
    if not db:
        await callback.message.answer("📋 БД доступов пуста")
        return
    
    bot = callback.message.bot if callback.message else callback.bot
    if not bot:
        await callback.message.answer("❌ Ошибка: бот недоступен")
        return
    
    lines = ["📋 *Список пользователей и их разрешения:*\n"]
    
    user_ids = [int(user_id) for user_id in db.keys() if str(user_id).isdigit()]
    
    username_tasks = [get_username_by_id(bot, user_id) for user_id in user_ids]
    usernames = await asyncio.gather(*username_tasks, return_exceptions=True)
    
    username_map = {}
    for user_id, username_result in zip(user_ids, usernames):
        if isinstance(username_result, str):
            username_map[user_id] = username_result
        elif isinstance(username_result, BaseException):
            logger.debug(f"Ошибка получения username для {user_id}: {username_result}")
    
    for user_id, data in sorted(db.items(), key=lambda x: (int(x[0]) if str(x[0]).isdigit() else 0)):
        uid = int(user_id) if str(user_id).isdigit() else 0
        if uid in username_map:
            current_username = username_map[uid]
        else:
            current_username = data.get("username", "")
        
        added_at = data.get("added_at", "")
        permissions = data.get("permissions", DEFAULT_PERMISSIONS.copy())
        
        user_info = f"*ID: {user_id}*"
        if current_username:
            user_info += f" (@{current_username})"
        if added_at:
            user_info += f"\nДобавлен: {added_at[:10]}"
        
        lines.append(user_info)
        lines.append("Разрешения:")
        
        for perm_key, perm_name in PERMISSIONS.items():
            status = "✅" if permissions.get(perm_key, False) else "❌"
            lines.append(f"  {status} {perm_name}")
        
        lines.append("")
    
    text = "\n".join(lines)
    
    if len(text) > 4000:
        buf = io.BytesIO(text.encode("utf-8"))
        await callback.message.answer_document(
            types.BufferedInputFile(buf.getvalue(), filename="access_list.txt")
        )
    else:
        await callback.message.answer(text, parse_mode=ParseMode.MARKDOWN)


# ------------------------------------------------------------------ #
#  admin_manage_permissions
# ------------------------------------------------------------------ #

@router.callback_query(F.data == "admin_manage_permissions")
async def admin_manage_permissions(callback: types.CallbackQuery, state: FSMContext):
    """Начинает процесс управления разрешениями пользователя."""
    if callback.from_user.id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return
    
    if not callback.message:
        await safe_callback_answer(callback, "❌ Ошибка: сообщение недоступно", show_alert=True)
        return
    
    await safe_callback_answer(callback, "⏳ Загрузка списка пользователей...")
    
    await state.set_state(AdminStates.manage_permissions_user_waiting)
    
    db = get_access_list()
    if not db:
        await callback.message.answer("❌ Нет пользователей в базе. Сначала добавьте пользователя.")
        await state.clear()
        return
    
    bot = callback.message.bot if callback.message else callback.bot
    if not bot:
        await callback.message.answer("❌ Ошибка: бот недоступен")
        await state.clear()
        return
    
    user_ids = [int(user_id) for user_id in db.keys() if str(user_id).isdigit()]
    
    username_tasks = [get_username_by_id(bot, user_id) for user_id in user_ids]
    usernames = await asyncio.gather(*username_tasks, return_exceptions=True)
    
    username_map = {}
    for user_id, username_result in zip(user_ids, usernames):
        if isinstance(username_result, str):
            username_map[user_id] = username_result
        elif isinstance(username_result, BaseException):
            logger.debug(f"Ошибка получения username для {user_id}: {username_result}")
    
    users_list = "👥 *Выберите пользователя для управления разрешениями:*\n\n"
    for user_id, data in sorted(db.items(), key=lambda x: (int(x[0]) if str(x[0]).isdigit() else 0)):
        uid = int(user_id) if str(user_id).isdigit() else 0
        if uid in username_map:
            current_username = username_map[uid]
        else:
            current_username = data.get("username", "")
        user_display = f"ID: {user_id}"
        if current_username:
            user_display += f" (@{current_username})"
        users_list += f"• {user_display}\n"
    
    users_list += "\nВведите TG ID или @username пользователя:"
    
    await callback.message.answer(users_list, parse_mode=ParseMode.MARKDOWN)


# ------------------------------------------------------------------ #
#  _handle_admin_navigation helper
# ------------------------------------------------------------------ #

def _handle_admin_navigation(text: str) -> Optional[str]:
    """
    Проверяет навигационную команду.
    Returns: "back" | "admin" | None
    """
    t = (text or "").strip()
    if t in ("🔙 Назад", "🏠 Главное меню"):
        return "back"
    if t == "👨‍💼 Админ-панель":
        return "admin"
    return None


# ------------------------------------------------------------------ #
#  process_manage_permissions_user (FSM)
# ------------------------------------------------------------------ #

@router.message(AdminStates.manage_permissions_user_waiting)
async def process_manage_permissions_user(message: types.Message, state: FSMContext):
    """Обрабатывает выбор пользователя для управления разрешениями."""
    if message.from_user.id != ADMIN_ID:
        return
    
    text = message.text or ""
    
    nav = _handle_admin_navigation(text)
    if nav:
        await state.clear()
        if nav == "admin" and message.from_user and message.from_user.id == ADMIN_ID:
            help_text = "👨‍💼 *Админ-панель*\n\nИспользуйте кнопки ниже для управления доступом:"
            await safe_send_text(
                message.bot,
                message.chat.id,
                help_text,
                parse_mode=ParseMode.MARKDOWN,
                reply_markup=build_admin_keyboard(),
            )
        else:
            from handlers.commands import cmd_start
            await cmd_start(message, state)
        return
    
    user_id = None
    text_stripped = text.strip()
    
    if text_stripped.startswith("@"):
        user_id = await get_id_by_username(message.bot, text_stripped)
        if not user_id:
            await message.answer(
                f"❌ Не удалось найти пользователя {text_stripped}.\n"
                "Проверьте username или введите числовой TG ID."
            )
            return
    else:
        try:
            user_id = int(text_stripped)
        except ValueError:
            await message.answer("❌ Некорректный формат. Введите числовой TG ID или @username.")
            return
    
    db = get_access_list()
    if str(user_id) not in db:
        await message.answer(f"❌ Пользователь {user_id} не найден в базе.")
        await state.clear()
        return
    
    await state.update_data(selected_user_id=user_id)
    
    permissions = get_user_permissions(user_id)
    user_data = db[str(user_id)]
    
    bot = message.bot
    current_username = await get_username_by_id(bot, user_id)
    if not current_username:
        current_username = user_data.get("username", "")
    
    keyboard_buttons = []
    for perm_key, perm_name in PERMISSIONS.items():
        current_status = permissions.get(perm_key, False)
        status_icon = "✅" if current_status else "❌"
        keyboard_buttons.append([
            types.InlineKeyboardButton(
                text=f"{status_icon} {perm_name}",
                callback_data=f"perm_toggle_{user_id}_{perm_key}",
            )
        ])
    
    keyboard_buttons.append([
        types.InlineKeyboardButton(
            text="🔙 Назад",
            callback_data="admin_back",
        )
    ])
    
    keyboard = types.InlineKeyboardMarkup(inline_keyboard=keyboard_buttons)
    
    user_display = f"ID: {user_id}"
    if current_username:
        user_display += f" (@{current_username})"
    user_display_safe = html.escape(user_display)
    
    text_msg = (
        f"🔐 <b>Управление разрешениями</b>\n\n"
        f"Пользователь: {user_display_safe}\n\n"
        f"Нажмите на разрешение для переключения:"
    )
    
    await message.answer(text_msg, parse_mode=ParseMode.HTML, reply_markup=keyboard)
    await state.clear()


# ------------------------------------------------------------------ #
#  toggle_permission
# ------------------------------------------------------------------ #

@router.callback_query(F.data.startswith("perm_toggle_"))
async def toggle_permission(callback: types.CallbackQuery):
    """Переключает разрешение пользователя."""
    if callback.from_user.id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return
    
    parts = callback.data.split("_")
    if len(parts) != 4:
        await safe_callback_answer(callback, "❌ Ошибка формата", show_alert=True)
        return
    
    try:
        user_id = int(parts[2])
        permission = parts[3]
    except (ValueError, IndexError):
        await safe_callback_answer(callback, "❌ Ошибка парсинга", show_alert=True)
        return
    
    if permission not in PERMISSIONS:
        await safe_callback_answer(callback, "❌ Неизвестное разрешение", show_alert=True)
        return
    
    current_value = has_permission(user_id, permission)
    new_value = not current_value
    
    if set_user_permission(user_id, permission, new_value):
        status = "выдано" if new_value else "отозвано"
        perm_name = PERMISSIONS[permission]
        await safe_callback_answer(callback, f"✅ Разрешение '{perm_name}' {status}", show_alert=False)
        
        permissions = get_user_permissions(user_id)
        keyboard_buttons = []
        for perm_key, perm_name in PERMISSIONS.items():
            current_status = permissions.get(perm_key, False)
            status_icon = "✅" if current_status else "❌"
            keyboard_buttons.append([
                types.InlineKeyboardButton(
                    text=f"{status_icon} {perm_name}",
                    callback_data=f"perm_toggle_{user_id}_{perm_key}",
                )
            ])
        
        keyboard_buttons.append([
            types.InlineKeyboardButton(
                text="🔙 Назад",
                callback_data="admin_back",
            )
        ])
        
        keyboard = types.InlineKeyboardMarkup(inline_keyboard=keyboard_buttons)
        
        try:
            await callback.message.edit_reply_markup(reply_markup=keyboard)
        except Exception:
            pass
    else:
        await safe_callback_answer(callback, "❌ Ошибка при изменении разрешения", show_alert=True)


# ------------------------------------------------------------------ #
#  admin_mass_edit_permissions
# ------------------------------------------------------------------ #

@router.callback_query(F.data == "admin_mass_edit_permissions")
async def admin_mass_edit_permissions(callback: types.CallbackQuery):
    """Показывает меню для массового редактирования прав всех пользователей."""
    if callback.from_user.id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return
    
    if not callback.message:
        await safe_callback_answer(callback, "❌ Ошибка: сообщение недоступно", show_alert=True)
        return
    
    await safe_callback_answer(callback, "⏳ Загрузка...")
    
    db = get_access_list()
    if not db:
        await callback.message.answer("❌ Нет пользователей в базе.")
        return
    
    keyboard_buttons = []
    for perm_key, perm_name in PERMISSIONS.items():
        keyboard_buttons.append([
            types.InlineKeyboardButton(
                text=f"➕ {perm_name} (всем)",
                callback_data=f"mass_perm_add_{perm_key}",
            ),
            types.InlineKeyboardButton(
                text=f"➖ {perm_name} (у всех)",
                callback_data=f"mass_perm_remove_{perm_key}",
            ),
        ])
    
    keyboard_buttons.append([
        types.InlineKeyboardButton(
            text="🔙 Назад",
            callback_data="admin_back",
        )
    ])
    
    keyboard = types.InlineKeyboardMarkup(inline_keyboard=keyboard_buttons)
    
    user_count = len([uid for uid in db.keys() if str(uid).isdigit()])
    
    text_msg = (
        f"⚡ <b>Массовое редактирование прав</b>\n\n"
        f"Пользователей в базе: {user_count}\n\n"
        f"Выберите действие для каждого разрешения:"
    )
    
    try:
        await callback.message.edit_text(text_msg, parse_mode=ParseMode.HTML, reply_markup=keyboard)
    except Exception as e:
        logger.error(f"Ошибка при редактировании сообщения: {e}")
        await callback.message.answer(text_msg, parse_mode=ParseMode.HTML, reply_markup=keyboard)


# ------------------------------------------------------------------ #
#  mass_perm_add
# ------------------------------------------------------------------ #

@router.callback_query(F.data.startswith("mass_perm_add_"))
async def mass_perm_add(callback: types.CallbackQuery):
    """Добавляет разрешение всем пользователям."""
    if callback.from_user.id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return
    
    parts = callback.data.split("_")
    if len(parts) != 4:
        await safe_callback_answer(callback, "❌ Ошибка формата", show_alert=True)
        return
    
    permission = parts[3]
    if permission not in PERMISSIONS:
        await safe_callback_answer(callback, "❌ Неизвестное разрешение", show_alert=True)
        return
    
    await safe_callback_answer(callback, "⏳ Обработка...")
    
    db = get_access_list()
    if not db:
        await safe_callback_answer(callback, "❌ Нет пользователей в базе", show_alert=True)
        return
    
    updated_count = 0
    for user_id_str in db.keys():
        if not str(user_id_str).isdigit():
            continue
        user_id = int(user_id_str)
        if user_id == ADMIN_ID:
            continue
        
        if set_user_permission(user_id, permission, True):
            updated_count += 1
    
    perm_name = PERMISSIONS[permission]
    await safe_callback_answer(callback, 
        f"✅ Разрешение '{perm_name}' добавлено {updated_count} пользователям",
        show_alert=True
    )
    
    if callback.message:
        db = get_access_list()
        keyboard_buttons = []
        for perm_key, perm_name_item in PERMISSIONS.items():
            keyboard_buttons.append([
                types.InlineKeyboardButton(
                    text=f"➕ {perm_name_item} (всем)",
                    callback_data=f"mass_perm_add_{perm_key}",
                ),
                types.InlineKeyboardButton(
                    text=f"➖ {perm_name_item} (у всех)",
                    callback_data=f"mass_perm_remove_{perm_key}",
                ),
            ])
        
        keyboard_buttons.append([
            types.InlineKeyboardButton(
                text="🔙 Назад",
                callback_data="admin_back",
            )
        ])
        
        keyboard = types.InlineKeyboardMarkup(inline_keyboard=keyboard_buttons)
        user_count = len([uid for uid in db.keys() if str(uid).isdigit()])
        text_msg = (
            f"⚡ <b>Массовое редактирование прав</b>\n\n"
            f"Пользователей в базе: {user_count}\n\n"
            f"Выберите действие для каждого разрешения:"
        )
        try:
            await callback.message.edit_text(text_msg, parse_mode=ParseMode.HTML, reply_markup=keyboard)
        except Exception:
            pass


# ------------------------------------------------------------------ #
#  mass_perm_remove
# ------------------------------------------------------------------ #

@router.callback_query(F.data.startswith("mass_perm_remove_"))
async def mass_perm_remove(callback: types.CallbackQuery):
    """Убирает разрешение у всех пользователей."""
    if callback.from_user.id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return
    
    parts = callback.data.split("_")
    if len(parts) != 4:
        await safe_callback_answer(callback, "❌ Ошибка формата", show_alert=True)
        return
    
    permission = parts[3]
    if permission not in PERMISSIONS:
        await safe_callback_answer(callback, "❌ Неизвестное разрешение", show_alert=True)
        return
    
    await safe_callback_answer(callback, "⏳ Обработка...")
    
    db = get_access_list()
    if not db:
        await safe_callback_answer(callback, "❌ Нет пользователей в базе", show_alert=True)
        return
    
    updated_count = 0
    for user_id_str in db.keys():
        if not str(user_id_str).isdigit():
            continue
        user_id = int(user_id_str)
        if user_id == ADMIN_ID:
            continue
        
        if set_user_permission(user_id, permission, False):
            updated_count += 1
    
    perm_name = PERMISSIONS[permission]
    await safe_callback_answer(callback, 
        f"✅ Разрешение '{perm_name}' убрано у {updated_count} пользователей",
        show_alert=True
    )
    
    if callback.message:
        db = get_access_list()
        keyboard_buttons = []
        for perm_key, perm_name_item in PERMISSIONS.items():
            keyboard_buttons.append([
                types.InlineKeyboardButton(
                    text=f"➕ {perm_name_item} (всем)",
                    callback_data=f"mass_perm_add_{perm_key}",
                ),
                types.InlineKeyboardButton(
                    text=f"➖ {perm_name_item} (у всех)",
                    callback_data=f"mass_perm_remove_{perm_key}",
                ),
            ])
        
        keyboard_buttons.append([
            types.InlineKeyboardButton(
                text="🔙 Назад",
                callback_data="admin_back",
            )
        ])
        
        keyboard = types.InlineKeyboardMarkup(inline_keyboard=keyboard_buttons)
        user_count = len([uid for uid in db.keys() if str(uid).isdigit()])
        text_msg = (
            f"⚡ <b>Массовое редактирование прав</b>\n\n"
            f"Пользователей в базе: {user_count}\n\n"
            f"Выберите действие для каждого разрешения:"
        )
        try:
            await callback.message.edit_text(text_msg, parse_mode=ParseMode.HTML, reply_markup=keyboard)
        except Exception:
            pass


# ------------------------------------------------------------------ #
#  admin_export_users
# ------------------------------------------------------------------ #

@router.callback_query(F.data == "admin_export_users")
async def admin_export_users(callback: types.CallbackQuery):
    """Экспортирует список пользователей в формате JSON для удобного переноса."""
    if callback.from_user.id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return
    
    if not callback.message:
        await safe_callback_answer(callback, "❌ Ошибка: сообщение недоступно", show_alert=True)
        return
    
    await safe_callback_answer(callback, "⏳ Подготовка экспорта...")
    
    db = get_access_list()
    
    if not db:
        await callback.message.answer("📋 БД доступов пуста")
        return
    
    bot = callback.message.bot if callback.message else callback.bot
    if not bot:
        await callback.message.answer("❌ Ошибка: бот недоступен")
        return
    
    user_ids = [int(user_id) for user_id in db.keys() if str(user_id).isdigit()]
    
    username_tasks = [get_username_by_id(bot, user_id) for user_id in user_ids]
    usernames = await asyncio.gather(*username_tasks, return_exceptions=True)
    
    username_map = {}
    for user_id, username_result in zip(user_ids, usernames):
        if isinstance(username_result, str):
            username_map[user_id] = username_result
    
    export_data = {}
    for user_id, data in sorted(db.items(), key=lambda x: (int(x[0]) if str(x[0]).isdigit() else 0)):
        uid = int(user_id) if str(user_id).isdigit() else 0
        if uid in username_map:
            current_username = username_map[uid]
        else:
            current_username = data.get("username", "")
        
        export_data[user_id] = {
            "user_id": int(user_id) if str(user_id).isdigit() else user_id,
            "username": current_username,
            "added_at": data.get("added_at", ""),
            "permissions": data.get("permissions", DEFAULT_PERMISSIONS.copy()),
        }
    
    json_data = json.dumps(export_data, ensure_ascii=False, indent=2, default=str)
    
    text_lines = ["📤 *Экспорт пользователей*\n\n"]
    text_lines.append("Формат для добавления:\n")
    text_lines.append("```")
    
    for user_id, user_data in export_data.items():
        uid = user_data["user_id"]
        username = user_data["username"]
        text_lines.append(f"{uid}  # @{username}" if username else f"{uid}")
    
    text_lines.append("```")
    text_lines.append("\nИли используйте JSON файл ниже для полного переноса.")
    
    text_msg = "\n".join(text_lines)
    
    await callback.message.answer(text_msg, parse_mode=ParseMode.MARKDOWN)
    
    json_bytes = json_data.encode("utf-8")
    buf = io.BytesIO(json_bytes)
    await callback.message.answer_document(
        types.BufferedInputFile(buf.getvalue(), filename="users_export.json")
    )


# ------------------------------------------------------------------ #
#  admin_check_wg
# ------------------------------------------------------------------ #

@router.callback_query(F.data == "admin_check_wg")
async def admin_check_wg(callback: types.CallbackQuery):
    """Проверка подключения WireGuard."""
    if callback.from_user.id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return

    await safe_callback_answer(callback, "⏳ Проверяю WireGuard...")

    status = check_wg_connection()

    lines = ["🔌 *Проверка WireGuard*\n"]

    if status.get("last_error") and not status.get("config_found"):
        lines.append("ℹ️ WireGuard недоступен")
        lines.append(f"   _{status['last_error']}_")
        lines.append("\n💡 *WireGuard нужен для резервного подключения*")
        lines.append("   при массовых 504 ошибках от GOST endpoints.")
        lines.append("\n   Для работы WireGuard:")
        lines.append("   1. Убедитесь что конфиг есть: `wg/TGBOT.conf`")
        lines.append("   2. Проверьте что WireGuard контейнер запущен в docker-compose")
    else:
        if status["config_found"]:
            lines.append(f"✅ Конфиг: `{status['config_path']}`")
            lines.append(f"   Контейнер: `{status.get('container_name', 'wireguard')}`")
            lines.append(f"   Интерфейс: `{status['interface_name'] or '—'}`")
            lines.append(f"   IP: `{status['interface_ip'] or '—'}`")
            if status["interface_up"]:
                lines.append("\n   **Статус: 🟢 Контейнер доступен**")
            else:
                lines.append("\n   **Статус: 🔴 Контейнер недоступен**")
                if status.get("last_error"):
                    lines.append(f"   _{status['last_error']}_")
        else:
            lines.append(f"❌ Конфиг не найден: `{status['config_path']}`")
            if status.get("last_error"):
                lines.append(f"   _{status['last_error']}_")

    text = "\n".join(lines)
    
    keyboard_buttons = []
    if status.get("config_found"):
        if not status.get("interface_up"):
            keyboard_buttons.append([
                types.InlineKeyboardButton(
                    text="🔄 Проверить доступность",
                    callback_data="admin_wg_up"
                )
            ])
        keyboard_buttons.append([
            types.InlineKeyboardButton(
                text="🔄 Обновить статус",
                callback_data="admin_check_wg"
            )
        ])
    keyboard_buttons.append([
        types.InlineKeyboardButton(text="🔙 Назад", callback_data="admin_back")
    ])
    
    back_kb = types.InlineKeyboardMarkup(inline_keyboard=keyboard_buttons)
    try:
        await callback.message.edit_text(
            text, parse_mode=ParseMode.MARKDOWN, reply_markup=back_kb
        )
    except Exception:
        await callback.message.answer(
            text, parse_mode=ParseMode.MARKDOWN, reply_markup=back_kb
        )


# ------------------------------------------------------------------ #
#  admin_wg_up
# ------------------------------------------------------------------ #

@router.callback_query(F.data == "admin_wg_up")
async def admin_wg_up(callback: types.CallbackQuery):
    """Проверить доступность WireGuard контейнера."""
    if callback.from_user.id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return
    
    await safe_callback_answer(callback, "⏳ Проверяю WireGuard контейнер...")
    
    if ensure_wg_interface_up():
        await safe_callback_answer(callback, "✅ WireGuard контейнер доступен!", show_alert=True)
    else:
        await safe_callback_answer(callback, "❌ WireGuard контейнер недоступен. Проверьте docker-compose.", show_alert=True)
    
    await admin_check_wg(callback)


# ------------------------------------------------------------------ #
#  admin_wg_down
# ------------------------------------------------------------------ #

@router.callback_query(F.data == "admin_wg_down")
async def admin_wg_down(callback: types.CallbackQuery):
    """Проверить статус WireGuard контейнера."""
    if callback.from_user.id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return
    
    await safe_callback_answer(callback, "ℹ️ WireGuard управляется через docker-compose", show_alert=True)
    
    await admin_check_wg(callback)


# ------------------------------------------------------------------ #
#  admin_back
# ------------------------------------------------------------------ #

@router.callback_query(F.data == "admin_back")
async def admin_back(callback: types.CallbackQuery):
    """Возврат в админ-панель."""
    if callback.from_user.id != ADMIN_ID:
        await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
        return
    
    if not callback.message:
        await safe_callback_answer(callback, "❌ Ошибка: сообщение недоступно", show_alert=True)
        return
    
    help_text = (
        "👨‍💼 *Админ-панель*\n\n"
        "Используйте кнопки ниже для управления:"
    )
    
    try:
        await callback.message.edit_text(
            help_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=build_admin_keyboard(),
        )
    except Exception as e:
        logger.error(f"Ошибка при редактировании сообщения: {e}")
        await callback.message.answer(
            help_text,
            parse_mode=ParseMode.MARKDOWN,
            reply_markup=build_admin_keyboard(),
        )
    await safe_callback_answer(callback, "")


# ------------------------------------------------------------------ #
#  admin_stats_callback
# ------------------------------------------------------------------ #

@router.callback_query(F.data == "admin_stats")
async def admin_stats_callback(callback: types.CallbackQuery):
    """Показывает статистику через админ-панель."""
    try:
        if callback.from_user.id != ADMIN_ID:
            await safe_callback_answer(callback, "❌ Только администратор", show_alert=True)
            return
        
        await safe_callback_answer(callback, "⏳ Загрузка статистики...")
        
        bot = None
        if callback.message:
            bot = callback.message.bot
        if bot is None:
            bot = callback.bot
        if bot is None:
            logger.warning("Bot is None in admin_stats_callback, создаем новый bot instance")
            bot = Bot(
                settings.TG_TOKEN,
                default=DefaultBotProperties(parse_mode=ParseMode.HTML)
            )
        
        stats = get_stats()
        
        text = (
            "📊 *Статистика бота*\n\n"
            f"⏱️ *Время работы:*\n"
            f"• Дней: {stats['uptime_days']}\n"
            f"• Часов: {stats['uptime_hours']}\n"
            f"• Секунд: {stats['uptime_seconds']}\n\n"
            f"📈 *Использование:*\n"
            f"• Проверено доменов: {stats['total_domains_checked']}\n"
            f"• Уникальных пользователей: {stats['total_users']}\n\n"
        )
        
        if stats['top_domains']:
            text += "🔝 *Топ доменов:*\n"
            for domain, count in list(stats['top_domains'].items())[:5]:
                text += f"• {domain}: {count}\n"
            text += "\n"
        
        if stats['top_commands']:
            text += "⚙️ *Топ команд:*\n"
            for cmd, count in list(stats['top_commands'].items())[:5]:
                text += f"• {cmd}: {count}\n"
            text += "\n"
        
        if stats['top_errors']:
            text += "⚠️ *Топ ошибок:*\n"
            for error, count in list(stats['top_errors'].items())[:5]:
                text += f"• {error}: {count}\n"
        
        text += f"\n🔄 Последний сброс: {stats['last_reset']}"
        
        chat_id = callback.message.chat.id if callback.message else callback.from_user.id
        try:
            await safe_send_text(
                bot,
                chat_id,
                text,
                parse_mode=ParseMode.MARKDOWN
            )
        finally:
            if bot != callback.message.bot if callback.message else callback.bot:
                await bot.session.close()
        
    except Exception as e:
        logger.error(
            f"❌ Ошибка в admin_stats_callback | "
            f"user_id={callback.from_user.id if callback.from_user else None} | "
            f"error={type(e).__name__}: {str(e)}",
            exc_info=True
        )
        try:
            await safe_callback_answer(callback, "❌ Ошибка при загрузке статистики", show_alert=True)
        except Exception:
            pass
