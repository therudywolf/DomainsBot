from aiogram import types
from access import has_access, has_permission, ADMIN_ID, REQUEST_ACCESS_URL
from utils.prefs import get_mode, get_waf_mode

DEFAULT_MODE = "full"


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


def build_waf_mode_keyboard(current_mode: str) -> types.InlineKeyboardMarkup:
    """Inline-кнопки для переключения режима проверки WAF."""
    return types.InlineKeyboardMarkup(
        inline_keyboard=[
            [
                types.InlineKeyboardButton(
                    text=("✅ Policy" if current_mode == "policy" else "Policy"),
                    callback_data="waf_mode_policy",
                ),
                types.InlineKeyboardButton(
                    text=("✅ Light" if current_mode == "light" else "Light"),
                    callback_data="waf_mode_light",
                ),
            ]
        ]
    )


def build_monitoring_keyboard() -> types.InlineKeyboardMarkup:
    """Клавиатура для управления мониторингом."""
    return types.InlineKeyboardMarkup(
        inline_keyboard=[
            [
                types.InlineKeyboardButton(
                    text="➕ Добавить домен",
                    callback_data="monitor_add",
                ),
                types.InlineKeyboardButton(
                    text="➖ Удалить домен",
                    callback_data="monitor_remove",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="📋 Список доменов",
                    callback_data="monitor_list",
                ),
                types.InlineKeyboardButton(
                    text="📥 Экспорт",
                    callback_data="monitor_export",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="⏱️ Интервал",
                    callback_data="monitor_interval",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="⚙️ WAF таймаут",
                    callback_data="monitor_waf_timeout",
                ),
                types.InlineKeyboardButton(
                    text="🔄 Вкл/Выкл",
                    callback_data="monitor_toggle",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="💬 Чат для уведомлений",
                    callback_data="settings_notification_chat",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="🔙 Главное меню",
                    callback_data="main_menu",
                ),
            ],
        ]
    )


def build_main_menu_keyboard(user_id: int) -> types.ReplyKeyboardMarkup:
    """
    Создает главное меню с кнопками для быстрого доступа.
    
    Показывает только те функции, к которым у пользователя есть доступ.
    
    Args:
        user_id: ID пользователя для определения доступных функций
        
    Returns:
        ReplyKeyboardMarkup с кнопками главного меню
    """
    keyboard = []
    
    if has_access(user_id) and has_permission(user_id, "check_domains"):
        keyboard.append([
            types.KeyboardButton(text="🔍 Проверить домен"),
        ])
    
    if has_access(user_id) and has_permission(user_id, "monitoring"):
        if keyboard:
            keyboard[-1].append(types.KeyboardButton(text="📊 Мониторинг"))
        else:
            keyboard.append([types.KeyboardButton(text="📊 Мониторинг")])
    
    if has_access(user_id) and has_permission(user_id, "settings"):
        if keyboard and len(keyboard[-1]) < 2:
            keyboard[-1].append(types.KeyboardButton(text="⚙️ Настройки"))
        else:
            keyboard.append([types.KeyboardButton(text="⚙️ Настройки")])
    
    if has_access(user_id) and has_permission(user_id, "history"):
        if keyboard and len(keyboard[-1]) < 2:
            keyboard[-1].append(types.KeyboardButton(text="📋 История"))
        else:
            keyboard.append([types.KeyboardButton(text="📋 История")])
    
    if user_id == ADMIN_ID:
        keyboard.append([
            types.KeyboardButton(text="👨‍💼 Админ-панель"),
        ])
    
    keyboard.append([
        types.KeyboardButton(text="🔙 Назад"),
        types.KeyboardButton(text="🏠 Главное меню"),
    ])
    
    keyboard.append([
        types.KeyboardButton(text="ℹ️ Помощь"),
    ])
    
    return types.ReplyKeyboardMarkup(
        keyboard=keyboard,
        resize_keyboard=True,
        input_field_placeholder="Введите домен или выберите действие..."
    )


def build_settings_keyboard(user_id: int) -> types.InlineKeyboardMarkup:
    """
    Создает клавиатуру настроек пользователя.
    
    Args:
        user_id: ID пользователя
        
    Returns:
        InlineKeyboardMarkup с настройками
    """
    current_mode = get_mode(user_id, DEFAULT_MODE)
    current_waf_mode = get_waf_mode(user_id, "policy")
    
    return types.InlineKeyboardMarkup(
        inline_keyboard=[
            [
                types.InlineKeyboardButton(
                    text="📄 Режим отчета",
                    callback_data="settings_report_mode",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text=("✅ 🔎 Расширенный" if current_mode == "full" else "🔎 Расширенный"),
                    callback_data="mode_full",
                ),
                types.InlineKeyboardButton(
                    text=("✅ 📄 Короткий" if current_mode == "brief" else "📄 Короткий"),
                    callback_data="mode_brief",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="🛡️ Режим WAF",
                    callback_data="settings_waf_mode",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text=("✅ Policy" if current_waf_mode == "policy" else "Policy"),
                    callback_data="waf_mode_policy",
                ),
                types.InlineKeyboardButton(
                    text=("✅ Light" if current_waf_mode == "light" else "Light"),
                    callback_data="waf_mode_light",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="💬 Чат для уведомлений",
                    callback_data="settings_notification_chat",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="🔙 Главное меню",
                    callback_data="main_menu",
                ),
            ],
        ]
    )


def build_access_denied_keyboard() -> types.InlineKeyboardMarkup:
    """Кнопка для запроса доступа (если задан REQUEST_ACCESS_URL)."""
    if REQUEST_ACCESS_URL and REQUEST_ACCESS_URL.startswith(("http://", "https://")):
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
    return types.InlineKeyboardMarkup(inline_keyboard=[])


def build_admin_keyboard() -> types.InlineKeyboardMarkup:
    """Админ-панель кнопок с расширенным функционалом."""
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
                    text="📋 Список пользователей",
                    callback_data="admin_list_access",
                ),
                types.InlineKeyboardButton(
                    text="🔐 Управление разрешениями",
                    callback_data="admin_manage_permissions",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="⚡ Массовое редактирование прав",
                    callback_data="admin_mass_edit_permissions",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="📤 Экспорт пользователей",
                    callback_data="admin_export_users",
                ),
            ],
            [
                types.InlineKeyboardButton(
                    text="📊 Статистика",
                    callback_data="admin_stats",
                ),
                types.InlineKeyboardButton(
                    text="🔌 Проверить WireGuard",
                    callback_data="admin_check_wg",
                ),
            ],
        ]
    )
