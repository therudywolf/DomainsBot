from aiogram import types
from access import has_access, has_permission, ADMIN_ID, REQUEST_ACCESS_URL, is_admin_user, is_main_admin
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


def _monitoring_button_rows(
    prefix: str,
    run_now_callback: str,
    chat_row: list | None = None,
    tail_row: list | None = None,
) -> list:
    """
    Общие строки кнопок для клавиатур мониторинга (DRY).
    prefix — префикс callback_data для кнопок add, remove, list, export, interval, waf_timeout, toggle.
    run_now_callback — полный callback_data для «Проверить сейчас».
    chat_row — опциональная строка с кнопкой чата для уведомлений.
    tail_row — строка кнопок в конце (напр. «Главное меню» или «К мониторингу»).
    """
    rows = [
        [
            types.InlineKeyboardButton(text="➕ Добавить домен", callback_data=prefix + "add"),
            types.InlineKeyboardButton(text="➖ Удалить домен", callback_data=prefix + "remove"),
        ],
        [
            types.InlineKeyboardButton(text="📋 Список доменов", callback_data=prefix + "list"),
            types.InlineKeyboardButton(text="📥 Экспорт", callback_data=prefix + "export"),
        ],
        [types.InlineKeyboardButton(text="⏱️ Интервал", callback_data=prefix + "interval")],
        [
            types.InlineKeyboardButton(text="⚙️ WAF таймаут", callback_data=prefix + "waf_timeout"),
            types.InlineKeyboardButton(text="🔄 Вкл/Выкл", callback_data=prefix + "toggle"),
        ],
        [types.InlineKeyboardButton(text="▶️ Проверить сейчас", callback_data=run_now_callback)],
    ]
    if chat_row:
        rows.append(chat_row)
    if tail_row:
        rows.append(tail_row)
    return rows


def build_monitoring_keyboard(user_id: int = 0) -> types.InlineKeyboardMarkup:
    """Клавиатура для управления мониторингом (user_id для отображения кнопок админа)."""
    prefix = "monitor_"
    rows = _monitoring_button_rows(
        prefix,
        run_now_callback="monitor_run_now",
        chat_row=[types.InlineKeyboardButton(text="💬 Чат для уведомлений", callback_data="settings_notification_chat")],
        tail_row=[types.InlineKeyboardButton(text="🔙 Главное меню", callback_data="main_menu")],
    )
    if is_admin_user(user_id):
        rows.insert(-1, [
            types.InlineKeyboardButton(text="🌐 Глобальная панель", callback_data="monitor_switch_global"),
            types.InlineKeyboardButton(text="👥 Панели пользователей", callback_data="monitor_admin_panels"),
        ])
    return types.InlineKeyboardMarkup(inline_keyboard=rows)


def build_monitoring_global_keyboard() -> types.InlineKeyboardMarkup:
    """Клавиатура для глобальной панели мониторинга (только для админов)."""
    prefix = "monitor_global_"
    rows = _monitoring_button_rows(
        prefix,
        run_now_callback="monitor_run_now_global",
        chat_row=[types.InlineKeyboardButton(text="💬 Чат для уведомлений (общая)", callback_data="monitor_global_chat")],
        tail_row=[types.InlineKeyboardButton(text="🔙 К мониторингу", callback_data="monitor_back")],
    )
    return types.InlineKeyboardMarkup(inline_keyboard=rows)


def build_monitoring_admin_panel_keyboard(owner_key: str) -> types.InlineKeyboardMarkup:
    """Клавиатура для просмотра/редактирования панели пользователя или глобальной (админ)."""
    prefix = f"monitor_admin_{owner_key}_"
    rows = _monitoring_button_rows(
        prefix,
        run_now_callback=prefix + "run_now",
        chat_row=None,
        tail_row=[types.InlineKeyboardButton(text="🔙 К списку панелей", callback_data="monitor_admin_panels")],
    )
    return types.InlineKeyboardMarkup(inline_keyboard=rows)


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
    
    if is_admin_user(user_id):
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


def build_admin_keyboard(user_id: int = 0) -> types.InlineKeyboardMarkup:
    """Админ-панель кнопок с расширенным функционалом.
    
    Args:
        user_id: ID пользователя (для показа кнопок управления админами только главному)
    """
    rows = [
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
    
    if is_main_admin(user_id):
        rows.append([
            types.InlineKeyboardButton(
                text="👑 Выдать админку",
                callback_data="admin_grant_admin",
            ),
            types.InlineKeyboardButton(
                text="🚫 Снять админку",
                callback_data="admin_revoke_admin",
            ),
        ])
    
    return types.InlineKeyboardMarkup(inline_keyboard=rows)
