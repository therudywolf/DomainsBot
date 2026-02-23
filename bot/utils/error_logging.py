"""
Улучшенное логирование ошибок с traceback ID, контекстом пользователя и алертами.

Обеспечивает структурированное логирование для лучшего отслеживания и анализа ошибок.
"""

import logging
import traceback
import uuid
from datetime import datetime
from typing import Optional, Dict, Any
import json

logger = logging.getLogger(__name__)

# Хранилище для критических ошибок (для алертов администратору)
_critical_errors: list[Dict[str, Any]] = []
_MAX_CRITICAL_ERRORS = 100


def generate_error_id() -> str:
    """
    Генерирует уникальный ID для ошибки.
    
    Returns:
        Уникальный строковый идентификатор
    """
    return str(uuid.uuid4())[:8]


def log_error_with_context(
    error: Exception,
    user_id: Optional[int] = None,
    context: Optional[Dict[str, Any]] = None,
    level: str = "ERROR",
    send_alert: bool = False,
) -> str:
    """
    Логирует ошибку с контекстом пользователя и генерирует traceback ID.
    
    Args:
        error: Исключение для логирования
        user_id: ID пользователя (если доступен)
        context: Дополнительный контекст (домен, операция и т.д.)
        level: Уровень логирования (ERROR, WARNING, CRITICAL)
        send_alert: Отправлять ли алерт администратору
        
    Returns:
        Traceback ID для отслеживания ошибки
    """
    error_id = generate_error_id()
    error_type = type(error).__name__
    error_message = str(error)
    
    # Формируем структурированную информацию об ошибке
    error_info = {
        "error_id": error_id,
        "timestamp": datetime.now().isoformat(),
        "error_type": error_type,
        "error_message": error_message,
        "user_id": user_id,
        "context": context or {},
        "traceback": traceback.format_exc(),
    }
    
    # Логируем в структурированном формате (JSON для парсинга)
    log_message = json.dumps(error_info, ensure_ascii=False, indent=2)
    
    # Также логируем в читаемом формате
    readable_message = (
        f"[{error_id}] {error_type}: {error_message}\n"
        f"User: {user_id or 'N/A'}\n"
        f"Context: {context or {}}\n"
        f"Traceback:\n{traceback.format_exc()}"
    )
    
    # Логируем в зависимости от уровня
    if level == "CRITICAL":
        logger.critical(readable_message)
        if send_alert:
            _add_critical_error(error_info)
    elif level == "WARNING":
        logger.warning(readable_message)
    else:
        logger.error(readable_message)
    
    # Дополнительно логируем структурированную версию
    logger.debug(f"Structured error log [{error_id}]:\n{log_message}")
    
    return error_id


def _add_critical_error(error_info: Dict[str, Any]) -> None:
    """
    Добавляет критическую ошибку в список для алертов.
    
    Args:
        error_info: Информация об ошибке
    """
    _critical_errors.append(error_info)
    
    # Ограничиваем размер списка
    if len(_critical_errors) > _MAX_CRITICAL_ERRORS:
        _critical_errors.pop(0)


def get_critical_errors(limit: int = 10) -> list[Dict[str, Any]]:
    """
    Получает список критических ошибок.
    
    Args:
        limit: Максимальное количество ошибок
        
    Returns:
        Список критических ошибок
    """
    return _critical_errors[-limit:]


def clear_critical_errors() -> None:
    """Очищает список критических ошибок."""
    _critical_errors.clear()


def format_error_for_user(error_id: str, error_type: str) -> str:
    """
    Форматирует сообщение об ошибке для пользователя.
    
    Args:
        error_id: ID ошибки
        error_type: Тип ошибки
        
    Returns:
        Отформатированное сообщение
    """
    user_friendly_messages = {
        "DNS_ERROR": "Не удалось получить DNS информацию. Проверьте правильность домена.",
        "SSL_ERROR": "Не удалось проверить SSL сертификат. Возможно, домен не поддерживает HTTPS.",
        "WAF_ERROR": "Ошибка при проверке WAF. Попробуйте позже.",
        "GOST_ERROR": "Ошибка при проверке GOST сертификата. Сервис может быть недоступен.",
        "TIMEOUT_ERROR": "Превышено время ожидания. Попробуйте позже.",
        "CONNECTION_ERROR": "Ошибка соединения. Проверьте интернет-соединение.",
        "PROCESSING_ERROR": "Ошибка при проверке домена. Попробуйте позже или проверьте ввод.",
        "FILE_PROCESSING_ERROR": "Ошибка при обработке файла. Проверьте формат и попробуйте снова.",
    }
    
    message = user_friendly_messages.get(error_type, "Произошла ошибка при обработке запроса.")
    
    # HTML-разметка для корректного отображения кода при parse_mode=HTML (дефолт бота)
    return (
        f"❌ {message}\n\n"
        f"Код ошибки: <code>{error_id}</code>\n"
        f"Если проблема повторяется, обратитесь к администратору и укажите код ошибки."
    )





