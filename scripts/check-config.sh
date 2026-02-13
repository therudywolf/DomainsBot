#!/bin/bash
# Скрипт проверки конфигурации перед запуском

ENV_FILE="tg_domain_scanner_final/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "❌ Файл $ENV_FILE не найден"
    echo "   Создайте его из .env.example: cp tg_domain_scanner_final/.env.example tg_domain_scanner_final/.env"
    exit 1
fi

source "$ENV_FILE" 2>/dev/null || true

ERRORS=0

if [ -z "${TG_TOKEN:-}" ] || [ "$TG_TOKEN" = "your_telegram_bot_token_here" ] || [ "$TG_TOKEN" = "ID" ]; then
    echo "❌ TG_TOKEN не установлен"
    ERRORS=$((ERRORS + 1))
fi

if [ -z "${ADMIN_ID:-}" ] || [ "$ADMIN_ID" = "your_telegram_user_id_here" ]; then
    echo "❌ ADMIN_ID не установлен"
    ERRORS=$((ERRORS + 1))
fi

if [ $ERRORS -eq 0 ]; then
    echo "✅ Конфигурация корректна"
    echo "   TG_TOKEN: установлен"
    echo "   ADMIN_ID: $ADMIN_ID"
    exit 0
else
    echo ""
    echo "⚠️  Исправьте ошибки в файле $ENV_FILE"
    exit 1
fi
