#!/bin/bash
# Скрипт быстрого старта BotTGDomains "Под ключ"
# Автоматически настраивает и запускает бота

set -e

echo "🚀 BotTGDomains - Быстрый старт"
echo "================================"
echo ""

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Проверка Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker не установлен. Установите Docker и повторите попытку.${NC}"
    exit 1
fi

if ! command -v docker compose &> /dev/null && ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose не установлен. Установите Docker Compose и повторите попытку.${NC}"
    exit 1
fi

DOCKER_COMPOSE="docker compose"
if ! command -v docker compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
fi

echo -e "${GREEN}✅ Docker найден${NC}"
echo ""

# Переход в корневую директорию проекта
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "📁 Рабочая директория: $PROJECT_ROOT"
echo ""

# Создание директорий
echo "📁 Создание необходимых директорий..."
mkdir -p data
echo -e "${GREEN}✅ Директория data/ создана${NC}"

# Проверка WireGuard на хосте (для работы резервного подключения)
echo ""
echo "🔍 Проверка WireGuard на хосте..."
if lsmod | grep -q wireguard 2>/dev/null || modprobe wireguard 2>/dev/null; then
    echo -e "${GREEN}✅ Модуль WireGuard доступен на хосте${NC}"
else
    echo -e "${YELLOW}⚠️  Предупреждение: Модуль WireGuard не найден на хосте${NC}"
    echo "   Резервное подключение при 504 ошибках может не работать"
    echo "   Установите WireGuard: sudo apt-get install wireguard-tools"
fi
echo ""

# Проверка и создание .env файла
ENV_FILE="tg_domain_scanner_final/.env"
ENV_EXAMPLE="tg_domain_scanner_final/.env.example"

if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
        echo "📝 Создание файла конфигурации..."
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        echo -e "${GREEN}✅ Файл .env создан из .env.example${NC}"
        echo ""
        echo -e "${YELLOW}⚠️  ВАЖНО: Отредактируйте файл $ENV_FILE${NC}"
        echo "   Укажите следующие обязательные параметры:"
        echo "   - TG_TOKEN=ваш_токен_от_BotFather"
        echo "   - ADMIN_ID=ваш_telegram_user_id"
        echo ""
        read -p "Нажмите Enter после редактирования .env файла..."
    else
        echo -e "${RED}❌ Ошибка: .env.example не найден${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✅ Файл .env найден${NC}"
fi

echo ""

# Проверка обязательных переменных
echo "🔍 Проверка конфигурации..."
source "$ENV_FILE" 2>/dev/null || true

if [ -z "${TG_TOKEN:-}" ] || [ "$TG_TOKEN" = "your_telegram_bot_token_here" ] || [ "$TG_TOKEN" = "ID" ]; then
    echo -e "${RED}❌ Ошибка: TG_TOKEN не установлен в .env${NC}"
    echo "   Получите токен у @BotFather в Telegram"
    exit 1
fi

if [ -z "${ADMIN_ID:-}" ] || [ "$ADMIN_ID" = "your_telegram_user_id_here" ]; then
    echo -e "${RED}❌ Ошибка: ADMIN_ID не установлен в .env${NC}"
    echo "   Получите ваш ID у @userinfobot в Telegram"
    exit 1
fi

echo -e "${GREEN}✅ Конфигурация проверена${NC}"
echo ""

# Остановка существующих контейнеров
echo "🛑 Остановка существующих контейнеров (если есть)..."
$DOCKER_COMPOSE down 2>/dev/null || true
echo -e "${GREEN}✅ Готово${NC}"
echo ""

# Сборка и запуск
echo "🔨 Сборка и запуск сервисов..."
echo "   Это может занять несколько минут при первом запуске..."
echo ""

$DOCKER_COMPOSE up -d --build

echo ""
echo "⏳ Ожидание готовности сервисов..."
sleep 10

# Проверка статуса
echo ""
echo "📊 Статус сервисов:"
$DOCKER_COMPOSE ps

echo ""
echo -e "${GREEN}✅ Бот запущен!${NC}"
echo ""
echo "📋 Полезные команды:"
echo "   Просмотр логов:     $DOCKER_COMPOSE logs -f tgscanner"
echo "   Остановка:          $DOCKER_COMPOSE down"
echo "   Перезапуск:         $DOCKER_COMPOSE restart tgscanner"
echo "   Статус:             $DOCKER_COMPOSE ps"
echo ""
echo "🎉 Готово! Отправьте /start боту в Telegram"
