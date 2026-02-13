#!/bin/bash
set -euo pipefail

# Скрипт развертывания BotTGDomains на VM без интернета
# Использование: ./deploy.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR" && pwd)"
IMAGES_DIR="$PROJECT_ROOT/../images"
PROJECT_DIR="$PROJECT_ROOT"

echo "=========================================="
echo "BotTGDomains - Offline Deployment"
echo "=========================================="
echo ""

# Проверка наличия Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Ошибка: Docker не установлен"
    echo "   Установите Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Проверка наличия Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Ошибка: Docker Compose не установлен"
    echo "   Установите Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

# Определяем команду docker compose
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
else
    DOCKER_COMPOSE="docker-compose"
fi

# Проверка версии Docker
DOCKER_VERSION=$(docker --version | grep -oE '[0-9]+\.[0-9]+' | head -1)
REQUIRED_VERSION="20.10"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$DOCKER_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "⚠️  Предупреждение: Рекомендуется Docker $REQUIRED_VERSION или выше (установлено: $DOCKER_VERSION)"
fi

echo "✅ Docker установлен: $(docker --version)"
echo "✅ Docker Compose установлен: $($DOCKER_COMPOSE version | head -1)"
echo ""

# Проверка наличия директории с образами
if [ ! -d "$IMAGES_DIR" ]; then
    echo "⚠️  Предупреждение: Директория images/ не найдена"
    echo "   Ожидаемое расположение: $IMAGES_DIR"
    echo "   Продолжаем развертывание без загрузки образов..."
    echo ""
else
    echo "📦 Шаг 1: Загрузка Docker образов..."
    echo ""
    
    # Загружаем образы
    if [ -f "$IMAGES_DIR/gostsslcheck.tar" ]; then
        echo "  - Загрузка gostsslcheck.tar..."
        docker load -i "$IMAGES_DIR/gostsslcheck.tar"
        echo "    ✅ Образ gostsslcheck загружен"
    else
        echo "  ⚠️  gostsslcheck.tar не найден"
    fi
    
    if [ -f "$IMAGES_DIR/tgscanner.tar" ]; then
        echo "  - Загрузка tgscanner.tar..."
        docker load -i "$IMAGES_DIR/tgscanner.tar"
        echo "    ✅ Образ tgscanner загружен"
    else
        echo "  ⚠️  tgscanner.tar не найден"
    fi
    
    echo ""
fi

# Переходим в директорию проекта
cd "$PROJECT_DIR"

# Проверка наличия docker-compose.yml
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ Ошибка: docker-compose.yml не найден в $PROJECT_DIR"
    exit 1
fi

echo "📁 Шаг 2: Создание необходимых директорий..."
mkdir -p tg_domain_scanner_final/data
echo "✅ Директории созданы"
echo ""

# Проверка наличия .env файла
echo "⚙️  Шаг 3: Проверка конфигурации..."
if [ ! -f "tg_domain_scanner_final/.env" ]; then
    if [ -f "tg_domain_scanner_final/.env.example" ]; then
        echo "  ⚠️  Файл .env не найден, создаю из .env.example..."
        cp tg_domain_scanner_final/.env.example tg_domain_scanner_final/.env
        echo "  ✅ Файл .env создан"
        echo ""
        echo "  ⚠️  ВАЖНО: Отредактируйте файл tg_domain_scanner_final/.env"
        echo "     и укажите следующие обязательные параметры:"
        echo "     - TG_TOKEN=ваш_токен_от_BotFather"
        echo "     - ADMIN_ID=ваш_telegram_user_id"
        echo ""
        read -p "  Нажмите Enter после редактирования .env файла..."
    else
        echo "  ❌ Ошибка: .env.example не найден"
        echo "     Создайте файл tg_domain_scanner_final/.env вручную"
        exit 1
    fi
else
    echo "  ✅ Файл .env найден"
fi

echo ""

# Проверка обязательных переменных в .env
if [ -f "tg_domain_scanner_final/.env" ]; then
    source tg_domain_scanner_final/.env 2>/dev/null || true
    
    if [ -z "${TG_TOKEN:-}" ] || [ "$TG_TOKEN" = "ID" ]; then
        echo "  ⚠️  Предупреждение: TG_TOKEN не установлен в .env"
    fi
    
    if [ -z "${ADMIN_ID:-}" ]; then
        echo "  ⚠️  Предупреждение: ADMIN_ID не установлен в .env"
    fi
fi

echo ""

# Остановка существующих контейнеров (если есть)
echo "🛑 Шаг 4: Остановка существующих контейнеров (если есть)..."
$DOCKER_COMPOSE down 2>/dev/null || true
echo "✅ Готово"
echo ""

# Запуск сервисов
echo "🚀 Шаг 5: Запуск сервисов..."
echo ""

$DOCKER_COMPOSE up -d

if [ $? -ne 0 ]; then
    echo "❌ Ошибка при запуске сервисов"
    echo ""
    echo "Проверьте логи:"
    echo "  $DOCKER_COMPOSE logs"
    exit 1
fi

echo ""
echo "✅ Сервисы запущены"
echo ""

# Ожидание готовности сервисов
echo "⏳ Шаг 6: Ожидание готовности сервисов..."
sleep 5

# Проверка статуса
echo ""
echo "📊 Шаг 7: Проверка статуса сервисов..."
echo ""

$DOCKER_COMPOSE ps

echo ""
echo "=========================================="
echo "✅ Развертывание завершено успешно!"
echo "=========================================="
echo ""

# Проверка health checks
HEALTHY_COUNT=$($DOCKER_COMPOSE ps --format json | grep -c '"Health":"healthy"' || echo "0")
TOTAL_SERVICES=$($DOCKER_COMPOSE ps --format json | grep -c '"Name"' || echo "0")

if [ "$HEALTHY_COUNT" -gt 0 ]; then
    echo "✅ Сервисы проходят health checks: $HEALTHY_COUNT/$TOTAL_SERVICES"
else
    echo "⚠️  Health checks еще не завершены (это нормально, может занять до 30 секунд)"
fi

echo ""
echo "📋 Полезные команды:"
echo ""
echo "  Просмотр логов:"
echo "    $DOCKER_COMPOSE logs -f tgscanner"
echo "    $DOCKER_COMPOSE logs -f gostsslcheck1"
echo ""
echo "  Проверка статуса:"
echo "    $DOCKER_COMPOSE ps"
echo ""
echo "  Остановка сервисов:"
echo "    $DOCKER_COMPOSE down"
echo ""
echo "  Перезапуск сервисов:"
echo "    $DOCKER_COMPOSE restart"
echo ""
echo "  Просмотр всех логов:"
echo "    $DOCKER_COMPOSE logs -f"
echo ""

# Проверка доступности бота
echo "🔍 Проверка доступности бота..."
sleep 3

TGSCANNER_STATUS=$($DOCKER_COMPOSE ps tgscanner --format "{{.Status}}" 2>/dev/null || echo "")
if echo "$TGSCANNER_STATUS" | grep -q "Up"; then
    echo "✅ Контейнер tgscanner запущен"
    
    # Проверяем логи на наличие ошибок запуска
    if $DOCKER_COMPOSE logs tgscanner 2>&1 | grep -qi "error\|exception\|traceback" | head -5; then
        echo "⚠️  Обнаружены возможные ошибки в логах. Проверьте:"
        echo "    $DOCKER_COMPOSE logs tgscanner"
    fi
else
    echo "⚠️  Контейнер tgscanner не запущен. Проверьте логи:"
    echo "    $DOCKER_COMPOSE logs tgscanner"
fi

echo ""
echo "🎉 Готово! Бот должен быть доступен в Telegram."
echo ""
