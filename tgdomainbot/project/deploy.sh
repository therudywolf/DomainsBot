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
    
    # Проверяем какие образы были загружены и создаем теги для всех сервисов
    echo "  - Создание тегов для всех сервисов..."
    
    # Получаем имя загруженного образа gostsslcheck
    GOST_IMAGE=$(docker images --format "{{.Repository}}:{{.Tag}}" bottgdomains-gostsslcheck* | head -1)
    if [ -n "$GOST_IMAGE" ]; then
        echo "    Найден образ: $GOST_IMAGE"
        # Создаем теги для всех трех сервисов gostsslcheck
        docker tag "$GOST_IMAGE" bottgdomains-gostsslcheck1:latest 2>/dev/null || true
        docker tag "$GOST_IMAGE" bottgdomains-gostsslcheck2:latest 2>/dev/null || true
        docker tag "$GOST_IMAGE" bottgdomains-gostsslcheck3:latest 2>/dev/null || true
        echo "    ✅ Теги созданы для gostsslcheck1, gostsslcheck2, gostsslcheck3"
    fi
    
    # Получаем имя загруженного образа tgscanner
    TGSCANNER_IMAGE=$(docker images --format "{{.Repository}}:{{.Tag}}" bottgdomains-tgscanner* | head -1)
    if [ -n "$TGSCANNER_IMAGE" ]; then
        echo "    Найден образ: $TGSCANNER_IMAGE"
        docker tag "$TGSCANNER_IMAGE" bottgdomains-tgscanner:latest 2>/dev/null || true
        echo "    ✅ Тег создан для tgscanner"
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

# Создаем docker-compose.override.yml для использования уже загруженных образов
echo "📝 Создание docker-compose.override.yml для offline развертывания..."
cat > docker-compose.override.yml << 'EOF'
version: '3'
services:
  gostsslcheck1:
    image: bottgdomains-gostsslcheck1:latest
  gostsslcheck2:
    image: bottgdomains-gostsslcheck2:latest
  gostsslcheck3:
    image: bottgdomains-gostsslcheck3:latest
  tgscanner:
    image: bottgdomains-tgscanner:latest
EOF
echo "✅ docker-compose.override.yml создан"
echo ""

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

# Используем --no-build чтобы не собирать образы заново (они уже загружены)
# Также используем --pull never чтобы не пытаться скачивать образы из интернета
$DOCKER_COMPOSE up -d --no-build --pull never

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

# Информация об автозапуске
echo "📋 Информация об автозапуске:"
echo ""
echo "  ✅ Контейнеры настроены на автозапуск (restart: unless-stopped)"
echo "  ✅ Контейнеры запущены в фоновом режиме (docker-compose up -d)"
echo ""
echo "  ⚠️  Для автозапуска после перезагрузки системы убедитесь, что:"
echo "     1. Docker сервис запускается при загрузке:"
echo "        sudo systemctl enable docker"
echo "        sudo systemctl start docker"
echo ""
echo "     2. (Опционально) Создайте systemd service для автоматического запуска docker-compose:"
echo "        См. инструкции ниже"
echo ""

# Предложение создать systemd service
if command -v systemctl &> /dev/null && [ "$EUID" -eq 0 ]; then
    echo "  💡 Хотите создать systemd service для автозапуска? (y/n)"
    read -p "     " CREATE_SERVICE
    if [ "$CREATE_SERVICE" = "y" ] || [ "$CREATE_SERVICE" = "Y" ]; then
        SERVICE_FILE="/etc/systemd/system/bottgdomains.service"
        cat > "$SERVICE_FILE" << EOF
[Unit]
Description=BotTGDomains Telegram Bot
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable bottgdomains.service
        echo "    ✅ Systemd service создан и включен"
        echo "    📋 Управление:"
        echo "       sudo systemctl start bottgdomains   # Запуск"
        echo "       sudo systemctl stop bottgdomains    # Остановка"
        echo "       sudo systemctl status bottgdomains  # Статус"
    fi
fi

echo ""
