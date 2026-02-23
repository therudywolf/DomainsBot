#!/bin/bash
set -euo pipefail

# Скрипт развертывания BotTGDomains на VM без интернета
# Использование: ./deploy.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/docker-compose.yml" ]; then
    PROJECT_ROOT="$SCRIPT_DIR"
else
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
IMAGES_DIR="$PROJECT_ROOT/../images"
PROJECT_DIR="$PROJECT_ROOT"

echo "=========================================="
echo "BotTGDomains - Offline Deployment"
echo "=========================================="
echo ""

# Проверка наличия Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Ошибка: Docker не установлен"
    exit 1
fi

# Проверка наличия Docker Compose
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Ошибка: Docker Compose не установлен"
    exit 1
fi

if docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
else
    DOCKER_COMPOSE="docker-compose"
fi

echo "✅ Docker и Compose найдены"
echo ""

# Проверка WireGuard на хосте
echo "🔍 Проверка WireGuard на хосте..."
if lsmod | grep -q wireguard 2>/dev/null || modprobe wireguard 2>/dev/null; then
    echo "✅ Модуль WireGuard доступен на хосте"
else
    echo "⚠️  Предупреждение: Модуль WireGuard не найден на хосте"
fi
echo ""

# Загрузка образов
if [ ! -d "$IMAGES_DIR" ]; then
    echo "⚠️  Предупреждение: Директория images/ не найдена"
else
    echo "📦 Шаг 1: Загрузка Docker образов..."
    echo ""
    
    # GostSSLCheck
    if [ -f "$IMAGES_DIR/gostsslcheck.tar" ]; then
        echo "  - Загрузка gostsslcheck.tar..."
        docker load -i "$IMAGES_DIR/gostsslcheck.tar"
        echo "    ✅ Образ gostsslcheck загружен"
    else
        echo "  ⚠️  gostsslcheck.tar не найден"
    fi
    
    # TgScanner
    if [ -f "$IMAGES_DIR/tgscanner.tar" ]; then
        echo "  - Загрузка tgscanner.tar..."
        docker load -i "$IMAGES_DIR/tgscanner.tar"
        echo "    ✅ Образ tgscanner загружен"
    else
        echo "  ⚠️  tgscanner.tar не найден"
    fi

    # WireGuard (НОВОЕ)
    if [ -f "$IMAGES_DIR/wireguard.tar" ]; then
        echo "  - Загрузка wireguard.tar..."
        docker load -i "$IMAGES_DIR/wireguard.tar"
        echo "    ✅ Образ wireguard загружен"
    else
        echo "  ⚠️  wireguard.tar не найден (WireGuard может не запуститься без интернета)"
    fi
    
    echo ""
    
    # Тегирование
    echo "  - Создание тегов для сервисов..."
    
    GOST_IMAGE=$(docker images --format "{{.Repository}}:{{.Tag}}" bottgdomains-gostsslcheck* | head -1)
    if [ -n "$GOST_IMAGE" ]; then
        docker tag "$GOST_IMAGE" bottgdomains-gostsslcheck1:latest 2>/dev/null || true
        docker tag "$GOST_IMAGE" bottgdomains-gostsslcheck2:latest 2>/dev/null || true
        docker tag "$GOST_IMAGE" bottgdomains-gostsslcheck3:latest 2>/dev/null || true
        echo "    ✅ Теги для gostsslcheck созданы"
    fi
    
    TGSCANNER_IMAGE=$(docker images --format "{{.Repository}}:{{.Tag}}" bottgdomains-tgscanner* | head -1)
    if [ -n "$TGSCANNER_IMAGE" ]; then
        docker tag "$TGSCANNER_IMAGE" bottgdomains-tgscanner:latest 2>/dev/null || true
        echo "    ✅ Тег для tgscanner создан"
    fi
    
    echo ""
fi

# Переход в проект
cd "$PROJECT_DIR"

if [ ! -f "docker-compose.yml" ]; then
    echo "❌ Ошибка: docker-compose.yml не найден"
    exit 1
fi

# Создаем override
echo "📝 Создание docker-compose.override.yml..."
cat > docker-compose.override.yml << 'EOF'
services:
  gostsslcheck1:
    image: bottgdomains-gostsslcheck1:latest
  gostsslcheck2:
    image: bottgdomains-gostsslcheck2:latest
  gostsslcheck3:
    image: bottgdomains-gostsslcheck3:latest
  tgscanner:
    image: bottgdomains-tgscanner:latest
  wireguard:
    image: masipcat/wireguard-go:latest
EOF
echo "✅ docker-compose.override.yml создан"
echo ""

# Создаем директории
echo "📁 Шаг 2: Создание директорий..."
mkdir -p data
if [ ! -d "wg" ]; then
    mkdir -p wg
    echo "✅ Директория wg/ создана (не забудьте положить туда конфиг)"
else
    echo "✅ Директория wg/ существует"
fi
echo ""

# Проверка .env
echo "⚙️  Шаг 3: Проверка конфигурации..."
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "  ✅ Файл .env создан из примера. ОТРЕДАКТИРУЙТЕ ЕГО!"
        read -p "  Нажмите Enter после редактирования .env файла..."
    else
        echo "  ❌ Ошибка: .env не найден"
        exit 1
    fi
else
    echo "  ✅ Файл .env найден"
fi

# Запуск
echo "🛑 Шаг 4: Перезапуск контейнеров..."
$DOCKER_COMPOSE down 2>/dev/null || true
$DOCKER_COMPOSE up -d --no-build --pull never

if [ $? -ne 0 ]; then
    echo "❌ Ошибка при запуске"
    exit 1
fi

echo ""
echo "✅ Сервисы запущены. Ожидание..."
sleep 5
$DOCKER_COMPOSE ps

echo ""
echo "🎉 Развертывание завершено."