#!/bin/bash
set -euo pipefail

# Скрипт сборки и экспорта Docker образов для offline развертывания
# Использование: ./scripts/build-and-export.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
EXPORT_DIR="$PROJECT_ROOT/export"
ARCHIVE_NAME="bottgdomains-offline-$(date +%Y%m%d-%H%M%S).tar.gz"

echo "=========================================="
echo "BotTGDomains - Offline Build & Export"
echo "=========================================="
echo ""

# Проверка наличия Docker и Docker Compose
if ! command -v docker &> /dev/null; then
    echo "❌ Ошибка: Docker не установлен"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Ошибка: Docker Compose не установлен"
    exit 1
fi

# Определяем команду docker compose
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
else
    DOCKER_COMPOSE="docker-compose"
fi

cd "$PROJECT_ROOT"

echo "📦 Шаг 1: Подготовка WireGuard конфига..."
# Создаем директорию wg/ если её нет
if [ ! -d "wg" ]; then
    mkdir -p wg
    echo "  ℹ️  Директория wg/ создана"
fi

# Создаем пустой конфиг если его нет (для успешной сборки образа)
if [ ! -f "wg/TGBOT.conf" ]; then
    echo "  ⚠️  WireGuard конфиг не найден, создаю пустой файл для сборки образа"
    echo "# WireGuard конфиг будет добавлен при развертывании" > wg/TGBOT.conf
    echo "# Создайте правильный конфиг перед использованием" >> wg/TGBOT.conf
fi

echo ""
echo "📦 Шаг 2: Сборка Docker образов..."
echo ""

# Сборка всех образов
$DOCKER_COMPOSE build --no-cache

echo ""
echo "✅ Образы собраны успешно"
echo ""

# Создаем директорию для экспорта
echo "📁 Шаг 3: Создание директории для экспорта..."
rm -rf "$EXPORT_DIR"
mkdir -p "$EXPORT_DIR/images"
mkdir -p "$EXPORT_DIR/project"

echo "✅ Директория создана: $EXPORT_DIR"
echo ""

# Получаем имена образов из docker-compose
echo "💾 Шаг 4: Экспорт Docker образов..."

# Получаем имя проекта из docker-compose
PROJECT_NAME=$(basename "$PROJECT_ROOT" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')
if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
    PROJECT_NAME=$(echo "$COMPOSE_PROJECT_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')
fi
if [ -z "$PROJECT_NAME" ] || [ ${#PROJECT_NAME} -lt 3 ]; then
    PROJECT_NAME="bottgdomains"
fi

echo "   Имя проекта Docker Compose: $PROJECT_NAME"
echo ""

# --- ЭКСПОРТ GOST ---
echo "  - Экспорт образа gostsslcheck..."
GOST_IMAGE=""
GOST_IMAGE=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "^${PROJECT_NAME}-gostsslcheck[0-9]*:" | head -1)
if [ -z "$GOST_IMAGE" ]; then
    GOST_IMAGE=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "^bottgdomains-gostsslcheck[0-9]*:" | head -1)
fi
if [ -z "$GOST_IMAGE" ]; then
    GOST_IMAGE=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "^gostsslcheck[0-9]*:" | head -1)
fi
if [ -z "$GOST_IMAGE" ]; then
    GOST_IMAGE=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -i "gostsslcheck" | grep -v "<none>" | head -1)
fi

if [ -z "$GOST_IMAGE" ]; then
    echo "❌ Ошибка: Образ gostsslcheck не найден"
    exit 1
fi
echo "   Найден образ: $GOST_IMAGE"
docker save "$GOST_IMAGE" -o "$EXPORT_DIR/images/gostsslcheck.tar"
GOST_SIZE=$(du -h "$EXPORT_DIR/images/gostsslcheck.tar" | cut -f1)
echo "    ✅ gostsslcheck.tar сохранен (размер: $GOST_SIZE)"

# --- ЭКСПОРТ TGSCANNER ---
echo "  - Экспорт образа tgscanner..."
TGSCANNER_IMAGE=""
TGSCANNER_IMAGE=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "^${PROJECT_NAME}-tgscanner:" | head -1)
if [ -z "$TGSCANNER_IMAGE" ]; then
    TGSCANNER_IMAGE=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "^bottgdomains-tgscanner:" | head -1)
fi
if [ -z "$TGSCANNER_IMAGE" ]; then
    TGSCANNER_IMAGE=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "^tgscanner:" | head -1)
fi
if [ -z "$TGSCANNER_IMAGE" ]; then
    TGSCANNER_IMAGE=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -i "tgscanner" | grep -v "<none>" | head -1)
fi

if [ -z "$TGSCANNER_IMAGE" ]; then
    echo "❌ Ошибка: Образ tgscanner не найден"
    exit 1
fi
echo "   Найден образ: $TGSCANNER_IMAGE"
docker save "$TGSCANNER_IMAGE" -o "$EXPORT_DIR/images/tgscanner.tar"
TGSCANNER_SIZE=$(du -h "$EXPORT_DIR/images/tgscanner.tar" | cut -f1)
echo "    ✅ tgscanner.tar сохранен (размер: $TGSCANNER_SIZE)"

# --- ЭКСПОРТ WIREGUARD (НОВАЯ ЧАСТЬ) ---
echo "  - Экспорт образа wireguard (masipcat/wireguard-go)..."
# Пытаемся обновить образ, если есть сеть
docker pull masipcat/wireguard-go:latest 2>/dev/null || true

if docker image inspect masipcat/wireguard-go:latest >/dev/null 2>&1; then
    docker save masipcat/wireguard-go:latest -o "$EXPORT_DIR/images/wireguard.tar"
    WG_SIZE=$(du -h "$EXPORT_DIR/images/wireguard.tar" | cut -f1)
    echo "    ✅ wireguard.tar сохранен (размер: $WG_SIZE)"
else
    echo "    ❌ Ошибка: Образ masipcat/wireguard-go:latest не найден локально!"
    echo "       Сделайте 'docker pull masipcat/wireguard-go:latest' вручную."
    exit 1
fi

echo ""
echo "📊 Размеры экспортированных образов:"
echo "  - gostsslcheck.tar: $GOST_SIZE"
echo "  - tgscanner.tar: $TGSCANNER_SIZE"
echo "  - wireguard.tar: $WG_SIZE"
echo ""

# Копируем файлы проекта
echo "📋 Шаг 5: Копирование файлов проекта..."

# Копируем основные файлы и директории
cp docker-compose.yml "$EXPORT_DIR/project/"
cp -r tg_domain_scanner_final "$EXPORT_DIR/project/"
rm -f "$EXPORT_DIR/project/tg_domain_scanner_final/docker-compose.yml" 2>/dev/null || true
cp -r GostSSLCheck "$EXPORT_DIR/project/"

# Копируем директорию wg/
if [ -d "wg" ]; then
    echo "  - Копирование директории wg/..."
    mkdir -p "$EXPORT_DIR/project/wg"
    cp -r wg/* "$EXPORT_DIR/project/wg/" 2>/dev/null || true
fi

# Копируем скрипты развертывания
if [ -f "scripts/deploy.sh" ]; then
    cp scripts/deploy.sh "$EXPORT_DIR/project/"
    chmod +x "$EXPORT_DIR/project/deploy.sh"
fi

# Копируем доки
if [ -f "DEPLOYMENT_OFFLINE.md" ]; then cp DEPLOYMENT_OFFLINE.md "$EXPORT_DIR/project/"; fi
if [ -f "README.md" ]; then cp README.md "$EXPORT_DIR/project/"; fi
if [ -f "QUICKSTART.md" ]; then cp QUICKSTART.md "$EXPORT_DIR/project/"; fi

# Копируем .env.example
if [ -f "tg_domain_scanner_final/.env.example" ]; then
    cp tg_domain_scanner_final/.env.example "$EXPORT_DIR/project/tg_domain_scanner_final/"
fi

# Чистка мусора
rm -rf "$EXPORT_DIR/project/tg_domain_scanner_final/data" 2>/dev/null || true
rm -rf "$EXPORT_DIR/project/tg_domain_scanner_final/__pycache__" 2>/dev/null || true
rm -rf "$EXPORT_DIR/project/tg_domain_scanner_final/**/__pycache__" 2>/dev/null || true
find "$EXPORT_DIR/project" -name "*.pyc" -delete 2>/dev/null || true
find "$EXPORT_DIR/project" -name ".pytest_cache" -type d -exec rm -rf {} + 2>/dev/null || true

echo "✅ Файлы проекта скопированы"
echo ""

# Создаем README для экспорта
cat > "$EXPORT_DIR/project/README_DEPLOYMENT.txt" << 'EOF'
==========================================
BotTGDomains - Offline Deployment Package
==========================================

Этот архив содержит все необходимое для развертывания BotTGDomains на VM без интернета.

1. Распакуйте архив:
   tar -xzf bottgdomains-offline-*.tar.gz

2. Перейдите в директорию project:
   cd bottgdomains-offline-*/project

3. Запустите скрипт развертывания:
   ./deploy.sh

Или вручную:
   docker load -i ../images/gostsslcheck.tar
   docker load -i ../images/tgscanner.tar
   docker load -i ../images/wireguard.tar
   docker-compose up -d
EOF

echo "📝 Создан README_DEPLOYMENT.txt"
echo ""

# Создаем архив
echo "🗜️  Шаг 6: Создание архива..."
cd "$EXPORT_DIR"
tar -czf "$PROJECT_ROOT/$ARCHIVE_NAME" images/ project/
ARCHIVE_SIZE=$(du -h "$PROJECT_ROOT/$ARCHIVE_NAME" | cut -f1)

echo ""
echo "✅ Архив создан: $ARCHIVE_NAME"
echo "📦 Размер архива: $ARCHIVE_SIZE"
echo ""

# Создаем checksum
echo "🔐 Шаг 7: Создание checksum..."
cd "$PROJECT_ROOT"
if command -v sha256sum &> /dev/null; then
    sha256sum "$ARCHIVE_NAME" > "$ARCHIVE_NAME.sha256"
    echo "✅ Checksum создан: $ARCHIVE_NAME.sha256"
elif command -v shasum &> /dev/null; then
    shasum -a 256 "$ARCHIVE_NAME" > "$ARCHIVE_NAME.sha256"
    echo "✅ Checksum создан: $ARCHIVE_NAME.sha256"
fi

echo ""
echo "=========================================="
echo "✅ Сборка и экспорт завершены успешно!"
echo "=========================================="