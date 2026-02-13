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

echo "📦 Шаг 1: Сборка Docker образов..."
echo ""

# Сборка всех образов
$DOCKER_COMPOSE build --no-cache

echo ""
echo "✅ Образы собраны успешно"
echo ""

# Создаем директорию для экспорта
echo "📁 Шаг 2: Создание директории для экспорта..."
rm -rf "$EXPORT_DIR"
mkdir -p "$EXPORT_DIR/images"
mkdir -p "$EXPORT_DIR/project"

echo "✅ Директория создана: $EXPORT_DIR"
echo ""

# Получаем имена образов из docker-compose
echo "💾 Шаг 3: Экспорт Docker образов..."

# Получаем имя проекта из docker-compose
PROJECT_NAME=$(basename "$PROJECT_ROOT" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')

# Экспортируем образы
echo "  - Экспорт образа gostsslcheck..."
GOST_IMAGE="$($DOCKER_COMPOSE images -q gostsslcheck1 | head -1)"
if [ -z "$GOST_IMAGE" ]; then
    echo "❌ Ошибка: Образ gostsslcheck не найден"
    exit 1
fi
docker save "$GOST_IMAGE" -o "$EXPORT_DIR/images/gostsslcheck.tar"
echo "    ✅ gostsslcheck.tar сохранен"

echo "  - Экспорт образа tgscanner..."
TGSCANNER_IMAGE="$($DOCKER_COMPOSE images -q tgscanner | head -1)"
if [ -z "$TGSCANNER_IMAGE" ]; then
    echo "❌ Ошибка: Образ tgscanner не найден"
    exit 1
fi
docker save "$TGSCANNER_IMAGE" -o "$EXPORT_DIR/images/tgscanner.tar"
echo "    ✅ tgscanner.tar сохранен"

# Проверяем размеры файлов
GOST_SIZE=$(du -h "$EXPORT_DIR/images/gostsslcheck.tar" | cut -f1)
TGSCANNER_SIZE=$(du -h "$EXPORT_DIR/images/tgscanner.tar" | cut -f1)

echo ""
echo "📊 Размеры экспортированных образов:"
echo "  - gostsslcheck.tar: $GOST_SIZE"
echo "  - tgscanner.tar: $TGSCANNER_SIZE"
echo ""

# Копируем файлы проекта
echo "📋 Шаг 4: Копирование файлов проекта..."

# Копируем основные файлы и директории
cp docker-compose.yml "$EXPORT_DIR/project/"
cp -r tg_domain_scanner_final "$EXPORT_DIR/project/"
cp -r GostSSLCheck "$EXPORT_DIR/project/"

# Копируем скрипт развертывания
cp scripts/deploy.sh "$EXPORT_DIR/project/"
chmod +x "$EXPORT_DIR/project/deploy.sh"

# Копируем документацию
if [ -f "DEPLOYMENT_OFFLINE.md" ]; then
    cp DEPLOYMENT_OFFLINE.md "$EXPORT_DIR/project/"
fi
if [ -f "README.md" ]; then
    cp README.md "$EXPORT_DIR/project/"
fi

# Копируем .env.example если есть
if [ -f "tg_domain_scanner_final/.env.example" ]; then
    cp tg_domain_scanner_final/.env.example "$EXPORT_DIR/project/tg_domain_scanner_final/"
fi

# Исключаем ненужные файлы
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

СОДЕРЖИМОЕ:
- images/          - Docker образы (tar файлы)
- project/         - Исходный код проекта
- deploy.sh        - Скрипт автоматического развертывания

ИНСТРУКЦИЯ ПО РАЗВЕРТЫВАНИЮ:

1. Распакуйте архив на целевой VM:
   tar -xzf bottgdomains-offline-*.tar.gz

2. Перейдите в директорию проекта:
   cd bottgdomains-offline-*/project

3. Запустите скрипт развертывания:
   ./deploy.sh

Или выполните шаги вручную:

1. Загрузите Docker образы:
   docker load -i ../images/gostsslcheck.tar
   docker load -i ../images/tgscanner.tar

2. Создайте файл .env:
   cp tg_domain_scanner_final/.env.example tg_domain_scanner_final/.env
   # Отредактируйте .env и укажите TG_TOKEN и ADMIN_ID

3. Запустите сервисы:
   docker-compose up -d

4. Проверьте статус:
   docker-compose ps
   docker-compose logs -f tgscanner

ТРЕБОВАНИЯ:
- Docker 20.10+
- Docker Compose 2.0+
- Linux система
- Минимум 5 GB свободного места на диске

ПОДДЕРЖКА:
См. DEPLOYMENT_OFFLINE.md для подробных инструкций.
EOF

echo "📝 Создан README_DEPLOYMENT.txt"
echo ""

# Создаем архив
echo "🗜️  Шаг 5: Создание архива..."
cd "$EXPORT_DIR"
tar -czf "$PROJECT_ROOT/$ARCHIVE_NAME" images/ project/

# Проверяем размер архива
ARCHIVE_SIZE=$(du -h "$PROJECT_ROOT/$ARCHIVE_NAME" | cut -f1)

echo ""
echo "✅ Архив создан: $ARCHIVE_NAME"
echo "📦 Размер архива: $ARCHIVE_SIZE"
echo ""

# Создаем checksum
echo "🔐 Шаг 6: Создание checksum..."
cd "$PROJECT_ROOT"
if command -v sha256sum &> /dev/null; then
    sha256sum "$ARCHIVE_NAME" > "$ARCHIVE_NAME.sha256"
    echo "✅ Checksum создан: $ARCHIVE_NAME.sha256"
elif command -v shasum &> /dev/null; then
    shasum -a 256 "$ARCHIVE_NAME" > "$ARCHIVE_NAME.sha256"
    echo "✅ Checksum создан: $ARCHIVE_NAME.sha256"
else
    echo "⚠️  Предупреждение: Не удалось создать checksum (sha256sum/shasum не найден)"
fi

echo ""
echo "=========================================="
echo "✅ Сборка и экспорт завершены успешно!"
echo "=========================================="
echo ""
echo "📦 Архив готов: $ARCHIVE_NAME"
echo "📁 Расположение: $PROJECT_ROOT"
echo ""
echo "📋 Следующие шаги:"
echo "1. Перенесите архив на целевую VM через SFTP"
echo "2. Распакуйте архив: tar -xzf $ARCHIVE_NAME"
echo "3. Перейдите в project/ и запустите ./deploy.sh"
echo ""
echo "💡 Для проверки целостности архива:"
if [ -f "$ARCHIVE_NAME.sha256" ]; then
    echo "   sha256sum -c $ARCHIVE_NAME.sha256"
fi
echo ""
