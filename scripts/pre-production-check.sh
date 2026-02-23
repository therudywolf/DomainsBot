#!/bin/bash
# Скрипт проверки готовности к продакшену
# Использование: ./scripts/pre-production-check.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=========================================="
echo "🔍 Проверка готовности к продакшену"
echo "=========================================="
echo ""

ERRORS=0
WARNINGS=0

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Функция для вывода ошибки
error() {
    echo -e "${RED}❌ $1${NC}"
    ERRORS=$((ERRORS + 1))
}

# Функция для вывода предупреждения
warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
    WARNINGS=$((WARNINGS + 1))
}

# Функция для вывода успеха
success() {
    echo -e "${GREEN}✅ $1${NC}"
}

cd "$PROJECT_ROOT"

# 1. Проверка .env файла
echo "📋 Проверка безопасности..."
echo ""

ENV_FILE=".env"
ENV_EXAMPLE=".env.example"

# Проверка, что .env не закоммичен в git
if git ls-files | grep -q "^\.env$"; then
    error ".env файл закоммичен в git! Это критическая проблема безопасности!"
else
    success ".env файл не закоммичен в git"
fi

# Проверка истории git на наличие секретов
if git log --all --full-history -S "TG_TOKEN" --source -- "*.env" | grep -q "TG_TOKEN"; then
    warning "В истории git найдены упоминания TG_TOKEN в .env файлах. Проверьте историю коммитов."
else
    success "История git не содержит секретов в .env файлах"
fi

# Проверка наличия .env.example
if [ ! -f "$ENV_EXAMPLE" ]; then
    error ".env.example не найден"
else
    success ".env.example существует"
fi

# Проверка, что .env.example не содержит реальных токенов
if grep -q "your_telegram_bot_token_here\|your_telegram_user_id_here" "$ENV_EXAMPLE"; then
    success ".env.example содержит только примеры (без реальных токенов)"
else
    warning ".env.example может содержать реальные значения. Проверьте вручную."
fi

echo ""

# 2. Проверка зависимостей
echo "📦 Проверка зависимостей..."
echo ""

if [ ! -f "bot/requirements.txt" ]; then
    error "requirements.txt не найден"
else
    success "requirements.txt существует"
    
    # Проверка на wildcard зависимости без ограничений
    if grep -q "^[^#]*==\*$" "bot/requirements.txt"; then
        warning "Найдены зависимости с wildcard версиями без ограничений"
    else
        success "Все зависимости имеют ограничения версий"
    fi
fi

echo ""

# 3. Проверка Docker конфигурации
echo "🐳 Проверка Docker конфигурации..."
echo ""

if [ ! -f "docker-compose.yml" ]; then
    error "docker-compose.yml не найден"
else
    success "docker-compose.yml существует"
    
    # Проверка health checks
    if grep -q "healthcheck:" "docker-compose.yml"; then
        success "Health checks настроены"
    else
        warning "Health checks не найдены в docker-compose.yml"
    fi
    
    # Проверка restart policies
    if grep -q "restart:" "docker-compose.yml"; then
        success "Restart policies настроены"
    else
        warning "Restart policies не найдены"
    fi
fi

if [ ! -f "bot/Dockerfile" ]; then
    error "Dockerfile для бота не найден"
else
    success "Dockerfile для бота существует"
fi

if [ ! -f "gost/Dockerfile" ]; then
    error "Dockerfile для gost не найден"
else
    success "Dockerfile для gost существует"
fi

echo ""

# 4. Проверка скриптов развертывания
echo "🚀 Проверка скриптов развертывания..."
echo ""

if [ ! -f "scripts/deploy.sh" ]; then
    warning "scripts/deploy.sh не найден"
else
    success "scripts/deploy.sh существует"
    if [ -x "scripts/deploy.sh" ]; then
        success "scripts/deploy.sh исполняемый"
    else
        warning "scripts/deploy.sh не имеет прав на выполнение (chmod +x)"
    fi
fi

if [ -f "manage.sh" ]; then
    success "manage.sh существует"
    if [ -x "manage.sh" ]; then
        success "manage.sh исполняемый"
    else
        warning "manage.sh не имеет прав на выполнение (chmod +x)"
    fi
else
    warning "manage.sh не найден"
fi

echo ""

# 5. Проверка документации
echo "📚 Проверка документации..."
echo ""

DOCS=("README.md" "DEPLOYMENT_OFFLINE.md" "QUICKSTART.md")
for doc in "${DOCS[@]}"; do
    if [ -f "$doc" ]; then
        success "$doc существует"
    else
        warning "$doc не найден"
    fi
done

echo ""

# 6. Проверка .gitignore
echo "🔒 Проверка .gitignore..."
echo ""

if [ ! -f ".gitignore" ]; then
    error ".gitignore не найден"
else
    success ".gitignore существует"
    
    if grep -q "^\.env$" ".gitignore"; then
        success ".env в .gitignore"
    else
        error ".env не найден в .gitignore"
    fi
    
    if grep -q "^data/" ".gitignore" || grep -q "^data\*" ".gitignore"; then
        success "data/ в .gitignore"
    else
        warning "data/ может быть не в .gitignore"
    fi
fi

echo ""

# 7. Проверка наличия тестов
echo "🧪 Проверка тестов..."
echo ""

if [ -d "bot/tests" ]; then
    TEST_COUNT=$(find "bot/tests" -name "test_*.py" | wc -l)
    if [ "$TEST_COUNT" -gt 0 ]; then
        success "Найдено $TEST_COUNT тестовых файлов"
    else
        warning "Директория tests существует, но тестов не найдено"
    fi
else
    warning "Директория tests не найдена"
fi

echo ""

# Итоговый отчет
echo "=========================================="
echo "📊 Итоговый отчет"
echo "=========================================="
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✅ Все проверки пройдены успешно!${NC}"
    echo ""
    echo "Проект готов к продакшену."
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠️  Найдено предупреждений: $WARNINGS${NC}"
    echo ""
    echo "Проект готов к продакшену, но рекомендуется исправить предупреждения."
    exit 0
else
    echo -e "${RED}❌ Найдено ошибок: $ERRORS${NC}"
    if [ $WARNINGS -gt 0 ]; then
        echo -e "${YELLOW}⚠️  Найдено предупреждений: $WARNINGS${NC}"
    fi
    echo ""
    echo "Проект НЕ готов к продакшену. Исправьте ошибки перед развертыванием."
    exit 1
fi
