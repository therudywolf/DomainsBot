@echo off
REM Скрипт быстрого старта BotTGDomains "Под ключ" для Windows
REM Автоматически настраивает и запускает бота

echo 🚀 BotTGDomains - Быстрый старт
echo ================================
echo.

REM Проверка Docker
where docker >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Docker не установлен. Установите Docker Desktop и повторите попытку.
    exit /b 1
)

docker compose version >nul 2>&1
if %errorlevel% neq 0 (
    docker-compose version >nul 2>&1
    if %errorlevel% neq 0 (
        echo ❌ Docker Compose не установлен. Установите Docker Compose и повторите попытку.
        exit /b 1
    )
    set DOCKER_COMPOSE=docker-compose
) else (
    set DOCKER_COMPOSE=docker compose
)

echo ✅ Docker найден
echo.

REM Переход в корневую директорию проекта
cd /d "%~dp0\.."

echo 📁 Рабочая директория: %CD%
echo.

REM Создание директорий
echo 📁 Создание необходимых директорий...
if not exist "data" mkdir data
echo ✅ Директория data/ создана
echo.

REM Проверка и создание .env файла
set ENV_FILE=tg_domain_scanner_final\.env
set ENV_EXAMPLE=tg_domain_scanner_final\.env.example

if not exist "%ENV_FILE%" (
    if exist "%ENV_EXAMPLE%" (
        echo 📝 Создание файла конфигурации...
        copy "%ENV_EXAMPLE%" "%ENV_FILE%" >nul
        echo ✅ Файл .env создан из .env.example
        echo.
        echo ⚠️  ВАЖНО: Отредактируйте файл %ENV_FILE%
        echo    Укажите следующие обязательные параметры:
        echo    - TG_TOKEN=ваш_токен_от_BotFather
        echo    - ADMIN_ID=ваш_telegram_user_id
        echo.
        pause
    ) else (
        echo ❌ Ошибка: .env.example не найден
        exit /b 1
    )
) else (
    echo ✅ Файл .env найден
)

echo.

REM Остановка существующих контейнеров
echo 🛑 Остановка существующих контейнеров (если есть)...
%DOCKER_COMPOSE% down >nul 2>&1
echo ✅ Готово
echo.

REM Сборка и запуск
echo 🔨 Сборка и запуск сервисов...
echo    Это может занять несколько минут при первом запуске...
echo.

%DOCKER_COMPOSE% up -d --build

echo.
echo ⏳ Ожидание готовности сервисов...
timeout /t 10 /nobreak >nul

REM Проверка статуса
echo.
echo 📊 Статус сервисов:
%DOCKER_COMPOSE% ps

echo.
echo ✅ Бот запущен!
echo.
echo 📋 Полезные команды:
echo    Просмотр логов:     %DOCKER_COMPOSE% logs -f tgscanner
echo    Остановка:          %DOCKER_COMPOSE% down
echo    Перезапуск:         %DOCKER_COMPOSE% restart tgscanner
echo    Статус:             %DOCKER_COMPOSE% ps
echo.
echo 🎉 Готово! Отправьте /start боту в Telegram
pause
