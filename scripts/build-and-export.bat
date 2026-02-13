@echo off
setlocal enabledelayedexpansion

REM Скрипт сборки и экспорта Docker образов для offline развертывания (Windows)
REM Использование: scripts\build-and-export.bat

set SCRIPT_DIR=%~dp0
set PROJECT_ROOT=%SCRIPT_DIR%..
cd /d "%PROJECT_ROOT%"

set EXPORT_DIR=%PROJECT_ROOT%\export
set ARCHIVE_NAME=bottgdomains-offline-%date:~-4,4%%date:~-7,2%%date:~-10,2%-%time:~0,2%%time:~3,2%%time:~6,2%.tar.gz
set ARCHIVE_NAME=%ARCHIVE_NAME: =0%

echo ==========================================
echo BotTGDomains - Offline Build ^& Export
echo ==========================================
echo.

REM Проверка наличия Docker
where docker >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker не установлен или не найден в PATH
    exit /b 1
)

REM Проверка наличия Docker Compose
docker compose version >nul 2>&1
if errorlevel 1 (
    docker-compose version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Docker Compose не установлен
        exit /b 1
    ) else (
        set DOCKER_COMPOSE=docker-compose
    )
) else (
    set DOCKER_COMPOSE=docker compose
)

echo [1/6] Сборка Docker образов...
echo.

REM Сборка всех образов
%DOCKER_COMPOSE% build --no-cache
if errorlevel 1 (
    echo [ERROR] Ошибка при сборке образов
    exit /b 1
)

echo.
echo [OK] Образы собраны успешно
echo.

REM Создаем директорию для экспорта
echo [2/6] Создание директории для экспорта...
if exist "%EXPORT_DIR%" rmdir /s /q "%EXPORT_DIR%"
mkdir "%EXPORT_DIR%"
mkdir "%EXPORT_DIR%\images"
mkdir "%EXPORT_DIR%\project"

echo [OK] Директория создана: %EXPORT_DIR%
echo.

REM Экспорт образов
echo [3/6] Экспорт Docker образов...

REM Получаем ID образа gostsslcheck
for /f "tokens=*" %%i in ('%DOCKER_COMPOSE% images -q gostsslcheck1') do set GOST_IMAGE=%%i
if "!GOST_IMAGE!"=="" (
    echo [ERROR] Образ gostsslcheck не найден
    exit /b 1
)

echo   - Экспорт образа gostsslcheck...
docker save !GOST_IMAGE! -o "%EXPORT_DIR%\images\gostsslcheck.tar"
if errorlevel 1 (
    echo [ERROR] Ошибка при экспорте gostsslcheck
    exit /b 1
)
echo     [OK] gostsslcheck.tar сохранен

REM Получаем ID образа tgscanner
for /f "tokens=*" %%i in ('%DOCKER_COMPOSE% images -q tgscanner') do set TGSCANNER_IMAGE=%%i
if "!TGSCANNER_IMAGE!"=="" (
    echo [ERROR] Образ tgscanner не найден
    exit /b 1
)

echo   - Экспорт образа tgscanner...
docker save !TGSCANNER_IMAGE! -o "%EXPORT_DIR%\images\tgscanner.tar"
if errorlevel 1 (
    echo [ERROR] Ошибка при экспорте tgscanner
    exit /b 1
)
echo     [OK] tgscanner.tar сохранен

echo.
echo [OK] Образы экспортированы
echo.

REM Копируем файлы проекта
echo [4/6] Копирование файлов проекта...

copy docker-compose.yml "%EXPORT_DIR%\project\" >nul
xcopy /E /I /Y tg_domain_scanner_final "%EXPORT_DIR%\project\tg_domain_scanner_final\" >nul
xcopy /E /I /Y GostSSLCheck "%EXPORT_DIR%\project\GostSSLCheck\" >nul
copy scripts\deploy.sh "%EXPORT_DIR%\project\" >nul

if exist "DEPLOYMENT_OFFLINE.md" copy DEPLOYMENT_OFFLINE.md "%EXPORT_DIR%\project\" >nul
if exist "README.md" copy README.md "%EXPORT_DIR%\project\" >nul
if exist "tg_domain_scanner_final\.env.example" copy tg_domain_scanner_final\.env.example "%EXPORT_DIR%\project\tg_domain_scanner_final\" >nul

REM Удаляем ненужные файлы
if exist "%EXPORT_DIR%\project\tg_domain_scanner_final\data" rmdir /s /q "%EXPORT_DIR%\project\tg_domain_scanner_final\data"
for /d /r "%EXPORT_DIR%\project" %%d in (__pycache__) do @if exist "%%d" rmdir /s /q "%%d"
for /r "%EXPORT_DIR%\project" %%f in (*.pyc) do @if exist "%%f" del /q "%%f"

echo [OK] Файлы проекта скопированы
echo.

REM Создаем README для экспорта
(
echo ==========================================
echo BotTGDomains - Offline Deployment Package
echo ==========================================
echo.
echo Этот архив содержит все необходимое для развертывания BotTGDomains на VM без интернета.
echo.
echo СОДЕРЖИМОЕ:
echo - images/          - Docker образы ^(tar файлы^)
echo - project/         - Исходный код проекта
echo - deploy.sh        - Скрипт автоматического развертывания
echo.
echo ИНСТРУКЦИЯ ПО РАЗВЕРТЫВАНИЮ:
echo.
echo 1. Распакуйте архив на целевой VM:
echo    tar -xzf bottgdomains-offline-*.tar.gz
echo.
echo 2. Перейдите в директорию проекта:
echo    cd bottgdomains-offline-*/project
echo.
echo 3. Запустите скрипт развертывания:
echo    ./deploy.sh
echo.
echo Или выполните шаги вручную:
echo.
echo 1. Загрузите Docker образы:
echo    docker load -i ../images/gostsslcheck.tar
echo    docker load -i ../images/tgscanner.tar
echo.
echo 2. Создайте файл .env:
echo    cp tg_domain_scanner_final/.env.example tg_domain_scanner_final/.env
echo    # Отредактируйте .env и укажите TG_TOKEN и ADMIN_ID
echo.
echo 3. Запустите сервисы:
echo    docker-compose up -d
echo.
echo 4. Проверьте статус:
echo    docker-compose ps
echo    docker-compose logs -f tgscanner
echo.
echo ТРЕБОВАНИЯ:
echo - Docker 20.10+
echo - Docker Compose 2.0+
echo - Linux система
echo - Минимум 5 GB свободного места на диске
echo.
echo ПОДДЕРЖКА:
echo См. DEPLOYMENT_OFFLINE.md для подробных инструкций.
) > "%EXPORT_DIR%\project\README_DEPLOYMENT.txt"

echo [5/6] Создание архива...
echo.
echo [INFO] На Windows рекомендуется использовать 7-Zip или WinRAR для создания tar.gz
echo [INFO] Или использовать WSL для создания архива:
echo        wsl tar -czf %ARCHIVE_NAME% -C %EXPORT_DIR% images/ project/
echo.
echo [INFO] Альтернативно, можно использовать PowerShell:
echo        Compress-Archive -Path %EXPORT_DIR%\images, %EXPORT_DIR%\project -DestinationPath %PROJECT_ROOT%\%ARCHIVE_NAME%
echo.

REM Проверяем наличие tar в WSL или Git Bash
where wsl >nul 2>&1
if not errorlevel 1 (
    echo [INFO] Используется WSL для создания архива...
    wsl bash -c "cd '%PROJECT_ROOT%' && tar -czf '%ARCHIVE_NAME%' -C '%EXPORT_DIR%' images/ project/"
    if not errorlevel 1 (
        echo [OK] Архив создан: %ARCHIVE_NAME%
    ) else (
        echo [WARNING] Не удалось создать архив через WSL
        echo [INFO] Создайте архив вручную из директории %EXPORT_DIR%
    )
) else (
    where tar >nul 2>&1
    if not errorlevel 1 (
        echo [INFO] Используется tar для создания архива...
        tar -czf "%PROJECT_ROOT%\%ARCHIVE_NAME%" -C "%EXPORT_DIR%" images/ project/
        if not errorlevel 1 (
            echo [OK] Архив создан: %ARCHIVE_NAME%
        ) else (
            echo [WARNING] Не удалось создать архив
            echo [INFO] Создайте архив вручную из директории %EXPORT_DIR%
        )
    ) else (
        echo [WARNING] tar не найден. Создайте архив вручную:
        echo [INFO] Используйте 7-Zip или WinRAR для создания tar.gz из %EXPORT_DIR%
    )
)

echo.
echo ==========================================
echo [OK] Сборка и экспорт завершены!
echo ==========================================
echo.
echo [INFO] Архив готов: %ARCHIVE_NAME%
echo [INFO] Расположение: %PROJECT_ROOT%
echo.
echo [INFO] Следующие шаги:
echo 1. Перенесите архив на целевую VM через SFTP
echo 2. Распакуйте архив: tar -xzf %ARCHIVE_NAME%
echo 3. Перейдите в project/ и запустите ./deploy.sh
echo.

endlocal
