@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

REM Скрипт сборки и экспорта Docker образов для offline развертывания (Windows)
REM Использование: scripts\build-and-export.bat

set SCRIPT_DIR=%~dp0
REM Убираем завершающий слэш если есть
set SCRIPT_DIR=%SCRIPT_DIR:~0,-1%
set PROJECT_ROOT=%SCRIPT_DIR%\..
cd /d "%PROJECT_ROOT%"

REM Проверяем, что мы в правильной директории
if not exist "docker-compose.yml" (
    echo [ERROR] Не удалось найти docker-compose.yml
    echo [INFO] Текущая директория: %CD%
    echo [INFO] Ожидаемая директория: %PROJECT_ROOT%
    pause
    exit /b 1
)

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
echo [INFO] Текущая рабочая директория: %CD%
echo [INFO] Директория экспорта: %EXPORT_DIR%
echo.

REM Экспорт образов
echo [3/6] Экспорт Docker образов...

REM Получаем имя образа gostsslcheck
REM Docker Compose создает образы с именем проекта-сервис:latest
echo   - Поиск образа gostsslcheck...
set GOST_IMAGE=
REM Используем docker images с фильтром и берем первый результат
REM Создаем временный файл для надежного парсинга
echo [DEBUG] Выполняем: docker images bottgdomains-gostsslcheck* --format "{{.Repository}}:{{.Tag}}"
docker images bottgdomains-gostsslcheck* --format "{{.Repository}}:{{.Tag}}" > "%TEMP%\gost_images.txt" 2>&1
if exist "%TEMP%\gost_images.txt" (
    echo [DEBUG] Временный файл создан, размер:
    for %%F in ("%TEMP%\gost_images.txt") do echo   %%F - %%~zF байт
    echo [DEBUG] Содержимое файла:
    type "%TEMP%\gost_images.txt"
    for /f "usebackq tokens=*" %%i in ("%TEMP%\gost_images.txt") do (
        if "!GOST_IMAGE!"=="" (
            set GOST_IMAGE=%%i
            echo     [INFO] Найден образ: !GOST_IMAGE!
            goto :found_gost
        )
    )
    del "%TEMP%\gost_images.txt" >nul 2>&1
) else (
    echo [WARNING] Временный файл не создан, пробуем альтернативный способ...
    REM Альтернативный способ - через docker images без форматирования
    for /f "tokens=1,2" %%a in ('docker images bottgdomains-gostsslcheck* 2^>nul ^| findstr /V "REPOSITORY" ^| findstr /V "IMAGE"') do (
        if "!GOST_IMAGE!"=="" (
            if not "%%a"=="" (
                set GOST_IMAGE=%%a:%%b
                echo     [INFO] Найден образ (альтернативный способ): !GOST_IMAGE!
                goto :found_gost
            )
        )
    )
)
:found_gost

if "!GOST_IMAGE!"=="" (
    echo [ERROR] Образ gostsslcheck не найден
    echo [INFO] Доступные образы:
    docker images | findstr /C:"gostsslcheck" || echo   (нет образов gostsslcheck)
    pause
    exit /b 1
)

echo   - Экспорт образа gostsslcheck (!GOST_IMAGE!)...
docker save !GOST_IMAGE! -o "%EXPORT_DIR%\images\gostsslcheck.tar"
if errorlevel 1 (
    echo [ERROR] Ошибка при экспорте gostsslcheck
    echo [INFO] Образ: !GOST_IMAGE!
    echo [INFO] Попробуйте экспортировать вручную: docker save !GOST_IMAGE! -o "%EXPORT_DIR%\images\gostsslcheck.tar"
    pause
    exit /b 1
)
if exist "%EXPORT_DIR%\images\gostsslcheck.tar" (
    for %%F in ("%EXPORT_DIR%\images\gostsslcheck.tar") do set GOST_SIZE=%%~zF
    if !GOST_SIZE! LSS 1000 (
        echo     [ERROR] Файл gostsslcheck.tar слишком маленький (!GOST_SIZE! байт)
        pause
        exit /b 1
    )
    echo     [OK] gostsslcheck.tar сохранен (размер: !GOST_SIZE! байт)
) else (
    echo     [ERROR] Файл gostsslcheck.tar не создан!
    pause
    exit /b 1
)

REM Получаем имя образа tgscanner
echo   - Поиск образа tgscanner...
set TGSCANNER_IMAGE=
REM Используем docker images с фильтром и берем первый результат
REM Создаем временный файл для надежного парсинга
echo [DEBUG] Выполняем: docker images bottgdomains-tgscanner* --format "{{.Repository}}:{{.Tag}}"
docker images bottgdomains-tgscanner* --format "{{.Repository}}:{{.Tag}}" > "%TEMP%\tgscanner_images.txt" 2>&1
if exist "%TEMP%\tgscanner_images.txt" (
    echo [DEBUG] Временный файл создан, размер:
    for %%F in ("%TEMP%\tgscanner_images.txt") do echo   %%F - %%~zF байт
    echo [DEBUG] Содержимое файла:
    type "%TEMP%\tgscanner_images.txt"
    for /f "usebackq tokens=*" %%i in ("%TEMP%\tgscanner_images.txt") do (
        if "!TGSCANNER_IMAGE!"=="" (
            set TGSCANNER_IMAGE=%%i
            echo     [INFO] Найден образ: !TGSCANNER_IMAGE!
            goto :found_tgscanner
        )
    )
    del "%TEMP%\tgscanner_images.txt" >nul 2>&1
) else (
    echo [WARNING] Временный файл не создан, пробуем альтернативный способ...
    REM Альтернативный способ - через docker images без форматирования
    for /f "tokens=1,2" %%a in ('docker images bottgdomains-tgscanner* 2^>nul ^| findstr /V "REPOSITORY" ^| findstr /V "IMAGE"') do (
        if "!TGSCANNER_IMAGE!"=="" (
            if not "%%a"=="" (
                set TGSCANNER_IMAGE=%%a:%%b
                echo     [INFO] Найден образ (альтернативный способ): !TGSCANNER_IMAGE!
                goto :found_tgscanner
            )
        )
    )
)
:found_tgscanner

if "!TGSCANNER_IMAGE!"=="" (
    echo [ERROR] Образ tgscanner не найден
    echo [INFO] Доступные образы:
    docker images | findstr /C:"tgscanner" || echo   (нет образов tgscanner)
    pause
    exit /b 1
)

echo   - Экспорт образа tgscanner (!TGSCANNER_IMAGE!)...
docker save !TGSCANNER_IMAGE! -o "%EXPORT_DIR%\images\tgscanner.tar"
if errorlevel 1 (
    echo [ERROR] Ошибка при экспорте tgscanner
    echo [INFO] Образ: !TGSCANNER_IMAGE!
    echo [INFO] Попробуйте экспортировать вручную: docker save !TGSCANNER_IMAGE! -o "%EXPORT_DIR%\images\tgscanner.tar"
    pause
    exit /b 1
)
if exist "%EXPORT_DIR%\images\tgscanner.tar" (
    for %%F in ("%EXPORT_DIR%\images\tgscanner.tar") do set TGSCANNER_SIZE=%%~zF
    if !TGSCANNER_SIZE! LSS 1000 (
        echo     [ERROR] Файл tgscanner.tar слишком маленький (!TGSCANNER_SIZE! байт)
        pause
        exit /b 1
    )
    echo     [OK] tgscanner.tar сохранен (размер: !TGSCANNER_SIZE! байт)
) else (
    echo     [ERROR] Файл tgscanner.tar не создан!
    pause
    exit /b 1
)

echo.
echo [OK] Образы экспортированы
echo.

REM Копируем файлы проекта
echo [4/6] Копирование файлов проекта...
echo.

REM Проверяем наличие исходных файлов
if not exist "docker-compose.yml" (
    echo [ERROR] docker-compose.yml не найден в %PROJECT_ROOT%
    pause
    exit /b 1
)

if not exist "tg_domain_scanner_final" (
    echo [ERROR] Директория tg_domain_scanner_final не найдена в %PROJECT_ROOT%
    pause
    exit /b 1
)

if not exist "GostSSLCheck" (
    echo [ERROR] Директория GostSSLCheck не найдена в %PROJECT_ROOT%
    pause
    exit /b 1
)

echo   - Копирование docker-compose.yml...
copy docker-compose.yml "%EXPORT_DIR%\project\"
if errorlevel 1 (
    echo [ERROR] Ошибка при копировании docker-compose.yml
    pause
    exit /b 1
)
echo     [OK] docker-compose.yml скопирован

echo   - Копирование tg_domain_scanner_final...
echo [DEBUG] Исходная директория: %CD%\tg_domain_scanner_final
echo [DEBUG] Целевая директория: %EXPORT_DIR%\project\tg_domain_scanner_final
xcopy /E /I /Y /H tg_domain_scanner_final "%EXPORT_DIR%\project\tg_domain_scanner_final\"
if errorlevel 1 (
    echo [ERROR] Ошибка при копировании tg_domain_scanner_final (код ошибки: %ERRORLEVEL%)
    echo [INFO] Попытка альтернативного копирования через robocopy...
    robocopy tg_domain_scanner_final "%EXPORT_DIR%\project\tg_domain_scanner_final" /E /NFL /NDL /NJH /NJS
    if errorlevel 8 (
        echo [ERROR] Не удалось скопировать tg_domain_scanner_final (robocopy код: %ERRORLEVEL%)
        echo [DEBUG] Проверка существования исходной директории:
        dir tg_domain_scanner_final 2>&1
        echo [DEBUG] Проверка существования целевой директории:
        dir "%EXPORT_DIR%\project\" 2>&1
        pause
        exit /b 1
    )
)
REM Проверяем что файлы скопировались
if exist "%EXPORT_DIR%\project\tg_domain_scanner_final\bot.py" (
    echo     [OK] tg_domain_scanner_final скопирован (проверен bot.py)
    echo [DEBUG] Проверка количества скопированных файлов:
    dir /s /b "%EXPORT_DIR%\project\tg_domain_scanner_final\*.py" | find /c ".py"
) else (
    echo     [ERROR] bot.py не найден в скопированной директории!
    echo [DEBUG] Содержимое целевой директории:
    dir "%EXPORT_DIR%\project\tg_domain_scanner_final\" 2>&1
    pause
    exit /b 1
)

echo   - Копирование GostSSLCheck...
echo [DEBUG] Исходная директория: %CD%\GostSSLCheck
echo [DEBUG] Целевая директория: %EXPORT_DIR%\project\GostSSLCheck
xcopy /E /I /Y /H GostSSLCheck "%EXPORT_DIR%\project\GostSSLCheck\"
if errorlevel 1 (
    echo [ERROR] Ошибка при копировании GostSSLCheck (код ошибки: %ERRORLEVEL%)
    echo [INFO] Попытка альтернативного копирования через robocopy...
    robocopy GostSSLCheck "%EXPORT_DIR%\project\GostSSLCheck" /E /NFL /NDL /NJH /NJS
    if errorlevel 8 (
        echo [ERROR] Не удалось скопировать GostSSLCheck (robocopy код: %ERRORLEVEL%)
        echo [DEBUG] Проверка существования исходной директории:
        dir GostSSLCheck 2>&1
        echo [DEBUG] Проверка существования целевой директории:
        dir "%EXPORT_DIR%\project\" 2>&1
        pause
        exit /b 1
    )
)
REM Проверяем что файлы скопировались
if exist "%EXPORT_DIR%\project\GostSSLCheck\server.py" (
    echo     [OK] GostSSLCheck скопирован (проверен server.py)
    echo [DEBUG] Проверка количества скопированных файлов:
    dir /s /b "%EXPORT_DIR%\project\GostSSLCheck\*.py" | find /c ".py"
) else (
    echo     [ERROR] server.py не найден в скопированной директории!
    echo [DEBUG] Содержимое целевой директории:
    dir "%EXPORT_DIR%\project\GostSSLCheck\" 2>&1
    pause
    exit /b 1
)

echo   - Копирование deploy.sh...
if exist "scripts\deploy.sh" (
    copy scripts\deploy.sh "%EXPORT_DIR%\project\"
    if errorlevel 1 (
        echo [WARNING] Не удалось скопировать deploy.sh
    ) else (
        echo     [OK] deploy.sh скопирован
    )
) else (
    echo     [WARNING] scripts\deploy.sh не найден
)

if exist "DEPLOYMENT_OFFLINE.md" (
    echo   - Копирование DEPLOYMENT_OFFLINE.md...
    copy DEPLOYMENT_OFFLINE.md "%EXPORT_DIR%\project\"
    if errorlevel 1 (
        echo     [WARNING] Не удалось скопировать DEPLOYMENT_OFFLINE.md
    ) else (
        echo     [OK] DEPLOYMENT_OFFLINE.md скопирован
    )
)

if exist "README.md" (
    echo   - Копирование README.md...
    copy README.md "%EXPORT_DIR%\project\"
    if errorlevel 1 (
        echo     [WARNING] Не удалось скопировать README.md
    ) else (
        echo     [OK] README.md скопирован
    )
)

if exist "tg_domain_scanner_final\.env.example" (
    echo   - Копирование .env.example...
    copy tg_domain_scanner_final\.env.example "%EXPORT_DIR%\project\tg_domain_scanner_final\"
    if errorlevel 1 (
        echo     [WARNING] Не удалось скопировать .env.example
    ) else (
        echo     [OK] .env.example скопирован
    )
)

REM Удаляем ненужные файлы
echo   - Очистка ненужных файлов...
if exist "%EXPORT_DIR%\project\tg_domain_scanner_final\data" (
    rmdir /s /q "%EXPORT_DIR%\project\tg_domain_scanner_final\data" 2>nul
    echo     [OK] Удалена директория data/
)

REM Удаляем __pycache__
for /d /r "%EXPORT_DIR%\project" %%d in (__pycache__) do @if exist "%%d" (
    rmdir /s /q "%%d" 2>nul
)
echo     [OK] Удалены __pycache__ директории

REM Удаляем .pyc файлы
for /r "%EXPORT_DIR%\project" %%f in (*.pyc) do @if exist "%%f" del /q "%%f" 2>nul
echo     [OK] Удалены .pyc файлы

echo.
echo [OK] Файлы проекта скопированы

REM Проверяем, что файлы действительно скопировались
echo.
echo [INFO] Проверка скопированных файлов...
if exist "%EXPORT_DIR%\project\docker-compose.yml" (
    echo   [OK] docker-compose.yml найден
) else (
    echo   [ERROR] docker-compose.yml НЕ найден в экспорте!
)

if exist "%EXPORT_DIR%\project\tg_domain_scanner_final" (
    echo   [OK] tg_domain_scanner_final найден
) else (
    echo   [ERROR] tg_domain_scanner_final НЕ найден в экспорте!
)

if exist "%EXPORT_DIR%\project\GostSSLCheck" (
    echo   [OK] GostSSLCheck найден
) else (
    echo   [ERROR] GostSSLCheck НЕ найден в экспорте!
)

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
echo [INFO] Проверка содержимого export директории:
if exist "%EXPORT_DIR%\images" (
    echo   [OK] Директория images/ существует
    dir /b "%EXPORT_DIR%\images" 2>nul
) else (
    echo   [ERROR] Директория images/ не найдена!
)

if exist "%EXPORT_DIR%\project" (
    echo   [OK] Директория project/ существует
    echo   [INFO] Содержимое project/:
    dir /b "%EXPORT_DIR%\project" 2>nul
) else (
    echo   [ERROR] Директория project/ не найдена!
)
echo.

pause
endlocal
