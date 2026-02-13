# Руководство по offline развертыванию BotTGDomains

Это руководство описывает процесс развертывания BotTGDomains на виртуальной машине (VM) без доступа к интернету.

## Обзор процесса

Процесс состоит из двух этапов:

1. **Сборка и экспорт** (на машине с интернетом)
   - Сборка Docker образов
   - Экспорт образов в архив
   - Упаковка всего проекта в один архив

2. **Развертывание** (на целевой VM без интернета)
   - Перенос архива через SFTP
   - Распаковка архива
   - Загрузка Docker образов
   - Запуск сервисов

## Требования

### Для сборки (машина с интернетом)

- Docker 20.10+
- Docker Compose 2.0+
- Linux/Mac/Windows с поддержкой Docker
- Минимум 10 GB свободного места на диске
- Доступ к интернету для скачивания базовых образов

### Для развертывания (целевая VM)

- Linux система (Ubuntu 20.04+, Debian 11+, или аналогичная)
- Docker 20.10+
- Docker Compose 2.0+
- Минимум 5 GB свободного места на диске
- Доступ к SFTP для переноса архива

## Этап 1: Сборка и экспорт

### Linux/Mac

1. **Клонируйте репозиторий** (если еще не сделано):

```bash
git clone <repository_url>
cd BotTGDomains
```

2. **Сделайте скрипт исполняемым**:

```bash
chmod +x scripts/build-and-export.sh
```

3. **Запустите скрипт сборки**:

```bash
./scripts/build-and-export.sh
```

Скрипт выполнит следующие действия:
- Соберет все Docker образы
- Экспортирует образы в tar файлы
- Упакует все в архив `bottgdomains-offline-YYYYMMDD-HHMMSS.tar.gz`
- Создаст checksum файл для проверки целостности

4. **Проверьте результат**:

```bash
ls -lh bottgdomains-offline-*.tar.gz
sha256sum -c bottgdomains-offline-*.sha256  # Проверка целостности
```

### Windows

1. **Откройте командную строку или PowerShell** в директории проекта

2. **Запустите скрипт сборки**:

```cmd
scripts\build-and-export.bat
```

**Примечание:** На Windows скрипт может использовать WSL или Git Bash для создания tar.gz архива. Если эти инструменты недоступны, создайте архив вручную из директории `export/` используя 7-Zip или WinRAR.

3. **Альтернативный способ (PowerShell)**:

```powershell
# После выполнения build-and-export.bat
Compress-Archive -Path export\images, export\project -DestinationPath bottgdomains-offline.zip
```

Затем переименуйте `.zip` в `.tar.gz` или используйте 7-Zip для конвертации.

### Структура созданного архива

```
bottgdomains-offline-YYYYMMDD-HHMMSS.tar.gz
├── images/
│   ├── gostsslcheck.tar      # Docker образ для GOST проверки
│   └── tgscanner.tar         # Docker образ бота
└── project/
    ├── docker-compose.yml
    ├── deploy.sh             # Скрипт автоматического развертывания
    ├── README_DEPLOYMENT.txt
    ├── tg_domain_scanner_final/
    │   ├── .env.example
    │   └── ... (весь код проекта)
    └── GostSSLCheck/
        └── ... (код сервиса GOST)
```

## Этап 2: Перенос на целевую VM

### Через SFTP

1. **Подключитесь к целевой VM через SFTP**:

```bash
sftp user@target-vm-ip
```

2. **Перейдите в нужную директорию**:

```bash
cd /opt  # или другую директорию по вашему выбору
```

3. **Загрузите архив**:

```bash
put bottgdomains-offline-*.tar.gz
put bottgdomains-offline-*.sha256  # Если есть
```

4. **Выйдите из SFTP**:

```bash
exit
```

### Альтернативные способы переноса

- **SCP**:
```bash
scp bottgdomains-offline-*.tar.gz user@target-vm-ip:/opt/
```

- **USB/внешний диск**: Скопируйте архив на внешний носитель и перенесите физически

- **Локальная сеть**: Если VM доступна по локальной сети, используйте сетевые протоколы

## Этап 3: Развертывание на целевой VM

### Автоматическое развертывание (рекомендуется)

1. **Подключитесь к целевой VM**:

```bash
ssh user@target-vm-ip
```

2. **Перейдите в директорию с архивом**:

```bash
cd /opt  # или туда, куда вы загрузили архив
```

3. **Распакуйте архив**:

```bash
tar -xzf bottgdomains-offline-*.tar.gz
```

4. **Перейдите в директорию проекта**:

```bash
cd bottgdomains-offline-*/project
```

5. **Сделайте скрипт развертывания исполняемым**:

```bash
chmod +x deploy.sh
```

6. **Запустите скрипт развертывания**:

```bash
./deploy.sh
```

Скрипт автоматически:
- Проверит наличие Docker и Docker Compose
- Загрузит Docker образы
- Создаст необходимые директории
- Настроит конфигурацию (.env)
- Запустит все сервисы
- Проверит статус развертывания

### Ручное развертывание

Если автоматический скрипт не подходит, выполните шаги вручную:

1. **Распакуйте архив**:

```bash
tar -xzf bottgdomains-offline-*.tar.gz
cd bottgdomains-offline-*/project
```

2. **Загрузите Docker образы**:

```bash
docker load -i ../images/gostsslcheck.tar
docker load -i ../images/tgscanner.tar
```

3. **Создайте файл конфигурации**:

```bash
cp tg_domain_scanner_final/.env.example tg_domain_scanner_final/.env
nano tg_domain_scanner_final/.env  # или используйте другой редактор
```

**Обязательно укажите:**
- `TG_TOKEN` - токен бота от BotFather
- `ADMIN_ID` - ваш Telegram User ID

4. **Создайте директорию для данных**:

```bash
mkdir -p tg_domain_scanner_final/data
```

5. **Запустите сервисы**:

```bash
docker-compose up -d
```

6. **Проверьте статус**:

```bash
docker-compose ps
docker-compose logs -f tgscanner
```

## Проверка развертывания

### Проверка статуса сервисов

```bash
docker-compose ps
```

Все сервисы должны быть в состоянии `Up (healthy)`.

### Просмотр логов

```bash
# Логи бота
docker-compose logs -f tgscanner

# Логи GOST сервисов
docker-compose logs -f gostsslcheck1

# Все логи
docker-compose logs -f
```

### Проверка доступности бота

1. Откройте Telegram
2. Найдите вашего бота по имени
3. Отправьте команду `/start`
4. Бот должен ответить

## Управление сервисами

### Остановка

```bash
docker-compose down
```

### Перезапуск

```bash
docker-compose restart
```

### Обновление (после переноса нового архива)

1. Остановите текущие сервисы:
```bash
docker-compose down
```

2. Загрузите новые образы:
```bash
docker load -i ../images/gostsslcheck.tar
docker load -i ../images/tgscanner.tar
```

3. Запустите сервисы:
```bash
docker-compose up -d
```

## Troubleshooting

### Проблема: Docker образы не загружаются

**Решение:**
- Проверьте целостность tar файлов: `file images/*.tar`
- Убедитесь, что достаточно места на диске: `df -h`
- Проверьте права доступа: `ls -l images/`

### Проблема: Сервисы не запускаются

**Решение:**
1. Проверьте логи: `docker-compose logs`
2. Проверьте конфигурацию: `cat tg_domain_scanner_final/.env`
3. Убедитесь, что порты свободны: `netstat -tulpn | grep -E '8081|8082|8083'`

### Проблема: Health checks не проходят

**Решение:**
- Подождите 30-60 секунд (health checks могут занять время)
- Проверьте логи GOST сервисов: `docker-compose logs gostsslcheck1`
- Убедитесь, что базовый образ `rnix/openssl-gost:latest` загружен

### Проблема: Бот не отвечает в Telegram

**Решение:**
1. Проверьте токен в `.env`: `grep TG_TOKEN tg_domain_scanner_final/.env`
2. Проверьте логи бота: `docker-compose logs tgscanner`
3. Убедитесь, что бот запущен: `docker-compose ps tgscanner`

### Проблема: Недостаточно места на диске

**Решение:**
- Очистите неиспользуемые Docker образы: `docker system prune -a`
- Удалите старые логи: `docker-compose logs --tail=0`
- Освободите место на диске

## Размер архива

Ожидаемый размер архива: **2-5 GB** (зависит от размера базовых образов)

- gostsslcheck.tar: ~500 MB - 1 GB
- tgscanner.tar: ~500 MB - 1 GB
- Код проекта: ~10-50 MB

## Безопасность

### Рекомендации

1. **Не включайте .env файл в архив** - создавайте его на целевой VM
2. **Используйте SFTP с шифрованием** для переноса архива
3. **Проверяйте checksum** архива перед развертыванием
4. **Ограничьте доступ** к директории проекта на целевой VM
5. **Регулярно обновляйте** Docker образы для безопасности

### Проверка целостности архива

```bash
# На машине сборки
sha256sum bottgdomains-offline-*.tar.gz > archive.sha256

# На целевой VM
sha256sum -c archive.sha256
```

## Дополнительная информация

- Полная документация: `docs/DEPLOYMENT.md`
- Архитектура системы: `docs/ARCHITECTURE.md`
- API документация: `docs/API.md`

## Поддержка

При возникновении проблем:
1. Проверьте логи: `docker-compose logs`
2. Проверьте статус: `docker-compose ps`
3. Обратитесь к документации в `docs/`
4. Проверьте issues в репозитории проекта
