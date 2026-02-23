# Быстрый старт — BotTGDomains

Руководство по развёртыванию бота на Linux, macOS и Windows.

## Требования

- **Docker** 20.10+ и **Docker Compose** 2.0+
- **Telegram Bot Token** ([@BotFather](https://t.me/BotFather))
- **Telegram User ID** ([@userinfobot](https://t.me/userinfobot))

---

## Linux / macOS

Скрипты создадут нужные папки и подскажут настройку `.env`.

```bash
git clone https://github.com/therudywolf/BotTGDomains.git
cd BotTGDomains
chmod +x manage.sh start.sh
./start.sh
# или: ./manage.sh start
```

Скрипт проверит Docker/Compose, создаст `data/` и `wg/`, скопирует `.env` из `.env.example` при отсутствии и запустит сервисы. Заполните в `.env` значения **TG_TOKEN** и **ADMIN_ID**, затем при необходимости перезапустите: `./manage.sh restart`.

Для WireGuard положите конфиг в `wg/wg0.conf` (см. [WIREGUARD_SETUP_CHECKLIST.md](WIREGUARD_SETUP_CHECKLIST.md)).

---

## Windows

В PowerShell (от имени пользователя с Docker):

```powershell
git clone https://github.com/therudywolf/BotTGDomains.git
cd BotTGDomains
.\manage.ps1 start
# или: .\start.bat
```

Скрипт создаст `data\` и `wg\`, при отсутствии скопирует `.env` из `.env.example`. Заполните в `.env` **TG_TOKEN** и **ADMIN_ID**. Конфиг WireGuard — в `wg\wg0.conf`.

---

## Ручная установка (любая ОС)

### Шаг 1: Клонирование и подготовка

```bash
git clone https://github.com/therudywolf/BotTGDomains.git
cd BotTGDomains
mkdir -p data wg
```

### Шаг 2: Настройка конфигурации

```bash
cp .env.example .env
# Отредактируйте .env (nano, vim или любой редактор)
```

**Минимально заполните:**

```env
TG_TOKEN=ваш_токен_от_BotFather
ADMIN_ID=ваш_telegram_user_id
```

**Пример:**

```env
TG_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
ADMIN_ID=6323277521
REQUEST_ACCESS_URL=https://t.me/your_username
```

### Шаг 3: Запуск

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f tgscanner
```

**Готово.** Отправьте боту в Telegram команду `/start`.

---

## Проверка работы

1. **Статус контейнеров:** `docker compose ps` — сервисы в состоянии `Up (healthy)`.
2. **Логи:** `docker compose logs tgscanner | tail -20` — должно быть сообщение о готовности бота.
3. Отправьте боту в Telegram команду `/start`.

---

## Получение данных для .env

### Telegram Bot Token

1. Откройте [@BotFather](https://t.me/BotFather).
2. Отправьте `/newbot`, укажите имя и username бота.
3. Скопируйте токен (формат: `1234567890:ABCdefGHI...`).

### Telegram User ID

1. Откройте [@userinfobot](https://t.me/userinfobot).
2. Отправьте `/start`.
3. Скопируйте показанный ID.

---

## Управление

| Действие      | Команда |
|---------------|---------|
| Остановка     | `docker compose down` |
| Перезапуск    | `docker compose restart tgscanner` или `./manage.sh restart` / `.\manage.ps1 restart` |
| Логи (бот)    | `docker compose logs -f tgscanner` |
| Логи (все)    | `docker compose logs -f` |

### Обновление

```bash
docker compose down
git pull
docker compose up -d --build
```

---

## Дополнительные настройки

Параметры в `.env`: таймауты, rate limiting, логирование. Примеры:

```env
DNS_TIMEOUT=10
HTTP_TIMEOUT=15
GOST_CHECK_TIMEOUT=30
RATE_LIMIT_REQUESTS=60
RATE_LIMIT_WINDOW=60
LOG_LEVEL=DEBUG
```

---

## Решение проблем

- **Бот не запускается:** проверьте логи `docker compose logs tgscanner`, убедитесь, что в `.env` заданы `TG_TOKEN` и `ADMIN_ID` (токен в формате `число:строка`).
- **GOST не работает:** `docker compose ps`, логи gostsslcheck1/2/3, все контейнеры должны быть healthy.
- **«ADMIN_ID не задан»:** укажите в `.env` значение `ADMIN_ID=ваш_id`.

---

## Документация

- [../README.md](../README.md) — обзор проекта
- [DEPLOYMENT.md](DEPLOYMENT.md) — развёртывание
- [API.md](API.md) — API и команды
- [DEPLOYMENT_OFFLINE.md](DEPLOYMENT_OFFLINE.md) — офлайн-деплой
- [WIREGUARD_SETUP_CHECKLIST.md](WIREGUARD_SETUP_CHECKLIST.md) — настройка WireGuard
