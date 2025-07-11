# BotTGDomains – Domain Scanner Telegram Bot

![Python](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Telegram‑бот, который принимает списки доменов и возвращает отчёт со следующими характеристиками:

| Блок       | Что включено                                          |
| ---------- | ----------------------------------------------------- |
| **DNS**    | A, AAAA, MX, NS                                       |
| **SSL**    | CN, срок действия сертификата, поддержка ГОСТ‑шифров  |
| **WAF**    | Простая проверка Cloudflare / ddos‑guard и пр.        |
| **Режимы** | 🔎 «Расширенный» (все поля) / 📄 «Короткий» (без DNS) |

## Быстрый старт

```bash
git clone <repo>
cd BotTGDomains
cp .env.example .env         # Проставьте TG_TOKEN
docker compose up --build -d
```

> `docker compose` поднимет сам бот и контейнер проверочного сервиса `gostsslcheck`.

## Архитектура

```
.
├── bot/                     # entry‑point Telegram‑логика
│   └── main.py
├── tg_domain_scanner/       # пакет с бизнес‑логикой
│   ├── utils/
│   │   ├── cache.py         # persistent TTL‑cache (6 h)
│   │   ├── prefs.py         # shelve хранилище настроек пользователей
│   │   └── ...
│   └── services/            # DSL, SSL, WAF helpers
├── docker-compose.yml
└── README.md
```

## Ключевые особенности / оптимизация

- **Persistent cache** – ответы хранятся 6 ч на диске (`domain_cache.db`), переживают рестарты.
- **Память режима** – выбор «Короткий/Расширенный» пишется в `user_prefs.db`.
- **Flood‑control** – прогресс‑бар редактируется не чаще 1 раза/3 с; Telegram API‑лимиты не выбиваются.
- **Оптимизация** – весь I/O асинхронный, `uvloop` используется автоматически, если установлен.
- **Докер** – минимальный образ `python:3.12-slim`, сборка кэширующая.

## Переменные окружения (.env)

| Переменная | Описание            | Значение по‑умолчанию |
| ---------- | ------------------- | --------------------- |
| `TG_TOKEN` | токен Telegram‑бота | —                     |

## Автор

RudyWolf
