# 🔎 BotTGDomains — Telegram-бот для анализа доменов

![Python](https://img.shields.io/badge/python-3.12-blue)
![License](https://img.shields.io/badge/license-MIT-green)

> Telegram-бот, который принимает списки доменов и возвращает отчёт со следующими характеристиками:

| Блок       | Что включено                                           |
| ---------- | ------------------------------------------------------ |
| **DNS**    | A, AAAA, MX, NS                                        |
| **SSL**    | CN, срок действия сертификата, поддержка ГОСТ-шифров   |
| **WAF**    | Простая проверка Cloudflare / ddos-guard и пр.         |
| **Режимы** | 🔎 «Расширенный» (all fields) / 📄 «Короткий» (no DNS) |

## ⚡️ Быстрый старт

```bash
git clone https://github.com/therudywolf/BotTGDomains.git
cd BotTGDomains
cp .env.example .env         # Проставьте TG_TOKEN
docker compose up --build -d
```

> `docker compose` поднимет сам бот и контейнер проверочного сервиса `gostsslcheck`.

## 🛋️ Архитектура

```
.
├── bot/                     # entry-point Telegram-логика
│   └── main.py
├── tg_domain_scanner/       # пакет с бизнес-логикой
│   ├── utils/
│   │   ├── cache.py         # persistent TTL-cache (6h)
│   │   ├── prefs.py         # shelve-хранилка настроек
│   │   └── ...
│   └── services/        # DNS, SSL, WAF helpers
├── docker-compose.yml
└── README.md
```

## 🔹 Особенности

- **Кэш на диске** — `domain_cache.db` хранит ответы 6 часов и переживает рестарты.
- **Фиксация выбора** — режим отчётов (короткий/расширенный) сохраняется в `user_prefs.db`.
- **Flood control** — Telegram-обновление бара не чаще 1 раза в 3 секунды.
- **Асинхронность** — весь I/O работает на `asyncio`, `uvloop` подхвачивается автоматом.
- **Docker-friendly** — легкий образ `python:3.12-slim`, сборка с кэшем.

## 🏦 .env переменные

| Переменная | Описание            | По-умолчанию |
| ---------- | ------------------- | ------------ |
| `TG_TOKEN` | Токен Telegram-бота | —            |

## 🕊️ Автор

[therudywolf](https://github.com/therudywolf)

По всем вопросам или идеям: issue, pull request, или личка в Telegram.

> Вой-вой! 🪶
