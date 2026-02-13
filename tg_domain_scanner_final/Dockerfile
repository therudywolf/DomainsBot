FROM python:3.12-slim

# Устанавливаем необходимые зависимости включая WireGuard
# Проверка GOST выполняется через отдельные контейнеры GostSSLCheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wireguard-tools \
    iproute2 \
    openresolv \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем и устанавливаем зависимости Python
COPY tg_domain_scanner_final/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код приложения
COPY tg_domain_scanner_final/ .

# Создаем директорию для WireGuard конфига
RUN mkdir -p /app/wg

# Копируем конфиг WireGuard в образ
# Build context теперь родительская директория, поэтому wg/ доступна напрямую
# Если директории wg/ нет, COPY выдаст ошибку - используем скрипт сборки для обработки
# Или просто копируем если существует (требуем наличия файла)
COPY wg /app/wg

# Устанавливаем правильные права доступа для конфига WireGuard
RUN chmod 600 /app/wg/TGBOT.conf && \
    echo "✅ WireGuard конфиг скопирован в образ и права установлены (600)"

# Создаем директории для данных
RUN mkdir -p data

CMD ["python", "bot.py"]
