FROM python:3.12-slim

# Устанавливаем необходимые зависимости
# Проверка GOST выполняется через отдельные контейнеры GostSSLCheck
# WireGuard теперь работает в отдельном контейнере
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем и устанавливаем зависимости Python
COPY tg_domain_scanner_final/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код приложения
COPY tg_domain_scanner_final/ .

# Создаем директории для данных
RUN mkdir -p data

CMD ["python", "bot.py"]
