FROM python:3.12-slim

# Устанавливаем необходимые зависимости
# Проверка GOST выполняется через отдельные контейнеры gost
# WireGuard теперь работает в отдельном контейнере
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копируем и устанавливаем зависимости Python
COPY bot/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код приложения
COPY bot/ .

# Создаем директории для данных
RUN mkdir -p data

CMD ["python", "bot.py"]
