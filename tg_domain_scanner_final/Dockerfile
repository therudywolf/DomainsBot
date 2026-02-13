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
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем код приложения
COPY . .

# Создаем директории для данных
RUN mkdir -p data

CMD ["python", "bot.py"]
