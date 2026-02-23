# Базовый образ уже содержит OpenSSL 3 + gost-engine
FROM rnix/openssl-gost:latest

# --- Debian Stretch архив: подключаем и отключаем проверку подписи ---
RUN echo 'deb [trusted=yes] http://archive.debian.org/debian stretch main' > /etc/apt/sources.list && \
    echo 'Acquire::Check-Valid-Until "0";' > /etc/apt/apt.conf.d/99no-check-valid-until && \
    apt-get -o Acquire::AllowInsecureRepositories=yes update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 ca-certificates --allow-unauthenticated && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# --- Ваш скрипт проверки ГОСТ сертификата ---
COPY check.sh /usr/local/bin/check.sh
RUN chmod +x /usr/local/bin/check.sh

# --- Мини‑HTTP сервер на stdlib ---
COPY server.py /app/server.py
WORKDIR /app

EXPOSE 8080
CMD ["python3", "server.py"]
