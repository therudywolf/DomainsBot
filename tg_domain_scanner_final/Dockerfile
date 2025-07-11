FROM python:3.12-slim

# Install OpenSSL with GOST engine
RUN apt-get update &&     apt-get install -y --no-install-recommends         openssl         libssl-dev         libengine-gost-openssl1.1 &&     rm -rf /var/lib/apt/lists/*

# Enable GOST engine globally
RUN printf '\nopenssl_conf = openssl_def\n\n[openssl_def]\nengines = engine_section\n\n[engine_section]\ngost = gost_section\n\n[gost_section]\nengine_id = gost\ndynamic_path = /usr/lib/x86_64-linux-gnu/engines-1.1/gost.so\ndefault_algorithms = ALL:GOST2012:GOST2001:GOST94\n' >> /etc/ssl/openssl.cnf

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "bot.py"]
