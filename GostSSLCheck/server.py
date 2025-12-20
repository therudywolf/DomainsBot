#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP сервер для проверки GOST сертификатов.

Принимает GET запросы на /check?domain=example.com
Возвращает JSON с результатом проверки.
"""

import json
import logging
import subprocess
import re
import urllib.parse
import http.server
import socketserver
import sys
from typing import Optional

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

GOST_RE = re.compile(r":\s*(GOST.*|RUS CA|foreign CA)$")


def is_gost(domain: str) -> bool:
    """Проверяет, является ли сертификат домена GOST.
    
    Args:
        domain: Домен для проверки
        
    Returns:
        True если сертификат является GOST
    """
    try:
        logger.info("Checking GOST for domain: %s", domain)
        out = subprocess.check_output(
            ["/usr/local/bin/check.sh", domain],
            stderr=subprocess.STDOUT,
            timeout=15
        ).decode('utf-8', errors='replace')
        
        m = GOST_RE.search(out)
        result = bool(m and m.group(1).startswith("GOST"))
        logger.info("GOST check result for %s: %s", domain, result)
        return result
    except subprocess.TimeoutExpired:
        logger.error("Timeout checking GOST for domain: %s", domain)
        raise
    except subprocess.CalledProcessError as e:
        logger.error("Error checking GOST for domain %s: %s", domain, e)
        raise
    except Exception as e:
        logger.error("Unexpected error checking GOST for domain %s: %s", domain, e, exc_info=True)
        raise


def validate_domain(domain: str) -> bool:
    """Валидирует доменное имя.
    
    Args:
        domain: Домен для валидации
        
    Returns:
        True если домен валиден
    """
    if not domain or len(domain) > 253:
        return False
    # Простая проверка формата домена
    parts = domain.split('.')
    if len(parts) < 2:
        return False
    # Проверяем, что все части не пустые и не слишком длинные
    for part in parts:
        if not part or len(part) > 63:
            return False
        if not all(c.isalnum() or c == '-' for c in part):
            return False
    return True


class Handler(http.server.BaseHTTPRequestHandler):
    """HTTP обработчик запросов."""
    
    def do_GET(self):
        """Обрабатывает GET запросы."""
        p = urllib.parse.urlparse(self.path)
        
        # Health check endpoint
        if p.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode('utf-8'))
            return
        
        # Основной endpoint для проверки
        if p.path != "/check":
            self.send_error(404, "Not Found. Use /check?domain=example.com or /health")
            return

        # Извлекаем домен из параметров
        query_params = urllib.parse.parse_qs(p.query)
        domain = query_params.get("domain", [None])[0]
        
        if not domain:
            self.send_error(400, "Missing 'domain' parameter")
            return
        
        # Валидация домена
        if not validate_domain(domain):
            logger.warning("Invalid domain: %s", domain)
            self.send_error(400, "Invalid domain: %s" % domain)
            return

        # Выполняем проверку
        try:
            result = is_gost(domain)
            body = json.dumps(
                {"domain": domain, "is_gost": result}
            ).encode('utf-8')
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
                self.wfile.flush()
            except (BrokenPipeError, OSError):
                # Клиент закрыл соединение до получения ответа - это нормально
                logger.debug("Client closed connection before response sent for domain: %s", domain)
                return
            
        except subprocess.TimeoutExpired:
            logger.error("Timeout checking domain: %s", domain)
            try:
                self.send_error(504, "Check timeout")
            except (BrokenPipeError, OSError):
                logger.debug("Client closed connection during timeout error for domain: %s", domain)
        except subprocess.CalledProcessError as e:
            logger.error("Process error checking domain %s: %s", domain, e)
            try:
                self.send_error(500, "Check failed: %s" % str(e))
            except (BrokenPipeError, OSError):
                logger.debug("Client closed connection during process error for domain: %s", domain)
        except (BrokenPipeError, OSError) as e:
            # Клиент закрыл соединение - это не критическая ошибка
            logger.debug("Client closed connection for domain %s: %s", domain, e)
        except Exception as e:
            logger.error("Unexpected error checking domain %s: %s", domain, e, exc_info=True)
            try:
                self.send_error(500, "Internal error: %s" % str(e))
            except (BrokenPipeError, OSError):
                logger.debug("Client closed connection during error handling for domain: %s", domain)

    def log_message(self, format, *args):
        """Переопределяем логирование для подавления стандартных сообщений."""
        # Используем наш logger вместо стандартного
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    httpd = socketserver.TCPServer(("", port), Handler)
    try:
        logger.info("GostSSLCheck server started on port %d", port)
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Received stop signal")
    finally:
        httpd.server_close()
        logger.info("Server stopped")
