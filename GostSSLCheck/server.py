#!/usr/bin/env python3
import json, subprocess, re, urllib.parse, http.server, socketserver, sys

GOST_RE = re.compile(r":\s*(GOST.*|RUS CA|foreign CA)$")

def is_gost(domain: str) -> bool:
    out = subprocess.check_output(
        ["/usr/local/bin/check.sh", domain],
        stderr=subprocess.STDOUT, timeout=15
    ).decode()
    m = GOST_RE.search(out)
    return bool(m and m.group(1).startswith("GOST"))

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        if p.path != "/check":
            self.send_error(404)
            return

        domain = urllib.parse.parse_qs(p.query).get("domain", [None])[0]
        if not domain:
            self.send_error(400, "missing domain")
            return

        try:
            body = json.dumps(
                {"domain": domain, "is_gost": is_gost(domain)}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except subprocess.TimeoutExpired:
            self.send_error(504, "check timeout")
        except subprocess.CalledProcessError:
            self.send_error(500, "check failed")

    # приглушаем стандартный лог сервера
    def log_message(self, *_):
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    httpd = socketserver.TCPServer(("", port), Handler)
    try:
        print("Serving on :{}".format(port), flush=True)
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
