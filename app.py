"""Local-only dashboard server for a limited personal web-service lab."""

from __future__ import annotations

import argparse
import json
import threading
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from demo_lab import DemoLab
from scanner import scan_service, validate_request, validate_target

VERSION = "1.0"
MAX_REQUEST_BYTES = 1024
ROOT = Path(__file__).resolve().parent
ASSETS = {
    "/": ("static/index.html", "text/html; charset=utf-8"),
    "/static/app.css": ("static/app.css", "text/css; charset=utf-8"),
    "/static/app.js": ("static/app.js", "text/javascript; charset=utf-8"),
}


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Kunci JSON ganda.")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("Konstanta JSON tidak valid.")


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    server_version = "BoyLab-Local"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(8)

    def log_message(self, *_args):
        pass

    def _send(self, status, data, content_type="application/json; charset=utf-8"):
        if not isinstance(data, bytes):
            data = json.dumps(data, ensure_ascii=False, allow_nan=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _error(self, status, message):
        self._send(status, {"error": message})

    def _host_allowed(self):
        values = self.headers.get_all("Host", [])
        allowed = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        return len(values) == 1 and values[0] in allowed

    def do_GET(self):
        if not self._host_allowed():
            self._error(403, "Host lokal tidak diizinkan.")
            return
        if self.path == "/api/info":
            self._send(200, {"target": self.server.target, "demo_enabled": self.server.demo_enabled,
                             "demo_ports": [8771, 8772], "version": VERSION, "default_port": 8771})
            return
        asset = ASSETS.get(self.path)
        if not asset:
            self._error(404, "Halaman tidak tersedia.")
            return
        try:
            data = (ROOT / asset[0]).read_bytes()
        except OSError:
            self._error(503, "Berkas tampilan belum tersedia.")
            return
        self._send(200, data, asset[1])

    def do_POST(self):
        if not self._host_allowed():
            self._error(403, "Host lokal tidak diizinkan.")
            return
        origins = self.headers.get_all("Origin", [])
        if len(origins) != 1 or origins[0] != "http://" + self.headers["Host"]:
            self._error(403, "Origin harus sama dengan dashboard lokal.")
            return
        if self.path != "/api/scan":
            self._error(404, "API tidak tersedia.")
            return
        if self.headers.get_all("Transfer-Encoding"):
            self._error(400, "Transfer-Encoding tidak didukung.")
            return
        content_types = self.headers.get_all("Content-Type", [])
        if len(content_types) != 1 or content_types[0].lower() not in ("application/json", "application/json; charset=utf-8"):
            self._error(415, "Gunakan application/json.")
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal():
            self._error(400, "Content-Length tidak valid.")
            return
        if len(lengths[0]) > 6 or int(lengths[0]) > MAX_REQUEST_BYTES:
            self._error(413, "Permintaan melebihi batas 1024 byte.")
            return
        length = int(lengths[0])
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Permintaan terpotong.")
            payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)
            if not isinstance(payload, dict) or set(payload) != {"port", "scheme"}:
                raise ValueError("Skema tidak valid.")
            port, scheme = validate_request(payload["port"], payload["scheme"])
        except (ValueError, TypeError, UnicodeError, RecursionError, OSError):
            self._error(400, "Isi harus JSON dengan satu port 1–65535 dan scheme http/https.")
            return
        if not self.server.scan_lock.acquire(blocking=False):
            self._error(429, "Satu pemeriksaan masih berjalan; tunggu hingga selesai.")
            return
        try:
            result = scan_service(self.server.target, port, scheme)
        except Exception:
            status, result = 500, {"error": "Pemeriksaan tidak dapat diselesaikan."}
        else:
            status = 200
        finally:
            self.server.scan_lock.release()
        self._send(status, result)

    def do_HEAD(self):
        self._error(405, "Metode tidak didukung.")


def make_server(port=8770, target="127.0.0.1", demo_enabled=False):
    target = validate_target(target)
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("Port dashboard tidak valid.")
    server = LocalServer(("127.0.0.1", port), Handler)
    server.target = target
    server.demo_enabled = bool(demo_enabled)
    server.scan_lock = threading.Lock()
    return server


def main(argv=None):
    parser = argparse.ArgumentParser(description="Dashboard pemeriksaan konfigurasi web terbatas untuk lab milik sendiri.")
    parser.add_argument("--target", default="127.0.0.1", help="Satu IPv4 loopback/RFC1918 milik lab; bukan domain atau rentang.")
    parser.add_argument("--port", type=int, default=8770, help="Port dashboard lokal (bawaan: 8770).")
    parser.add_argument("--with-demo", action="store_true", help="Mulai dua layanan latihan HTTP loopback pada port 8771 dan 8772.")
    args = parser.parse_args(argv)
    try:
        target = validate_target(args.target)
        if not 1 <= args.port <= 65535:
            raise ValueError("Port dashboard harus 1 sampai 65535.")
        if args.with_demo and target != "127.0.0.1":
            raise ValueError("Demo memakai target 127.0.0.1; jalankan tanpa --target lain.")
        with ExitStack() as stack:
            server = make_server(args.port, target, args.with_demo)
            stack.callback(server.server_close)
            if args.with_demo:
                stack.enter_context(DemoLab())
            print(f"Dashboard lokal: http://127.0.0.1:{server.server_port}")
            print(f"Target tetap: {target}; hanya gunakan layanan lab milik sendiri atau berizin.")
            if args.with_demo:
                print("Demo HTTP loopback: 8771 (latihan awal) dan 8772 (header ditambah).")
            print("Buka di browser Kali. Tekan Ctrl+C di terminal ini untuk berhenti.")
            server.serve_forever()
    except KeyboardInterrupt:
        print("\nPemeriksa dihentikan.")
        return 0
    except (OSError, ValueError) as error:
        print(f"Tidak dapat memulai lab: {error}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
