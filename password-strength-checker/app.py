#!/usr/bin/env python3
"""Server loopback dan CLI edukatif; input tidak ditulis ke log atau disk."""

from __future__ import annotations

import argparse
import getpass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import warnings
from urllib.parse import urlsplit

from checker import check_password, policy_info

HERE = Path(__file__).resolve().parent
MAX_BODY_BYTES = 8192


def unique_json_object(pairs):
    """Tolak kunci ganda agar skema satu kolom tidak ambigu."""
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Kunci JSON ganda.")
        value[key] = item
    return value


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False


def make_handler(static_root: Path = HERE / "static"):
    assets = {"/": (static_root / "index.html", "text/html; charset=utf-8"),
              "/static/app.css": (static_root / "app.css", "text/css; charset=utf-8"),
              "/static/app.js": (static_root / "app.js", "text/javascript; charset=utf-8")}

    class Handler(BaseHTTPRequestHandler):
        server_version = "PasswordLab/1.0"
        sys_version = ""

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, format: str, *args: object) -> None:
            # Jangan mencatat path, header, body, hasil input, atau exception berisi input.
            return

        def _reply(self, status: int, payload: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self'; style-src 'self'; "
                             "connect-src 'self'; img-src 'self'; base-uri 'none'; "
                             "form-action 'none'; frame-ancestors 'none'")
            if status == 405:
                self.send_header("Allow", "GET, POST")
            self.end_headers()
            if self.command != "HEAD":
                try:
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        def _json(self, status: int, value: object) -> None:
            self._reply(status, json.dumps(value, ensure_ascii=False).encode("utf-8"),
                        "application/json; charset=utf-8")

        def _error(self, status: int, message: str) -> None:
            self.close_connection = True
            self._json(status, {"error": message})

        def send_error(self, code: int, message=None, explain=None) -> None:
            # Hilangkan pesan bawaan yang mungkin mengutip request.
            if code == 501:
                code = 405
            self._error(code, "Permintaan tidak didukung.")

        def _route(self) -> tuple[str, str] | None:
            hosts = self.headers.get_all("Host", [])
            allowed = {f"127.0.0.1:{self.server.server_port}",
                       f"localhost:{self.server.server_port}"}
            if len(hosts) != 1 or hosts[0] not in allowed:
                self._error(403, "Host lokal tidak sesuai.")
                return None
            try:
                parsed = urlsplit(self.path)
            except ValueError:
                self._error(400, "Alamat permintaan tidak valid.")
                return None
            if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
                self._error(400, "Gunakan alamat lokal tanpa parameter URL.")
                return None
            return parsed.path, hosts[0]

        def do_GET(self) -> None:
            route = self._route()
            if route is None:
                return
            path, _ = route
            if path == "/api/info":
                self._json(200, policy_info())
                return
            asset = assets.get(path)
            if asset is None:
                self._error(404, "Halaman tidak tersedia.")
                return
            filename, content_type = asset
            try:
                payload = filename.read_bytes()
            except OSError:
                self._error(500, "Berkas tampilan belum tersedia.")
                return
            self._reply(200, payload, content_type)

        def do_POST(self) -> None:
            route = self._route()
            if route is None:
                return
            path, host = route
            if path != "/api/check":
                self._error(404, "Halaman tidak tersedia.")
                return
            origins = self.headers.get_all("Origin", [])
            if len(origins) != 1 or origins[0] != f"http://{host}":
                self._error(403, "Buka pemeriksa dari halaman lokal yang sama.")
                return
            types = self.headers.get_all("Content-Type", [])
            if len(types) != 1 or types[0].split(";", 1)[0].strip().lower() != "application/json":
                self._error(415, "Permintaan harus memakai JSON.")
                return
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") is not None or len(lengths) != 1:
                self._error(411, "Panjang permintaan diperlukan.")
                return
            try:
                length = int(lengths[0])
            except ValueError:
                self._error(400, "Panjang permintaan tidak valid.")
                return
            if length < 1:
                self._error(400, "Isi permintaan diperlukan.")
                return
            if length > MAX_BODY_BYTES:
                self._error(413, "Ukuran permintaan melebihi batas lokal.")
                return
            try:
                raw = self.rfile.read(length)
                if len(raw) != length:
                    self._error(400, "Isi permintaan tidak lengkap.")
                    return
                value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_json_object)
            except (UnicodeError, ValueError, RecursionError, TimeoutError, OSError):
                self._error(400, "JSON permintaan tidak valid.")
                return
            if not isinstance(value, dict) or set(value) != {"password"} or not isinstance(value["password"], str):
                self._error(400, "Kirim satu kolom password berupa teks.")
                return
            try:
                result = check_password(value["password"])
            except ValueError as error:
                # check_password hanya memiliki pesan tetap, tidak berisi input.
                self._error(400, str(error))
                return
            self._json(200, result)

    return Handler


def run_cli() -> int:
    print("Password Strength Checker — latihan lokal")
    print("Gunakan password dummy; input tersembunyi dan tidak disimpan.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Password latihan: ")
        result = check_password(password)
    except getpass.GetPassWarning:
        print("Terminal tidak mendukung input tersembunyi. Gunakan terminal Kali biasa.", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt, OSError):
        print("\nInput dibatalkan atau terminal tidak tersedia.", file=sys.stderr)
        return 1
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(f"Status: {result['label']}")
    print(f"Panjang setelah NFC: {result['length']} karakter")
    for reason in result["reasons"]:
        print(f"- {reason}")
    print("Saran:")
    for suggestion in result["suggestions"]:
        print(f"- {suggestion}")
    print(result["notice"])
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pemeriksa password dummy lokal")
    parser.add_argument("--port", type=int, default=8766, help="port loopback (default 8766)")
    parser.add_argument("--cli", action="store_true", help="pakai input terminal tersembunyi")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port harus 1 sampai 65535")
    if args.cli:
        return run_cli()
    try:
        with LocalServer(("127.0.0.1", args.port), make_handler()) as server:
            print(f"Password Strength Checker: http://127.0.0.1:{args.port}")
            print("Buka di browser Kali. Input diproses di server lokal, tidak disimpan.")
            print("Tekan Ctrl+C untuk berhenti.")
            server.serve_forever(poll_interval=0.5)
    except OSError:
        print("Server lokal gagal dibuka; periksa apakah port sudah dipakai.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nPemeriksa dihentikan.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
