"""Harmless loopback-only examples: compare selected HTTP response headers."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "BoyLab-Demo"
    sys_version = ""

    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path != "/":
            self.send_error(404, "Halaman latihan tidak tersedia")
            return
        enhanced = self.server.enhanced
        profile = "Header ditambah" if enhanced else "Latihan awal"
        body = ("<!doctype html><html lang='id'><meta charset='utf-8'><title>Boy Lab</title>"
                f"<h1>{profile}</h1><p>Ini layanan demo lokal tanpa login atau data pribadi.</p>"
                "<p>Kedua profil memakai HTTP. Penambahan header tidak membuat seluruh aplikasi aman.</p></html>").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if enhanced:
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Set-Cookie", "lab_demo=DEMO_COOKIE_NOT_A_SECRET; Path=/; HttpOnly; SameSite=Lax")
        else:
            self.send_header("Set-Cookie", "lab_demo=DEMO_COOKIE_NOT_A_SECRET; Path=/")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class DemoServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class DemoLab:
    def __init__(self, ports=(8771, 8772)):
        self.ports = ports
        self.servers = []
        self.threads = []

    def __enter__(self):
        try:
            for index, port in enumerate(self.ports):
                server = DemoServer(("127.0.0.1", port), DemoHandler)
                server.enhanced = bool(index)
                self.servers.append(server)
            for server in self.servers:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                self.threads.append(thread)
        except BaseException:
            self.close()
            raise
        return self

    def close(self):
        for server, thread in zip(self.servers, self.threads):
            if thread.is_alive():
                server.shutdown()
        for server in self.servers:
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)
        self.servers = []
        self.threads = []

    def __exit__(self, *_args):
        self.close()
