#!/usr/bin/env python3
"""Dashboard pemantauan jaringan lokal untuk VM Linux, tanpa paket tambahan.

Statistik berasal dari /proc milik network namespace proses ini. Program tidak
menangkap payload, memindai host, atau menyimpan alamat tujuan ke disk.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
from threading import Event, Lock, Thread
import time
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
STATIC_FILES = {
    "/": (HERE / "static" / "index.html", "text/html; charset=utf-8"),
    "/static/app.css": (HERE / "static" / "app.css", "text/css; charset=utf-8"),
    "/static/app.js": (HERE / "static" / "app.js", "text/javascript; charset=utf-8"),
}
COUNTER_FIELDS = (
    "rx_bytes", "rx_packets", "rx_errors", "rx_dropped",
    "tx_bytes", "tx_packets", "tx_errors", "tx_dropped",
)
RATE_FIELDS = (
    ("rx_bytes", "rx_bytes_per_sec"),
    ("tx_bytes", "tx_bytes_per_sec"),
    ("rx_packets", "rx_packets_per_sec"),
    ("tx_packets", "tx_packets_per_sec"),
)
SOCKET_FILES = (
    ("tcp", "TCP4"), ("tcp6", "TCP6"),
    ("udp", "UDP4"), ("udp6", "UDP6"),
)


def parse_net_dev(contents: str) -> dict[str, dict[str, int]]:
    """Baca counter kumulatif dari format /proc/net/dev."""
    interfaces = {}
    for line in contents.splitlines():
        if ":" not in line:
            continue
        name, values = line.split(":", 1)
        parts = values.split()
        if len(parts) < 16:
            continue
        try:
            numbers = [int(value) for value in parts[:16]]
        except ValueError:
            continue
        interfaces[name.strip()] = dict(zip(COUNTER_FIELDS, (
            numbers[0], numbers[1], numbers[2], numbers[3],
            numbers[8], numbers[9], numbers[10], numbers[11],
        )))
    return interfaces


def parse_socket_table(contents: str, protocol: str) -> Counter[tuple[str, str]]:
    """Hitung baris socket; alamat dan port sengaja tidak diproses/ditampilkan."""
    counts: Counter[tuple[str, str]] = Counter()
    for line in contents.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        if protocol.startswith("TCP"):
            state = {"01": "ESTABLISHED", "0A": "LISTEN"}.get(parts[3].upper(), "OTHER")
        else:
            state = "UDP"
        counts[(protocol, state)] += 1
    return counts


def read_sockets(proc_root: Path) -> tuple[dict[str, int], list[dict[str, object]]]:
    counts: Counter[tuple[str, str]] = Counter()
    for filename, protocol in SOCKET_FILES:
        try:
            contents = (proc_root / filename).read_text(encoding="ascii")
        except FileNotFoundError:
            # Beberapa sistem tidak menyediakan tabel IPv6.
            continue
        counts.update(parse_socket_table(contents, protocol))
    summary = {
        "tcp_established": sum(number for (proto, state), number in counts.items()
                               if proto.startswith("TCP") and state == "ESTABLISHED"),
        "tcp_listening": sum(number for (proto, state), number in counts.items()
                            if proto.startswith("TCP") and state == "LISTEN"),
        "udp_sockets": sum(number for (proto, _), number in counts.items()
                           if proto.startswith("UDP")),
    }
    rows = [
        {"protocol": protocol, "state": state, "count": number}
        for (protocol, state), number in sorted(counts.items())
    ]
    return summary, rows


def calculate_rates(
    current: dict[str, int], previous: dict[str, int] | None, elapsed: float | None
) -> dict[str, float | None]:
    """Nilai None berarti baseline belum ada atau counter sempat reset."""
    if previous is None or elapsed is None or elapsed <= 0:
        return {name: None for _, name in RATE_FIELDS}
    if any(current[field] < previous[field] for field, _ in RATE_FIELDS):
        return {name: None for _, name in RATE_FIELDS}
    return {
        name: round((current[field] - previous[field]) / elapsed, 2)
        for field, name in RATE_FIELDS
    }


def choose_default_interface(interfaces: dict[str, object]) -> str | None:
    if "eth0" in interfaces:
        return "eth0"
    non_loopback = sorted(name for name in interfaces if name != "lo")
    if non_loopback:
        return non_loopback[0]
    return "lo" if "lo" in interfaces else next(iter(interfaces), None)


class Monitor:
    def __init__(self, proc_root: Path = Path("/proc/net"), interval: float = 1.0):
        self.proc_root = Path(proc_root)
        self.interval = interval
        self._lock = Lock()
        self._stop = Event()
        self._previous: dict[str, dict[str, int]] = {}
        self._previous_time: float | None = None
        self._history: defaultdict[str, deque] = defaultdict(lambda: deque(maxlen=60))
        self._snapshot: dict[str, object] = {"error": "Sampel pertama belum tersedia"}
        self._thread: Thread | None = None

    def sample(self, now: float | None = None) -> dict[str, object]:
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        monotonic_now = time.monotonic() if now is None else now
        raw = (self.proc_root / "dev").read_text(encoding="ascii")
        current = parse_net_dev(raw)
        if not current:
            raise ValueError("Tidak ada antarmuka jaringan di /proc/net/dev")
        sockets, connection_rows = read_sockets(self.proc_root)
        elapsed = (monotonic_now - self._previous_time) if self._previous_time is not None else None
        enriched = {}
        for name, counters in current.items():
            rates = calculate_rates(counters, self._previous.get(name), elapsed)
            enriched[name] = {**counters, **rates}
            self._history[name].append({
                "timestamp": timestamp,
                "rx_bps": rates["rx_bytes_per_sec"],
                "tx_bps": rates["tx_bytes_per_sec"],
            })
        for name in tuple(self._history):
            if name not in current:
                del self._history[name]
        snapshot = {
            "timestamp": timestamp,
            "default_interface": choose_default_interface(current),
            "interfaces": enriched,
            "history": {name: list(values) for name, values in self._history.items()},
            "sockets": sockets,
            "connections": connection_rows,
        }
        with self._lock:
            self._previous = current
            self._previous_time = monotonic_now
            self._snapshot = snapshot
        return snapshot

    def get_snapshot(self) -> dict[str, object]:
        with self._lock:
            return self._snapshot

    def start(self) -> None:
        self.sample()
        self._thread = Thread(target=self._poll, name="network-monitor", daemon=True)
        self._thread.start()

    def _poll(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.sample()
            except (OSError, ValueError) as error:
                with self._lock:
                    self._snapshot = {"error": f"Gagal membaca statistik lokal: {error}"}

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)


def make_handler(monitor: Monitor):
    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            hosts = self.headers.get_all("Host", [])
            allowed_hosts = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
            if len(hosts) != 1 or hosts[0] not in allowed_hosts:
                self._reply(403, b"Host lokal tidak diizinkan", "text/plain; charset=utf-8")
                return
            path = urlsplit(self.path).path
            if path == "/api/snapshot":
                snapshot = monitor.get_snapshot()
                payload = json.dumps(snapshot, ensure_ascii=False).encode("utf-8")
                status = 503 if "error" in snapshot else 200
                self._reply(status, payload, "application/json; charset=utf-8")
                return
            static = STATIC_FILES.get(path)
            if static is None:
                self._reply(404, b"Tidak ditemukan", "text/plain; charset=utf-8")
                return
            filename, content_type = static
            try:
                payload = filename.read_bytes()
            except OSError:
                self._reply(500, b"Aset dashboard tidak tersedia", "text/plain; charset=utf-8")
                return
            self._reply(200, payload, content_type)

        def _reply(self, status: int, payload: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt: str, *args: object) -> None:
            # Polling tiap detik tidak perlu membanjiri terminal.
            if not self.path.startswith("/api/snapshot"):
                super().log_message(fmt, *args)

    return DashboardHandler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Dashboard statistik jaringan VM Linux lokal")
    parser.add_argument("--port", type=int, default=8765, help="port lokal (default: 8765)")
    parser.add_argument("--interval", type=float, default=1.0, help="interval sampel detik (default: 1)")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535 or not 0.5 <= args.interval <= 10:
        parser.error("port harus 1–65535 dan interval harus 0.5–10 detik")
    if not Path("/proc/net/dev").exists():
        parser.error("jalankan di Linux/Kali: /proc/net/dev tidak tersedia")
    monitor = Monitor(interval=args.interval)
    try:
        monitor.start()
    except (OSError, ValueError) as error:
        parser.error(f"gagal mengambil sampel awal: {error}")
    try:
        with ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(monitor)) as server:
            server.daemon_threads = True
            print(f"Dashboard lokal: http://127.0.0.1:{args.port}")
            print("Buka alamat itu di browser Kali. Tekan Ctrl+C untuk berhenti.")
            server.serve_forever(poll_interval=0.5)
    except OSError as error:
        print(f"Gagal menjalankan server lokal: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nDashboard dihentikan.")
    finally:
        monitor.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
