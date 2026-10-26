"""Bounded, one-service HTTP configuration checks for a personal lab.

These observations are not CVE detection or proof of exploitability. No redirect,
authentication, response body, cookie value, DNS name, or proxy is used.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
from collections import Counter
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie

MAX_HEADER_BYTES = 32 * 1024
MAX_HEADERS = 100
DEADLINE_SECONDS = 6.0
NETWORK_TIMEOUT = 2.0
NOTICE = (
    "Pemeriksaan konfigurasi web terbatas pada satu respons GET /. "
    "Temuan perlu ditinjau; header yang ada tidak membuktikan sistem aman. "
    "Tidak ada pencarian CVE, eksploitasi, login, crawl, atau pengalihan."
)
PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
CHECK_IDS = ("tcp", "transport", "http", "csp", "frame", "nosniff", "referrer", "hsts", "cookies", "banner")
TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class ResponseLimitError(ValueError):
    """The response did not fit the small lab parser."""


def validate_target(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Target harus satu alamat IPv4 loopback atau privat RFC1918.")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError("Gunakan satu alamat IPv4 literal; nama domain dan rentang tidak didukung.") from error
    if not (address.is_loopback or any(address in network for network in PRIVATE_NETWORKS)):
        raise ValueError("Target dibatasi ke loopback atau jaringan privat RFC1918 milik lab.")
    return str(address)


def validate_request(port: int, scheme: str) -> tuple[int, str]:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Port harus bilangan bulat 1 sampai 65535.")
    if scheme not in ("http", "https") or not isinstance(scheme, str):
        raise ValueError("Protokol harus http atau https.")
    return port, scheme


def _check(identifier, status, title, evidence, meaning, recommendation):
    return dict(id=identifier, status=status, title=title, evidence=evidence, meaning=meaning, recommendation=recommendation)


def _unavailable(identifier, title, evidence="Respons HTTP belum dapat diperiksa."):
    return _check(identifier, "not_checked", title, evidence, "Tidak ada kesimpulan konfigurasi untuk pemeriksaan ini.", "Jalankan layanan lab yang benar, lalu ulangi pemeriksaan.")


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Batas waktu pemeriksaan tercapai.")
    return min(NETWORK_TIMEOUT, remaining)


def read_response_headers(connection, deadline):
    """Read only a bounded HTTP/1.x header block; never retain the body."""
    data = bytearray()
    while True:
        connection.settimeout(_remaining(deadline))
        chunk = connection.recv(min(4096, MAX_HEADER_BYTES + 1 - len(data)))
        if not chunk:
            raise ValueError("Respons HTTP tidak lengkap.")
        data.extend(chunk)
        end = data.find(b"\r\n\r\n")
        if end >= 0:
            end += 4
            if end > MAX_HEADER_BYTES:
                raise ResponseLimitError("Header melebihi batas.")
            return parse_header_block(bytes(data[:end]))
        if len(data) >= MAX_HEADER_BYTES:
            raise ResponseLimitError("Header melebihi batas.")


def parse_header_block(block):
    if len(block) > MAX_HEADER_BYTES or not block.endswith(b"\r\n\r\n"):
        raise ResponseLimitError("Header tidak sesuai batas parser.")
    lines = block[:-4].split(b"\r\n")
    if not lines or not re.fullmatch(rb"HTTP/1\.[01] ([2-5][0-9]{2})(?:[ \t][^\x00-\x08\x0a-\x1f\x7f]*)?", lines[0]):
        raise ValueError("Status HTTP tidak didukung.")
    if len(lines) - 1 > MAX_HEADERS:
        raise ResponseLimitError("Terlalu banyak header.")
    status = int(lines[0].split(b" ", 2)[1])
    headers = {}
    for line in lines[1:]:
        if not line or line[:1] in (b" ", b"\t") or b":" not in line:
            raise ValueError("Header HTTP tidak didukung.")
        key_bytes, value_bytes = line.split(b":", 1)
        try:
            key = key_bytes.decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("Nama header tidak valid.") from error
        if not TOKEN.fullmatch(key) or re.search(rb"[\x00-\x08\x0a-\x1f\x7f]", value_bytes):
            raise ValueError("Header HTTP tidak valid.")
        value = value_bytes.decode("iso-8859-1").strip(" \t")
        headers.setdefault(key.lower(), []).append(value)
    return status, headers


def _one(headers, name):
    values = headers.get(name, [])
    return values[0].strip() if len(values) == 1 else ""


def _cookie_check(headers):
    raw_cookies = headers.get("set-cookie", [])
    if not raw_cookies:
        return _check("cookies", "not_checked", "Atribut cookie", "Tidak ada Set-Cookie pada respons ini.", "Cookie dari halaman atau alur login lain belum diperiksa.", "Periksa cookie sesi pada alur aplikasi yang diizinkan secara terpisah.")
    missing = Counter()
    count = invalid = 0
    for raw_cookie in raw_cookies:
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except CookieError:
            invalid += 1
            continue
        if not cookie:
            invalid += 1
        for morsel in cookie.values():
            count += 1
            missing["Secure"] += not bool(morsel["secure"])
            missing["HttpOnly"] += not bool(morsel["httponly"])
            missing["SameSite"] += morsel["samesite"].lower() not in ("lax", "strict", "none")
    evidence = (
        f"{count} cookie terbaca; tanpa Secure: {missing['Secure']}; "
        f"tanpa HttpOnly: {missing['HttpOnly']}; SameSite tidak jelas: {missing['SameSite']}; "
        f"header tidak terbaca: {invalid}. Nilai dan nama cookie tidak disertakan."
    )
    needs_review = invalid or any(missing.values())
    return _check("cookies", "review" if needs_review else "observed", "Atribut cookie", evidence,
                  "Atribut hanya diamati secara sintaksis; kegunaan cookie dan perilaku browser belum diuji.",
                  "Tinjau kebutuhan HttpOnly/SameSite; cookie sensitif memerlukan Secure dan HTTPS yang benar.")


def analyse_headers(headers, scheme, status):
    """Interpret selected header syntax; never echo arbitrary header values."""
    checks = []
    if 300 <= status < 400:
        http_evidence = f"HTTP {status}; pengalihan tidak diikuti."
    else:
        http_evidence = f"HTTP {status}; hanya header respons ini diperiksa."
    checks.append(_check("http", "info", "Respons HTTP", http_evidence,
                         "Kode respons menjelaskan respons endpoint, bukan tingkat keamanan seluruh aplikasi.",
                         "Pastikan respons ini adalah halaman yang hendak dipelajari."))
    csp_values = headers.get("content-security-policy", [])
    csp = any(value.strip() for value in csp_values)
    checks.append(_check("csp", "observed" if csp else "review", "Content Security Policy (CSP)",
                         "Header CSP terlihat; efektivitas kebijakan belum divalidasi." if csp else "Header CSP tidak terlihat pada respons ini.",
                         "CSP dapat membatasi sumber konten yang boleh dimuat browser; kehadirannya saja belum cukup.",
                         "Susun dan uji kebijakan sesuai kebutuhan aplikasi; hindari menyalin kebijakan tanpa pengujian."))
    frame_csp = any(re.search(r"(?:^|;)\s*frame-ancestors\s+[^;\s]", value, re.I) for value in csp_values)
    frame_xfo = _one(headers, "x-frame-options").upper() in ("DENY", "SAMEORIGIN")
    checks.append(_check("frame", "observed" if frame_csp or frame_xfo else "review", "Pembatasan framing",
                         "Sintaks pembatasan framing terlihat; perilaku browser belum diuji." if frame_csp or frame_xfo else "X-Frame-Options DENY/SAMEORIGIN atau direktif frame-ancestors tidak terlihat.",
                         "Pembatasan framing membantu mengendalikan halaman yang boleh menampilkan aplikasi dalam frame.",
                         "Tinjau kebutuhan frame-ancestors atau X-Frame-Options dan uji integrasi yang memang dibutuhkan."))
    nosniff = _one(headers, "x-content-type-options").lower() == "nosniff"
    checks.append(_check("nosniff", "observed" if nosniff else "review", "X-Content-Type-Options",
                         "Nilai nosniff terlihat." if nosniff else "Nilai tunggal nosniff tidak terlihat.",
                         "nosniff meminta browser mengikuti tipe konten yang dideklarasikan; tipe konten tetap perlu benar.",
                         "Gunakan Content-Type yang sesuai dan tinjau X-Content-Type-Options: nosniff."))
    safe_referrers = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
    referrer = _one(headers, "referrer-policy").lower()
    checks.append(_check("referrer", "observed" if referrer in safe_referrers else "review", "Referrer-Policy",
                         "Salah satu nilai pembatas referrer yang dikenali terlihat." if referrer in safe_referrers else "Nilai pembatas yang dikenali alat ini tidak terlihat; browser dapat memiliki nilai bawaan.",
                         "Kebijakan ini mengatur informasi asal halaman yang dikirim browser saat berpindah halaman.",
                         "Pilih kebijakan sesuai privasi dan kebutuhan aplikasi; tinjau konteks sebelum menyebutnya celah."))
    if scheme == "https":
        hsts = _one(headers, "strict-transport-security")
        max_age = re.search(r"(?:^|;)\s*max-age\s*=\s*([0-9]+)\s*(?:;|$)", hsts, re.I)
        enabled = bool(max_age and any(char != "0" for char in max_age.group(1)))
        checks.append(_check("hsts", "observed" if enabled else "info", "HTTP Strict Transport Security (HSTS)",
                             "Sintaks max-age positif terlihat melalui HTTPS terverifikasi." if enabled else "Satu header dengan sintaks max-age positif tidak terlihat; bukan temuan kerentanan untuk target IP ini.",
                             "Target alat ini berupa IP literal. Browser tidak menerapkan HSTS untuk host IP literal; hasil ini hanya mengamati sintaks header, bukan penegakan HSTS.",
                             "Pelajari penerapan HSTS secara terpisah pada hostname dengan HTTPS yang valid; kesiapan hostname dan subdomain belum diperiksa."))
    else:
        checks.append(_check("hsts", "not_checked", "HTTP Strict Transport Security (HSTS)",
                             "Target menggunakan HTTP; HSTS tidak dinilai dari koneksi ini.",
                             "Browser mempelajari HSTS melalui HTTPS yang valid; header lewat HTTP tidak menyelesaikan masalah transport.",
                             "Gunakan HTTPS yang terverifikasi ketika mempelajari penerapan HSTS."))
    checks.append(_cookie_check(headers))
    checks.append(_check("banner", "info", "Informasi banner server",
                         "Header Server terlihat; nilai disembunyikan dalam ringkasan." if headers.get("server") else "Header Server tidak terlihat pada respons ini.",
                         "Banner hanya informasi yang diklaim server; tidak membuktikan software, versi sebenarnya, atau CVE.",
                         "Tinjau inventaris dan pembaruan server dari sistem milik sendiri; jangan menyimpulkan celah dari banner."))
    return checks


def _result(host, port, scheme, transport, checks):
    counts = Counter(check["status"] for check in checks)
    return {
        "schema_version": 1,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": {"host": host, "port": port, "scheme": scheme, "url": f"{scheme}://{host}:{port}/"},
        "transport": transport,
        "summary": {name: counts[name] for name in ("review", "observed", "info", "not_checked")},
        "checks": checks,
        "notice": NOTICE,
    }


def scan_service(host, port, scheme="http"):
    host = validate_target(host)
    port, scheme = validate_request(port, scheme)
    deadline = time.monotonic() + DEADLINE_SECONDS
    transport = {"tcp": "error", "tls": "not_checked", "http_status": None}
    checks = []
    titles = {"tcp": "Koneksi TCP", "transport": "Transport HTTP / HTTPS", "http": "Respons HTTP", "csp": "Content Security Policy (CSP)", "frame": "Pembatasan framing", "nosniff": "X-Content-Type-Options", "referrer": "Referrer-Policy", "hsts": "HTTP Strict Transport Security (HSTS)", "cookies": "Atribut cookie", "banner": "Informasi banner server"}
    connection = None
    try:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(_remaining(deadline))
        try:
            connection.connect((host, port))
        except ConnectionRefusedError:
            transport["tcp"] = "closed"
            checks.append(_check("tcp", "info", titles["tcp"], "Koneksi TCP ditolak pada saat pemeriksaan.", "Port ini belum menerima koneksi; penyebab pasti atau aturan firewall belum dibuktikan.", "Pastikan layanan dan nomor port lab sesuai."))
            return _result(host, port, scheme, transport, checks + [_unavailable(key, titles[key]) for key in CHECK_IDS[1:]])
        except (TimeoutError, socket.timeout):
            transport["tcp"] = "timeout"
            checks.append(_check("tcp", "info", titles["tcp"], "Koneksi TCP melewati batas waktu.", "Timeout tidak memastikan port tertutup atau terfilter.", "Periksa alamat, layanan, dan jaringan lab milik sendiri."))
            return _result(host, port, scheme, transport, checks + [_unavailable(key, titles[key]) for key in CHECK_IDS[1:]])
        except OSError:
            checks.append(_check("tcp", "info", titles["tcp"], "Koneksi TCP tidak berhasil dibuat.", "Ada kendala koneksi; belum ada penilaian konfigurasi HTTP.", "Periksa layanan dan konektivitas lab milik sendiri."))
            return _result(host, port, scheme, transport, checks + [_unavailable(key, titles[key]) for key in CHECK_IDS[1:]])
        transport["tcp"] = "open"
        checks.append(_check("tcp", "observed", titles["tcp"], "Koneksi TCP berhasil ke satu port yang dipilih.", "Ada layanan yang menerima koneksi; port terbuka sendiri bukan kerentanan.", "Cocokkan layanan dengan inventaris dan kebutuhan lab."))
        if scheme == "https":
            try:
                connection.settimeout(_remaining(deadline))
                context = ssl.create_default_context()
                context.keylog_filename = None
                connection = context.wrap_socket(connection, server_hostname=host)
                transport["tls"] = "valid"
                checks.append(_check("transport", "observed", titles["transport"], "TLS lolos verifikasi sertifikat bawaan Python untuk alamat target.", "Koneksi ini terverifikasi; algoritma, kedaluwarsa mendatang, dan seluruh konfigurasi TLS tidak diaudit.", "Pertahankan sertifikat dan konfigurasi TLS yang sesuai kebutuhan."))
            except (ssl.SSLError, OSError, TimeoutError):
                transport["tls"] = "failed"
                checks.append(_check("transport", "review", titles["transport"], "Handshake atau verifikasi TLS gagal; HTTP tidak dikirim dan verifikasi tidak dilewati.", "Sertifikat lab self-signed, ketidakcocokan alamat, protokol, atau koneksi dapat menjadi penyebab; penyebab pasti belum ditentukan.", "Periksa sertifikat dan layanan HTTPS lab, gunakan nama/alamat yang didukung; alat tidak menyediakan mode insecure."))
                return _result(host, port, scheme, transport, checks + [_unavailable(key, titles[key], "HTTP belum diperiksa karena TLS tidak berhasil diverifikasi.") for key in CHECK_IDS[2:]])
        else:
            local = ipaddress.IPv4Address(host).is_loopback
            checks.append(_check("transport", "info" if local else "review", titles["transport"],
                                 "HTTP tanpa TLS pada loopback latihan." if local else "HTTP tanpa TLS pada jaringan lab privat.",
                                 "HTTP tidak mengenkripsi trafik. Demo loopback memang memakai HTTP; ini bukan contoh transport produksi yang aman.",
                                 "Gunakan HTTPS terverifikasi untuk layanan sensitif di jaringan."))
        request = (f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: BoyLab-MiniScanner/1.0\r\nAccept: text/html,*/*;q=0.1\r\nConnection: close\r\n\r\n").encode("ascii")
        try:
            connection.settimeout(_remaining(deadline))
            connection.sendall(request)
            status, headers = read_response_headers(connection, deadline)
        except (ResponseLimitError, ValueError, OSError, TimeoutError):
            checks.extend([_unavailable("http", titles["http"], "Respons tidak lengkap, tidak didukung, terlalu besar, atau melewati batas waktu.")])
            checks.extend(_unavailable(key, titles[key]) for key in CHECK_IDS[3:])
            return _result(host, port, scheme, transport, checks)
        transport["http_status"] = status
        checks.extend(analyse_headers(headers, scheme, status))
        return _result(host, port, scheme, transport, checks)
    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    print(json.dumps(scan_service("127.0.0.1", 8771), ensure_ascii=False, indent=2))
