#!/usr/bin/env python3
"""Build a local, read-only dashboard of public DNS records for one domain."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import html
import ipaddress
import json
from pathlib import Path
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


GOOGLE_DOH = "https://dns.google/resolve"
GOOGLE_DOCS = "https://developers.google.com/speed/public-dns/docs/doh/json"
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")
TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}
DNS_ERRORS = {1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
RESERVED_SUFFIXES = {"local", "localhost", "test", "invalid", "example", "onion", "internal", "arpa"}
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
MAX_RESPONSE_BYTES = 1_000_000


@dataclass(frozen=True)
class LookupResult:
    record_type: str
    source_url: str
    state: str
    message: str
    answers: tuple[dict[str, str], ...] = ()


def validate_domain(raw: str) -> str:
    """Accept a public-looking DNS name, never a URL, IP address, or local name."""
    value = raw.strip()
    if value.endswith("."):
        value = value[:-1]  # A single trailing dot is valid for a fully qualified DNS name.
    if not value or any(char.isspace() for char in value):
        raise ValueError("Masukkan nama domain saja, misalnya example.com.")
    if any(char in value for char in "/\\:@?#"):
        raise ValueError("Masukkan domain saja, tanpa URL, port, email, atau path.")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("Alamat IP bukan nama domain yang didukung proyek ini.")
    try:
        domain = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Nama domain tidak valid.") from exc
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(not LABEL_RE.fullmatch(label) for label in labels):
        raise ValueError("Format domain tidak valid; gunakan nama seperti example.com.")
    if labels[-1] in RESERVED_SUFFIXES or len(labels[-1]) < 2 or labels[-1].isdigit():
        raise ValueError("Gunakan domain publik, bukan nama lokal atau domain khusus uji.")
    return domain


def query_url(domain: str, record_type: str) -> str:
    # Fixed provider and fixed record types keep user input out of the URL host/path.
    return GOOGLE_DOH + "?" + urlencode(
        {"name": domain, "type": record_type, "edns_client_subnet": "0.0.0.0/0"}
    )


def fetch_dns(domain: str, record_type: str) -> LookupResult:
    """Make one bounded lookup; never retry automatically."""
    url = query_url(domain, record_type)
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "OSINT-Dashboard-Lab/1.0"})
    try:
        with urlopen(request, timeout=8) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        if exc.code == 429:
            return LookupResult(record_type, url, "rate_limited", "HTTP 429: terlalu banyak permintaan; pencarian dihentikan.")
        return LookupResult(record_type, url, "http_error", f"HTTP {exc.code}: sumber DNS tidak dapat menjawab.")
    except (URLError, TimeoutError, OSError) as exc:
        return LookupResult(record_type, url, "network_error", f"Koneksi gagal: {exc}.")
    if len(raw) > MAX_RESPONSE_BYTES:
        return LookupResult(record_type, url, "invalid_response", "Respons DNS terlalu besar untuk ditampilkan.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return LookupResult(record_type, url, "invalid_response", "Respons DNS bukan JSON yang didukung.")
    if not isinstance(data, dict) or type(data.get("Status")) is not int:
        return LookupResult(record_type, url, "invalid_response", "Respons DNS tidak memiliki status yang valid.")
    status = data["Status"]
    if status != 0:
        label = DNS_ERRORS.get(status, f"kode {status}")
        return LookupResult(record_type, url, "dns_error", f"DNS {label}: kueri tidak menghasilkan jawaban sukses.")
    answer_data = data.get("Answer", [])
    if not isinstance(answer_data, list):
        return LookupResult(record_type, url, "invalid_response", "Field Answer DNS tidak valid.")
    answers: list[dict[str, str]] = []
    for item in answer_data[:100]:
        if not isinstance(item, dict):
            return LookupResult(record_type, url, "invalid_response", "Isi Answer DNS tidak valid.")
        number = item.get("type")
        if type(number) is not int:
            return LookupResult(record_type, url, "invalid_response", "Tipe record dalam Answer DNS tidak valid.")
        answers.append(
            {
                "name": str(item.get("name", "—")),
                "type": TYPE_NAMES.get(number, f"TYPE {number}"),
                "ttl": str(item.get("TTL", "—")),
                "data": str(item.get("data", "—")),
            }
        )
    if not answers:
        return LookupResult(record_type, url, "empty", "Tidak ada record untuk tipe ini pada waktu pemeriksaan.")
    message = f"{len(answers)} record ditampilkan."
    if len(answer_data) > 100:
        message += " Respons dibatasi pada 100 record pertama."
    return LookupResult(record_type, url, "ok", message, tuple(answers))


def collect_dns(domain: str, fetcher=fetch_dns) -> tuple[LookupResult, ...]:
    results: list[LookupResult] = []
    halted = False
    for record_type in RECORD_TYPES:
        if halted:
            results.append(LookupResult(record_type, "", "skipped", "Dilewati setelah server mengirim HTTP 429."))
            continue
        result = fetcher(domain, record_type)
        results.append(result)
        if result.state == "rate_limited":
            halted = True
    return tuple(results)


def demo_results() -> tuple[LookupResult, ...]:
    """Clearly fictional records; no network call is made in demo mode."""
    samples = {
        "A": ("contoh.test.", "A", "300", "192.0.2.10"),
        "AAAA": ("contoh.test.", "AAAA", "300", "2001:db8::10"),
        "MX": ("contoh.test.", "MX", "300", "10 mail.contoh.test."),
        "NS": ("contoh.test.", "NS", "300", "ns1.contoh.test."),
        "TXT": ("contoh.test.", "TXT", "300", '"v=spf1 -all"'),
    }
    return tuple(
        LookupResult(
            record_type,
            "",
            "demo",
            "Data contoh buatan untuk latihan; bukan hasil kueri DNS.",
            ({"name": row[0], "type": row[1], "ttl": row[2], "data": row[3]},),
        )
        for record_type, row in samples.items()
    )


def escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def render_section(result: LookupResult, demo: bool) -> str:
    title = escape(result.record_type)
    message = escape(result.message)
    rows = "".join(
        "<tr>"
        f"<td><code>{escape(row['name'])}</code></td>"
        f"<td>{escape(row['type'])}</td>"
        f"<td>{escape(row['ttl'])}</td>"
        f"<td><code class='wrap'>{escape(row['data'])}</code></td>"
        "</tr>"
        for row in result.answers
    )
    if not rows:
        rows = "<tr><td colspan='4'>Tidak ada data yang bisa ditampilkan.</td></tr>"
    source = (
        "Sumber: data demo buatan (offline)."
        if demo
        else (
            f"Sumber: <a href='{escape(result.source_url)}' rel='noopener noreferrer' "
            f"target='_blank'>Google Public DNS — kueri {title}</a>."
            if result.source_url
            else "Sumber: tidak dikueri."
        )
    )
    return (
        "<section class='panel'>"
        f"<div class='section-head'><h2>{title}</h2><span class='badge {escape(result.state)}'>{escape(result.state.replace('_', ' '))}</span></div>"
        f"<p class='message'>{message}</p>"
        "<div class='table-scroll'><table><thead><tr><th>Nama</th><th>Tipe</th><th>TTL (detik)</th><th>Data publik</th></tr></thead>"
        f"<tbody>{rows}</tbody></table></div>"
        f"<p class='source'>{source}</p>"
        "</section>"
    )


def render_html(domain: str, results: tuple[LookupResult, ...], timestamp: str, demo: bool = False) -> str:
    safe_domain = escape(domain)
    safe_time = escape(timestamp)
    sections = "".join(render_section(result, demo) for result in results)
    mode = "DEMO OFFLINE — DATA BUATAN" if demo else "HASIL DNS PUBLIK"
    intro = (
        "Dashboard ini memakai data contoh buatan. Tidak ada permintaan jaringan dan alamat contoh bukan temuan nyata."
        if demo
        else "Dashboard ini menampilkan jawaban DNS publik pada waktu pemeriksaan. Data dapat berubah dan tidak membuktikan keamanan domain."
    )
    privacy_note = (
        "Mode demo tidak mengirim kueri. Dalam mode langsung, resolver Google melihat domain yang ditanyakan dan alamat IP pengirim."
        if demo
        else "Resolver Google melihat domain yang ditanyakan dan alamat IP pengirim kueri."
    )
    if demo:
        summary = f"<div class='stat'><strong>{len(results)}</strong><span>Tipe data buatan</span></div>"
    else:
        with_answers = sum(result.state == "ok" for result in results)
        empty = sum(result.state == "empty" for result in results)
        issues = len(results) - with_answers - empty
        summary = (
            f"<div class='stat'><strong>{with_answers}</strong><span>Tipe berjawab</span></div>"
            f"<div class='stat'><strong>{empty}</strong><span>Tipe tanpa jawaban</span></div>"
            f"<div class='stat'><strong>{issues}</strong><span>Tipe gagal/dilewati</span></div>"
        )
    return f"""<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT DNS • {safe_domain}</title>
<style>
:root{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#e7eef8;background:#101b2e}}
*{{box-sizing:border-box}}body{{margin:0}}a{{color:#8cd5ff}}code{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}}
header{{padding:2.3rem max(1rem,calc((100vw - 1000px)/2));background:linear-gradient(125deg,#132943,#1b5271)}}
.eyebrow{{font-weight:800;letter-spacing:.08em;color:#a4ecde;font-size:.78rem}}h1{{font-size:clamp(1.7rem,5vw,2.6rem);margin:.3rem 0}}header p{{max-width:54rem;line-height:1.6}}
main{{max-width:1032px;margin:auto;padding:1.2rem 1rem 3rem}}.meta{{display:flex;gap:.8rem;flex-wrap:wrap;margin:0 0 1.2rem}}
.meta span{{border:1px solid #55708b;border-radius:999px;padding:.45rem .8rem;background:#1d3049;color:#d9eaf6;font-size:.88rem}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.8rem;margin:0 0 1.2rem}}
.stat{{background:#1b2a41;border:1px solid #36516b;border-radius:12px;padding:.8rem 1rem;display:flex;flex-direction:column;gap:.2rem}}
.stat strong{{font-size:1.6rem;color:#a4ecde}}.stat span{{font-size:.85rem;color:#c3d4e2}}
.panel{{background:#1b2a41;border:1px solid #36516b;border-radius:14px;padding:1rem;margin:0 0 1rem;box-shadow:0 6px 24px #0002}}
.section-head{{display:flex;justify-content:space-between;align-items:center;gap:.7rem}}h2{{margin:.15rem 0;font-size:1.35rem}}
.badge{{padding:.25rem .55rem;border-radius:999px;background:#294d5b;color:#b9f3d8;font-size:.75rem;text-transform:uppercase;font-weight:800}}
.badge.dns_error,.badge.http_error,.badge.network_error,.badge.invalid_response,.badge.rate_limited{{background:#593a3a;color:#ffd6c9}}
.badge.skipped,.badge.empty{{background:#4f4854;color:#f1dfbc}}.badge.demo{{background:#64512d;color:#fff0b7}}
.message,.source{{line-height:1.5;color:#c3d4e2}}.source{{font-size:.83rem;overflow-wrap:anywhere;margin-bottom:.1rem}}
.table-scroll{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;text-align:left;min-width:580px}}
th,td{{padding:.7rem .5rem;border-bottom:1px solid #3a506a;vertical-align:top}}th{{font-size:.82rem;color:#a6becf}}
td{{font-size:.9rem}}.wrap{{overflow-wrap:anywhere;word-break:break-word}}footer{{color:#c3d4e2;line-height:1.6;padding:.2rem .5rem}}
@media(max-width:600px){{header{{padding:1.5rem 1rem}}.panel{{padding:.8rem}}}}
</style>
</head>
<body>
<header><div class="eyebrow">{mode}</div><h1>Dashboard OSINT Domain</h1><p><strong>{safe_domain}</strong> — {escape(intro)}</p></header>
<main><div class="meta"><span>Waktu dibuat: {safe_time} UTC</span><span>5 tipe record: A, AAAA, MX, NS, TXT</span><span>Metode: kueri DNS pasif</span></div>
<div class="stats">{summary}</div>
{sections}
<footer><p>DNS adalah data publik yang dapat berubah. TTL menunjukkan lama cache jawaban dalam detik, bukan umur domain. {escape(privacy_note)} Tidak ada pemindaian port, pencarian data pribadi, atau penilaian kerentanan.</p>
<p>Dokumentasi penyedia: <a href="{GOOGLE_DOCS}" rel="noopener noreferrer" target="_blank">Google Public DNS JSON API</a>. Dashboard ini adalah artefak latihan yang dibuat secara lokal.</p></footer></main>
</body></html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Buat dashboard HTML lokal dari DNS publik satu domain.")
    parser.add_argument("domain", nargs="?", help="Nama domain publik, misalnya example.com")
    parser.add_argument("--demo", action="store_true", help="Gunakan data buatan tanpa internet")
    args = parser.parse_args()
    if args.demo:
        if args.domain:
            parser.error("Mode --demo tidak menerima domain; data contoh sudah ditentukan.")
        domain = "contoh.test"
        results = demo_results()
        print("Mode DEMO: hanya data buatan; tidak ada kueri internet.")
    else:
        if not args.domain:
            parser.error("Masukkan domain atau gunakan --demo.")
        try:
            domain = validate_domain(args.domain)
        except ValueError as exc:
            parser.error(str(exc))
        print(f"Mengambil maksimal {len(RECORD_TYPES)} tipe record DNS publik untuk {domain} ...")
        results = collect_dns(domain)
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    page = render_html(domain, results, timestamp, demo=args.demo)
    output_dir = Path(__file__).resolve().parent / "output"
    output_dir.mkdir(exist_ok=True)
    mode = "DEMO-" if args.demo else ""
    output_path = output_dir / f"dashboard-{mode}{domain}-{now.strftime('%Y%m%dT%H%M%SZ')}.html"
    output_path.write_text(page, encoding="utf-8")
    print(f"Dashboard tersimpan: {output_path}")
    for result in results:
        print(f"  {result.record_type}: {result.state} - {result.message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
