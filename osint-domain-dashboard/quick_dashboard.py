"""Starter kecil: ambil DNS publik satu domain dan buat dashboard HTML lokal."""

from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import urlopen


DOMAIN = "example.com"
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")
TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}
rows = []

for requested_type in RECORD_TYPES:
    source = "https://dns.google/resolve?" + urlencode(
        {"name": DOMAIN, "type": requested_type}
    )
    try:
        with urlopen(source, timeout=10) as response:
            raw = response.read(1_000_001)
        if len(raw) > 1_000_000:
            raise ValueError("respons terlalu besar")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("respons bukan objek JSON")
        status = payload.get("Status")
        answers = payload.get("Answer", [])
        if status != 0:
            rows.append((requested_type, "—", "—", f"DNS status {status}", source))
        elif not isinstance(answers, list):
            rows.append((requested_type, "—", "—", "format Answer salah", source))
        elif not answers:
            rows.append((requested_type, "—", "—", "tidak ada jawaban", source))
        else:
            for answer in answers[:100]:
                if not isinstance(answer, dict):
                    continue
                record_type = TYPE_NAMES.get(answer.get("type"), requested_type)
                rows.append((record_type, answer.get("data", "—"),
                             answer.get("TTL", "—"), "OK", source))
        print(f"{requested_type}: DNS status {status}, {len(answers) if isinstance(answers, list) else 0} jawaban")
    except HTTPError as error:
        rows.append((requested_type, "—", "—", f"HTTP {error.code}", source))
        print(f"{requested_type}: HTTP {error.code}")
        if error.code == 429:
            print("Batas permintaan tercapai; berhenti.")
            break
    except (URLError, OSError, ValueError, TypeError) as error:
        rows.append((requested_type, "—", "—", f"gagal: {error}", source))
        print(f"{requested_type}: gagal: {error}")

table_rows = "\n".join(
    "<tr>" + "".join(f"<td>{escape(str(value))}</td>" for value in row[:4])
    + f'<td><a href="{escape(row[4], quote=True)}">Sumber</a></td></tr>'
    for row in rows
)
timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
page = f"""<!doctype html>
<html lang="id"><head><meta charset="utf-8"><title>Dashboard OSINT DNS</title>
<style>body{{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 16px;
background:#101b2e;color:#e7eef8}}a{{color:#8cd5ff}}table{{width:100%;border-collapse:collapse;
background:#1b2a41}}th,td{{border:1px solid #43536b;padding:9px;text-align:left;
overflow-wrap:anywhere}}th{{background:#243c59}}.scroll{{overflow-x:auto}}</style></head>
<body><h1>Dashboard OSINT DNS</h1><p>Domain: <strong>{escape(DOMAIN)}</strong><br>
Waktu pengambilan: {escape(timestamp)}<br>Sumber: Google Public DNS JSON API</p>
<div class="scroll"><table><thead><tr><th>Tipe</th><th>Data publik</th><th>TTL (detik)</th>
<th>Status</th><th>URL sumber</th></tr></thead><tbody>{table_rows}</tbody></table></div>
<p>Ini snapshot DNS publik, bukan penilaian keamanan. TTL adalah lama cache jawaban.</p>
</body></html>"""
Path("dashboard.html").write_text(page, encoding="utf-8")
print("Selesai: dashboard.html")
