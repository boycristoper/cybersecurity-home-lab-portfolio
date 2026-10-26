"""Periksa beberapa tanda pada berkas .eml lokal tanpa membuka tautan/lampiran."""

import argparse
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path
import re
from urllib.parse import urlsplit


MAX_EMAIL_BYTES = 512_000
MAX_TEXT_CHARS = 100_000
URGENCY_PHRASES = ("segera", "mendesak", "urgent", "akun akan diblokir")
RISKY_EXTENSIONS = (".exe", ".scr", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".hta", ".lnk")


def domain_from_address(address):
    """Ambil domain dari satu alamat email yang bentuknya sederhana."""
    email_address = parseaddr(str(address))[1]
    local, separator, domain = email_address.rpartition("@")
    domain = domain.lower().rstrip(".")
    if local and separator and re.fullmatch(r"[a-z0-9.-]+", domain) and "." in domain:
        return domain
    return None


class LinkReader(HTMLParser):
    """Baca teks dan tujuan tautan HTML; tidak mengakses jaringan."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.visible_text = []
        self._href = None
        self._label = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._label = []

    def handle_data(self, data):
        self.visible_text.append(data)
        if self._href is not None:
            self._label.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(("".join(self._label), self._href))
            self._href = None
            self._label = []


def http_host(url):
    """Kembalikan host hanya untuk URL HTTP(S) absolut."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() in ("http", "https"):
            return parsed.hostname.lower().rstrip(".") if parsed.hostname else None
    except ValueError:
        pass
    return None


def analyze_file(path):
    """Kembalikan status dan alasan. Aturan ini bukan pembuktian phishing."""
    with Path(path).open("rb") as file:
        raw = file.read(MAX_EMAIL_BYTES + 1)
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError("berkas melebihi batas 512.000 byte")

    message = BytesParser(policy=policy.default).parsebytes(raw)
    indicators = []

    from_domain = domain_from_address(message.get("From", ""))
    reply_addresses = getaddresses([str(message.get("Reply-To", ""))])
    reply_domains = sorted({domain for _, address in reply_addresses
                            if (domain := domain_from_address(address))})
    if from_domain:
        for reply_domain in reply_domains:
            if reply_domain != from_domain:
                indicators.append(
                    f"Reply-To memakai domain {reply_domain}, berbeda dari From {from_domain}."
                )

    text_parts = [str(message.get("Subject", ""))]
    html_parts = []
    for part in message.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            if filename:
                suffix = Path(filename).suffix.lower()
                if suffix in RISKY_EXTENSIONS:
                    indicators.append(
                        f"Nama lampiran {filename!r} memakai ekstensi {suffix}."
                    )
            continue  # Isi lampiran tidak dibuka atau dieksekusi.

        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError, ValueError, TypeError):
            continue
        if not isinstance(content, str):
            continue
        content = content[:MAX_TEXT_CHARS]
        if part.get_content_type() == "text/html":
            html_parts.append(content)
        else:
            text_parts.append(content)

    for html in html_parts:
        reader = LinkReader()
        reader.feed(html)
        text_parts.append(" ".join(reader.visible_text))
        for label, href in reader.links:
            shown = re.search(r"https?://[^\s<>]+", label, flags=re.IGNORECASE)
            visible_host = http_host(shown.group(0).rstrip(".,;)]}")) if shown else None
            target_host = http_host(href)
            if visible_host and target_host and visible_host != target_host:
                indicators.append(
                    f"Teks tautan menampilkan {visible_host}, tetapi targetnya {target_host}."
                )

    all_text = " ".join(text_parts).casefold()
    found_phrases = [phrase for phrase in URGENCY_PHRASES if phrase in all_text]
    if found_phrases:
        indicators.append("Ada bahasa mendesak: " + ", ".join(found_phrases) + ".")

    status = ("perlu ditinjau" if indicators
              else "tidak ada indikator dari aturan terbatas")
    return {"status": status, "indicators": indicators}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("email_file", type=Path, help="berkas .eml lokal yang akan diperiksa")
    args = parser.parse_args()
    try:
        result = analyze_file(args.email_file)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Gagal membaca email: {error}\n")

    print("Status:", result["status"])
    if result["indicators"]:
        print("Alasan:")
        for indicator in result["indicators"]:
            print("-", indicator)
    else:
        print("Aturan sederhana ini tidak menemukan indikator yang diperiksa.")
    print("Kesimpulan terbatas: hasil ini bukan bukti email aman atau phishing.")
    print("Jangan buka tautan/lampiran; verifikasi lewat kanal resmi bila ragu.")


if __name__ == "__main__":
    main()
