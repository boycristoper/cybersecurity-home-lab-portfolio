"""Pemeriksaan awal dua indikator pada email .eml lokal (tanpa internet)."""

from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
import re
import sys


def domain(header):
    address = parseaddr(str(header))[1]
    return address.rsplit("@", 1)[1].lower().rstrip(".") if "@" in address else None


def check(path):
    with Path(path).open("rb") as file:
        raw = file.read(512_001)
    if len(raw) > 512_000:
        raise ValueError("email melebihi batas 512.000 byte")
    message = BytesParser(policy=policy.default).parsebytes(raw)
    reasons = []
    sender = domain(message.get("From", ""))
    reply = domain(message.get("Reply-To", ""))
    if sender and reply and sender != reply:
        reasons.append(f"Domain Reply-To ({reply}) berbeda dari From ({sender}).")

    content = [str(message.get("Subject", ""))]
    for part in message.walk():
        if part.get_content_type() != "text/plain" or part.get_content_disposition() == "attachment":
            continue
        try:
            body = part.get_content()
        except (LookupError, UnicodeError, ValueError, TypeError):
            continue
        if isinstance(body, str):
            content.append(body[:100_000])
    text = "\n".join(content)[:100_000]
    match = re.search(r"\b(segera|mendesak|urgent)\b", text, re.IGNORECASE)
    if match:
        reasons.append(f"Ada kata mendesak: {match.group(0)!r}.")
    return reasons


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Pemakaian: python3 quick_detector.py contoh.eml")
    try:
        findings = check(sys.argv[1])
    except (OSError, ValueError) as error:
        sys.exit(f"Gagal membaca email: {error}")
    print("Status:", "perlu ditinjau" if findings else "tidak ada indikator dari aturan terbatas")
    for finding in findings:
        print("-", finding)
    print("Catatan: hasil ini bukan bukti email aman atau phishing.")
