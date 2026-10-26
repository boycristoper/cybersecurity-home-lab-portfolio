"""Aturan edukatif untuk password dummy; bukan estimator jaminan keamanan."""

from __future__ import annotations

import unicodedata

MIN_LENGTH = 15
MAX_LENGTH = 256
VERSION = "1.0"

# Contoh kecil yang dikurasi untuk demonstrasi, bukan basis data kebocoran.
_BLOCKLIST_EXAMPLES = (
    "123456", "12345678", "123456789", "1234567890",
    "123456789012345", "1234567890123456",
    "password", "password123", "password123456789", "passwordpassword",
    "qwerty", "qwerty123", "qwertyuiopasdfgh",
    "admin", "admin123", "letmein", "iloveyou",
    "rahasia", "rahasia123", "selamatdatang",
)
BLOCKLIST = frozenset(unicodedata.normalize("NFC", item).casefold()
                      for item in _BLOCKLIST_EXAMPLES)
NOTICE = ("Hasil ini hanya pemeriksaan aturan lokal yang terbatas, bukan jaminan "
          "password kuat, aman, unik, atau belum pernah bocor.")


def policy_info() -> dict[str, object]:
    return {"min_length": MIN_LENGTH, "max_length": MAX_LENGTH,
            "blocklist_size": len(BLOCKLIST), "normalization": "NFC",
            "version": VERSION}


def has_full_repetition(text: str) -> bool:
    """Cari pengulangan penuh karakter/motif pendek, tanpa mencetak motif."""
    folded = text.casefold()
    if len(folded) >= 4 and len(set(folded)) == 1:
        return True
    if len(folded) < 8:
        return False
    for width in range(2, min(8, len(folded) // 2) + 1):
        if len(folded) % width == 0 and folded == folded[:width] * (len(folded) // width):
            return True
    return False


def has_obvious_sequence(text: str) -> bool:
    """Heuristik urutan; dapat false positive dan tidak mencakup semua pola."""
    folded = text.casefold()
    for row, width in (("0123456789", 4), ("abcdefghijklmnopqrstuvwxyz", 4),
                       ("qwertyuiop", 5), ("asdfghjkl", 5), ("zxcvbnm", 5)):
        for direction in (row, row[::-1]):
            if any(direction[start:start + width] in folded
                   for start in range(len(direction) - width + 1)):
                return True
    return False


def check_password(password: str) -> dict[str, object]:
    """Proses hanya dalam memori; hasil tidak menyertakan input atau fragmennya."""
    if not isinstance(password, str):
        raise ValueError("Password latihan harus berupa teks.")
    if len(password) > MAX_LENGTH * 4:
        raise ValueError("Input terlalu panjang; batasnya 256 karakter setelah normalisasi NFC.")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in password):
        raise ValueError("Input berisi karakter Unicode yang tidak valid.")
    normalized = unicodedata.normalize("NFC", password)
    length = len(normalized)
    if not normalized or normalized.isspace():
        raise ValueError("Masukkan password latihan yang tidak kosong atau seluruhnya spasi.")
    if length > MAX_LENGTH:
        raise ValueError("Input terlalu panjang; batasnya 256 karakter setelah normalisasi NFC.")

    long_enough = length >= MIN_LENGTH
    blocked = normalized.casefold() in BLOCKLIST
    repeated = has_full_repetition(normalized)
    sequenced = has_obvious_sequence(normalized)
    checks = [
        {"id": "length", "label": "Panjang minimal 15 karakter",
         "passed": long_enough,
         "detail": ("Memenuhi panjang profil latihan ini." if long_enough else
                    "Panjang belum mencapai 15 karakter pada profil latihan ini.")},
        {"id": "blocklist", "label": "Tidak cocok daftar contoh lokal",
         "passed": not blocked,
         "detail": ("Tidak cocok dengan seluruh entri daftar contoh yang kecil." if not blocked else
                    "Seluruh input cocok dengan satu entri daftar contoh lokal.")},
        {"id": "repetition", "label": "Tidak ada pengulangan penuh sederhana",
         "passed": not repeated,
         "detail": ("Aturan ini tidak menemukan pengulangan penuh sederhana." if not repeated else
                    "Terlihat pengulangan penuh karakter atau motif pendek.")},
        {"id": "sequence", "label": "Tidak ada urutan sederhana yang dikenali",
         "passed": not sequenced,
         "detail": ("Aturan ini tidak menemukan urutan contoh yang dikenali." if not sequenced else
                    "Terlihat urutan huruf, angka, atau tombol keyboard yang mudah dikenali.")},
    ]
    reasons = []
    suggestions = []
    if not long_enough:
        reasons.append("Panjang masih di bawah 15 karakter pada profil latihan ini.")
        suggestions.append("Buat contoh yang lebih panjang, misalnya beberapa kata yang tidak berpola.")
    if blocked:
        reasons.append("Seluruh input cocok dengan daftar contoh password umum lokal.")
        suggestions.append("Pilih contoh lain yang tidak umum; perubahan huruf besar saja tidak cukup.")
    if repeated:
        reasons.append("Ada pengulangan penuh karakter atau motif pendek.")
        suggestions.append("Tambahkan variasi kata atau karakter, bukan mengulang blok yang sama.")
    if sequenced:
        reasons.append("Ada urutan huruf, angka, atau keyboard yang dikenali aturan.")
        suggestions.append("Hindari urutan sederhana; gunakan susunan yang lebih sulit diperkirakan.")

    if not long_enough or blocked or repeated:
        status, label = "needs_improvement", "Perlu diperbaiki"
    elif sequenced:
        status, label = "review", "Perlu ditinjau"
    else:
        status, label = "limited_pass", "Lolos pemeriksaan terbatas"
        reasons.append("Tidak ditemukan indikator dari empat aturan yang tersedia.")
        suggestions.append("Untuk akun nyata, gunakan password unik; password manager dapat membantu.")
    suggestions.append("Contoh publik dalam proyek ini hanya untuk latihan, bukan untuk akun sungguhan.")
    return {
        "status": status, "label": label, "length": length,
        "min_length": MIN_LENGTH, "max_length": MAX_LENGTH,
        "checks": checks, "reasons": reasons, "suggestions": suggestions,
        "notice": NOTICE, "blocklist_size": len(BLOCKLIST), "normalization": "NFC",
    }
