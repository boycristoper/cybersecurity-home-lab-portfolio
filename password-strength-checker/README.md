# Password Strength Checker — lab lokal

**Penulis/pelaksana lab:** Boy Cristoper

**Status:** kode dan dokumentasi disiapkan dengan bantuan AI; hasil praktik Boy untuk proyek ini belum dicatat. Hasil pengujian pengembangan dicatat terpisah di TESTING.md setelah dijalankan.

Aplikasi edukatif untuk memeriksa kelemahan umum pada password latihan dan menjelaskan alasannya. Tersedia tampilan browser dan mode terminal. Python standar saja; tanpa pip, akun, atau layanan eksternal.

## Jalankan di Kali

Dari root repo portofolio yang sudah diambil dari GitHub:

```bash
cd password-strength-checker
python3 -m unittest discover -s tests -v
python3 app.py
```

Jika ringkasan tes menunjukkan OK, buka `http://127.0.0.1:8766` di browser pada mesin yang menjalankan Python. Biarkan terminal server tetap berjalan. Tekan Ctrl+C untuk berhenti. Di Windows, gunakan `python` jika `python3` tidak tersedia.

Untuk alternatif ZIP melalui folder bersama milik Boy, ikuti [PANDUAN.md](PANDUAN.md). Folder proyek tersebut sudah terlihat di Kali pada 26 Oktober 2026, tetapi belum ada hasil praktik aplikasi Boy yang dicatat.

Untuk mode terminal tanpa browser:

```bash
python3 app.py --cli
```

Ketik password latihan saat diminta. Karakter tidak ditampilkan oleh getpass pada terminal yang mendukungnya. Jangan menaruh password sebagai argumen perintah. Program berhenti jika input tersembunyi tidak didukung.

## Fitur

- Pemeriksaan panjang (profil latihan minimum 15, maksimum 256 code point setelah normalisasi NFC).
- Pencocokan seluruh input terhadap daftar kecil contoh password umum lokal.
- Deteksi pengulangan sederhana dan peringatan urutan yang mudah ditebak.
- Alasan hasil, saran perbaikan, dan empat indikator yang bisa diperiksa.
- Dukungan spasi/Unicode; tidak mewajibkan campuran huruf besar, angka, dan simbol.
- Tombol contoh dummy publik, tampil/sembunyikan input, serta hapus input/hasil.

## Cara membaca hasil

| Kategori | Makna terbatas |
|---|---|
| Perlu diperbaiki | Panjang kurang, cocok daftar contoh, atau pengulangan sederhana terdeteksi |
| Perlu ditinjau | Panjang mencukupi tetapi ada urutan/pola yang ditandai aturan |
| Lolos pemeriksaan terbatas | Tidak terkena pemeriksaan yang tersedia; bukan bukti kuat, aman, atau belum bocor |

Program tidak menghitung persentase keamanan, entropi yang diklaim pasti, maupun waktu pembobolan. Daftar lokal bersifat demonstrasi dan tidak mengecek database kebocoran.

## Alur data

Browser mengirim input melalui POST JSON ke proses Python di loopback Kali. Python memeriksa input dalam memori dan mengembalikan kategori, panjang, indikator, serta saran tanpa mengembalikan password. Program tidak menyimpan input, tidak mencatatnya di log, dan tidak mengirimnya ke layanan eksternal. Ini bukan analisis browser-only: server lokal menerima input.

Gunakan password dummy yang dibuat khusus untuk latihan. Semua contoh bawaan bersifat publik dan tidak untuk dipakai pada akun. Kode ini adalah lab lokal, bukan sistem autentikasi produksi atau implementasi bersertifikasi NIST.

## Berkas yang dipelajari

| Berkas | Peran |
|---|---|
| checker.py | Aturan pemeriksaan dan umpan balik tanpa input mentah |
| app.py | Server lokal dan mode terminal getpass |
| static/index.html | Struktur antarmuka |
| static/app.css | Tampilan |
| static/app.js | Interaksi dan permintaan ke API lokal |
| tests/ | Pengujian evaluator dan HTTP |
| PANDUAN.md | Langkah lengkap, arti tampilan, dan dokumentasi portofolio |
| LAPORAN-TEMPLATE.md | Catatan praktik pribadi yang belum diisi |

## Rujukan

Pilihan panjang 15 untuk profil latihan password sebagai satu-satunya faktor, penerimaan spasi/Unicode, serta tidak adanya aturan komposisi merujuk [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html#passwords). Ambang 15 bukan jaminan kekuatan; penggunaan MFA memiliki konteks berbeda. Pemeriksaan pola tambahan adalah heuristik edukatif proyek ini, bukan klaim kepatuhan terhadap keseluruhan pedoman.

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#implement-proper-password-strength-controls)
- [Python getpass](https://docs.python.org/3.13/library/getpass.html)
