# OSINT Domain Dashboard

Dashboard HTML lokal untuk mengumpulkan dan menampilkan informasi DNS publik dari satu domain. DNS menghubungkan nama domain dengan informasi seperti alamat IP dan server email. Proyek memakai Python standar, tanpa paket pip.

**Status praktik:** Boy telah menampilkan dashboard lima tipe record di Kali pada 23 Oktober 2026. Folder proyek terlihat kembali pada 26 Oktober 2026. Ringkasan pengamatan dan batas buktinya ada di [PRAKTIK.md](PRAKTIK.md). Kode awal dibantu AI; penjelasan lengkap dengan kata Boy sendiri belum dicatat.

## Mulai cepat

Dari root repo, jalankan di Terminal Kali:

```bash
cd osint-domain-dashboard
python3 -m unittest discover -s tests -v
python3 build_dashboard.py --demo
```

Tes dan mode demo tidak memerlukan internet. Demo memakai domain `contoh.test` dengan data fiktif. Buka berkas HTML pada path yang dicetak terminal; hasil berada di `output/` dan tidak dimasukkan ke Git.

Untuk mengambil data DNS publik dari domain contoh:

```bash
python3 build_dashboard.py example.com
```

Perintah langsung membutuhkan internet dan mengirim domain yang diminta serta IP klien ke Google Public DNS. Program membuat paling banyak lima kueri, lalu menampilkan sumber, waktu UTC, status, serta TTL. Respons HTTP 429 menghentikan kueri tambahan. Gunakan nama domain saja, tanpa URL, path, email, port, atau alamat IP.

`quick_dashboard.py` adalah versi singkat satu berkas untuk latihan awal; hasilnya bernama `dashboard.html`. Versi `build_dashboard.py` menyediakan validasi dan penanganan hasil yang lebih lengkap. Pada Windows, gunakan `python` bila `python3` tidak tersedia.

## Membaca hasil

| Record | Makna |
|---|---|
| A | Alamat IPv4 yang diumumkan DNS |
| AAAA | Alamat IPv6 yang diumumkan DNS |
| MX | Server tujuan email dan prioritasnya |
| NS | Server nama domain |
| TXT | Teks publik, termasuk sebagian kebijakan email |

TTL adalah lama jawaban dapat disimpan dalam cache, dalam detik. Hasil merupakan snapshot resolver pada waktu pengambilan dan bisa berubah. Status `OK` menunjukkan hasil kueri yang ditampilkan, bukan jaminan domain aman. Tidak ada pemindaian port atau pencarian data pribadi. Kegagalan kueri tidak membuktikan suatu record tidak ada.

## Dokumentasi

- [Catatan praktik yang telah terlihat](PRAKTIK.md)
- [Template untuk hasil dan penjelasan pribadi](LAPORAN-TEMPLATE.md)
- [Kode collector lengkap](build_dashboard.py)
- [Google Public DNS JSON API](https://developers.google.com/speed/public-dns/docs/doh/json)
