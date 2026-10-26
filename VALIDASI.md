# Validasi portofolio pada 26 Oktober 2026

Pengujian berikut dilakukan oleh asisten pada Windows dengan Python 3.12.10. Ini validasi kode dalam susunan repo lima proyek, bukan hasil menjalankan ulang aplikasi di VM Kali milik Boy.

## Pengujian otomatis

```text
python scripts/check_projects.py
```

| Proyek | Jumlah tes | Hasil aktual |
|---|---:|---|
| OSINT Domain Dashboard | 10 | OK |
| Phishing Email Detector | 5 | OK |
| Network Monitoring Dashboard | 5 | OK |
| Password Strength Checker | 19 | OK |
| Mini Vulnerability Scanner | 22 | OK |
| Total | 61 | Seluruh suite lulus |

Setiap suite berjalan dalam proses Python terpisah agar modul bernama `app` tidak berbenturan. Tes DNS menggunakan respons tiruan, email memakai data fiktif, dan pengujian HTTP menggunakan server loopback lokal. Tes tidak melakukan pemindaian jaringan lain atau kueri DNS eksternal.

## Perbaikan kode

- Collector OSINT kini mengembalikan status `invalid_response` saat struktur JSON terlalu dalam atau tipe record jawaban tidak berupa integer. Dua regresi ditambahkan untuk mencegah error tidak tertangani.
- Dashboard monitoring jaringan kini memeriksa satu header Host yang sesuai dengan localhost dan port server, sebelum mengirim API atau aset. Tes HTTP yang sudah ada diperluas untuk menolak Host eksternal, hilang, dan ganda.

Lima tes monitoring yang pernah dijalankan Boy di Kali adalah pengujian versi sebelumnya. Lulusnya pemeriksaan baru di Windows tidak menyatakan bahwa perbaikan terbaru sudah dipasang atau diuji di VM Kali.

## Pemeriksaan publikasi

Tautan dokumentasi lokal ditinjau setelah pemindahan proyek. Berkas cache Python, output HTML otomatis, screenshot percakapan pribadi, dan email pribadi tidak disertakan. Dua email `.eml` yang dipublikasikan adalah fixture latihan fiktif. Pratinjau scanner dan password checker berlabel pengembangan asisten.

Keberadaan lima folder proyek di Kali sudah diperlihatkan pada 26 Oktober 2026. Status tiap proyek dan batas klaim CV dicatat pada [STATUS-PROYEK.md](STATUS-PROYEK.md).
