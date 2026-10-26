# Portofolio Mini Project Cybersecurity

**Boy Cristoper** · Fresh graduate Teknik Informatika · Pembelajaran cybersecurity melalui WPU dan praktik lab Kali Linux.

Lima proyek pribadi untuk mempelajari data DNS, indikator phishing, monitoring jaringan, pemeriksaan password, dan konfigurasi layanan web. Portofolio ini mencatat fungsi alat dan kontribusi praktik yang benar-benar dilakukan. Kode awal disiapkan dengan bantuan AI.

## Proyek pilihan

| Proyek | Fungsi | Status praktik Boy |
|---|---|---|
| [OSINT Domain Dashboard](osint-domain-dashboard/README.md) | Menampilkan record DNS publik, TTL, sumber, dan waktu pengambilan | Dashboard lima tipe record sudah diperlihatkan di Kali |
| [Phishing Email Detector](phishing-email-detector/README.md) | Triase indikator pada email latihan secara offline | Versi dasar dua indikator diuji dengan dua email fiktif |
| [Network Monitoring Dashboard](network-monitoring-dashboard/README.md) | Memantau laju RX/TX dan ringkasan socket TCP/UDP lokal | Dashboard, ping loopback 10/10, dan lima tes sudah diperlihatkan di Kali |
| [Password Strength Checker](password-strength-checker/README.md) | Menjelaskan kelemahan umum password latihan | Folder tersedia di Kali; praktik aplikasinya belum tercatat |
| [Mini Vulnerability Scanner](mini-vulnerability-scanner/README.md) | Memeriksa konfigurasi dasar satu layanan web lab | Folder tersedia di Kali; praktik pemindaian belum tercatat |

Status diperbarui **26 Oktober 2026**. Screenshot daftar folder mengonfirmasi kelima direktori ada di Kali; keberadaan folder belum membuktikan seluruh kode sudah dijalankan. Rangkuman pribadi dan laporan praktik masih dapat dilengkapi.

## Mulai dari GitHub

```bash
git clone https://github.com/boycristoper/cybersecurity-home-lab-portfolio.git
cd cybersecurity-home-lab-portfolio
```

Masuk ke **satu folder proyek** dan ikuti README di dalamnya. Semua proyek memakai Python standar tanpa paket pip. Dashboard monitoring jaringan membutuhkan Linux karena membaca `/proc`. Pencarian DNS langsung membutuhkan internet; mode demo OSINT dan contoh email bekerja offline.

| Folder proyek | Perintah awal dari dalam folder | Hasil |
|---|---|---|
| `osint-domain-dashboard` | `python3 build_dashboard.py --demo` | Berkas HTML dengan data fiktif berlabel demo |
| `phishing-email-detector` | `python3 quick_detector.py samples/contoh-perlu-ditinjau.eml` | Alasan triase pada contoh fiktif |
| `network-monitoring-dashboard` | `python3 app.py` | Dashboard di `http://127.0.0.1:8765` |
| `password-strength-checker` | `python3 app.py` | Dashboard di `http://127.0.0.1:8766` |
| `mini-vulnerability-scanner` | `python3 app.py --with-demo` | Dashboard di `http://127.0.0.1:8770` beserta dua layanan latihan |

Alamat loopback dibuka pada mesin yang menjalankan aplikasi. Di Windows, gunakan `python` jika `python3` tidak tersedia. Tekan `Ctrl+C` di terminal server untuk berhenti.

## Pengujian dan dokumentasi

Jalankan seluruh suite dalam proses terpisah dari root repo:

```bash
python3 scripts/check_projects.py
```

Perintah ini menjalankan tes yang sudah disediakan setiap proyek. Tes OSINT memakai respons tiruan; tes HTTP memakai loopback lokal. Hasil tes pengembangan tidak menggantikan praktik Boy di Kali.

- [Status dan sumber verifikasi](STATUS-PROYEK.md)
- [Validasi susunan portofolio](VALIDASI.md)
- [Bagian mini project untuk CV](cv/PROYEK-CV.md)

## Lingkup kontribusi

Proyek ini adalah pembelajaran pribadi, bukan pengalaman kerja profesional. Praktik yang sudah ditunjukkan meliputi menjalankan kode di Kali, melihat hasil DNS, menguji email fiktif, dan mengamati statistik jaringan. Password checker serta scanner dicatat sebagai proyek dalam pembelajaran sampai praktiknya diperlihatkan.

Laporan tidak menyatakan email pasti aman, password pasti kuat, atau sistem bebas celah. Pengujian dilakukan pada contoh latihan dan layanan lokal. Screenshot yang memuat percakapan pribadi tidak dimasukkan ke repo.
