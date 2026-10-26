# Validasi pengembangan — bukan praktik Boy di Kali

**Tanggal pencatatan:** 25 Oktober 2026, Asia/Jakarta.

**Lingkungan:** Windows, Python 3.12.10, browser in-app. Target nyata pada pengujian ini hanya server demo loopback buatan proyek. Target privat lain dan layanan produksi tidak dipindai. Praktik Boy di VM Kali belum dilakukan untuk proyek ini.

## Tes otomatis yang benar-benar dijalankan

```text
python -m unittest discover -s tests -v

Ran 22 tests in 1.303s

OK
```

Komposisi: 10 tes aturan, 6 tes jaringan dengan mock, dan 6 tes HTTP lokal nyata. Cakupan meliputi pembatasan IP dan port, nilai header, penghilangan nama/nilai cookie, respons yang dibatasi ukurannya, tidak mengikuti redirect, satu permintaan GET tetap, TLS tanpa fallback, status koneksi gagal, validasi JSON, Host/Origin, kunci satu pemeriksaan, rute statis, serta perbandingan demo nyata. Koneksi loopback untuk suite lengkap dijalankan dengan akses lokal yang disetujui setelah sandbox menolak koneksi klien.

Pada integrasi awal, dua tes menemukan pemeriksaan penanda cookie yang terlalu umum dan pelepasan kunci scan yang terjadi setelah respons terkirim. Penanda dummy dibuat khusus dan kunci dilepas setelah pemindaian selesai sebelum respons dikirim. Suite lengkap di atas lulus setelah perbaikan tersebut. Tidak ada perubahan logika setelah hasil ini selain dokumentasi.

## Pengamatan browser nyata

Sebelum publikasi GitHub pada tanggal yang sama, isi scanner dipindahkan ke root repo dan suite lengkap dijalankan lagi dari susunan tersebut: `Ran 22 tests in 1.200s`, lalu `OK`. Berkas runtime dan UI sama dengan paket pengembangan; README publik serta cara mengambil proyek dirapikan.

| Tindakan | Pengamatan aktual |
|---|---|
| Buka dashboard dengan `--with-demo` | Konfigurasi terbaca, target tetap `127.0.0.1`, tombol demo tersedia |
| Periksa HTTP port 8771 | HTTP 200; review 5, observed 1, info 3, not_checked 1 |
| Pilih profil 8772 | Hasil lama tersembunyi sebelum pemeriksaan baru |
| Periksa HTTP port 8772 | HTTP 200; review 1, observed 5, info 3, not_checked 1 |
| Filter Perlu ditinjau pada 8772 | Hanya kartu atribut cookie; Secure belum ada, HttpOnly dan SameSite terlihat |
| Unduh laporan profil 8771 | File JSON terbentuk melalui tombol browser; nama/nilai cookie tidak disertakan |
| HTTPS ke demo HTTP port 8772 | TLS gagal, HTTP belum terbaca, 8 pemeriksaan belum dilakukan |
| Bersihkan hasil | Panel hasil tersembunyi kembali |
| Lebar 1280 px | Lebar konten 1265 px sesuai area dokumen; empat kolom ringkasan |
| Lebar 390 px | Lebar konten 375 px sesuai area dokumen; tidak melebar horizontal |
| Sintaks JavaScript | `node --check static/app.js` selesai tanpa kesalahan |

Pratinjau memakai port dashboard bawaan 8770. Override viewport untuk uji responsif sudah dikembalikan. Server pratinjau dihentikan setelah validasi.

`preview-development.jpg` adalah screenshot pengembangan asisten, menampilkan hasil HTTP port 8772 dengan filter Perlu ditinjau. `examples/lab-awal-development.json` berasal dari unduhan browser pada pengujian 8771. Keduanya adalah bukti pengembangan memakai data demo, bukan bukti praktik Kali atau temuan pada sistem nyata milik Boy.

## Batas yang masih berlaku

TLS sukses diuji melalui mock konteks terverifikasi; demo bawaan hanya HTTP. Kegagalan TLS terhadap demo HTTP diuji nyata. Tidak ada audit sertifikat HTTPS nyata, pemindaian sistem operasi, pemetaan CVE, pengujian eksploitasi, atau jaminan seluruh skenario protokol tercakup. Kehadiran header hanya pengamatan terbatas dan laporan tidak menyatakan target aman.
