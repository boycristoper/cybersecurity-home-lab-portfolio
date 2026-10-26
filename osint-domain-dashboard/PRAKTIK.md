# Catatan praktik OSINT Domain Dashboard

**Pelaksana:** Boy Cristoper. **Pencatatan:** 26 Oktober 2026, Asia/Jakarta. Catatan ini diringkas dengan bantuan AI dari bukti praktik yang sebelumnya dibagikan Boy, bukan hasil menjalankan ulang kueri.

## Yang sudah terlihat

Pada 23 Oktober 2026, Boy memperlihatkan respons DNS tipe A untuk `example.com` melalui browser dan Python di Kali. Screenshot berikutnya menampilkan halaman lokal berjudul Dashboard OSINT DNS, sumber Google Public DNS JSON API, waktu pengambilan `2026-10-23 10:18:21 UTC`, serta baris A, AAAA, MX, NS, dan TXT.

Pengamatan pada screenshot mencakup dua IPv4 pada record A, dua IPv6 pada AAAA, MX bernilai `0 .`, dua server NS, serta TXT termasuk `v=spf1 -all`. TTL terlihat pada tiap baris. Label hasil pada dashboard adalah `OK`; respons JSON lengkap untuk semua tipe dan perintah pembuat halaman tidak terlihat seluruhnya. Nilai tersebut adalah snapshot saat itu, bukan informasi domain terkini.

Pada 26 Oktober 2026, keluaran `ls ~/projects` kembali memperlihatkan folder `osint-domain-dashboard` di Kali. Ini memastikan keberadaan folder; bukan bukti program dijalankan ulang pada tanggal tersebut.

## Kontribusi dan batas

Kode starter, mode demo, dan panduan disiapkan dengan bantuan AI. Boy menjalankan latihan DNS dan menampilkan dashboard lokal. Analisis tertulis dengan kata Boy sendiri belum dicatat. Versi collector lengkap dalam repo tidak boleh dianggap sudah dijalankan di Kali hanya karena versi singkat telah ditampilkan.

Screenshot mentah tidak disertakan dalam publikasi ini karena juga memuat tab atau aplikasi pribadi. Catatan ini menggunakan bagian keluaran yang relevan. Tidak ada email pribadi, kredensial, atau trafik jaringan lain yang dipublikasikan.

Latihan ini mempelajari informasi DNS publik, bukan penilaian keamanan domain. Isi [template laporan](LAPORAN-TEMPLATE.md) untuk mencatat langkah aktual berikutnya dan penjelasan pribadi.
