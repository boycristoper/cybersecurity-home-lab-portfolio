# Analisis referensi — dataset PCAP sintetis

**Asal data:** dibuat oleh `scripts/generate_reference.py`; tidak ada VM atau server nyata yang dihubungi. Laporan ini adalah jawaban contoh yang diverifikasi secara programatis, bukan laporan praktik pribadi Boy Cristoper melalui GUI Wireshark.

## Identitas dan metode

- Berkas: `samples/synthetic-reference.pcap`
- SHA256: `239f4a867e088150aa60806609902a355e38923ceb0e32a468aa30e224b90130`
- Waktu skenario: 1 Januari 2026, 00:00:00–00:00:04,010 UTC; tetap, bukan tanggal eksekusi lab.
- Endpoint buatan: client `192.168.77.10`, target `192.168.77.20`.
- Metode penyusunan: pembacaan paket offline dengan analyzer Python; pemeriksaan format, checksum dan respons koneksi melalui unittest. GUI Wireshark/TShark belum dijalankan dalam penyusunan paket.
- Bukti yang dapat direproduksi: [JSON ringkasan](reference-summary.json), [CSV per frame](reference-frames.csv), [manifest dan deskripsi frame](../samples/manifest.json).

## Ringkasan hasil

| Ukuran | Hasil |
|---|---|
| Total frame | 38 |
| Durasi skenario | 4,01 detik |
| ARP / ICMP / TCP | 2 / 4 / 32 frame, kategori eksklusif |
| Awal pesan HTTP di dalam TCP | 2, bukan tambahan terhadap total 38 |
| SYN awal | 6 paket pada 6 tuple koneksi berbeda di dataset ini |
| Port tujuan SYN unik | 21, 22, 80, 445, 3306, 9999 |
| Respons SYN/ACK | Port 80, 21, 22, 3306 |
| Respons RST/ACK | Port 445, 9999 |
| Checksum IPv4/TCP/ICMP gagal | Tidak ditemukan pada dataset buatan ini |

## Temuan 1: resolusi ARP dan ICMP

Frame **1** berisi ARP request dari client, mencari `192.168.77.20`, dengan tujuan Ethernet broadcast. Frame **2** membalas pemetaan target ke MAC sintetis `02:00:00:00:00:20`; MAC client adalah `02:00:00:00:00:10`.

Frame **3–4** dan **5–6** adalah dua pasang ICMP echo request/reply, identifier 77, sequence 1 dan 2. Selisih request/reply masing-masing 10 ms adalah nilai yang ditentukan generator, bukan pengukuran performa jaringan nyata.

Interpretasi: dataset menunjukkan tahapan pengenalan alamat link layer dan uji konektivitas. Tidak membuktikan kualitas koneksi atau konfigurasi host nyata.

## Temuan 2: HTTP tanpa TLS

Tuple koneksi: `192.168.77.10:51000 → 192.168.77.20:80`.

| Bukti | Frame |
|---|---|
| SYN → SYN/ACK → ACK | 7 → 8 → 9 |
| Request `GET / HTTP/1.1` | 10 |
| Respons `HTTP/1.1 200 OK` | 12 |
| Penutupan koneksi | 14–16 |

Request, header dan body respons terdapat sebagai plaintext. Body menyatakan bahwa halaman adalah latihan sintetis. Ini memperagakan keterbacaan HTTP tanpa TLS; tidak menunjukkan kebocoran data pengguna nyata. Untuk layanan nyata, penggunaan HTTPS dan validasi konfigurasi TLS adalah tindak lanjut yang relevan, bukan perubahan yang dilakukan dalam proyek ini.

## Temuan 3: pola percobaan koneksi ke beberapa port

Dalam interval skenario 2,000–4,010 detik, client melakukan lima rangkaian koneksi ke target yang sama:

| Port | Port sumber | SYN | Balasan | Observasi |
|---|---|---|---|---|
| 21 | 52000 | 17 | 18 SYN/ACK | Target merespons tahap pembukaan koneksi |
| 22 | 52001 | 23 | 24 SYN/ACK | Target merespons tahap pembukaan koneksi |
| 445 | 52002 | 29 | 30 RST/ACK | Penolakan koneksi diamati |
| 3306 | 52003 | 31 | 32 SYN/ACK | Target merespons tahap pembukaan koneksi |
| 9999 | 52004 | 37 | 38 RST/ACK | Penolakan koneksi diamati |

Interpretasi: pola ini menyerupai probing beberapa port pada skenario yang sengaja dibuat. Asal-usul dataset menjelaskan bahwa aktivitas adalah latihan. Tidak ada bukti penyerang, keberhasilan eksploitasi, login, transfer berkas atau malware.

Nomor port tidak cukup untuk mengidentifikasi aplikasi atau versinya. Tidak adanya respons pada capture lain juga tidak cukup untuk menyatakan port pasti filtered. Data nyata memerlukan konteks, observasi retransmisi, cakupan capture dan aturan jaringan.

## Batas analisis

Dataset tidak berisi DNS, UDP, IPv6, TLS, loss atau retransmisi yang sengaja dibuat. HTTP berada dalam satu segmen per pesan; analyzer tidak melakukan TCP reassembly. Respons port dan waktu pada dataset tidak boleh disalin sebagai hasil Metasploitable nyata. Hasil checksum baik pada sampel ini tidak berarti semua capture VM nyata akan sama, karena offloading dapat memengaruhi tampilan checksum.

Langkah berikutnya: jalankan workbook di Wireshark, lalu rekam traffic dua VM sesuai panduan dan tulis laporan terpisah menggunakan frame milik capture sendiri.
