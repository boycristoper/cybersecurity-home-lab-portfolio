# Network Monitoring Dashboard

Dashboard lokal untuk mengamati laju trafik antarmuka VM Kali sendiri dan ringkasan socket TCP/UDP. Halaman diperbarui setiap detik menggunakan Python standar dan statistik `/proc` Linux. Tidak memerlukan pip, sudo, atau packet capture.

**Status praktik:** dashboard sudah dijalankan Boy di Kali, diuji dengan ping loopback 10/10 balasan, dan lima tes otomatis berakhir `OK`. Kode awal dan tes dibantu AI; ringkasan dengan kata Boy sendiri masih perlu dilengkapi. Lihat [PRAKTIK.md](PRAKTIK.md).

## Jalankan di Kali atau Linux

Dari root repo:

```bash
cd network-monitoring-dashboard
python3 -m unittest discover -s tests -v
python3 app.py
```

Buka `http://127.0.0.1:8765` di browser pada Kali yang menjalankan Python. Biarkan terminal server terbuka dan tekan `Ctrl+C` untuk berhenti. Runtime dashboard membutuhkan Linux; jangan menganggap Windows mempunyai sumber statistik `/proc` yang sama.

## Arti tampilan

| Bagian | Makna |
|---|---|
| Data masuk RX | Byte diterima per detik pada antarmuka terpilih |
| Data keluar TX | Byte dikirim per detik pada antarmuka terpilih |
| Paket masuk dan keluar | Dua laju paket per detik, bukan jumlah pengguna |
| Grafik | Riwayat 60 sampel terakhir selama aplikasi berjalan |
| TCP terhubung | Entri socket TCP dalam keadaan ESTABLISHED |
| TCP menunggu | Entri socket TCP LISTEN |
| Socket UDP | Entri socket UDP pada saat sampel diambil |

Laju dihitung dari selisih counter dibagi selang waktu dua sampel. Sampel pertama membentuk baseline; counter yang reset memerlukan baseline baru. Memilih antarmuka mengubah kartu laju dan grafik, sedangkan ringkasan socket mencakup seluruh namespace jaringan VM.

## Latihan loopback

Pilih antarmuka `lo`, lalu di terminal Kali kedua jalankan:

```bash
ping -c 10 127.0.0.1
```

`lo` adalah jalur komunikasi di dalam mesin sendiri. RX dan TX dapat sama dan garis grafik dapat bertumpuk. Dashboard juga memakai loopback saat browser meminta data, sehingga trafik tetap dapat terlihat setelah ping selesai. Puncak grafik tidak otomatis seluruhnya berasal dari ping.

## Batas hasil dan dokumentasi

Dashboard membaca counter antarmuka dan tabel socket, bukan isi paket atau seluruh lalu lintas LAN. Jumlah socket bukan jumlah serangan. Ping memakai ICMP; keberhasilannya tidak mengharuskan jumlah socket TCP/UDP bertambah. Halaman tidak menampilkan endpoint tujuan atau payload dan tidak menyimpan sampel ke disk.

- [Catatan praktik Boy dan hasil tes Kali](PRAKTIK.md)
- [Template untuk pengamatan pribadi](LAPORAN-TEMPLATE.md)
- [Statistik jaringan Linux](https://www.kernel.org/doc/html/latest/networking/statistics.html)
- [Tabel TCP proc](https://www.kernel.org/doc/html/latest/networking/proc_net_tcp.html)
