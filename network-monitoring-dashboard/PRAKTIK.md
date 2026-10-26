# Catatan praktik Network Monitoring Dashboard

**Pelaksana:** Boy Cristoper. **Tanggal pencatatan praktik:** 25 Oktober 2026, Asia/Jakarta. **Pembaruan inventaris:** 26 Oktober 2026.

Catatan ini diringkas dengan bantuan AI dari screenshot praktik Boy di Kali, bukan simulasi trafik yang dibuat ulang oleh asisten. Log VM menampilkan 24 Oktober 2026; sinkronisasi jam VM belum diperiksa.

## Kegiatan yang telah terlihat

Boy mengekstrak paket ke folder proyek, menjalankan server lokal, dan membuka dashboard di Firefox Kali pada `127.0.0.1:8765`. Antarmuka `lo` dipilih untuk pengujian lokal. Pada 26 Oktober 2026, folder `network-monitoring-dashboard` masih terlihat dalam daftar proyek di Kali.

Perintah ping yang dijalankan:

```bash
ping -c 10 127.0.0.1
```

Transkripsi hasil yang terlihat:

```text
10 packets transmitted, 10 received, 0% packet loss, time 9220ms
rtt min/avg/max/mdev = 0.018/0.043/0.139/0.035 ms
```

Target adalah loopback Kali sendiri. Hasil ini tidak menguji internet atau perangkat lain.

Screenshot dashboard memperlihatkan satu sampel RX dan TX masing-masing 11,8 KiB/det dan laju paket masing-masing 12 pkt/det. Browser juga berkomunikasi dengan dashboard melalui loopback, sehingga angka tersebut tidak dapat dianggap seluruhnya hasil ping. Ringkasan socket adalah potret namespace VM pada saat sampel, bukan jumlah serangan.

## Tes di Kali

Boy menjalankan `python3 -m unittest discover -s tests -v` dari folder proyek. Ringkasan yang terlihat:

```text
Ran 5 tests in 0.514s

OK
```

Tes mencakup parsing counter, baseline dan reset, agregasi socket, fixture IPv4/IPv6, serta API dan aset HTTP lokal. Hasil ini berlaku pada kasus uji yang tersedia, bukan jaminan penggunaan produksi.

## Kontribusi dan bukti

Kode awal, tampilan, tes, dan panduan disiapkan dengan bantuan AI. Boy menjalankan server, mengamati antarmuka, melakukan ping, dan menjalankan tes di Kali. Penjelasan lengkap dengan kata Boy sendiri dan perubahan kode mandiri belum dicatat.

Screenshot mentah tetap disimpan lokal karena juga memperlihatkan aplikasi atau percakapan pribadi. Publikasi ini memakai transkripsi keluaran yang relevan. Isi [template laporan](LAPORAN-TEMPLATE.md) untuk pengamatan berikutnya dan analisis pribadi.
