# Catatan verifikasi paket

Tanggal pemeriksaan: 21 Oktober 2026 WIB. Runtime: Python 3.12.10, Windows.

Perintah yang benar-benar dijalankan dari folder repository:

```text
python scripts/generate_reference.py
python scripts/analyze_pcap.py samples/synthetic-reference.pcap --label synthetic-reference --json reports/reference-summary.json --csv reports/reference-frames.csv
python -m unittest discover -s tests -v
```

Hasil pengujian: enam test lulus, meliputi:

1. Reproduksi deterministik dan jumlah frame/protokol serta respons TCP yang diharapkan.
2. Pemeriksaan wire format dan checksum melalui penjumlahan independen.
3. Deteksi checksum IPv4 yang sengaja dirusak.
4. Penolakan file terpotong, PCAPNG dan link type yang tidak didukung.
5. Pembacaan variasi header big endian dan timestamp nanodetik.
6. Empat SYN/ACK yang benar terdeteksi; ACK atau port balasan yang salah tidak dianggap pasangan koneksi.

SHA256 dataset: `239f4a867e088150aa60806609902a355e38923ceb0e32a468aa30e224b90130`.

Hasil analisis: 38 frame (ARP 2, ICMP 4, TCP 32), dua awal pesan HTTP, enam SYN awal, empat respons SYN/ACK, dua respons RST/ACK, tanpa checksum gagal pada paket sintetis. Tautan lokal Markdown dan pasangan code fence juga diperiksa.

Belum dilakukan melalui penyusunan paket: menjalankan VM, membuat capture lab nyata, menjalankan TShark, atau mengamati file melalui GUI Wireshark. Tes Python tidak membuktikan semua perilaku dissector Wireshark; pemeriksaan GUI adalah bagian workbook pengguna.
