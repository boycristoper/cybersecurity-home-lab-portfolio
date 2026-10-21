# 03 — Workbook analisis Wireshark

Mulai dengan `samples/synthetic-reference.pcap`. Semua angka jawaban contoh berasal dari **dataset buatan**, bukan capture VM Boy Cristoper. Timestamp skenario tetap dan tidak membuktikan kapan seseorang melakukan praktik.

## A. Pastikan berkas yang dianalisis

Di folder repository, PowerShell:

```powershell
Get-FileHash -LiteralPath samples/synthetic-reference.pcap -Algorithm SHA256
```

Hash yang diharapkan:

```text
239f4a867e088150aa60806609902a355e38923ceb0e32a468aa30e224b90130
```

Cocokkan dengan `samples/manifest.json`. Hash berbeda berarti angka/frame pada laporan referensi belum tentu berlaku. Tulis provenance, hash, versi Wireshark dan tanggal kamu membuka file pada log belajar.

## B. Periksa keseluruhan capture

1. Buka file memakai **File → Open** di Wireshark.
2. Kosongkan display filter. Pilih **Statistics → Capture File Properties** untuk melihat total frame dan waktu.
3. Periksa **Statistics → Protocol Hierarchy** dan **Conversations → TCP**. Pastikan statistik tidak sedang dibatasi display filter.
4. Catat hasil pengamatanmu sebelum membaca laporan jawaban.

Target pemeriksaan contoh: 38 frame, dua IP privat, durasi 4,01 detik, enam percakapan TCP. Pada Protocol Hierarchy, HTTP adalah bagian dari TCP; jumlah per lapisan tidak boleh dijumlahkan sembarangan. Analyzer pendamping mengelompokkan protokol secara eksklusif menjadi ARP 2, ICMP 4, TCP 32.

## C. Telusuri pertanyaan dan bukti

| Langkah | Display filter | Yang harus kamu jelaskan |
|---|---|---|
| 1. Resolusi alamat | `arp` | IP yang dicari, MAC client/target, broadcast request dan unicast reply. |
| 2. Uji konektivitas | `icmp` | Pasangan echo request/reply memakai identifier dan sequence. |
| 3. Koneksi HTTP | `tcp.port == 80` | Handshake, payload dan penutupan koneksi. |
| 4. Request web | `http.request` | Method, URI, Host dan siapa client-nya. |
| 5. Balasan web | `http.response` | Status code dan body yang terlihat. |
| 6. Koneksi awal | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Jumlah SYN dan port tujuan unik; bukan bukti penyerang. |
| 7. Respons koneksi | `tcp.flags.syn == 1 && tcp.flags.ack == 1` | Pasangkan dengan tuple dan ACK dari SYN sebelumnya. |
| 8. Koneksi ditolak | `tcp.flags.reset == 1` | Pasangan SYN dan RST/ACK. |
| 9. Probe contoh | `ip.src == 192.168.77.10 && tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport != 80` | Lima port yang dihubungi pada jendela waktu 2–4 detik skenario. |

Gunakan `tcp.flags.syn == 1`; `tcp.flags.syn` saja hanya memeriksa keberadaan field boolean dan dapat mencocokkan paket saat nilainya 0. Sintaks di atas adalah **display filter**, bukan capture filter. [Manual Wireshark](https://www.wireshark.org/docs/man-pages/wireshark-filter)

Pilih request HTTP lalu klik kanan **Follow → TCP Stream**. Jelaskan mengapa pesan bisa dibaca: koneksi HTTP ini tidak memakai TLS. Jangan menyimpulkan HTTPS dapat dibaca dengan cara yang sama.

Saat menghitung SYN, bedakan paket dengan percobaan koneksi unik. Capture nyata dapat mengandung retransmisi. Ketika hanya melihat port, jangan langsung menamai aplikasi atau versinya: perlu bukti handshake aplikasi/banner lain yang sah.

## D. Periksa ulang dengan alat offline

Python, dari folder repo:

```powershell
python scripts/analyze_pcap.py samples/synthetic-reference.pcap --label synthetic-reference --json reports/reference-summary.json --csv reports/reference-frames.csv
```

Bandingkan frame di CSV dengan Wireshark. Ringkasan Python dibuat dari byte paket; script tidak mengubah capture, menjalankan jaringan, atau membuka VM. Ia tidak mendekode DNS/UDP/IPv6/VLAN, tidak menyusun ulang fragmen/stream, dan hanya mengenali awal pesan HTTP yang berada dalam satu segmen. Untuk capture nyata dan keputusan analisis gunakan Wireshark/TShark.

Jika TShark tersedia (contoh di Kali):

```bash
tshark -r samples/synthetic-reference.pcap -q -z io,phs
tshark -r samples/synthetic-reference.pcap -Y 'http.request || http.response' -T fields -E header=y -e frame.number -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.response.code
tshark -r samples/synthetic-reference.pcap -Y 'tcp.flags.syn == 1 && tcp.flags.ack == 0' -T fields -E header=y -e frame.number -e frame.time_relative -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport
```

Command TShark ini disediakan untuk praktik pengguna. Penyusunan paket tidak mengklaim telah menjalankannya atau membuka GUI Wireshark.

### Capture lab asli berformat PCAPNG

Wireshark dan TShark membaca PCAPNG langsung. Analyzer Python latihan ini hanya membaca PCAP klasik dengan link type Ethernet. Bila ingin mencoba analyzer pada capture Ethernet lab sendiri, pertahankan berkas asli dan buat salinan:

```bash
editcap -F pcap evidence/pcaps/01-baseline.pcapng evidence/pcaps/01-baseline-classic.pcap
python3 scripts/analyze_pcap.py evidence/pcaps/01-baseline-classic.pcap --label personal-lab --json evidence/terminal/01-summary.json --csv evidence/terminal/01-frames.csv
```

Konversi dapat membuang metadata PCAPNG. Catat hash **kedua file** dan file mana yang digunakan untuk analisis. Jika capture berisi link type yang tidak didukung, gunakan TShark, jangan memaksanya menjadi Ethernet.

## E. Tulis hasil dengan kata-katamu sendiri

Untuk setiap temuan, isi:

1. **Observasi:** hal yang terlihat pada frame tertentu.
2. **Interpretasi:** penjelasan yang didukung observasi.
3. **Keterbatasan:** hal yang belum dapat dibuktikan dari capture.
4. **Tindak lanjut:** langkah validasi atau perbaikan yang relevan.

Contoh yang baik: "SYN frame 29 diikuti RST/ACK frame 30 dari arah sebaliknya; koneksi ditolak pada skenario ini. Nomor port 445 saja tidak membuktikan aplikasi yang berjalan."

Bandingkan jawaban dengan [laporan referensi](../reports/reference-analysis.md) setelah menyelesaikan analisis. Hasil capture lab sendiri tidak harus sama dengan dataset sintetis.

Referensi: [TCP fields](https://www.wireshark.org/docs/dfref/t/tcp.html), [ARP fields](https://www.wireshark.org/docs/dfref/a/arp.html), [ICMP fields](https://www.wireshark.org/docs/dfref/i/icmp.html), [HTTP fields](https://www.wireshark.org/docs/dfref/h/http.html), [TShark](https://www.wireshark.org/docs/man-pages/tshark.html), [editcap](https://www.wireshark.org/docs/man-pages/editcap.html).
