# 02 — Capture dan analisis paket milik lab sendiri

Status dokumen: **prosedur latihan**, belum merupakan laporan hasil eksekusi. Capture referensi sintetis pada `samples/` berbeda dengan capture nyata yang akan kamu buat di sini.

Selesaikan [setup home lab](01-home-lab.md) dahulu. Kali menggunakan `192.168.77.10/24`, Metasploitable 2 `192.168.77.20/24`, dan kedua VM hanya memiliki satu NIC Internal Network `labnet` tanpa gateway.

Tujuan praktik: menjelaskan bagaimana ARP menemukan MAC target, ICMP menguji koneksi, TCP membangun koneksi HTTP, serta HTTP mengirim request dan response. Latihan tambahan membandingkan percobaan koneksi ke beberapa port target dengan traffic web biasa.

## 1. Siapkan folder dan catatan sesi di Kali

Gunakan working copy repository ini di Kali. Jika belum ada, buat folder kerja sementara dengan nama yang sama; gabungkan hasil nyata dengan repository setelah sesi selesai. Seluruh perintah Linux berikut dijalankan di **Kali**, bukan di Windows PowerShell.

```bash
mkdir -p "$HOME/cybersecurity-home-lab-portfolio"
cd "$HOME/cybersecurity-home-lab-portfolio"
mkdir -p evidence/pcaps evidence/terminal evidence/screenshots evidence/published
date -Is | tee evidence/terminal/01-session.txt
uname -r | tee -a evidence/terminal/01-session.txt
wireshark --version | head -n 1 | tee -a evidence/terminal/01-session.txt
dumpcap --version | head -n 1 | tee -a evidence/terminal/01-session.txt
ip -br -4 address | tee -a evidence/terminal/01-session.txt
ip -4 route | tee -a evidence/terminal/01-session.txt
```

Catat zona waktu Kali. Jika berbeda dari WIB, tulis perbedaannya saat menyusun timeline; jangan mengganti timestamp capture agar terlihat sama dengan contoh.

## 2. Pilih interface capture yang benar

```bash
ip -br link
sudo dumpcap -D
```

Cocokkan NIC yang memiliki `.10` dengan nama yang ditampilkan `dumpcap -D`. Jangan memilih `any`, `lo`, interface Wi-Fi Windows, atau adapter NAT. Ganti contoh `eth0` berikut dengan nama NIC **Kali milikmu**:

```bash
CAPTURE_IF='eth0'
```

`dumpcap -i` menerima nama interface yang tercantum dalam daftar `-D`; `-w` menentukan file output. File pcapng adalah format bawaan dumpcap. [Manual resmi dumpcap](https://www.wireshark.org/docs/man-pages/dumpcap.html)

## 3. Capture baseline — terminal A

Biarkan kedua VM menyala. Di terminal A Kali, jalankan:

```bash
sudo dumpcap -i "$CAPTURE_IF" -p -f 'arp or (host 192.168.77.10 and host 192.168.77.20)' -a duration:120 -w evidence/pcaps/01-baseline.pcapng
```

Capture berhenti otomatis setelah 120 detik, atau tekan Ctrl+C setelah latihan selesai. `-p` tidak meminta promiscuous mode; Kali hanya perlu melihat traffic yang dibuat/diterimanya sendiri. Filter capture menyimpan ARP dan pertukaran IPv4 antara dua IP lab. **Ini filter capture**, yang berbeda sintaksnya dengan filter display Wireshark. Jangan mengganti `-f` dengan `http` karena filter capture tidak menggunakan nama dissector HTTP. [Wireshark: capture dan display filter](https://www.wireshark.org/docs/man-pages/tshark.html)

Tunggu pesan bahwa capture telah dimulai sebelum membuat traffic.

## 4. Buat traffic normal — terminal B

Buka terminal B di Kali. Masuk ke folder kerja yang sama. Variabel shell terminal A tidak otomatis tersedia di terminal B: tetapkan ulang nama interface yang benar.

```bash
cd "$HOME/cybersecurity-home-lab-portfolio"
LAB_IF='eth0'
date -Is | tee evidence/terminal/01-traffic.txt
sudo ip neigh flush to 192.168.77.20 dev "$LAB_IF"
ping -c 3 192.168.77.20 | tee -a evidence/terminal/01-traffic.txt
curl --noproxy '*' --connect-timeout 3 --max-time 10 -v http://192.168.77.20/ -o /dev/null 2>&1 | tee -a evidence/terminal/01-traffic.txt
date -Is | tee -a evidence/terminal/01-traffic.txt
```

Menghapus entri neighbor **target lab ini saja** memicu resolusi ARP baru. `curl` mengambil halaman root tanpa login dan mengabaikan proxy environment. Tidak ada DNS lookup yang diperlukan karena URL menggunakan alamat IP langsung.

Kembali ke terminal A dan tunggu capture selesai. Jika file sudah pernah ada, pakai nama baru untuk percobaan ulang; jangan menimpa evidence sesi yang ingin dilaporkan.

## 5. Buka dan periksa capture

Di Kali, setelah dumpcap berhenti:

```bash
sudo chown "$(id -u):$(id -g)" evidence/pcaps/01-baseline.pcapng
capinfos evidence/pcaps/01-baseline.pcapng | tee evidence/terminal/01-capture-info.txt
sha256sum evidence/pcaps/01-baseline.pcapng | tee evidence/terminal/01-baseline.sha256
wireshark evidence/pcaps/01-baseline.pcapng
```

Jalankan Wireshark sebagai pengguna biasa. `capinfos` membantu memeriksa jenis file, waktu, durasi, jumlah paket, dan interface yang tersedia pada metadata. Hash mengikat catatanmu ke berkas yang dianalisis. [Manual capinfos](https://www.wireshark.org/docs/man-pages/capinfos.html)

Di Wireshark, masukkan filter berikut **satu per satu** pada kolom display filter, lalu tekan Enter. Filter display hanya mengubah tampilan; paket tetap berada dalam berkas. [Wireshark: display filter](https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html)

| Filter display | Yang diperiksa dan dicatat |
| --- | --- |
| `arp` | ARP request dan reply. Siapa bertanya alamat MAC `.20`, siapa menjawab? Catat nomor frame dan MAC nyata. |
| `icmp` | Echo request/reply. Cocokkan identifier dan sequence; jangan menyimpulkan jumlah paket tanpa menghitung. |
| `tcp.port == 80` | Handshake, transfer data, dan penutupan koneksi HTTP. Ikuti satu pasangan IP/port yang sama. |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN awal dari client. Balasan SYN/ACK diperiksa pada stream yang sama. |
| `http.request` | Method, URI, Host, dan alamat pengirim request. |
| `http.response` | Status code dan header respons yang benar-benar tertangkap. |
| `ip.addr == 192.168.77.20` | Pertukaran IPv4 dengan target. ARP tidak ikut karena bukan paket IPv4. |

Untuk melihat isi HTTP, pilih frame request lalu **Analyze → Follow → TCP Stream**, atau klik kanan → Follow → TCP Stream. Catat `tcp.stream` milik koneksi yang kamu pilih, jangan menganggap stream selalu bernomor 0. [Wireshark: Follow Stream](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html)

Lihat juga **Statistics → Protocol Hierarchy** dan **Statistics → Conversations → TCP**. Jika opsi **Limit to display filter** aktif, angka statistik mungkin hanya mencerminkan paket yang cocok dengan filter; tulis kondisi ini pada laporan. [Wireshark: Conversations](https://www.wireshark.org/docs/wsug_html_chunked/ChStatConversations.html)

### Pertanyaan analisis yang wajib dijawab

1. Frame mana yang membuktikan pemetaan IP `.20` ke MAC? Apa beda alamat broadcast dan unicast di sini?
2. Mana tiga frame handshake TCP untuk request HTTP yang kamu pilih? Catat sumber/tujuan, port, dan flag.
3. Apa method dan URI HTTP? Apa status code balasannya? Adakah data aplikasi yang terbaca tanpa dekripsi?
4. Mengapa halaman HTTP biasa ini tidak membuktikan serangan? Apa keterbatasan mengamati capture dari satu endpoint?
5. Apa yang terjadi jika ARP tidak terlihat? Periksa kapan capture dimulai serta apakah cache neighbor sudah terisi.

HTTP tanpa TLS menampilkan header/body yang tertangkap sebagai plaintext. Hubungkan observasi itu ke rekomendasi penggunaan HTTPS untuk aplikasi nyata; jangan menulis bahwa semua traffic internet dapat dibaca dengan cara yang sama.

## 6. Ekspor ringkasan yang dapat diperiksa ulang

Contoh berikut membaca capture offline, bukan mengambil traffic tambahan:

```bash
tshark -r evidence/pcaps/01-baseline.pcapng -q -z io,phs > evidence/terminal/01-protocol-hierarchy.txt
tshark -r evidence/pcaps/01-baseline.pcapng -Y 'http.request || http.response' -T fields -E header=y -e frame.number -e frame.time_relative -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.response.code > evidence/terminal/01-http.tsv
```

TShark memakai `-r` untuk membaca berkas, `-Y` untuk display filter, dan `-T fields`/`-e` untuk mengekspor field. [Manual TShark](https://www.wireshark.org/docs/man-pages/tshark.html)

Jumlah frame, waktu, port client, header, dan pembagian segmen bisa berbeda pada setiap sesi. Hasil tidak perlu sama dengan capture referensi sintetis. Untuk analyzer Python repository, ikuti panduan analisis dan konversi format pada dokumen berikutnya; capture nyata di sini berformat **pcapng**.

## 7. Opsional — observasi percobaan koneksi terbatas

Kerjakan setelah baseline selesai. Gunakan working copy repository yang memiliki `scripts/probe_lab.py`; tidak perlu memasang Metasploit atau menggunakan exploit. Script dibatasi ke **192.168.77.20**, menghubungi sekali per port `21`, `22`, `445`, `3306`, dan `9999`, dengan timeout dan jeda. Ia hanya membuat koneksi TCP lalu menutupnya.

Di terminal A, tentukan ulang `CAPTURE_IF` jika membuka terminal baru, lalu:

```bash
sudo dumpcap -i "$CAPTURE_IF" -p -f 'arp or (host 192.168.77.10 and host 192.168.77.20)' -a duration:45 -w evidence/pcaps/02-probes.pcapng
```

Setelah capture dimulai, di terminal B:

```bash
python3 scripts/probe_lab.py | tee evidence/terminal/02-probes.txt
```

Setelah capture berhenti:

```bash
sudo chown "$(id -u):$(id -g)" evidence/pcaps/02-probes.pcapng
sha256sum evidence/pcaps/02-probes.pcapng | tee evidence/terminal/02-probes.sha256
wireshark evidence/pcaps/02-probes.pcapng
```

Analisis filter SYN awal, SYN/ACK, dan `tcp.flags.reset == 1`. Cocokkan hasil program dengan paket yang benar-benar tertangkap. Port `9999` dipilih sebagai kandidat pembanding; jangan menganggapnya pasti tertutup sebelum memeriksa respons. RST dapat menunjukkan penolakan koneksi; timeout dapat disebabkan pemfilteran, koneksi terputus, atau target tidak merespons. Port terbuka tidak otomatis membuktikan kerentanan yang dapat dieksploitasi.

Dalam laporan, sebut aktivitas ini **percobaan koneksi yang dibuat sendiri di lab**. Beberapa SYN ke port berbeda dapat menjadi petunjuk probing dalam konteks lain, tetapi capture ini tidak membuktikan adanya penyerang.

## 8. Evidence dan kriteria selesai

Simpan bukti asli di `evidence/pcaps/`, `evidence/terminal/`, dan `evidence/screenshots/`. File mentah tidak otomatis dipublikasikan; pilih salinan yang sudah kamu periksa untuk `evidence/published/` sesuai aturan repository.

| Bukti | Yang membuatnya meyakinkan |
| --- | --- |
| Catatan sesi | Tanggal, zona waktu, versi alat, NIC, serta alamat lab. |
| Screenshot ARP | Filter, nomor frame, dan detail request/reply yang kamu jelaskan. |
| Screenshot TCP | SYN → SYN/ACK → ACK dalam koneksi HTTP yang sama. |
| Screenshot HTTP | Request dan response yang menjadi dasar kesimpulan. |
| Ringkasan teks | Statistik/TSV nyata, hash berkas, dan referensi nomor frame. |
| Laporan analisis | Tujuan, metode, observasi, interpretasi, keterbatasan, dan langkah berikutnya dengan kata-katamu sendiri. |

Jangan mengunggah VM image, capture jaringan pribadi/kantor, password akun, token, atau screenshot halaman pribadi. Untuk proyek ini, raw capture seharusnya hanya berisi dua VM latihan; periksa endpoint dan isi stream sebelum memilih evidence publik. Tulis dengan jelas jika melakukan redaksi screenshot; hash asli tidak berlaku untuk file yang sudah diubah.

Proyek baru dapat disebut **sudah dikerjakan** di CV setelah kamu membuat capture sendiri, menjawab pertanyaan di atas, serta menautkan evidence dan laporan. File panduan dan capture sintetis dapat membantu latihan, tetapi bukan bukti pengalaman menjalankan home lab.

Rujukan resmi diperiksa 21 Oktober 2026.
