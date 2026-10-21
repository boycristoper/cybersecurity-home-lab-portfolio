# 04 — GitHub dan CV

Profil penulis: [boycristoper](https://github.com/boycristoper). Nama repository yang disarankan: `cybersecurity-home-lab-portfolio`.

Status saat paket disusun: file lokal tersedia. Repository GitHub **belum dibuat/diunggah melalui panduan ini**. Tautan repo publik belum boleh disebut aktif sebelum unggah terverifikasi. Integrasi GitHub dapat digunakan setelah pemasangan/koneksi akun dikonfirmasi.

## Apa yang layak dipublikasikan sekarang?

Dokumentasi, script, PCAP sintetis dan laporan referensi dapat dipublikasikan sebagai starter project dengan status belajar yang jelas. Untuk menjadikannya portofolio pribadi yang kuat, jalankan workbook, isi log belajar dan tambahkan pengamatanmu. Lab VM tetap berstatus direncanakan sampai ada capture dan bukti nyata.

Capture sintetis sengaja aman untuk dibagikan dan tidak berasal dari jaringan pribadi. File di `evidence/pcaps/`, `terminal/`, `screenshots/` diabaikan Git. Pilih bukti yang telah diperiksa untuk `evidence/published/`. Jangan menambahkan image VM, ISO atau kredensial. Jika mau membagikan capture asli, periksa dahulu seluruh endpoint dan isi stream; ekspor salinan khusus lab, dokumentasikan redaksi dan hash baru bila ada.

## Unggah melalui GitHub

Jika menggunakan integrasi, pastikan akun tujuan `boycristoper` dan pilihan public/private sesuai keinginan sebelum membuat repo. Publikasikan isi folder proyek saja; jangan memasukkan dokumen riset perusahaan dari folder induk.

Alternatif melalui browser setelah kamu memilih membuat repo sendiri:

1. Masuk ke GitHub, buat repository dengan nama di atas dan deskripsi: `Beginner SOC portfolio: isolated home-lab guide, synthetic PCAP analysis, and reproducible evidence workflow.`
2. Pilih visibilitas yang kamu inginkan. Untuk ditautkan perekrut tanpa undangan, repo perlu dapat diakses publik.
3. Unggah **isi** folder proyek, termasuk dotfile `.gitignore` dan `.gitattributes`. Jangan mengunggah ZIP sebagai satu-satunya isi repo; ekstrak lebih dahulu agar README dan folder mudah ditinjau.
4. Periksa README, tautan relatif, PCAP sample, laporan dan tidak adanya file pribadi.
5. Setelah repo terbuka, verifikasi URL yang sebenarnya sebelum menaruhnya pada CV. Pin repo di profil jika kamu ingin menonjolkannya.

## Alternatif Git CLI

Jika repository lokal belum memiliki `.git`, jalankan dua perintah berikut dari folder proyek. Jika sudah, lewati bagian ini.

```powershell
git init -b main
git status --short
```

Setelah memeriksa berkas yang akan dimasukkan:

```powershell
git add README.md LEARNING_LOG.md .gitignore .gitattributes docs samples scripts reports tests evidence
git diff --cached --stat
git commit -m "Add cybersecurity lab starter and synthetic PCAP analysis"
```

Jika Git meminta identitas, gunakan nama/email GitHub milikmu atau email noreply yang diberikan GitHub; jangan menyalin email orang lain. Buat repo **kosong** pada akunmu sebelum menambahkan remote. GitHub akan menampilkan URL HTTPS dan instruksi push yang benar. Jangan masukkan password/token ke script atau README. Jika remote sudah ada, periksa dahulu dengan `git remote -v`, jangan menggantinya tanpa memahami tujuannya.

Panduan produk: [GitHub — menambahkan proyek lokal](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github), [GitHub — upload file](https://docs.github.com/en/repositories/working-with-files/managing-files/adding-a-file-to-a-repository).

## Kalimat CV sesuai tahap

### Sekarang, sebelum kamu menjalankan praktik

Jika perlu mencantumkan pembelajaran berjalan:

> **Cybersecurity Home Lab & Packet Analysis — proyek pembelajaran berjalan.** Menyiapkan lab VirtualBox–Kali–Metasploitable dan latihan analisis paket untuk memperkuat fondasi jaringan serta keamanan siber.

Jangan memakai kalimat bentuk selesai untuk konfigurasi atau analisis yang belum kamu lakukan.

### Setelah kamu menjalankan analisis contoh dan dapat menjelaskannya

> Menganalisis dataset PCAP sintetis berisi 38 frame untuk menjelaskan ARP, ICMP, handshake TCP, HTTP plaintext dan pola koneksi ke beberapa port; mendokumentasikan filter, frame bukti dan batas interpretasi.

Tambahkan `Wireshark` hanya jika kamu benar-benar memakai Wireshark untuk kegiatan itu. Jika menggunakan analyzer Python yang disediakan, sebutkan sebagai script pendamping yang ditinjau/dijalankan, bukan mengaku menulis sendiri seluruh kode.

### Setelah lab pribadi selesai dan ada bukti

> Membangun lab terisolasi menggunakan VirtualBox, Kali Linux dan Metasploitable 2; merekam serta menganalisis traffic ARP, ICMP, HTTP dan koneksi TCP dengan Wireshark, disertai laporan dan bukti yang dapat ditinjau.

Versi Inggris, setelah kegiatan yang sama benar-benar dikerjakan:

> Built an isolated VirtualBox lab with Kali Linux and Metasploitable 2; captured and analyzed ARP, ICMP, HTTP, and TCP traffic using Wireshark, documenting packet-level evidence and analysis limitations.

Letakkan pada bagian **Projects**, bukan pengalaman kerja. Isi bulan/tahun sesuai tanggal praktik sendiri, tambahkan tautan repo yang sudah aktif, serta cantumkan tools yang benar-benar digunakan. Jangan mengklaim menangani insiden perusahaan, menguji klien atau melakukan penetration test profesional dari latihan ini.
