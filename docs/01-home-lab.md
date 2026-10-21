# 01 — Membangun home lab yang terisolasi

Status dokumen: **panduan praktik, bukan bukti bahwa lab sudah dijalankan**. Isi hasil nyata dan screenshot setelah kamu mengerjakannya. Rancangan ini untuk Windows x86-64 sebagai host, Kali sebagai mesin analisis, dan Metasploitable 2 sebagai target latihan milik sendiri.

## Hasil yang akan kamu buktikan

- Dua VM dapat berkomunikasi pada jaringan internal yang sama.
- Kamu memahami IP, subnet, interface, routing, dan perbedaan host dengan guest.
- Target rentan tidak terhubung ke internet atau jaringan rumah/kantor.
- Ada catatan konfigurasi, hasil pengujian, dan screenshot yang bisa ditinjau perekrut.

Pemeriksaan host secara read-only pada saat persiapan menemukan VirtualBox sudah terpasang dan VM bernama **`Kali linux`** sudah terdaftar. Belum ada konfigurasi VM yang diubah atau VM yang dinyalakan untuk proyek ini. **Gunakan Kali yang ada bila memang VM belajar milikmu**; jangan mengimpor ulang atau mengganti disk VM itu. Jika berisi pekerjaan penting, simpan dahulu dan buat snapshot sebelum mengubah pengaturan lab. Langkah unduh/impor di bawah berlaku hanya jika belum mempunyai Kali yang dapat digunakan.

Host memiliki sekitar 8 GB RAM; saat pemeriksaan, RAM bebas hanya sekitar 1,4 GB. Tutup aplikasi yang berat sebelum menyalakan dua VM. Rencana hemat untuk lab ini: Kali 1–2 vCPU, RAM 2 GB; target 1 vCPU, RAM 512–768 MB. Kali dengan 1,5 GB mungkin terasa lambat. Jika Windows tetap kekurangan RAM, kerjakan analisis capture referensi terlebih dahulu atau tambah RAM sebelum menjalankan kedua guest. Angka alokasi ini saran lab, bukan spesifikasi minimum resmi produk. Sisakan juga ruang disk untuk image, ekstraksi, dan snapshot.

## Topologi dan batas praktik

```text
Windows host — VirtualBox
    │
    └── Internal Network: labnet (tanpa gateway)
          ├── Kali:            192.168.77.10/24
          └── Metasploitable2: 192.168.77.20/24

Tidak ada adapter NAT/Bridged pada kedua VM selama latihan.
```

**Internal Network** menghubungkan VM yang memakai nama jaringan sama. Host Windows dan LAN tidak menjadi anggota jaringan itu. **Host-only** juga melibatkan host; **Bridged** menempatkan VM pada jaringan fisik. Karena target sengaja rentan, rancangan ini memakai Internal Network. Wireshark dijalankan **di Kali**, sebab interface Wi-Fi/Ethernet Windows tidak melihat lalu lintas internal ini. [Oracle: mode jaringan](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/networkingdetails.html)

Ruang lingkup: hanya Kali `.10` dan target `.20`. Jangan mengganti target menjadi IP publik, situs perusahaan, atau perangkat orang lain. Tidak diperlukan eksploit, brute force, pencurian kredensial, atau malware untuk menyelesaikan proyek ini.

## 1. Ambil aplikasi dan image resmi

Jika aplikasi/image belum ada, unduh di Windows:

1. [VirtualBox untuk Windows](https://www.virtualbox.org/wiki/Downloads). Pada host yang diperiksa aplikasi sudah ada, jadi tidak perlu instal ulang. Paket dasar cukup; Extension Pack tidak diperlukan untuk latihan ini.
2. [Kali — Pre-built Virtual Machines](https://www.kali.org/get-kali/#kali-virtual-machines): pilih **VirtualBox**, arsitektur x86-64/amd64. Gunakan image rilis stabil yang tersedia saat kamu mengunduh.
3. [Metasploitable 2 — dokumentasi Rapid7](https://docs.rapid7.com/metasploit/metasploitable-2/): ikuti tautan unduhan yang dirujuk di halaman tersebut. Pilih Metasploitable **2**, bukan installer Metasploit Framework atau Metasploitable 3.

Untuk image Kali, ikuti [panduan verifikasi resmi](https://www.kali.org/docs/introduction/download-official-kali-linux-images/). Di PowerShell, hash lokal dapat dihitung dengan contoh berikut; ganti path dengan berkas yang benar:

```powershell
Get-FileHash -LiteralPath 'C:\path\ke\kali-virtualbox-amd64.7z' -Algorithm SHA256
```

Bandingkan dengan SHA256 untuk **berkas dan versi yang sama** pada sumber resmi. Jangan menyalin hash versi lain dari tutorial. Catat nama berkas, URL sumber, tanggal unduh, dan hasil verifikasi di laporan. Jika sumber Metasploitable tidak menyediakan hash terverifikasi, tulis keterbatasan itu; hash yang kamu hitung sendiri hanya membantu pemeriksaan konsistensi berkas.

## 2. Tambahkan Kali dan siapkan alat sebelum target dijalankan

1. **Jika memakai VM `Kali linux` yang sudah ada**, lewati proses impor. Pastikan itu VM yang benar, simpan pekerjaan, dan ambil snapshot sebelum mengubah pengaturan. Gunakan kredensial VM milikmu, bukan mengasumsikan password default.
2. **Hanya untuk image baru:** ekstrak arsip Kali dengan aplikasi yang mendukung `.7z`. Di VirtualBox, pilih **Add/Open** dan buka `.vbox` hasil ekstraksi. Image pre-built memakai konfigurasi ini; tidak perlu disk kosong atau instalasi ISO. [Kali: impor image VirtualBox](https://www.kali.org/docs/virtualization/import-premade-virtualbox/)
3. Periksa RAM/CPU dan adapter sebelum start. Khusus image pre-built resmi baru, login bawaan adalah `kali` / `kali`; ubah password melalui `passwd` setelah login.
4. **Hanya pada tahap persiapan ini**, Kali boleh menggunakan satu adapter NAT untuk mengunduh alat. Metasploitable belum diimpor/dijalankan. Jika alat sudah ada, tahap unduh dapat dilewati.
5. Di terminal **Kali**, periksa alat:

```bash
command -v wireshark
command -v dumpcap
command -v tshark
command -v curl
command -v python3
```

Jika ada yang belum tersedia dan Kali masih pada tahap NAT persiapan:

```bash
sudo apt update
sudo apt install wireshark tshark curl python3
```

Jika installer menanyakan izin capture bagi pengguna non-root, kamu boleh memilih **No**: panduan capture berikut memakai `sudo dumpcap`, kemudian membuka hasil memakai Wireshark sebagai pengguna biasa.

6. Bila ingin menyalin repository ini ke Kali, lakukan juga pada tahap persiapan. Semua perintah capture nanti dijalankan dari folder repository **di dalam Kali**, bukan di PowerShell Windows.
7. Matikan Kali dengan menu shutdown. Pastikan status VirtualBox **Powered Off**, bukan Saved.
8. Buka **Settings → Network** Kali: Adapter 1 → **Internal Network**, Name → `labnet`, **Cable Connected** aktif. Nonaktifkan adapter lainnya. Jangan menyisakan adapter NAT kedua.

Jangan menghubungkan Kali ke NAT dan `labnet` bersamaan. Apabila kelak perlu internet lagi, matikan target terlebih dahulu, matikan Kali, lalu tukar satu adapter Kali ke NAT. Kembalikan ke Internal Network sebelum latihan berikutnya.

## 3. Buat VM target Metasploitable 2

1. Ekstrak unduhan Metasploitable 2. Simpan seluruh berkas hasil ekstraksi bersama-sama.
2. Buat VM baru bernama `Metasploitable2-Lab`, tipe Linux, Ubuntu **32-bit**. Pilih **Skip unattended installation** bila opsi tersebut muncul; jangan memasang ISO.
3. Pada disk, pilih **Use an Existing Virtual Hard Disk File** dan pilih `.vmdk` Metasploitable dari hasil ekstraksi. Image target ini sudah berisi sistem operasi. VirtualBox mendukung VMDK. [Oracle: disk virtual](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/storage.html)
4. Sebelum start pertama, atur **Settings → Network → Adapter 1 → Internal Network → `labnet`**, Cable Connected aktif. Matikan semua adapter tambahan. Jika NIC tidak terdeteksi pada OS lama, gunakan model **PCnet-FAST III (Am79C973)** pada pengaturan Advanced adapter.
5. Target tidak memakai Shared Folders, Shared Clipboard, Drag and Drop, atau port forwarding. Nonaktifkan pula fitur berbagi tersebut pada konfigurasi target.
6. Start target, login `msfadmin` / `msfadmin`. Ini kredensial default **mesin latihan**, bukan akun pribadi. Rapid7 menjelaskan target ini sengaja rentan dan dapat dijalankan di VirtualBox. [Rapid7: Metasploitable 2](https://docs.rapid7.com/metasploit/metasploitable-2/)

## 4. Beri alamat sementara pada interface yang benar

Jalankan langkah di bagian ini **hanya di konsol VM yang disebutkan**. Jangan menjalankannya pada WSL, host Linux, router, atau komputer kerja. Alamat IP sengaja dibuat sementara: setelah reboot, periksa dan ulangi bila perlu.

### A. Di Kali

```bash
hostname
ip -br link
ip -br -4 address
```

Cari NIC Ethernet VM selain `lo`. Contoh nama `eth0` atau `enp0s3`; namanya dapat berbeda. Bila perlu, cocokkan MAC pada `ip link` dengan MAC Adapter 1 di VirtualBox. **Ganti nilai `LAB_IF` berikut dengan NIC yang benar**:

```bash
LAB_IF='eth0'
```

Apabila NetworkManager mengelola NIC tersebut, putuskan koneksi otomatisnya agar DHCP tidak menimpa alamat manual:

```bash
nmcli device status
sudo nmcli device disconnect "$LAB_IF"
```

Jika NIC memang sudah disconnected/unmanaged, lanjutkan; tidak perlu mengubah koneksi NIC lain. `nmcli device disconnect` menghentikan autoconnect perangkat sampai koneksi diaktifkan kembali secara manual. [NetworkManager: nmcli](https://networkmanager.dev/docs/api/latest/nmcli.html) Kemudian, masih di **Kali**:

```bash
sudo ip addr flush dev "$LAB_IF"
sudo ip link set dev "$LAB_IF" up
sudo ip addr add 192.168.77.10/24 dev "$LAB_IF"
sudo ip route flush default
sudo sysctl -w net.ipv4.ip_forward=0
ip -4 addr show dev "$LAB_IF"
ip -4 route
```

### B. Di Metasploitable 2

OS target lebih tua, jadi gunakan bentuk perintah yang tidak bergantung pada opsi `ip -br`:

```bash
hostname
ip link show
ip -4 addr show
```

Identifikasi NIC Ethernet selain `lo`. Ganti `eth0` di nilai variabel jika nama yang terlihat berbeda:

```bash
LAB_IF='eth0'
sudo dhclient -r "$LAB_IF"
sudo ip addr flush dev "$LAB_IF"
sudo ip link set dev "$LAB_IF" up
sudo ip addr add 192.168.77.20/24 dev "$LAB_IF"
sudo ip route flush default
sudo sysctl -w net.ipv4.ip_forward=0
ip -4 addr show dev "$LAB_IF"
ip -4 route
```

Perintah `flush` hanya untuk NIC/default route **VM latihan** yang baru disiapkan. Tidak ada gateway atau DNS yang perlu ditambahkan. Dari setiap VM, rute IPv4 seharusnya menunjukkan subnet `192.168.77.0/24` pada NIC lab dan tidak memiliki baris `default`. Hasil persisnya mengikuti nama NIC milikmu; jangan menyalin hasil contoh sebagai bukti.

## 5. Uji koneksi dan simpan bukti nyata

Di Kali:

```bash
ping -c 3 192.168.77.20
curl --noproxy '*' --connect-timeout 3 --max-time 10 -I http://192.168.77.20/
ip -4 route get 192.168.77.20
```

Kriteria lolos:

- Ping memiliki balasan dari `.20` atau kamu dapat menjelaskan hasil gagal yang ditemukan.
- Request HTTP menerima respons dari server target; catat kode respons yang **benar-benar muncul**.
- Rute ke `.20` langsung melalui NIC lab, menggunakan alamat sumber `.10`.
- Pengaturan VirtualBox menunjukkan satu adapter Internal Network pada masing-masing VM, tanpa NAT/Bridged.
- Kedua VM tidak memiliki default route. Pemeriksaan rute dan pengaturan adapter lebih berguna daripada hanya mengandalkan ping internet yang bisa diblokir firewall.

Simpan screenshot sendiri di `evidence/screenshots/`, misalnya:

| Nama berkas yang disarankan | Isi yang perlu terlihat |
| --- | --- |
| `01-kali-labnet.png` | Adapter Kali: Internal Network `labnet` |
| `02-target-labnet.png` | Adapter target dan adapter tambahan nonaktif |
| `03-ip-routes.png` | Alamat kedua VM serta rute tanpa default |
| `04-connectivity.png` | Hasil ping dan respons HTTP dari lab sendiri |

Nama di atas adalah **rencana evidence**. File screenshot tidak disediakan karena eksekusi VM belum dilakukan melalui panduan ini. Hindari menampilkan informasi pribadi pada desktop, nama Wi-Fi, atau tab lain.

## 6. Snapshot, akhir sesi, dan pemulihan

Setelah pengaturan lolos, ambil snapshot bernama `01-isolated-baseline` pada kedua VM. Tulis apakah snapshot dibuat saat VM menyala atau mati. Alamat manual yang hanya ada di memori akan hilang setelah guest reboot; jalankan ulang langkah 4 jika diperlukan.

Sebelum restore snapshot Kali, simpan salinan evidence di luar disk VM, sebab restore mengembalikan isi disk dan bisa menghapus capture yang baru dibuat. Matikan **target**, lalu pindahkan evidence dari Kali ke host menggunakan media sementara yang hanya dibagikan ke Kali, atau aktifkan NAT Kali untuk mengirim repository setelah target mati. Lepas sharing/kembalikan mode Internal Network sebelum menghidupkan target lagi. [Oracle: snapshot dan restore](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/working-with-vms.html)

Di akhir sesi, shutdown target lalu Kali. Saat menggunakan kembali snapshot lama, **periksa ulang adapter**: snapshot juga memulihkan pengaturan VM. Jangan menyalakan target jika mode jaringan sudah berubah.

## Jika belum berhasil

| Gejala | Pemeriksaan pertama |
| --- | --- |
| VM 64-bit tidak tersedia / VM gagal start | Cek dukungan serta aktivasi VT-x/AMD-V sesuai panduan produsen. Catat pesan error; jangan menonaktifkan fitur keamanan Windows tanpa alasan yang jelas. |
| Target tidak mempunyai NIC | Cek Cable Connected, model adapter, lalu `ip link show`; coba PCnet-FAST III untuk guest lama. |
| Ping tidak dibalas | Cocokkan nama `labnet`, alamat `.10`/`.20`, subnet `/24`, dan interface `UP` pada keduanya. |
| Alamat manual berubah | Pastikan koneksi DHCP Kali diputus pada NIC lab dan ulangi langkah 4. |
| HTTP tidak merespons, ping berhasil | Di target cek `sudo service apache2 status`; bila layanan memang berhenti, `sudo service apache2 start`, lalu uji ulang. Catat perbaikan ini. |
| Tidak bisa mengakses internet di lab | Sesuai rancangan isolasi. Tidak perlu menambahkan gateway pada target. |

## Catatan untuk laporan

Isi sendiri: tanggal praktik, Windows/VirtualBox/Kali yang digunakan, spesifikasi VM, nama NIC, sumber image, hasil verifikasi, hasil uji, masalah yang ditemui, dan perbaikannya. Bagian capture berikutnya ada pada [02 — Capture dan analisis lalu lintas](02-capture-lab.md).

Rujukan resmi diperiksa 21 Oktober 2026. Nama menu dapat berubah antar versi; catat versi yang benar-benar kamu pakai.
