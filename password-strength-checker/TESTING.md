# Validasi pengembangan — bukan hasil praktik Boy

**Tanggal pencatatan:** 25 Oktober 2026, Asia/Jakarta

**Lingkungan asisten:** Windows, Python 3.12.10; browser in-app untuk integrasi antarmuka. Praktik langsung di VM Kali Boy belum dilakukan untuk proyek ini.

## Pengujian otomatis

Perintah dijalankan dari folder password-strength-checker:

```text
python -m unittest discover -s tests -v
```

Keluaran akhir aktual pada host pengembangan:

```text
Ran 19 tests in 0.824s

OK
```

Komposisi: 8 tes aturan, 2 tes CLI, 9 tes HTTP lokal. Cakupan: batas panjang/NFC/spasi, pencocokan seluruh blocklist, pengulangan/urutan, tanpa aturan komposisi wajib, tanpa pengembalian input, getpass tanpa echo/fallback, Host/Origin, tipe/ukuran/skema JSON, JSON bertingkat/kunci ganda/integer panjang, aset/header, dan tidak adanya log permintaan.

Pada percobaan awal sandbox Windows, koneksi klien loopback ditolak. Suite penuh kemudian berhasil dijalankan dengan akses loopback lokal yang disetujui; tidak ada layanan eksternal yang dihubungi. Catatan ini adalah uji pengembangan, bukan screenshot praktik Kali.

## Pengujian antarmuka nyata

| Uji browser | Pengamatan aktual |
|---|---|
| Contoh pendek | Perlu diperbaiki, panjang 6 |
| Contoh berulang | Perlu diperbaiki, panjang 18 |
| Contoh pola | Perlu ditinjau, panjang 18 |
| Contoh frasa | Lolos pemeriksaan terbatas, panjang 27 |
| Spasi saja | Pesan penolakan tetap tampil, tanpa input |
| 257 karakter | Ditolak secara eksplisit; penghitung menampilkan 257, tidak dipotong diam-diam |
| Tampilkan/sembunyikan | Tipe field berubah menjadi text lalu kembali password |
| Hapus input | Penghitung kembali 0; hasil tersembunyi; input kembali bermasker |
| Ekspor ringkasan | JSON berisi kategori/panjang/indikator/saran, tanpa teks contoh frasa |
| Tampilan 1280 dan 390 piksel | Lebar dokumen tidak melebihi area konten; breakpoint kecil dapat dibaca tanpa scroll horizontal |
| Sintaks JavaScript | node --check static/app.js selesai tanpa error |

Integrasi browser memakai port pratinjau 8767; port bawaan untuk pengguna tetap 8766. Tidak ada perubahan aturan antara pratinjau dan paket. Pemeriksaan kode independen menemukan label indikator terbalik dan pengecualian parser JSON bertingkat; keduanya diperbaiki sebelum validasi akhir.

`preview-development.jpg` adalah screenshot pengujian asisten di Windows memakai contoh dummy publik, bukan bukti praktik Boy di Kali. `examples/ringkasan-contoh.json` adalah hasil ekspor pada pengujian browser yang sama.

## Batas validasi

Tes mencakup kasus yang disediakan, bukan seluruh input atau audit keamanan produksi. Blocklist berisi 20 contoh dan pola hanya heuristik terbatas. Tidak ada pemeriksaan kebocoran online, estimasi entropi/waktu pembobolan, atau jaminan password aman.
