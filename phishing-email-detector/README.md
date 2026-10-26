# Phishing Email Detector

Pemeriksa indikator phishing pada satu file email `.eml` lokal. Program membantu triase awal dengan menjelaskan alasan sebuah email perlu ditinjau manusia. Python standar sudah cukup; tidak ada koneksi internet, pembukaan tautan, pengiriman email, atau eksekusi lampiran.

**Status praktik:** Boy sudah menjalankan detektor dasar dua indikator pada dua email fiktif di Kali. Versi lengkap empat indikator tersedia dalam repo, tetapi praktik versi tersebut di Kali belum tercatat. Kode awal dibantu AI. Rincian ada di [PRAKTIK.md](PRAKTIK.md).

## Mulai dari versi dasar

Dari root repo, jalankan di Terminal Kali:

```bash
cd phishing-email-detector
python3 quick_detector.py samples/contoh-perlu-ditinjau.eml
python3 quick_detector.py samples/contoh-tanpa-indikator.eml
```

Versi dasar memeriksa perbedaan domain `From` dan `Reply-To`, serta kata mendesak pada subjek atau isi teks biasa. `From` adalah pengirim yang tertulis; `Reply-To` adalah alamat tujuan balasan. Contoh dalam `samples/` fiktif dan dapat digunakan tanpa email pribadi.

## Versi empat indikator dan tes

```bash
python3 -m unittest discover -s tests -v
python3 analyze_email.py samples/contoh-perlu-ditinjau.eml
python3 analyze_email.py samples/contoh-tanpa-indikator.eml
```

Di Windows, gunakan `python` bila `python3` tidak tersedia.

| Pemeriksaan | Yang ditandai |
|---|---|
| Domain pengirim dan balasan | Domain `Reply-To` berbeda dari `From` |
| Bahasa mendesak | Kata seperti segera atau urgent |
| Nama lampiran | Ekstensi tertentu yang perlu ditinjau |
| Tautan HTML | Host pada teks URL berbeda dari tujuan tautan |

Versi lengkap membatasi file masukan hingga 512.000 byte. Pemeriksaan lampiran hanya membaca nama file, bukan menganalisis atau menjalankan isinya.

## Menafsirkan status

`Perlu ditinjau` berarti ada aturan yang menemukan indikator. `Tidak ada indikator dari aturan terbatas` berarti aturan yang tersedia tidak menemukan tanda tersebut. Kedua hasil belum memastikan email aman atau phishing.

Perbedaan alamat balasan dan kata mendesak bisa muncul pada email sah. Program belum memverifikasi SPF, DKIM, DMARC, reputasi, atau keaslian pengirim. Jangan memasukkan email pribadi atau pekerjaan ke repo publik.

## Dokumentasi

- [Catatan praktik dua email fiktif](PRAKTIK.md)
- [Template hasil dan penjelasan pribadi](LAPORAN-TEMPLATE.md)
- [Versi dasar](quick_detector.py)
- [Versi empat indikator](analyze_email.py)
