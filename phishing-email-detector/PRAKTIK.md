# Catatan praktik Phishing Email Detector

**Pelaksana:** Boy Cristoper. **Pencatatan:** 26 Oktober 2026, Asia/Jakarta. Catatan ini merangkum bukti praktik Boy yang dibagikan pada 23 Oktober 2026; bukan hasil pemeriksaan email asli atau pengujian ulang oleh Boy hari ini.

## Yang sudah dijalankan

Boy membuat dan membaca `contoh.eml` fiktif di Kali. Email latihan memakai pengirim pada `portal.test`, alamat balasan pada `balasan.test`, dan kata Segera. Perintah `python3 quick_detector.py contoh.eml` menghasilkan:

```text
Status: perlu ditinjau
- Domain Reply-To (balasan.test) berbeda dari From (portal.test).
- Ada kata mendesak: 'Segera'.
Catatan: hasil ini bukan bukti email aman atau phishing.
```

Boy kemudian menjalankan detektor dasar pada `contoh-biasa.eml` fiktif. Hasil yang terlihat adalah `Status: tidak ada indikator dari aturan terbatas`. Ini menunjukkan perbedaan hasil dua contoh berdasarkan dua aturan dasar; tidak membuktikan email kedua aman.

Pada 26 Oktober 2026, folder `phishing-email-detector` terlihat pada keluaran daftar proyek Kali. Keberadaan folder tidak memastikan semua skrip atau sampel dari versi repo ini sudah berada di dalamnya.

## Kontribusi dan batas

Kode awal disediakan dengan bantuan AI. Boy menyalin, menjalankan, dan membandingkan detektor dasar pada dua contoh fiktif. Praktik `analyze_email.py` versi empat indikator, perubahan kode mandiri, dan penjelasan lengkap dengan kata Boy sendiri belum dicatat.

Contoh pada `samples/` adalah data latihan yang disiapkan bersama kode, bukan email nyata. Screenshot mentah yang juga memperlihatkan percakapan pribadi tidak dimasukkan ke repo publik. Catatan ini menggunakan transkripsi hasil yang relevan.

Isi [template laporan](LAPORAN-TEMPLATE.md) untuk menjelaskan hasil berikutnya, kemungkinan salah deteksi, dan kontribusi pribadi secara tepat.
