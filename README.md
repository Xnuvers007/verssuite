<div align="center">
  <img src="https://img.shields.io/badge/Security-Proxy-red?style=for-the-badge&logo=shield" alt="Security"/>
  <h1> Vers Suite</h1>
  <p><b>A Modern, Fast, and Advanced Web Security Testing & Interception Proxy</b></p>
  
  [![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=flat&logo=python)](https://www.python.org/)
  [![PyQt5](https://img.shields.io/badge/GUI-PyQt5-green.svg?style=flat&logo=qt)](https://riverbankcomputing.com/software/pyqt/intro)
  [![Mitmproxy](https://img.shields.io/badge/Proxy-mitmproxy-orange.svg?style=flat)](https://mitmproxy.org/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat)](https://opensource.org/licenses/MIT)
</div>

<br/>

**Vers Suite** adalah aplikasi proksi intersepsi modern (terinspirasi dari _Burp Suite_) yang dibangun khusus untuk pengujian keamanan web, *penetration testing*, dan pembelajaran. Menggunakan **Python**, **PyQt5**, dan mesin **mitmproxy** yang powerfull, Vers Suite menawarkan UI yang bersih, fungsionalitas mumpuni, serta kecepatan yang optimal.

---

## ⚡ Fitur Utama

- 🛡️ **Real-Time Interception**: Tangkap, modifikasi, teruskan (Forward / Forward All), atau buang (Drop / Drop All) *request* HTTP/HTTPS secara langsung. Mendukung Response Interception.
- 📡 **HTTP History & Advanced Metadata**: Log lengkap lalu lintas web Anda. Ditambah otomatisasi deteksi *WAF* (Web Application Firewall), identifikasi server, keamanan *Headers*, hingga deteksi *Cloudflare*.
- 🔁 **Repeater**: Manipulasi dan kirim ulang *request* secara manual untuk menginspeksi *response*. Dilengkapi fitur *Grouping/Ungrouping* dan *Smart Search/Filter*.
- 🎯 **Intruder**: *Fuzzing* otomatis berbasis *payload* (mendukung kategori *OWASP Top 10*) untuk eksploitasi dan pengujian kerentanan secara efisien (mendukung penyesuaian *thread*).
- 🔧 **Decoder Tools**: Utilitas praktis untuk *URL mapping*, *Base64*, *HTML*, dan *Hex encoding/decoding*.
- 🔒 **HTTPS Support**: Dukungan penuh HTTPS dengan panduan instalasi sertifikat CA *mitmproxy* langsung dari dalam aplikasi.
- ✨ **Pro UI**: Tema gelap elegan profesional ala *hacker-tools*, dengan pemisahan Menu Bar untuk akses tools lebih cepat.

---

## 🚀 Instalasi

Pastikan Anda memiliki [Python 3.10+](https://www.python.org/downloads/) (diuji pada Python 3.12). Direkomendasikan menggunakan sistem operasi Windows, namun Linux dan macOS tetap kompatibel dengan sedikit penyesuaian.

1. **Clone Repositori:**
   ```bash
   git clone https://github.com/Xnuvers007/verssuite.git
   cd verssuite
   ```

2. **Buat Virtual Environment:**
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # Linux/macOS:
   source venv/bin/activate
   ```

3. **Install Dependensi:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Cara Penggunaan

Jalankan Vers Suite:
```bash
python main.py
```

1. Konfigurasikan proxy browser/perangkat Anda ke listener Vers Suite (Default: 127.0.0.1:8080).
2. Mulai proxy dari *header bar*.
3. Akses pengaturan tambahan melalui **Menu Bar** (File, Project, Help) atau buka **Scope** dan **Match & Replace Rules**.
4. Aktifkan **Intercept** untuk menahan lalu lintas. Pilih *request*, modifikasi, lalu klik **Forward** atau **Drop**.
5. Untuk mengirim ke tab lain, cukup klik kanan pada request tersebut untuk mengirim ke **Repeater** atau **Intruder**.

**Catatan HTTPS interception**: Buka dialog `Help > Install CA Certificate` untuk melihat petunjuk pemasangan dan folder penyimpanan sertifikat CA mitmproxy.

---

## 📑 Changelogs

### v1.1.0 (Current)
- **UI Refactor & Polish**: Memperkenalkan sistem Menu Bar (File, Project, Help) bergaya Burp Suite untuk antarmuka yang jauh lebih rapi.
- **Header Optimization**: Mengatasi masalah teks terpotong (truncated text) pada resolusi yang lebih kecil dengan menyederhanakan toolbar utama, memprioritaskan kontrol Proxy yang essensial.
- **In-App Changelogs**: Menambahkan tombol "Changelogs" langsung di menu `Help`.

### v1.0.1
-  Peningkatan stabilitas Response Interception.
-  Penyempurnaan tema dark mode dan highlighter proxy history.
-  Hotfix minor pada *Intruder payload loading*.

### v1.0.0
-  Rilis awal Vers Suite Proxy! HTTP/HTTPS interception, Repeater, Intruder, Decoder.

---

## 📁 Struktur Proyek
```bash
core/       - Mesin Proxy dan integrasi mitmproxy
ui/         - Komponen antarmuka PyQt5 dan styling (Tabs)
payloads/   - Kamus payload untuk pengujian Intruder (OWASP Top 10, dll)
main.py     - Titik masuk (Entry point) aplikasi
README.md   - Dokumentasi proyek
LICENSE     - Lisensi MIT
```

---

## ❤️ Dukungan & Donasi
Jika proyek ini membantu Anda, pertimbangkan untuk mendukung pengembang!
-  **Trakteer**: [https://trakteer.id/Xnuvers007](https://trakteer.id/Xnuvers007)
-  **Saweria**: [https://saweria.co/Xnuvers007](https://saweria.co/Xnuvers007)

## 👦 Author
Tetap terhubung untuk update menarik lainnya!
- **GitHub**: [Xnuvers007](https://github.com/Xnuvers007)
- **YouTube**: [xnuvers0077](https://www.youtube.com/@xnuvers0077)
- **Instagram**: [@indradwi.25](https://www.instagram.com/indradwi.25)
- **LinkedIn**: [Indra Dwi Aryadi](https://www.linkedin.com/in/indradwiaryadi)
- **Facebook**: [indradwi.25](https://www.facebook.com/indradwi.25)

---

## ⚖️ Peringatan Legal (Disclaimer)

*Alat ini dirancang khusus untuk keperluan edukasi dan pengujian keamanan yang sah.* Anda **diwajibkan** untuk memiliki otorisasi formal sebelum mencegat, menganalisis, atau mengeksploitasi lalu lintas target. Segala bentuk penyalahgunaan adalah tanggung jawab penuh dari pengguna akhir.

<div align="center">
  <sub>Built with ❤️ by Indra Dwi Aryadi.</sub>
</div>
