"""
Vers Suite - Certificate Manager
Helps users install the mitmproxy CA certificate for HTTPS interception.
"""

import os
import platform
import subprocess
import shutil
from pathlib import Path


CERT_DIR = Path.home() / ".mitmproxy"
CERT_PEM  = CERT_DIR / "mitmproxy-ca-cert.pem"
CERT_CER  = CERT_DIR / "mitmproxy-ca-cert.cer"
CERT_P12  = CERT_DIR / "mitmproxy-ca-cert.p12"


def cert_exists() -> bool:
    return CERT_PEM.exists() or CERT_CER.exists()


def get_cert_path() -> str | None:
    if CERT_PEM.exists(): return str(CERT_PEM)
    if CERT_CER.exists(): return str(CERT_CER)
    return None


def get_install_instructions(proxy_host: str = "127.0.0.1", proxy_port: int = 8080) -> str:
    sys = platform.system()
    cert = get_cert_path() or str(CERT_PEM)
    proxy_addr = f"{proxy_host}:{proxy_port}"

    if sys == "Windows":
        return (
            f"A) Generate & install CA certificate (Windows)\n"
            f"1. Start Vers Suite proxy once (agar sertifikat dibuat).\n"
            f"2. Open folder: {CERT_DIR}\n"
            f"3. Double-click: mitmproxy-ca-cert.cer\n"
            f"4. Click: Install Certificate → Local Machine\n"
            f"5. Store location: Trusted Root Certification Authorities\n"
            f"6. Finish, lalu restart browser.\n\n"
            f"B) Set browser proxy ke Vers Suite\n"
            f"Gunakan alamat proxy: {proxy_addr}\n"
            f"(Port bisa diubah sesuai keinginan user di Vers Suite; browser harus pakai port yang sama.)\n\n"
            f"Chrome / Microsoft Edge / Brave / Opera (Windows)\n"
            f"1. Buka browser → Settings.\n"
            f"2. Cari: Proxy, lalu pilih 'Open your computer's proxy settings'.\n"
            f"3. Aktifkan 'Use a proxy server'.\n"
            f"4. Address: {proxy_host}\n"
            f"5. Port   : {proxy_port}\n"
            f"6. Save, lalu reload browser.\n\n"
            f"Firefox (manual proxy + import cert)\n"
            f"1. Settings → General → Network Settings → Settings...\n"
            f"2. Pilih 'Manual proxy configuration'.\n"
            f"3. HTTP Proxy: {proxy_host}  Port: {proxy_port}\n"
            f"4. Centang 'Use this proxy server for all protocols'.\n"
            f"5. Certificates: Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import\n"
            f"6. Pilih file: {cert}\n"
            f"7. Centang trust untuk website, lalu OK dan restart Firefox.\n\n"
            f"Tips\n"
            f"- Jika Anda mengubah port di header Vers Suite (contoh 8080 → 8888), ulangi setting browser ke port baru.\n"
            f"- Pastikan proxy Vers Suite status 'running' sebelum testing."
        )
    elif sys == "Darwin":
        return (
            f"A) Generate & install CA certificate (macOS)\n"
            f"1. Start Vers Suite proxy once (agar sertifikat dibuat).\n"
            f"2. Run:\n"
            f"   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {cert}\n"
            f"   Atau import manual via Keychain Access.\n\n"
            f"B) Set browser proxy\n"
            f"Gunakan alamat proxy: {proxy_addr}\n"
            f"(Port bisa Anda ganti, tapi browser wajib mengikuti port yang sama.)\n\n"
            f"Chrome / Edge / Brave / Opera (pakai system proxy macOS)\n"
            f"- System Settings → Network → (active network) → Details → Proxies\n"
            f"- Enable Web Proxy (HTTP) dan Secure Web Proxy (HTTPS)\n"
            f"- Server: {proxy_host}  Port: {proxy_port}\n\n"
            f"Safari (macOS)\n"
            f"- Safari mengikuti System Proxy macOS (tidak ada proxy setting terpisah di Safari).\n"
            f"- Jadi cukup set di: System Settings → Network → (active network) → Details → Proxies\n"
            f"- Enable Web Proxy (HTTP) dan Secure Web Proxy (HTTPS)\n"
            f"- Server: {proxy_host}  Port: {proxy_port}\n"
            f"- Pastikan sertifikat mitmproxy sudah trusted di Keychain (System keychain).\n\n"
            f"Firefox\n"
            f"- Preferences → General → Network Settings → Manual proxy configuration\n"
            f"- HTTP Proxy: {proxy_host}  Port: {proxy_port}\n"
            f"- Import cert: Preferences → Privacy & Security → View Certificates → Import\n"
            f"- Select: {cert}"
        )
    else:
        return (
            f"A) Generate & install CA certificate (Linux)\n"
            f"1. Start Vers Suite proxy once (agar sertifikat dibuat).\n"
            f"2. Certificate location: {cert}\n"
            f"3. System trust (Debian/Ubuntu):\n"
            f"   sudo cp {cert} /usr/local/share/ca-certificates/mitmproxy.crt\n"
            f"   sudo update-ca-certificates\n\n"
            f"B) Set browser proxy\n"
            f"Gunakan alamat proxy: {proxy_addr}\n"
            f"(Port bisa diubah user; browser harus menggunakan port yang sama.)\n\n"
            f"Chrome / Edge / Brave / Opera\n"
            f"- Gunakan system proxy desktop environment, atau jalankan browser dengan opsi proxy.\n"
            f"- Host: {proxy_host}  Port: {proxy_port}\n\n"
            f"Firefox\n"
            f"- Preferences → Privacy & Security → Certificates → Import\n"
            f"- Select: {cert}\n"
            f"- Network Settings → Manual proxy configuration\n"
            f"- HTTP Proxy: {proxy_host}  Port: {proxy_port}"
        )


def open_cert_dir():
    sys = platform.system()
    path = str(CERT_DIR)
    try:
        if sys == "Windows":
            os.startfile(path)
        elif sys == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:
        pass


def export_cert(destination: str) -> bool:
    src = get_cert_path()
    if not src:
        return False
    try:
        shutil.copy(src, destination)
        return True
    except Exception:
        return False