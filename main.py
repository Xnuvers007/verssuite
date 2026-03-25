#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║          VERS SUITE  —  Web Security Proxy               ║
║          by Xnuvers007                                   ║
║          Inspired by Burp Suite                          ║
╚══════════════════════════════════════════════════════════╝

Usage:
    python main.py

Requirements:
    pip install -r requirements.txt
"""

import sys
import os
import logging

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(__file__))

# Suppress mitmproxy noise
logging.getLogger("mitmproxy").setLevel(logging.ERROR)
logging.getLogger("asyncio").setLevel(logging.ERROR)

from PyQt5.QtWidgets import QApplication, QSplashScreen, QLabel
from PyQt5.QtCore    import Qt, QTimer
from PyQt5.QtGui     import QFont, QPixmap, QPainter, QColor, QLinearGradient

from ui.main_window import MainWindow
from ui.styles      import DARK_STYLESHEET


def make_splash() -> QSplashScreen:
    """Create a branded splash screen."""
    pixmap = QPixmap(600, 280)
    pixmap.fill(QColor("#0d0d0f"))

    painter = QPainter(pixmap)
    # Gradient bar
    grad = QLinearGradient(0, 0, 600, 0)
    grad.setColorAt(0.0, QColor("#001020"))
    grad.setColorAt(0.5, QColor("#0d0d2a"))
    grad.setColorAt(1.0, QColor("#001020"))
    painter.fillRect(0, 0, 600, 280, grad)

    # Border
    painter.setPen(QColor("#1e1e2e"))
    painter.drawRect(0, 0, 599, 279)

    # Title
    font = QFont("Segoe UI", 36, QFont.Bold)
    painter.setFont(font)
    painter.setPen(QColor("#00d4ff"))
    painter.drawText(pixmap.rect(), Qt.AlignCenter, "◈ VERS SUITE")

    # Subtitle
    font2 = QFont("Segoe UI", 13)
    painter.setFont(font2)
    painter.setPen(QColor("#404060"))
    painter.drawText(0, 185, 600, 30, Qt.AlignCenter, "Web Security Proxy  —  by Xnuvers007")

    # Tagline
    font3 = QFont("Segoe UI", 10)
    painter.setFont(font3)
    painter.setPen(QColor("#303050"))
    painter.drawText(0, 215, 600, 24, Qt.AlignCenter, "Intercept  ·  Repeater  ·  Intruder  ·  Decoder")

    # Bottom bar
    painter.fillRect(0, 260, 600, 20, QColor("#0a0a14"))
    painter.setPen(QColor("#303050"))
    font4 = QFont("Consolas", 9)
    painter.setFont(font4)
    painter.drawText(0, 260, 600, 20, Qt.AlignCenter, "Initializing…")
    painter.end()

    splash = QSplashScreen(pixmap, Qt.WindowStaysOnTopHint)
    splash.setMask(pixmap.mask())
    return splash


def main():
    # High-DPI support
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("Vers Suite")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Xnuvers007")
    app.setStyleSheet(DARK_STYLESHEET)

    # Splash
    splash = make_splash()
    splash.show()
    app.processEvents()

    # Small delay for splash
    import time
    time.sleep(1.2)

    # Main window
    window = MainWindow()
    window.show()
    splash.finish(window)

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()