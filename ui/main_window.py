"""
Vers Suite - Main Window
Central hub combining all tabs and proxy lifecycle management.
"""

import os
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTabWidget, QStatusBar,
    QLineEdit, QSpinBox, QFrame, QDialog, QTextEdit,
    QSplitter, QAction, QMenuBar, QMessageBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSlot, QUrl, QObject, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon, QColor, QPalette, QDesktopServices

from core import (
    ProxyServer, cert_exists, get_install_instructions, open_cert_dir,
    load_config, save_config, APP_VERSION, APP_AUTHOR, REPO_URL,
    check_for_updates, ScopeManager, MatchReplaceEngine, save_session, load_session
)
from .intercept_tab import InterceptTab
from .history_tab   import HistoryTab
from .repeater_tab  import RepeaterTab
from .intruder_tab  import IntruderTab
from .comparer_tab  import ComparerTab
from .sequencer_tab import SequencerTab
from .websocket_tab import WebSocketTab
from .scope_dialog  import ScopeDialog
from .match_replace_dialog import MatchReplaceDialog
from .styles        import DARK_STYLESHEET, COLORS
from PyQt5.QtWidgets import QFileDialog, QShortcut
from PyQt5.QtGui import QKeySequence


# ─────────────────────────────────────────────
# Certificate dialog
# ─────────────────────────────────────────────
class CertDialog(QDialog):
    def __init__(self, proxy_host: str = "127.0.0.1", proxy_port: int = 8080, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Vers Suite — Browser Certificate Setup")
        self.setMinimumWidth(620)
        self.setMinimumHeight(400)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("🔒  Install CA Certificate for HTTPS Interception")
        title.setStyleSheet("font-size:15px; font-weight:700; color:#00d4ff;")
        layout.addWidget(title)

        instructions = QTextEdit()
        instructions.setReadOnly(True)
        instructions.setPlainText(get_install_instructions(proxy_host, proxy_port))
        instructions.setStyleSheet(
            "background:#0a0a0f; color:#c8c8cc; "
            "font-family: 'Consolas', monospace; font-size:12px;"
        )
        layout.addWidget(instructions)

        btn_bar = QHBoxLayout()
        btn_open = QPushButton("📂  Open Certificate Folder")
        btn_open.setObjectName("btn_cert")
        btn_open.clicked.connect(open_cert_dir)
        btn_bar.addWidget(btn_open)
        btn_bar.addStretch()
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        btn_bar.addWidget(btn_close)
        layout.addLayout(btn_bar)


class UpdateCheckWorker(QObject):
    finished = pyqtSignal(object)

    def run(self):
        result = check_for_updates(APP_VERSION)
        self.finished.emit(result)


# ─────────────────────────────────────────────
# Main Window
# ─────────────────────────────────────────────
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scope_manager = ScopeManager()
        self.match_replace_engine = MatchReplaceEngine()
        self.proxy = ProxyServer()
        self.proxy.scope_manager = self.scope_manager
        self.proxy.match_replace_engine = self.match_replace_engine

        self._req_count  = 0
        self._update_thread = None
        self._update_worker = None
        self._poll_timer = QTimer()
        self._setup_ui()
        self._setup_connections()
        self._setup_shortcuts()
        self._apply_config()
        self._poll_timer.timeout.connect(self._poll_proxy_events)
        self._poll_timer.start(80)   # Poll every 80 ms

    # ══════════════════════════════════════════
    # UI Setup
    # ══════════════════════════════════════════
    def _setup_ui(self):
        self.setWindowTitle(f"Vers Suite  ·  v{APP_VERSION}  ·  by {APP_AUTHOR}")
        self.setMinimumSize(1200, 780)
        self.setStyleSheet(DARK_STYLESHEET)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._build_menus()

        # ── Header bar ─────────────────────────
        header = self._build_header()
        root.addWidget(header)

        # ── Tab widget ─────────────────────────
        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.North)

        # Proxy tab (Intercept + History sub-tabs)
        self.proxy_page = QWidget()
        proxy_layout = QVBoxLayout(self.proxy_page)
        proxy_layout.setContentsMargins(0, 0, 0, 0)
        proxy_layout.setSpacing(0)

        proxy_sub = QTabWidget()
        proxy_sub.setStyleSheet(
            "QTabBar::tab { padding: 5px 14px; min-width:70px; font-size:12px; }"
        )

        self.intercept_tab = InterceptTab()
        self.history_tab   = HistoryTab()
        proxy_sub.addTab(self.intercept_tab, "Intercept")
        proxy_sub.addTab(self.history_tab,   "HTTP History")
        proxy_layout.addWidget(proxy_sub)

        self.repeater_tab  = RepeaterTab()
        self.intruder_tab  = IntruderTab()
        self.comparer_tab  = ComparerTab()
        self.sequencer_tab = SequencerTab()
        self.websocket_tab = WebSocketTab()

        self.repeater_page = RepeaterWidget(self.repeater_tab)
        self.intruder_page = IntruderWidget(self.intruder_tab)
        self.comparer_page = QWidget()
        cl = QVBoxLayout(self.comparer_page)
        cl.setContentsMargins(0,0,0,0)
        cl.addWidget(self.comparer_tab)

        self.tabs.addTab(self.proxy_page,      "🔀  Proxy")
        self.tabs.addTab(self.repeater_page,   "🔁  Repeater")
        self.tabs.addTab(self.intruder_page,   "⚡  Intruder")
        self.tabs.addTab(self.comparer_page,   "⇄  Comparer")
        self.tabs.addTab(self.sequencer_tab,   "🔬  Sequencer")
        self.tabs.addTab(self.websocket_tab,   "🔌  WebSocket")
        self.tabs.addTab(self._build_decoder_tab(), "🔧  Decoder")
        self.tabs.addTab(self._build_about_tab(),   "ℹ  About")

        root.addWidget(self.tabs, stretch=1)

        # ── Status bar ─────────────────────────
        self.status_bar  = QStatusBar()
        self.lbl_proxy_status = QLabel("  ⬤  Proxy: Stopped")
        self.lbl_proxy_status.setObjectName("status_err")
        self.lbl_intercept_status = QLabel("  Intercept: Off  ")
        self.lbl_intercept_status.setStyleSheet("color:#505070;")
        self.lbl_req_count = QLabel("  Requests: 0  ")
        self.lbl_req_count.setStyleSheet("color:#505070;")

        self.status_bar.addWidget(self.lbl_proxy_status)
        self.status_bar.addWidget(QLabel(" | "))
        self.status_bar.addWidget(self.lbl_intercept_status)
        self.status_bar.addWidget(QLabel(" | "))
        self.status_bar.addWidget(self.lbl_req_count)
        self.setStatusBar(self.status_bar)

    def _build_menus(self):
        menubar = self.menuBar()
        
        file_menu = menubar.addMenu("&File")
        
        save_act = QAction("Save Session\tCtrl+S", self)
        save_act.triggered.connect(self._save_session)
        file_menu.addAction(save_act)

        load_act = QAction("Load Session\tCtrl+O", self)
        load_act.triggered.connect(self._load_session)
        file_menu.addAction(load_act)

        file_menu.addSeparator()
        
        exit_act = QAction("Exit", self)
        exit_act.triggered.connect(self.close)
        file_menu.addAction(exit_act)

        project_menu = menubar.addMenu("&Project")
        scope_act = QAction("Target Scope", self)
        scope_act.triggered.connect(self._show_scope_dialog)
        project_menu.addAction(scope_act)

        rules_act = QAction("Match && Replace Rules", self)
        rules_act.triggered.connect(self._show_match_replace_dialog)
        project_menu.addAction(rules_act)

        help_menu = menubar.addMenu("&Help")
        cert_act = QAction("Install CA Certificate", self)
        cert_act.triggered.connect(self._show_cert_dialog)
        help_menu.addAction(cert_act)

        changelogs_act = QAction("Changelogs", self)
        changelogs_act.triggered.connect(self._show_changelogs)
        help_menu.addAction(changelogs_act)

        update_act = QAction("Check for Updates", self)
        update_act.triggered.connect(self._on_check_update)
        help_menu.addAction(update_act)

    def _show_changelogs(self):
        changelogs_text = (
            "<h3>What's New in v1.1.0</h3>"
            "<ul>"
            "<li><b>UI Overhaul:</b> Implemented a professional Menu Bar for File, Project, and Help options.</li>"
            "<li><b>Cleaner Layout:</b> Fixed truncated text and crowded buttons in the header to give it a clean, Burp Suite-like appearance.</li>"
            "<li><b>Version Bump:</b> Officially migrated from v1.0.1 to v1.1.0 for better semantic versioning!</li>"
            "</ul><br>"
            "<h3>Previous (v1.0.1)</h3>"
            "<ul>"
            "<li>Added Response Interception functionality.</li>"
            "<li>Hotfixes for payload loading and proxy state toggling.</li>"
            "<li>Initial stable release.</li>"
            "</ul>"
        )
        box = QMessageBox(self)
        box.setWindowTitle("Vers Suite - Changelogs")
        box.setTextFormat(Qt.RichText)
        box.setText(changelogs_text)
        box.exec_()

    def _build_header(self) -> QWidget:
        header = QWidget()
        header.setFixedHeight(60)
        header.setStyleSheet(
            "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #0a0a14, stop:0.5 #0d0d1a, stop:1 #0a0a14);"
            "border-bottom: 1px solid #1e1e2e;"
        )
        hl = QHBoxLayout(header)
        hl.setContentsMargins(16, 0, 16, 0)
        hl.setSpacing(12)

        # Logo / brand
        brand = QLabel("◈ VERS SUITE")
        brand.setObjectName("title_label")
        brand.setFont(QFont("Segoe UI", 16, QFont.Bold))
        hl.addWidget(brand)

        ver = QLabel(f"v{APP_VERSION}  |  by {APP_AUTHOR}")
        ver.setObjectName("subtitle_label")
        hl.addWidget(ver)

        line = QFrame()
        line.setFrameShape(QFrame.VLine)
        line.setStyleSheet("color:#1e1e2e;")
        hl.addWidget(line)

        # Host / Port
        hl.addWidget(QLabel("Host:"))
        self.host_input = QLineEdit("127.0.0.1")
        self.host_input.setMaximumWidth(130)
        self.host_input.setToolTip("Proxy listen host")
        hl.addWidget(self.host_input)

        hl.addWidget(QLabel("Port:"))
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(8080)
        self.port_input.setMaximumWidth(75)
        self.port_input.setToolTip("Proxy listen port")
        hl.addWidget(self.port_input)

        # Start / Stop
        self.btn_start = QPushButton("▶  Start Proxy")
        self.btn_start.setObjectName("btn_start")
        self.btn_start.clicked.connect(self._on_start)
        hl.addWidget(self.btn_start)

        self.btn_stop = QPushButton("⏹  Stop")
        self.btn_stop.setObjectName("btn_stop")
        self.btn_stop.clicked.connect(self._on_stop)
        self.btn_stop.setEnabled(False)
        hl.addWidget(self.btn_stop)

        line2 = QFrame()
        line2.setFrameShape(QFrame.VLine)
        line2.setStyleSheet("color:#1e1e2e;")
        hl.addWidget(line2)

        self.btn_intercept = QPushButton("⬤  Intercept: OFF")
        self.btn_intercept.setObjectName("btn_intercept_on")
        self.btn_intercept.setCheckable(True)
        self.btn_intercept.clicked.connect(self._on_intercept_toggle)
        hl.addWidget(self.btn_intercept)

        self.btn_resp_intercept = QPushButton("⬤  Resp Int: OFF")
        self.btn_resp_intercept.setObjectName("btn_intercept_on")
        self.btn_resp_intercept.setCheckable(True)
        self.btn_resp_intercept.clicked.connect(self._on_resp_intercept_toggle)
        hl.addWidget(self.btn_resp_intercept)

        hl.addStretch()

        return header

    def _build_decoder_tab(self) -> QWidget:
        """Simple encoder/decoder utility."""
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        layout.addWidget(QLabel("DECODER / ENCODER"))

        btn_bar = QHBoxLayout()
        for label, func in [
            ("URL Encode",   lambda: self._decode_action("url_enc")),
            ("URL Decode",   lambda: self._decode_action("url_dec")),
            ("Base64 Enc",   lambda: self._decode_action("b64_enc")),
            ("Base64 Dec",   lambda: self._decode_action("b64_dec")),
            ("HTML Encode",  lambda: self._decode_action("html_enc")),
            ("HTML Decode",  lambda: self._decode_action("html_dec")),
            ("Hex Encode",   lambda: self._decode_action("hex_enc")),
            ("Hex Decode",   lambda: self._decode_action("hex_dec")),
        ]:
            btn = QPushButton(label)
            btn.clicked.connect(func)
            btn_bar.addWidget(btn)
        btn_bar.addStretch()
        layout.addLayout(btn_bar)

        splitter = QSplitter(Qt.Horizontal)
        font = QFont("Cascadia Code", 11)
        font.setStyleHint(QFont.Monospace)

        self.decoder_input = QTextEdit()
        self.decoder_input.setObjectName("raw_request")
        self.decoder_input.setFont(font)
        self.decoder_input.setPlaceholderText("Input…")
        splitter.addWidget(self.decoder_input)

        self.decoder_output = QTextEdit()
        self.decoder_output.setObjectName("response_view")
        self.decoder_output.setFont(font)
        self.decoder_output.setReadOnly(True)
        self.decoder_output.setPlaceholderText("Output…")
        splitter.addWidget(self.decoder_output)

        layout.addWidget(splitter, stretch=1)
        return w

    def _build_about_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setAlignment(Qt.AlignTop)

        title = QLabel("◈ VERS SUITE")
        title.setObjectName("title_label")
        title.setFont(QFont("Segoe UI", 28, QFont.Bold))
        layout.addWidget(title)

        layout.addWidget(QLabel(
            "A professional web security interception proxy.\n"
            "Inspired by Burp Suite — built for pentesters.\n"
        ))

        for line in [
            f"Author   : {APP_AUTHOR}",
            f"Version  : {APP_VERSION}",
            "Engine   : mitmproxy (MITM + SSL CA)",
            "UI       : PyQt5",
            "",
            "Features :",
            "  ✔  Real-time request interception & editing",
            "  ✔  HTTP/HTTPS MITM with automatic CA cert",
            "  ✔  Repeater — replay & tweak requests",
            "  ✔  Intruder — multi-payload fuzzing (OWASP Top 10)",
            "  ✔  Decoder — URL / Base64 / HTML / Hex",
            "  ✔  HTTP History with search & filter",
            "",
            "Payload categories (OWASP Top 10 + extras) are in /payloads/",
        ]:
            lbl = QLabel(line)
            lbl.setStyleSheet("color:#7070a0; font-size:13px;")
            layout.addWidget(lbl)

        layout.addSpacing(12)

        support_title = QLabel("SUPPORT DEVELOPER")
        support_title.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        layout.addWidget(support_title)

        donate_bar = QHBoxLayout()
        btn_trakteer = QPushButton("❤️  Trakteer")
        btn_trakteer.clicked.connect(
            lambda _, u="https://trakteer.id/Xnuvers007": self._open_url(u)
        )
        btn_saweria = QPushButton("☕  Saweria")
        btn_saweria.clicked.connect(
            lambda _, u="https://saweria.co/Xnuvers007": self._open_url(u)
        )
        donate_bar.addWidget(btn_trakteer)
        donate_bar.addWidget(btn_saweria)
        donate_bar.addStretch()
        layout.addLayout(donate_bar)

        layout.addSpacing(8)

        social_title = QLabel("AUTHOR LINKS")
        social_title.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        layout.addWidget(social_title)

        social_bar = QHBoxLayout()
        links = [
            ("GitHub", "https://github.com/Xnuvers007"),
            ("YouTube", "https://www.youtube.com/@xnuvers0077"),
            ("Instagram", "https://www.instagram.com/indradwi.25"),
            ("LinkedIn", "https://www.linkedin.com/in/indradwiaryadi"),
            ("Facebook", "https://www.facebook.com/indradwi.25"),
        ]
        for name, url in links:
            btn = QPushButton(name)
            btn.clicked.connect(lambda _, u=url: self._open_url(u))
            social_bar.addWidget(btn)
        social_bar.addStretch()
        layout.addLayout(social_bar)

        layout.addStretch()
        return w

    # ══════════════════════════════════════════
    # Signal / slot wiring
    # ══════════════════════════════════════════
    def _setup_connections(self):
        # Intercept tab → proxy
        self.intercept_tab.forward_signal.connect(self._on_forward)
        self.intercept_tab.drop_signal.connect(self._on_drop)
        self.intercept_tab.forward_all_signal.connect(self._on_forward_all)
        self.intercept_tab.drop_all_signal.connect(self._on_drop_all)
        self.intercept_tab.response_forward_signal.connect(self._on_response_forward)
        self.intercept_tab.response_drop_signal.connect(self._on_response_drop)

        # History tab → repeater/intruder
        self.history_tab.send_to_repeater.connect(self._to_repeater)
        self.history_tab.send_to_intruder.connect(self._to_intruder)

    def _setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+F"), self).activated.connect(self.intercept_tab.btn_forward.click)
        QShortcut(QKeySequence("Ctrl+D"), self).activated.connect(self.intercept_tab.btn_drop.click)
        QShortcut(QKeySequence("Ctrl+Shift+F"), self).activated.connect(self.intercept_tab.btn_forward_all.click)
        QShortcut(QKeySequence("Ctrl+R"), self).activated.connect(self.intercept_tab.btn_to_repeater.click)
        QShortcut(QKeySequence("Ctrl+I"), self).activated.connect(self.intercept_tab.btn_to_intruder.click)
        QShortcut(QKeySequence("Ctrl+Enter"), self).activated.connect(self.repeater_tab.btn_send.click)
        QShortcut(QKeySequence("Ctrl+S"), self).activated.connect(self._save_session)
        QShortcut(QKeySequence("Ctrl+O"), self).activated.connect(self._load_session)
        for i in range(1, 9):
            QShortcut(QKeySequence(f"Ctrl+{i}"), self).activated.connect(lambda idx=i-1: self.tabs.setCurrentIndex(idx) if idx < self.tabs.count() else None)


    # ══════════════════════════════════════════
    # Proxy lifecycle
    # ══════════════════════════════════════════
    @pyqtSlot()
    def _on_start(self):
        host = self.host_input.text().strip() or "127.0.0.1"
        port = self.port_input.value()
        self.proxy.start(host, port)
        self.btn_start.setEnabled(False)
        self.host_input.setEnabled(False)
        self.port_input.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self._save_config()

    @pyqtSlot()
    def _on_stop(self):
        self.proxy.flush_intercepts()
        self.proxy.disable_intercept()
        self.proxy.stop()
        self.btn_start.setEnabled(True)
        self.host_input.setEnabled(True)
        self.port_input.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.lbl_proxy_status.setText("  ⬤  Proxy: Stopped")
        self.lbl_proxy_status.setObjectName("status_err")
        self.lbl_proxy_status.setStyleSheet("color:#ff5252; font-weight:600;")

    @pyqtSlot(bool)
    def _on_intercept_toggle(self, checked):
        if checked:
            self.proxy.enable_intercept()
            self.btn_intercept.setText("⬤  Intercept: ON")
            self.btn_intercept.setStyleSheet("background:#1a0033; color:#ea00ff; border:1px solid #ea00ff; font-weight:700; padding:7px 18px;")
            self.lbl_intercept_status.setText("  Intercept: ON  ")
            self.lbl_intercept_status.setStyleSheet("color:#ea00ff; font-weight:600;")
        else:
            self.proxy.disable_intercept()
            self.btn_intercept.setText("⬤  Intercept: OFF")
            self.btn_intercept.setStyleSheet("")
            self.lbl_intercept_status.setText("  Intercept: Off  ")
            self.lbl_intercept_status.setStyleSheet("color:#505070;")
        self._save_config()

    @pyqtSlot(bool)
    def _on_resp_intercept_toggle(self, checked):
        if checked:
            self.proxy.enable_response_intercept()
            self.btn_resp_intercept.setText("⬤  Resp Int: ON")
            self.btn_resp_intercept.setStyleSheet("background:#1a0033; color:#ea00ff; border:1px solid #ea00ff; font-weight:700; padding:7px 18px;")
        else:
            self.proxy.disable_response_intercept()
            self.btn_resp_intercept.setText("⬤  Resp Int: OFF")
            self.btn_resp_intercept.setStyleSheet("")
            self.proxy.flush_response_intercepts()
        self._save_config()

    def _show_scope_dialog(self):
        dlg = ScopeDialog(self.scope_manager, self)
        dlg.exec_()
        self._save_config()

    def _show_match_replace_dialog(self):
        dlg = MatchReplaceDialog(self.match_replace_engine, self)
        dlg.exec_()
        self._save_config()

    # ══════════════════════════════════════════
    # Proxy event polling
    # ══════════════════════════════════════════
    def _poll_proxy_events(self):
        while not self.proxy.event_queue.empty():
            try:
                event = self.proxy.event_queue.get_nowait()
                self._handle_event(event)
            except Exception:
                pass

    def _handle_event(self, event: dict):
        t = event.get("type")

        if t == "proxy_started":
            host = event["host"]
            port = event["port"]
            self.lbl_proxy_status.setText(f"  ⬤  Proxy: {host}:{port}")
            self.lbl_proxy_status.setStyleSheet("color:#00e676; font-weight:600;")

        elif t == "proxy_error":
            self.lbl_proxy_status.setText(f"  ⬤  Error: {event['message'][:40]}")
            self.lbl_proxy_status.setStyleSheet("color:#ff5252; font-weight:600;")
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)

        elif t == "intercept":
            self._req_count += 1
            self.lbl_req_count.setText(f"  Requests: {self._req_count}  ")
            self.intercept_tab.show_intercepted(event)
            self.history_tab.add_request(event)
            # Switch to Proxy tab > Intercept
            self.tabs.setCurrentWidget(self.proxy_page)

        elif t == "history":
            self._req_count += 1
            self.lbl_req_count.setText(f"  Requests: {self._req_count}  ")
            self.history_tab.add_request(event)

        elif t == "response":
            self.intercept_tab.update_response_meta(event)
            self.history_tab.update_response(event)

        elif t == "response_intercept":
            self.intercept_tab.show_intercepted_response(event)
            self.history_tab.update_response(event)

        elif t == "websocket":
            self.websocket_tab.add_message(event)

    # ══════════════════════════════════════════
    # Intercept actions
    # ══════════════════════════════════════════
    @pyqtSlot(str, dict)
    def _on_forward(self, flow_id: str, mods: dict):
        self.proxy.forward_flow(flow_id, mods)

    @pyqtSlot(str)
    def _on_drop(self, flow_id: str):
        self.proxy.drop_flow(flow_id)

    @pyqtSlot()
    def _on_forward_all(self):
        self.proxy.flush_intercepts()

    @pyqtSlot()
    def _on_drop_all(self):
        self.proxy.drop_all_intercepts()

    @pyqtSlot(str, dict)
    def _on_response_forward(self, flow_id: str, mods: dict):
        self.proxy.forward_response(flow_id, mods)

    @pyqtSlot(str)
    def _on_response_drop(self, flow_id: str):
        self.proxy.drop_response(flow_id)

    @pyqtSlot(str, tuple)
    def _to_repeater(self, raw: str, host_port: tuple):
        self.repeater_tab.load_request(raw, host_port)
        self.tabs.setCurrentWidget(self.repeater_page)

    @pyqtSlot(str)
    def _to_intruder(self, raw: str):
        self.intruder_tab.load_request(raw)
        self.tabs.setCurrentWidget(self.intruder_page)

    # ══════════════════════════════════════════
    # Certificate dialog
    # ══════════════════════════════════════════
    def _show_cert_dialog(self):
        host = self.host_input.text().strip() or "127.0.0.1"
        port = self.port_input.value()
        dlg = CertDialog(host, port, self)
        dlg.exec_()

    @pyqtSlot()
    def _on_check_update(self):
        if self._update_thread is not None and self._update_thread.isRunning():
            return

        self.status_bar.showMessage("Checking updates...", 2000)

        self._update_thread = QThread(self)
        self._update_worker = UpdateCheckWorker()
        self._update_worker.moveToThread(self._update_thread)

        self._update_thread.started.connect(self._update_worker.run)
        self._update_worker.finished.connect(self._on_update_check_finished)
        self._update_worker.finished.connect(self._update_thread.quit)
        self._update_worker.finished.connect(self._update_worker.deleteLater)
        self._update_thread.finished.connect(self._update_thread.deleteLater)
        self._update_thread.start()

    @pyqtSlot(object)
    def _on_update_check_finished(self, result):
        self._update_worker = None
        self._update_thread = None

        status = result.get("status", "error")
        latest = result.get("latest_version") or "unknown"
        url = result.get("url") or REPO_URL
        message = result.get("message", "Failed to check updates.")

        if status == "update-available":
            reply = QMessageBox.question(
                self,
                "Update Available",
                (
                    f"Current version: {APP_VERSION}\n"
                    f"Latest version: {latest}\n\n"
                    "Open release page now?"
                ),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if reply == QMessageBox.Yes:
                self._open_url(url)
            return

        if status == "up-to-date":
            QMessageBox.information(
                self,
                "Check Update",
                f"You are already on the latest version ({latest}).",
            )
            return

        QMessageBox.warning(
            self,
            "Check Update",
            f"{message}\n\nYou can check manually at:\n{REPO_URL}",
        )

    # ══════════════════════════════════════════
    # Decoder actions
    # ══════════════════════════════════════════
    def _decode_action(self, mode: str):
        import urllib.parse, base64, html
        text = self.decoder_input.toPlainText()
        try:
            if mode == "url_enc":  out = urllib.parse.quote(text, safe="")
            elif mode == "url_dec":out = urllib.parse.unquote(text)
            elif mode == "b64_enc":out = base64.b64encode(text.encode()).decode()
            elif mode == "b64_dec":out = base64.b64decode(text.encode()).decode("utf-8", "replace")
            elif mode == "html_enc":out = html.escape(text)
            elif mode == "html_dec":out = html.unescape(text)
            elif mode == "hex_enc":out = text.encode().hex()
            elif mode == "hex_dec":out = bytes.fromhex(text.replace(" ","")).decode("utf-8","replace")
            else: out = text
        except Exception as e:
            out = f"[Error] {e}"
        self.decoder_output.setPlainText(out)

    def _open_url(self, url: str):
        QDesktopServices.openUrl(QUrl(url))

    def closeEvent(self, event):
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Question)
        box.setWindowTitle("Exit Vers Suite")
        box.setText("Do you want to exit Vers Suite?")
        box.setInformativeText("Save settings before exit?")
        btn_save_exit = box.addButton("Save and Exit", QMessageBox.AcceptRole)
        _ = box.addButton("Exit without Saving", QMessageBox.DestructiveRole)
        btn_cancel = box.addButton("Cancel", QMessageBox.RejectRole)
        box.setDefaultButton(btn_cancel)

        box.exec_()
        clicked = box.clickedButton()
        if clicked == btn_cancel:
            event.ignore()
            return

        if clicked == btn_save_exit:
            self._save_config()

        if self.proxy.running:
            self.proxy.flush_intercepts()
            self.proxy.stop()

        event.accept()

    # ══════════════════════════════════════════
    # Session Management
    # ══════════════════════════════════════════
    def _save_session(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Project Session", "project.verssuite", "Vers Suite Sessions (*.verssuite)"
        )
        if not path:
            return

        data = {
            "history_flows": list(self.history_tab._flows.values()),
            "history_responses": self.history_tab._responses,
            "history_notes": self.history_tab.get_notes(),
            "repeater_sessions": self.repeater_tab.export_sessions(),
            "scope_rules": self.scope_manager.to_list(),
            "scope_enabled": self.scope_manager.enabled,
            "match_replace_rules": self.match_replace_engine.to_list(),
            "match_replace_enabled": self.match_replace_engine.enabled,
            "config": load_config()
        }

        if save_session(path, data):
            QMessageBox.information(self, "Success", "Session saved successfully.")
        else:
            QMessageBox.critical(self, "Error", "Failed to save session.")

    def _load_session(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Project Session", "", "Vers Suite Sessions (*.verssuite)"
        )
        if not path:
            return

        data = load_session(path)
        if not data:
            QMessageBox.critical(self, "Error", "Failed to load session (invalid or corrupted file).")
            return

        self.history_tab.clear_history()
        self.history_tab.set_notes(data.get("history_notes", {}))
        for flow in data.get("history_flows", []):
            self.history_tab.add_request(flow)
        for fid, resp in data.get("history_responses", {}).items():
            resp["flow_id"] = fid
            self.history_tab.update_response(resp)

        self.repeater_tab.import_sessions(data.get("repeater_sessions", []))

        self.scope_manager.load_from_list(data.get("scope_rules", []))
        self.scope_manager.enabled = data.get("scope_enabled", False)

        self.match_replace_engine.load_from_list(data.get("match_replace_rules", []))
        self.match_replace_engine.enabled = data.get("match_replace_enabled", False)

        cfg = data.get("config", {})
        if cfg:
            save_config(cfg)
        self._apply_config()

        QMessageBox.information(self, "Success", "Session loaded successfully.")

    # ══════════════════════════════════════════
    # Config & Certs
    # ══════════════════════════════════════════
    def _apply_config(self):
        cfg = load_config()
        self.host_input.setText(str(cfg.get("host", "127.0.0.1")))
        self.port_input.setValue(int(cfg.get("port", 8080)))
        
        intercept_enabled = bool(cfg.get("intercept_enabled", False))
        self.btn_intercept.setChecked(intercept_enabled)
        self._on_intercept_toggle(intercept_enabled)

        resp_intercept_enabled = bool(cfg.get("response_intercept_enabled", False))
        self.btn_resp_intercept.setChecked(resp_intercept_enabled)
        self._on_resp_intercept_toggle(resp_intercept_enabled)

        self.scope_manager.enabled = cfg.get("scope_enabled", False)
        self.scope_manager.load_from_list(cfg.get("scope_rules", []))

        self.match_replace_engine.enabled = cfg.get("match_replace_enabled", False)
        self.match_replace_engine.load_from_list(cfg.get("match_replace_rules", []))

    def _save_config(self):
        cfg = {
            "host": self.host_input.text().strip() or "127.0.0.1",
            "port": self.port_input.value(),
            "intercept_enabled": self.btn_intercept.isChecked(),
            "response_intercept_enabled": self.btn_resp_intercept.isChecked(),
            "scope_enabled": self.scope_manager.enabled,
            "scope_rules": self.scope_manager.to_list(),
            "match_replace_enabled": self.match_replace_engine.enabled,
            "match_replace_rules": self.match_replace_engine.to_list()
        }
        save_config(cfg)


# ─────────────────────────────────────────────
# Thin wrapper widgets (needed for tab display)
# ─────────────────────────────────────────────
class RepeaterWidget(QWidget):
    def __init__(self, tab_widget):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(tab_widget)

class IntruderWidget(QWidget):
    def __init__(self, tab_widget):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(tab_widget)