"""
Vers Suite - Sequencer Tab
Token randomness / entropy analyzer.
"""

import socket
import ssl
import time
import re
import threading
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QTextEdit, QLabel, QLineEdit, QSpinBox,
    QCheckBox, QFrame, QGroupBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QProgressBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QColor
from core.sequencer import analyze_entropy


class CollectWorker(QObject):
    """Worker that sends the same request N times and collects tokens."""
    got_token = pyqtSignal(str)         # emitted per collected token
    progress  = pyqtSignal(int, int)    # (done, total)
    finished  = pyqtSignal()
    error_sig = pyqtSignal(str)

    def __init__(self, host, port, raw_request, use_ssl, count, header_name, regex_pattern, timeout=10):
        super().__init__()
        self.host = host
        self.port = port
        self.raw_request = raw_request
        self.use_ssl = use_ssl
        self.count = count
        self.header_name = header_name
        self.regex_pattern = regex_pattern
        self.timeout = timeout
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        for i in range(self.count):
            if self._stop:
                break
            try:
                token = self._send_and_extract()
                if token:
                    self.got_token.emit(token)
            except Exception as e:
                self.error_sig.emit(str(e))
            self.progress.emit(i + 1, self.count)
        self.finished.emit()

    def _send_and_extract(self) -> str:
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)

        raw = self.raw_request.replace("\r\n", "\n").replace("\n", "\r\n")
        if not raw.endswith("\r\n\r\n"):
            raw += "\r\n\r\n"
        sock.sendall(raw.encode("utf-8", errors="replace"))

        chunks = []
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            chunks.append(chunk)
        sock.close()

        resp = b"".join(chunks).decode("utf-8", errors="replace")

        # Extract from header
        if self.header_name:
            for line in resp.split("\r\n"):
                if line.lower().startswith(self.header_name.lower() + ":"):
                    return line.split(":", 1)[1].strip()

        # Extract from body via regex
        if self.regex_pattern:
            body_start = resp.find("\r\n\r\n")
            body = resp[body_start + 4:] if body_start >= 0 else resp
            m = re.search(self.regex_pattern, body)
            if m:
                return m.group(1) if m.groups() else m.group(0)

        return ""


class SequencerTab(QWidget):
    """Token entropy analyzer UI."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._tokens = []
        self._worker = None
        self._thread = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        splitter = QSplitter(Qt.Horizontal)

        # ── Left: token input ─────────────────────
        left_panel = QWidget()
        ll = QVBoxLayout(left_panel)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(6)

        # Manual input
        manual_group = QGroupBox("MANUAL INPUT")
        manual_layout = QVBoxLayout(manual_group)
        manual_layout.setSpacing(4)
        manual_layout.addWidget(QLabel("Paste tokens (one per line):"))
        self.token_edit = QTextEdit()
        self.token_edit.setObjectName("raw_request")
        self.token_edit.setFont(QFont("Cascadia Code", 10))
        self.token_edit.setPlaceholderText("abc123def456\nxyz789ghi012\n…")
        manual_layout.addWidget(self.token_edit)

        btn_bar = QHBoxLayout()
        self.btn_analyze = QPushButton("🔬  Analyze Tokens")
        self.btn_analyze.setObjectName("btn_send")
        self.btn_analyze.clicked.connect(self._on_analyze_manual)
        btn_bar.addWidget(self.btn_analyze)

        self.btn_clear = QPushButton("🗑  Clear")
        self.btn_clear.clicked.connect(self._clear_all)
        btn_bar.addWidget(self.btn_clear)
        btn_bar.addStretch()
        manual_layout.addLayout(btn_bar)
        ll.addWidget(manual_group)

        # Auto-collect
        collect_group = QGroupBox("AUTO-COLLECT FROM SERVER")
        cl = QVBoxLayout(collect_group)
        cl.setSpacing(4)

        h1 = QHBoxLayout()
        h1.addWidget(QLabel("Host:"))
        self.host_input = QLineEdit("127.0.0.1")
        self.host_input.setMaximumWidth(160)
        h1.addWidget(self.host_input)
        h1.addWidget(QLabel("Port:"))
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(80)
        self.port_input.setMaximumWidth(80)
        h1.addWidget(self.port_input)
        self.ssl_check = QCheckBox("HTTPS")
        h1.addWidget(self.ssl_check)
        cl.addLayout(h1)

        h2 = QHBoxLayout()
        h2.addWidget(QLabel("Requests:"))
        self.count_spin = QSpinBox()
        self.count_spin.setRange(10, 1000)
        self.count_spin.setValue(100)
        self.count_spin.setMaximumWidth(80)
        h2.addWidget(self.count_spin)
        h2.addStretch()
        cl.addLayout(h2)

        h3 = QHBoxLayout()
        h3.addWidget(QLabel("Extract from header:"))
        self.header_input = QLineEdit("Set-Cookie")
        self.header_input.setMaximumWidth(180)
        h3.addWidget(self.header_input)
        cl.addLayout(h3)

        h4 = QHBoxLayout()
        h4.addWidget(QLabel("Or regex on body:"))
        self.regex_input = QLineEdit("")
        self.regex_input.setPlaceholderText("e.g. token=([a-f0-9]+)")
        self.regex_input.setMaximumWidth(220)
        h4.addWidget(self.regex_input)
        cl.addLayout(h4)

        cl.addWidget(QLabel("Request template:"))
        self.request_edit = QTextEdit()
        self.request_edit.setObjectName("raw_request")
        self.request_edit.setFont(QFont("Cascadia Code", 10))
        self.request_edit.setPlaceholderText("GET / HTTP/1.1\nHost: example.com\n\n")
        self.request_edit.setMaximumHeight(120)
        cl.addWidget(self.request_edit)

        collect_btns = QHBoxLayout()
        self.btn_collect = QPushButton("⚡  Collect & Analyze")
        self.btn_collect.setObjectName("btn_attack")
        self.btn_collect.clicked.connect(self._on_collect)
        collect_btns.addWidget(self.btn_collect)
        self.btn_stop = QPushButton("⏹  Stop")
        self.btn_stop.setObjectName("btn_drop")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._on_stop)
        collect_btns.addWidget(self.btn_stop)
        collect_btns.addStretch()
        cl.addLayout(collect_btns)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setMaximumHeight(10)
        cl.addWidget(self.progress)

        ll.addWidget(collect_group)
        splitter.addWidget(left_panel)

        # ── Right: results ────────────────────────
        right_panel = QWidget()
        rl = QVBoxLayout(right_panel)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)

        results_hdr = QLabel("ANALYSIS RESULTS")
        results_hdr.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        rl.addWidget(results_hdr)

        self.results_view = QTextEdit()
        self.results_view.setReadOnly(True)
        self.results_view.setObjectName("response_view")
        self.results_view.setFont(QFont("Cascadia Code", 11))
        self.results_view.setPlaceholderText("Results will appear here after analysis…")
        rl.addWidget(self.results_view)

        # Char distribution table
        dist_hdr = QLabel("CHARACTER DISTRIBUTION (top 32)")
        dist_hdr.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        rl.addWidget(dist_hdr)

        self.dist_table = QTableWidget(0, 3)
        self.dist_table.setHorizontalHeaderLabels(["Char", "Count", "Frequency"])
        self.dist_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.dist_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.dist_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.dist_table.setAlternatingRowColors(True)
        self.dist_table.verticalHeader().setVisible(False)
        self.dist_table.setColumnWidth(0, 60)
        self.dist_table.setColumnWidth(1, 80)
        self.dist_table.setMaximumHeight(240)
        rl.addWidget(self.dist_table)

        splitter.addWidget(right_panel)
        splitter.setSizes([500, 500])
        layout.addWidget(splitter, stretch=1)

    # ── Public API ─────────────────────────────
    def load_tokens(self, tokens_text: str):
        self.token_edit.setPlainText(tokens_text)

    # ── Actions ────────────────────────────────
    def _on_analyze_manual(self):
        text = self.token_edit.toPlainText()
        tokens = [l.strip() for l in text.split("\n") if l.strip()]
        self._display_results(tokens)

    def _on_collect(self):
        raw = self.request_edit.toPlainText().strip()
        if not raw:
            return
        self._tokens.clear()
        self.progress.setMaximum(self.count_spin.value())
        self.progress.setValue(0)
        self.btn_collect.setEnabled(False)
        self.btn_stop.setEnabled(True)

        self._thread = QThread()
        self._worker = CollectWorker(
            self.host_input.text().strip() or "127.0.0.1",
            self.port_input.value(),
            raw,
            self.ssl_check.isChecked(),
            self.count_spin.value(),
            self.header_input.text().strip(),
            self.regex_input.text().strip(),
        )
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.got_token.connect(self._on_got_token)
        self._worker.progress.connect(lambda d, t: self.progress.setValue(d))
        self._worker.finished.connect(self._on_collect_done)
        self._worker.error_sig.connect(lambda msg: None)
        self._worker.finished.connect(self._thread.quit)
        self._thread.start()

    def _on_stop(self):
        if self._worker:
            self._worker.stop()

    def _on_got_token(self, token: str):
        self._tokens.append(token)

    def _on_collect_done(self):
        self.btn_collect.setEnabled(True)
        self.btn_stop.setEnabled(False)
        if self._tokens:
            self.token_edit.setPlainText("\n".join(self._tokens))
            self._display_results(self._tokens)

    def _display_results(self, tokens):
        if not tokens:
            self.results_view.setPlainText("No tokens to analyze.")
            return

        results = analyze_entropy(tokens)

        verdict = results["verdict"]
        verdict_color = {
            "Excellent": "#00e676",
            "Good": "#40c4ff",
            "Fair": "#ffab00",
            "Poor": "#ff5252",
        }.get(verdict, "#c8c8cc")

        lines = [
            f"═══════════════════════════════════════",
            f"  ENTROPY ANALYSIS REPORT",
            f"═══════════════════════════════════════",
            f"",
            f"  Verdict      : {verdict}",
            f"  Tokens       : {results['token_count']}",
            f"  Avg Length   : {results['avg_length']} chars",
            f"  Unique       : {results['unique_tokens']}/{results['token_count']} ({results['unique_ratio']*100:.1f}%)",
            f"",
            f"  ── Shannon Entropy ──",
            f"  Bits/char    : {results['entropy_bits']}",
            f"  Total bits   : {results['total_entropy_bits']}",
            f"  Unique chars : {results['unique_chars']}",
            f"",
            f"  ── Chi-Square Test ──",
            f"  χ² value     : {results['chi_square']}",
            f"  Result       : {results['chi_square_result']}",
            f"",
            f"  ── Interpretation ──",
        ]

        if verdict == "Excellent":
            lines.append("  ✔ Tokens show excellent randomness.")
            lines.append("  ✔ Very difficult to predict or brute-force.")
        elif verdict == "Good":
            lines.append("  ✔ Tokens show good randomness.")
            lines.append("  ⚠ Minor patterns may exist but exploitation is difficult.")
        elif verdict == "Fair":
            lines.append("  ⚠ Token randomness is fair but not ideal.")
            lines.append("  ⚠ Consider using a stronger PRNG.")
        else:
            lines.append("  ✖ Token randomness is POOR!")
            lines.append("  ✖ Tokens may be predictable — serious security risk.")

        self.results_view.setPlainText("\n".join(lines))

        # Character distribution table
        self.dist_table.setRowCount(0)
        total_chars = sum(results.get("char_distribution", {}).values())
        for char, count in list(results.get("char_distribution", {}).items())[:32]:
            row = self.dist_table.rowCount()
            self.dist_table.insertRow(row)
            display_char = repr(char) if char in (" ", "\t", "\n", "\r") else char
            self.dist_table.setItem(row, 0, QTableWidgetItem(display_char))
            self.dist_table.setItem(row, 1, QTableWidgetItem(str(count)))
            freq = f"{(count/total_chars)*100:.2f}%" if total_chars > 0 else "0%"
            self.dist_table.setItem(row, 2, QTableWidgetItem(freq))

    def _clear_all(self):
        self.token_edit.clear()
        self.results_view.clear()
        self.dist_table.setRowCount(0)
        self._tokens.clear()
        self.progress.setValue(0)
