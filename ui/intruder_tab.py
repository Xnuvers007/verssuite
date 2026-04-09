"""
Vers Suite - Intruder Tab
Automated payload injection (OWASP Top 10 categories).
Modes: Sniper | Battering Ram | Cluster Bomb
"""

import os
import re
import time
import socket
import ssl
import threading
import json
import csv
from typing import List, Tuple, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QTextEdit, QLabel, QLineEdit, QSpinBox,
    QComboBox, QCheckBox, QFrame, QTableWidget, QTableWidgetItem,
    QHeaderView, QFileDialog, QProgressBar, QAbstractItemView,
    QGroupBox, QScrollArea
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt5.QtGui import QColor, QFont, QTextCursor, QTextCharFormat
from .styles import status_color, COLORS
from .intercept_tab import HttpHighlighter
import itertools


PAYLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "payloads")


# ─────────────────────────────────────────────
# Attack Worker
# ─────────────────────────────────────────────
class AttackWorker(QObject):
    result  = pyqtSignal(int, str, int, int, float)  # (idx, payload_str, status, length, ms)
    progress = pyqtSignal(int, int)                   # (done, total)
    finished = pyqtSignal()
    stopped  = pyqtSignal()

    def __init__(self, host, port, raw_template, mode, payload_sets, use_ssl, concurrency=5, timeout=10):
        super().__init__()
        self.host        = host
        self.port        = port
        self.raw_template = raw_template
        self.mode        = mode             # "Sniper", "Battering Ram", "Cluster Bomb"
        self.payload_sets = payload_sets    # dict of {set_idx (int): list of payloads}
        self.use_ssl     = use_ssl
        self.concurrency = concurrency
        self.timeout     = timeout
        self._stop       = False

    def stop(self):
        self._stop = True

    def run(self):
        lock  = threading.Lock()
        done  = [0]
        threads = []
        tasks = []

        # Find markers
        marker_count = self.raw_template.count("§") // 2
        if marker_count == 0:
            marker_count = 1

        # Build task list depending on mode
        if self.mode == "Sniper":
            set1 = self.payload_sets.get(1, [])
            for m_idx in range(marker_count):
                for p in set1:
                    tasks.append((m_idx, [p]))

        elif self.mode == "Battering Ram":
            set1 = self.payload_sets.get(1, [])
            for p in set1:
                tasks.append((None, [p] * marker_count))

        elif self.mode == "Cluster Bomb":
            lists = [self.payload_sets.get(i + 1, []) for i in range(marker_count)]
            # If a list is empty for a marker, use a default empty string so product doesn't yield nothing
            lists = [l if l else [""] for l in lists]
            for combo in itertools.product(*lists):
                tasks.append((None, list(combo)))

        total = len(tasks)
        if total == 0:
            self.finished.emit()
            return

        sema  = threading.Semaphore(self.concurrency)

        for idx, (m_idx, p_list) in enumerate(tasks):
            if self._stop:
                self.stopped.emit()
                return

            def task(i=idx, m=m_idx, pl=p_list):
                sema.acquire()
                try:
                    if self._stop:
                        return
                    status, length, ms = self._send_one(m, pl)
                    p_str = " | ".join(pl)
                    self.result.emit(i, p_str[:100], status, length, ms)
                    with lock:
                        done[0] += 1
                        self.progress.emit(done[0], total)
                finally:
                    sema.release()

            t = threading.Thread(target=task, daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        if not self._stop:
            self.finished.emit()

    def _send_one(self, target_marker_idx: Optional[int], mapped_payloads: List[str]) -> Tuple[int, int, float]:
        try:
            # Reconstruct request by replacing markers
            parts = self.raw_template.split("§")
            if len(parts) % 2 == 0:
                parts.append("") # Malformed markers, fallback

            raw = ""
            for i, part in enumerate(parts):
                if i % 2 == 0:
                    raw += part
                else:
                    marker_idx = i // 2
                    if target_marker_idx is not None:
                        # Sniper mode: only inject one marker, clear others
                        if marker_idx == target_marker_idx:
                            raw += mapped_payloads[0]
                    else:
                        # Battering Ram / Cluster Bomb: inject mapped payload
                        if marker_idx < len(mapped_payloads):
                            raw += mapped_payloads[marker_idx]

            raw = raw.replace("\r\n", "\n").replace("\n", "\r\n")
            if not raw.endswith("\r\n\r\n"):
                raw += "\r\n\r\n"

            t0   = time.time()
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if self.use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.host)

            sock.sendall(raw.encode("utf-8", errors="replace"))

            chunks = []
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                chunks.append(chunk)
            sock.close()

            elapsed = (time.time() - t0) * 1000
            resp_raw = b"".join(chunks)
            status = 0
            first_line = resp_raw.split(b"\r\n")[0].decode("utf-8", errors="replace")
            resp_parts = first_line.split()
            if len(resp_parts) >= 2:
                try:
                    status = int(resp_parts[1])
                except ValueError:
                    pass
            return status, len(resp_raw), round(elapsed, 1)

        except Exception:
            return 0, 0, 0.0

# ─────────────────────────────────────────────
# Intruder Tab
# ─────────────────────────────────────────────
class IntruderTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker  = None
        self._thread  = None
        self._results: list = []
        self._payload_sets: dict = {i: "" for i in range(1, 11)} # up to 10 sets
        self._current_set = 1
        self._setup_ui()
        self._load_payload_list()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # ═══ Top splitter: Request + Config ═══
        top_splitter = QSplitter(Qt.Horizontal)

        # ── Request Panel ──────────────────────
        req_panel = QWidget()
        rq = QVBoxLayout(req_panel)
        rq.setContentsMargins(0, 0, 0, 0)
        rq.setSpacing(4)

        rq_title = QLabel("TARGET REQUEST  —  wrap injection points with  §  markers")
        rq_title.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        rq.addWidget(rq_title)

        self.request_edit = QTextEdit()
        self.request_edit.setObjectName("raw_request")
        self.request_edit.setPlaceholderText(
            "Paste your HTTP request here.\n"
            "Wrap injection positions with § symbols, e.g.:\n\n"
            "POST /login HTTP/1.1\n"
            "Host: target.com\nContent-Type: application/x-www-form-urlencoded\n\n"
            "username=admin&password=§FUZZ§"
        )
        font = QFont("Cascadia Code", 11)
        font.setStyleHint(QFont.Monospace)
        self.request_edit.setFont(font)
        self._hl = HttpHighlighter(self.request_edit.document())
        rq.addWidget(self.request_edit)

        # Marker helper buttons
        marker_bar = QHBoxLayout()
        btn_add_marker = QPushButton("§ Add §FUZZ§ Marker")
        btn_add_marker.clicked.connect(self._add_marker)
        btn_clear_markers = QPushButton("✖ Clear Markers")
        btn_clear_markers.clicked.connect(self._clear_markers)
        marker_bar.addWidget(btn_add_marker)
        marker_bar.addWidget(btn_clear_markers)
        marker_bar.addStretch()
        rq.addLayout(marker_bar)

        top_splitter.addWidget(req_panel)

        # ── Config Panel ────────────────────────
        cfg_panel = QWidget()
        cfg_panel.setMinimumWidth(320)
        cfg_panel.setMaximumWidth(380)
        cfg = QVBoxLayout(cfg_panel)
        cfg.setContentsMargins(8, 0, 0, 0)
        cfg.setSpacing(10)

        # Target
        tgt_group = QGroupBox("TARGET")
        tgt_layout = QVBoxLayout(tgt_group)
        tgt_layout.setSpacing(4)
        h1 = QHBoxLayout()
        h1.addWidget(QLabel("Host:"))
        self.host_input = QLineEdit("127.0.0.1")
        h1.addWidget(self.host_input)
        tgt_layout.addLayout(h1)
        h2 = QHBoxLayout()
        h2.addWidget(QLabel("Port:"))
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(80)
        h2.addWidget(self.port_input)
        self.ssl_check = QCheckBox("HTTPS")
        h2.addWidget(self.ssl_check)
        tgt_layout.addLayout(h2)
        cfg.addWidget(tgt_group)

        # Attack settings
        atk_group = QGroupBox("ATTACK SETTINGS")
        atk_layout = QVBoxLayout(atk_group)
        atk_layout.setSpacing(6)

        h3 = QHBoxLayout()
        h3.addWidget(QLabel("Mode:"))
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Sniper", "Battering Ram", "Cluster Bomb"])
        h3.addWidget(self.mode_combo)
        atk_layout.addLayout(h3)

        h4 = QHBoxLayout()
        h4.addWidget(QLabel("Threads:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setValue(10)
        h4.addWidget(self.threads_spin)
        atk_layout.addLayout(h4)

        h5 = QHBoxLayout()
        h5.addWidget(QLabel("Timeout:"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(10)
        self.timeout_spin.setSuffix(" s")
        h5.addWidget(self.timeout_spin)
        atk_layout.addLayout(h5)

        cfg.addWidget(atk_group)

        # Payload source
        pl_group = QGroupBox("PAYLOADS")
        pl_layout = QVBoxLayout(pl_group)
        pl_layout.setSpacing(6)

        ps_src = QHBoxLayout()
        ps_src.addWidget(QLabel("Payload Set:"))
        self.payload_set_combo = QComboBox()
        self.payload_set_combo.addItems([str(i) for i in range(1, 11)])
        self.payload_set_combo.currentTextChanged.connect(self._on_payload_set_change)
        ps_src.addWidget(self.payload_set_combo)
        ps_src.addStretch()
        pl_layout.addLayout(ps_src)

        pl_src = QHBoxLayout()
        pl_src.addWidget(QLabel("Category:"))
        self.payload_combo = QComboBox()
        self.payload_combo.currentTextChanged.connect(self._on_payload_select)
        pl_src.addWidget(self.payload_combo)
        pl_layout.addLayout(pl_src)

        self.payload_edit = QTextEdit()
        self.payload_edit.setObjectName("raw_request")
        self.payload_edit.setPlaceholderText("One payload per line…")
        self.payload_edit.setFont(QFont("Cascadia Code", 10))
        self.payload_edit.setMaximumHeight(180)
        self.payload_edit.textChanged.connect(self._on_payload_text_changed)
        pl_layout.addWidget(self.payload_edit)

        btn_load_file = QPushButton("📂  Load from file…")
        btn_load_file.clicked.connect(self._load_payload_file)
        pl_layout.addWidget(btn_load_file)

        self.lbl_payload_count = QLabel("0 payloads")
        self.lbl_payload_count.setStyleSheet("color:#505070; font-size:11px;")
        pl_layout.addWidget(self.lbl_payload_count)
        self.payload_edit.textChanged.connect(self._update_payload_count)

        cfg.addWidget(pl_group)

        # Filter
        flt_group = QGroupBox("GREP / FILTER")
        flt_layout = QVBoxLayout(flt_group)
        self.grep_input = QLineEdit()
        self.grep_input.setPlaceholderText("Highlight responses containing…")
        flt_layout.addWidget(self.grep_input)
        cfg.addWidget(flt_group)

        cfg.addStretch()

        # Attack button
        self.btn_attack = QPushButton("⚡  START ATTACK")
        self.btn_attack.setObjectName("btn_attack")
        self.btn_attack.clicked.connect(self._on_attack)
        cfg.addWidget(self.btn_attack)

        self.btn_stop = QPushButton("⏹  Stop")
        self.btn_stop.setObjectName("btn_drop")
        self.btn_stop.clicked.connect(self._on_stop)
        self.btn_stop.setEnabled(False)
        cfg.addWidget(self.btn_stop)

        cfg_scroll = QScrollArea()
        cfg_scroll.setWidgetResizable(True)
        cfg_scroll.setFrameShape(QFrame.NoFrame)
        cfg_scroll.setWidget(cfg_panel)
        top_splitter.addWidget(cfg_scroll)
        top_splitter.setSizes([600, 280])
        layout.addWidget(top_splitter)

        # ═══ Results section ═══════════════════
        res_title = QLabel("RESULTS")
        res_title.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px; margin-top:6px;")
        layout.addWidget(res_title)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximumHeight(10)
        layout.addWidget(self.progress_bar)

        # Stats bar
        stats_bar = QHBoxLayout()
        self.lbl_done    = QLabel("Done: 0")
        self.lbl_errors  = QLabel("Errors: 0")
        self.lbl_elapsed = QLabel("")
        for lbl in [self.lbl_done, self.lbl_errors, self.lbl_elapsed]:
            lbl.setStyleSheet("color:#505070; font-size:11px;")
            stats_bar.addWidget(lbl)
        stats_bar.addStretch()

        btn_clear_results = QPushButton("🗑 Clear")
        btn_clear_results.setMaximumWidth(70)
        btn_clear_results.clicked.connect(self._clear_results)
        stats_bar.addWidget(btn_clear_results)

        btn_export = QPushButton("💾 Export CSV")
        btn_export.setMaximumWidth(100)
        btn_export.clicked.connect(self._export_csv)
        stats_bar.addWidget(btn_export)

        btn_export_json = QPushButton("{} Export JSON".format("💾"))
        btn_export_json.setMaximumWidth(110)
        btn_export_json.clicked.connect(self._export_json)
        stats_bar.addWidget(btn_export_json)

        btn_import_csv = QPushButton("⤒ Import CSV")
        btn_import_csv.setMaximumWidth(110)
        btn_import_csv.clicked.connect(self._import_csv)
        stats_bar.addWidget(btn_import_csv)

        btn_import_json = QPushButton("⤒ Import JSON")
        btn_import_json.setMaximumWidth(120)
        btn_import_json.clicked.connect(self._import_json)
        stats_bar.addWidget(btn_import_json)

        layout.addLayout(stats_bar)

        # Results table
        self.results_table = QTableWidget(0, 6)
        self.results_table.setHorizontalHeaderLabels(
            ["#", "Payload", "Status", "Length", "Time (ms)", "Match"]
        )
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setColumnWidth(0, 40)
        self.results_table.setColumnWidth(2, 60)
        self.results_table.setColumnWidth(3, 80)
        self.results_table.setColumnWidth(4, 80)
        self.results_table.setColumnWidth(5, 60)
        self.results_table.setMaximumHeight(300)
        layout.addWidget(self.results_table)

        self._attack_start = 0
        self._error_count  = 0

    # ── Public API ─────────────────────────────
    def load_request(self, raw: str):
        self.request_edit.setPlainText(raw)

    # ── Private ────────────────────────────────
    def _load_payload_list(self):
        self.payload_combo.clear()
        self.payload_combo.addItem("— select category —")
        if os.path.isdir(PAYLOAD_DIR):
            for fname in sorted(os.listdir(PAYLOAD_DIR)):
                if fname.endswith(".txt"):
                    label = fname.replace(".txt", "").replace("_", " ").title()
                    self.payload_combo.addItem(label, userData=os.path.join(PAYLOAD_DIR, fname))

    def _on_payload_set_change(self, text):
        if not text.isdigit():
            return
        new_set = int(text)
        self._current_set = new_set
        self.payload_edit.blockSignals(True)
        self.payload_edit.setPlainText(self._payload_sets[new_set])
        self.payload_edit.blockSignals(False)
        self._update_payload_count()

    def _on_payload_text_changed(self):
        self._payload_sets[self._current_set] = self.payload_edit.toPlainText()
        self._update_payload_count()

    def _on_payload_select(self, text):
        if text.startswith("—"):
            return
        idx  = self.payload_combo.currentIndex()
        path = self.payload_combo.itemData(idx)
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            self.payload_edit.setPlainText(content)
        except Exception as e:
            self.payload_edit.setPlainText(f"Error loading: {e}")
        self.payload_combo.setCurrentIndex(0)

    def _load_payload_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Payload File", PAYLOAD_DIR, "Text Files (*.txt);;All Files (*)"
        )
        if path:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    self.payload_edit.setPlainText(f.read())
            except Exception as e:
                self.payload_edit.setPlainText(f"Error: {e}")

    def _update_payload_count(self):
        lines = [l for l in self.payload_edit.toPlainText().split("\n") if l.strip()]
        self.lbl_payload_count.setText(f"{len(lines)} payloads in Set {self._current_set}")

    def _add_marker(self):
        cursor = self.request_edit.textCursor()
        selected = cursor.selectedText()
        if selected:
            cursor.insertText(f"§{selected}§")
        else:
            cursor.insertText("§FUZZ§")

    def _clear_markers(self):
        text = self.request_edit.toPlainText()
        text = re.sub(r"§([^§]*)§", r"\1", text)
        self.request_edit.setPlainText(text)

    def _get_payloads_dict(self) -> dict:
        result = {}
        for k, v in self._payload_sets.items():
            lines = [l.strip() for l in v.split("\n") if l.strip()]
            if lines:
                result[k] = lines
        return result

    def _on_attack(self):
        raw_tpl  = self.request_edit.toPlainText().strip()
        payload_sets = self._get_payloads_dict()
        mode = self.mode_combo.currentText()

        if not raw_tpl:
            return
        if not payload_sets:
            return

        host    = self.host_input.text().strip() or "127.0.0.1"
        port    = self.port_input.value()
        use_ssl = self.ssl_check.isChecked()
        threads = self.threads_spin.value()
        timeout = self.timeout_spin.value()

        self._clear_results()
        self.btn_attack.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self._attack_start = time.time()

        self._thread = QThread()
        self._worker = AttackWorker(host, port, raw_tpl, mode, payload_sets, use_ssl, threads, timeout)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.result.connect(self._on_result)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_attack_done)
        self._worker.stopped.connect(self._on_attack_done)
        self._worker.finished.connect(self._thread.quit)
        self._worker.stopped.connect(self._thread.quit)
        self._thread.start()

    def _on_stop(self):
        if self._worker:
            self._worker.stop()

    def _on_result(self, idx: int, payload: str, status: int, length: int, ms: float):
        self._append_result(idx, payload, status, length, ms)

    def _on_progress(self, done: int, total: int):
        self.progress_bar.setValue(done)
        self.lbl_done.setText(f"Done: {done}/{total}")
        elapsed = time.time() - self._attack_start
        self.lbl_elapsed.setText(f"Elapsed: {elapsed:.1f}s")

    def _on_attack_done(self):
        self.btn_attack.setEnabled(True)
        self.btn_stop.setEnabled(False)

    def _clear_results(self):
        self.results_table.setRowCount(0)
        self._results.clear()
        self._error_count = 0
        self.progress_bar.setValue(0)
        self.lbl_done.setText("Done: 0")
        self.lbl_errors.setText("Errors: 0")
        self.lbl_elapsed.setText("")

    def _export_csv(self):
        if not self._results:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "intruder_results.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["idx","payload","status","length","ms"])
                writer.writeheader()
                writer.writerows(self._results)
        except Exception as e:
            pass

    def _export_json(self):
        if not self._results:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "intruder_results.json", "JSON Files (*.json)"
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._results, f, indent=2, ensure_ascii=True)
        except Exception:
            pass

    def _import_csv(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Results", "", "CSV Files (*.csv)"
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
        except Exception:
            return
        if not rows:
            return
        self._clear_results()
        for row in rows:
            try:
                idx = int(row.get("idx", 0))
                payload = row.get("payload", "")
                status = int(row.get("status", 0)) if row.get("status") else 0
                length = int(row.get("length", 0)) if row.get("length") else 0
                ms = float(row.get("ms", 0)) if row.get("ms") else 0.0
            except Exception:
                continue
            self._append_result(idx, payload, status, length, ms)

    def _import_json(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Results", "", "JSON Files (*.json)"
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return
        if not isinstance(data, list):
            return
        self._clear_results()
        for row in data:
            if not isinstance(row, dict):
                continue
            try:
                idx = int(row.get("idx", 0))
                payload = row.get("payload", "")
                status = int(row.get("status", 0)) if row.get("status") else 0
                length = int(row.get("length", 0)) if row.get("length") else 0
                ms = float(row.get("ms", 0)) if row.get("ms") else 0.0
            except Exception:
                continue
            self._append_result(idx, payload, status, length, ms)

    def _append_result(self, idx: int, payload: str, status: int, length: int, ms: float):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)

        col_color = status_color(status) if status else "#505070"
        match = ""

        items = [
            (str(idx + 1), Qt.AlignCenter, COLORS["text_dim"]),
            (payload[:80],  Qt.AlignLeft,   COLORS["yellow"]),
            (str(status) if status else "ERR", Qt.AlignCenter, col_color),
            (str(length),   Qt.AlignRight,  COLORS["text"]),
            (f"{ms:.1f}",   Qt.AlignRight,  COLORS["text"]),
            (match,         Qt.AlignCenter, COLORS["green"]),
        ]
        for col, (text, align, color) in enumerate(items):
            item = QTableWidgetItem(text)
            item.setTextAlignment(align | Qt.AlignVCenter)
            item.setForeground(QColor(color))
            self.results_table.setItem(row, col, item)

        if status == 0:
            self._error_count += 1
            self.lbl_errors.setText(f"Errors: {self._error_count}")

        self._results.append({
            "idx": idx, "payload": payload, "status": status,
            "length": length, "ms": ms
        })