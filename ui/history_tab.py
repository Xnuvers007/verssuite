"""
Vers Suite - HTTP History Tab
Shows all proxied requests/responses with details.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QTextEdit, QLabel,
    QPushButton, QHeaderView, QLineEdit, QComboBox, QAbstractItemView,
    QFileDialog, QMenu, QAction, QApplication, QCheckBox, QInputDialog
)
import json
import csv
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from .styles import status_color, COLORS
from .intercept_tab import HttpHighlighter
from core.sensitive_patterns import has_sensitive_data


class HistoryTab(QWidget):
    send_to_repeater = pyqtSignal(str, tuple)   # (raw_request, (host, port))
    send_to_intruder = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._flows: dict = {}   # flow_id -> flow_data
        self._responses: dict = {}
        self._notes: dict = {}   # flow_id -> note string
        self._order: list = []   # ordered flow_ids
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # ── Toolbar ────────────────────────────
        tb = QHBoxLayout()
        tb.setSpacing(8)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("🔍  Filter (URL, method, status, notes…)")
        self.search_box.textChanged.connect(self._apply_filter)
        self.search_box.setMaximumWidth(360)
        tb.addWidget(self.search_box)

        self.method_filter = QComboBox()
        self.method_filter.addItems(["All Methods", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
        self.method_filter.currentTextChanged.connect(self._apply_filter)
        tb.addWidget(self.method_filter)

        self.chk_scope_only = QCheckBox("Scope Only")
        self.chk_scope_only.setToolTip("Show only in-scope requests")
        self.chk_scope_only.stateChanged.connect(self._apply_filter)
        tb.addWidget(self.chk_scope_only)

        tb.addStretch()

        self.lbl_count = QLabel("0 requests")
        self.lbl_count.setStyleSheet("color:#505070; font-size:11px;")
        tb.addWidget(self.lbl_count)

        btn_export_json = QPushButton("⤓ JSON")
        btn_export_json.setToolTip("Export history session to JSON")
        btn_export_json.clicked.connect(self._export_json)
        btn_export_json.setMaximumWidth(80)
        tb.addWidget(btn_export_json)

        btn_import_json = QPushButton("⤒ JSON")
        btn_import_json.setToolTip("Import history session from JSON")
        btn_import_json.clicked.connect(self._import_json)
        btn_import_json.setMaximumWidth(80)
        tb.addWidget(btn_import_json)

        btn_export_csv = QPushButton("⤓ CSV")
        btn_export_csv.setToolTip("Export history session to CSV")
        btn_export_csv.clicked.connect(self._export_csv)
        btn_export_csv.setMaximumWidth(80)
        tb.addWidget(btn_export_csv)

        btn_import_csv = QPushButton("⤒ CSV")
        btn_import_csv.setToolTip("Import history session from CSV")
        btn_import_csv.clicked.connect(self._import_csv)
        btn_import_csv.setMaximumWidth(80)
        tb.addWidget(btn_import_csv)

        btn_clear = QPushButton("🗑  Clear")
        btn_clear.clicked.connect(self.clear_history)
        btn_clear.setMaximumWidth(80)
        tb.addWidget(btn_clear)

        layout.addLayout(tb)

        # ── Splitter ───────────────────────────
        splitter = QSplitter(Qt.Vertical)

        # Request table
        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(
            ["#", "Method", "Host", "Path", "Status", "Length", "Time (ms)", "⚠", "Notes"]
        )
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(8, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Interactive)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setColumnWidth(0, 40)
        self.table.setColumnWidth(1, 70)
        self.table.setColumnWidth(2, 200)
        self.table.setColumnWidth(4, 60)
        self.table.setColumnWidth(5, 80)
        self.table.setColumnWidth(6, 75)
        self.table.setColumnWidth(7, 30)
        self.table.currentCellChanged.connect(self._on_row_select)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_table_menu)
        self.table.doubleClicked.connect(self._on_double_click)
        splitter.addWidget(self.table)

        # Detail panel
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(4)

        # Action buttons for selected request
        btn_bar = QHBoxLayout()
        self.btn_repeater = QPushButton("↗  Send to Repeater")
        self.btn_repeater.clicked.connect(self._on_to_repeater)
        self.btn_repeater.setEnabled(False)
        self.btn_intruder = QPushButton("⚡  Send to Intruder")
        self.btn_intruder.clicked.connect(self._on_to_intruder)
        self.btn_intruder.setEnabled(False)
        btn_bar.addWidget(self.btn_repeater)
        btn_bar.addWidget(self.btn_intruder)
        btn_bar.addStretch()
        detail_layout.addLayout(btn_bar)

        # Request / response side-by-side
        detail_splitter = QSplitter(Qt.Horizontal)

        req_panel = QWidget()
        rq_layout = QVBoxLayout(req_panel)
        rq_layout.setContentsMargins(0, 0, 0, 0)
        rq_layout.setSpacing(2)
        rq_layout.addWidget(QLabel("REQUEST"))
        self.req_view = QTextEdit()
        self.req_view.setReadOnly(True)
        self.req_view.setObjectName("raw_request")
        self._hl_req = HttpHighlighter(self.req_view.document())
        font = QFont("Cascadia Code", 10)
        font.setStyleHint(QFont.Monospace)
        self.req_view.setFont(font)
        rq_layout.addWidget(self.req_view)
        detail_splitter.addWidget(req_panel)

        resp_panel = QWidget()
        rp_layout = QVBoxLayout(resp_panel)
        rp_layout.setContentsMargins(0, 0, 0, 0)
        rp_layout.setSpacing(2)
        rp_layout.addWidget(QLabel("RESPONSE"))
        self.resp_view = QTextEdit()
        self.resp_view.setReadOnly(True)
        self.resp_view.setObjectName("response_view")
        self._hl_resp = HttpHighlighter(self.resp_view.document())
        self.resp_view.setFont(font)
        rp_layout.addWidget(self.resp_view)
        detail_splitter.addWidget(resp_panel)

        detail_layout.addWidget(detail_splitter)
        splitter.addWidget(detail_widget)
        splitter.setSizes([350, 300])

        layout.addWidget(splitter, stretch=1)

    # ── Public API ─────────────────────────────
    def add_request(self, flow_data: dict):
        fid = flow_data["flow_id"]
        if fid in self._flows:
            return  # Already exists (intercept mode re-adds)
        self._flows[fid] = flow_data
        self._order.append(fid)
        self._insert_row(flow_data, len(self._order))

    def update_response(self, resp_data: dict):
        fid = resp_data["flow_id"]
        self._responses[fid] = resp_data
        # Update row colors
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.data(Qt.UserRole) == fid:
                code = resp_data.get("status_code", 0)
                color = status_color(code)
                status_item = QTableWidgetItem(str(code))
                status_item.setForeground(QColor(color))
                status_item.setData(Qt.UserRole, fid)
                self.table.setItem(row, 4, status_item)

                length_item = QTableWidgetItem(self._format_size(resp_data.get("length", 0)))
                length_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.table.setItem(row, 5, length_item)

                time_item = QTableWidgetItem(f"{resp_data.get('elapsed_ms', 0):.1f}")
                time_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.table.setItem(row, 6, time_item)
                break

        self.lbl_count.setText(f"{len(self._order)} requests")

    def clear_history(self):
        self._flows.clear()
        self._responses.clear()
        self._order.clear()
        self.table.setRowCount(0)
        self.req_view.clear()
        self.resp_view.clear()
        self.btn_repeater.setEnabled(False)
        self.btn_intruder.setEnabled(False)
        self.lbl_count.setText("0 requests")

    def get_notes(self) -> dict:
        """Return all notes for session save."""
        return dict(self._notes)

    def set_notes(self, notes: dict):
        """Restore notes from session load."""
        self._notes = dict(notes)
        # Update table
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item:
                fid = item.data(Qt.UserRole)
                note = self._notes.get(fid, "")
                notes_item = self.table.item(row, 8)
                if notes_item:
                    notes_item.setText(note)

    # ── Private helpers ────────────────────────
    def _format_size(self, n: int) -> str:
        if n < 1024: return f"{n} B"
        if n < 1024*1024: return f"{n/1024:.1f} KB"
        return f"{n/1024/1024:.1f} MB"

    def _insert_row(self, flow_data: dict, idx: int):
        row = self.table.rowCount()
        self.table.insertRow(row)

        fid = flow_data["flow_id"]
        items = [
            (str(idx), Qt.AlignCenter),
            (flow_data.get("method", "?"), Qt.AlignCenter),
            (flow_data.get("host", "?"), Qt.AlignLeft),
            (flow_data.get("path", "/"), Qt.AlignLeft),
            ("…", Qt.AlignCenter),
            ("…", Qt.AlignRight),
            ("…", Qt.AlignRight),
        ]

        for col, (text, align) in enumerate(items):
            item = QTableWidgetItem(text)
            item.setTextAlignment(align | Qt.AlignVCenter)
            item.setData(Qt.UserRole, fid)
            if col == 1:  # method color
                color_map = {"GET": "#00e676","POST": "#40c4ff","PUT": "#ffab00",
                             "DELETE": "#ff5252","PATCH": "#ea00ff"}
                item.setForeground(QColor(color_map.get(flow_data.get("method",""), "#c0c0cc")))
            self.table.setItem(row, col, item)

        # Sensitive data badge (column 7)
        raw_text = self._build_raw_request(flow_data)
        sensitive = has_sensitive_data(raw_text)
        badge_item = QTableWidgetItem("⚠" if sensitive else "")
        badge_item.setTextAlignment(Qt.AlignCenter)
        badge_item.setForeground(QColor("#ff5252" if sensitive else "#303040"))
        badge_item.setData(Qt.UserRole, fid)
        self.table.setItem(row, 7, badge_item)

        # Notes column (column 8)
        note = self._notes.get(fid, "")
        note_item = QTableWidgetItem(note)
        note_item.setForeground(QColor("#7070a0"))
        note_item.setData(Qt.UserRole, fid)
        self.table.setItem(row, 8, note_item)

    def _apply_filter(self):
        method_f = self.method_filter.currentText()
        text_f   = self.search_box.text().lower()
        for row in range(self.table.rowCount()):
            fid_item = self.table.item(row, 0)
            if not fid_item:
                continue
            fid = fid_item.data(Qt.UserRole)
            flow = self._flows.get(fid, {})
            method = flow.get("method", "")
            url    = flow.get("url", "").lower()
            host   = flow.get("host", "").lower()
            status = str(self._responses.get(fid, {}).get("status_code", ""))

            visible = True
            if method_f != "All Methods" and method != method_f:
                visible = False
            if text_f and text_f not in url and text_f not in host and text_f not in status:
                # Also search in notes
                note = self._notes.get(fid, "").lower()
                if text_f not in note:
                    visible = False
            if self.chk_scope_only.isChecked():
                flow_obj = self._flows.get(fid, {})
                if not flow_obj.get("in_scope", True):
                    visible = False
            self.table.setRowHidden(row, not visible)

    def _on_row_select(self, row, col, prev_row, prev_col):
        item = self.table.item(row, 0)
        if not item:
            return
        fid = item.data(Qt.UserRole)
        flow = self._flows.get(fid, {})
        resp = self._responses.get(fid, {})

        # Build raw request
        raw = f"{flow.get('method','?')} {flow.get('path','/')} {flow.get('http_version','HTTP/1.1')}\n"
        for k, v in flow.get("headers", {}).items():
            raw += f"{k}: {v}\n"
        raw += "\n"
        raw += flow.get("body", "")
        self.req_view.setPlainText(raw)

        # Build raw response
        if resp:
            raw_r = f"HTTP/1.1 {resp.get('status_code','?')} {resp.get('reason','')}\n"
            for k, v in resp.get("headers", {}).items():
                raw_r += f"{k}: {v}\n"
            raw_r += "\n"
            raw_r += resp.get("body", "")
            self.resp_view.setPlainText(raw_r)
        else:
            self.resp_view.setPlainText("(No response yet)")

        self.btn_repeater.setEnabled(True)
        self.btn_intruder.setEnabled(True)

    def _selected_flow(self):
        row = self.table.currentRow()
        if row < 0:
            return None, None
        item = self.table.item(row, 0)
        if not item:
            return None, None
        fid  = item.data(Qt.UserRole)
        flow = self._flows.get(fid)
        return fid, flow

    def _on_to_repeater(self):
        _, flow = self._selected_flow()
        if not flow:
            return
        raw = self.req_view.toPlainText()
        host = flow.get("host", "localhost")
        port = flow.get("port", 80)
        self.send_to_repeater.emit(raw, (host, port))

    def _on_to_intruder(self):
        _, flow = self._selected_flow()
        if not flow:
            return
        raw = self.req_view.toPlainText()
        self.send_to_intruder.emit(raw)

    def _on_table_menu(self, pos):
        _, flow = self._selected_flow()
        if not flow:
            return
        fid = flow.get("flow_id")
        resp = self._responses.get(fid, {})

        menu = QMenu(self)
        act_copy_url = QAction("Copy URL", self)
        act_copy_req_headers = QAction("Copy Request Headers", self)
        act_copy_resp_headers = QAction("Copy Response Headers", self)
        act_copy_raw_req = QAction("Copy Raw Request", self)
        act_copy_raw_resp = QAction("Copy Raw Response", self)
        act_send_repeater = QAction("Send to Repeater", self)
        act_send_intruder = QAction("Send to Intruder", self)

        menu.addAction(act_copy_url)
        menu.addAction(act_copy_req_headers)
        menu.addAction(act_copy_resp_headers)
        menu.addSeparator()
        menu.addAction(act_copy_raw_req)
        menu.addAction(act_copy_raw_resp)
        menu.addSeparator()
        menu.addAction(act_send_repeater)
        menu.addAction(act_send_intruder)

        menu.addSeparator()
        act_edit_note = QAction("📝 Edit Note", self)
        act_edit_note.triggered.connect(lambda: self._edit_note_for_flow(fid))
        menu.addAction(act_edit_note)

        act_to_comparer = QAction("⇄ Send to Comparer (Left)", self)
        act_to_comparer.triggered.connect(lambda: self._send_to_comparer(flow, resp))
        menu.addAction(act_to_comparer)

        def to_clipboard(text: str):
            QApplication.clipboard().setText(text or "")

        act_copy_url.triggered.connect(lambda: to_clipboard(flow.get("url", "")))
        act_copy_req_headers.triggered.connect(
            lambda: to_clipboard(self._headers_to_text(flow.get("headers", {})))
        )
        act_copy_resp_headers.triggered.connect(
            lambda: to_clipboard(self._headers_to_text(resp.get("headers", {})))
        )
        act_copy_raw_req.triggered.connect(
            lambda: to_clipboard(self._build_raw_request(flow))
        )
        act_copy_raw_resp.triggered.connect(
            lambda: to_clipboard(self._build_raw_response(resp))
        )
        act_send_repeater.triggered.connect(self._on_to_repeater)
        act_send_intruder.triggered.connect(self._on_to_intruder)

        menu.exec_(self.table.viewport().mapToGlobal(pos))

    def _on_double_click(self, index):
        """Double-click on Notes column to edit."""
        if index.column() == 8:  # Notes column
            item = self.table.item(index.row(), 0)
            if not item:
                return
            fid = item.data(Qt.UserRole)
            self._edit_note_for_flow(fid)

    def _edit_note_for_flow(self, fid: str):
        current_note = self._notes.get(fid, "")
        text, ok = QInputDialog.getText(
            self, "Edit Note", "Note for this request:",
            text=current_note
        )
        if ok:
            self._notes[fid] = text
            # Update table cell
            for row in range(self.table.rowCount()):
                row_item = self.table.item(row, 0)
                if row_item and row_item.data(Qt.UserRole) == fid:
                    notes_item = self.table.item(row, 8)
                    if notes_item:
                        notes_item.setText(text)
                    break

    def _send_to_comparer(self, flow: dict, resp: dict):
        from PyQt5.QtCore import QCoreApplication
        app = QCoreApplication.instance()
        for w in app.topLevelWidgets():
            if hasattr(w, "comparer_tab"):
                raw_req = self._build_raw_request(flow)
                w.comparer_tab.load_left(raw_req)
                if hasattr(w, "comparer_page"):
                    w.tabs.setCurrentWidget(w.comparer_page)
                break

    def _headers_to_text(self, headers: dict) -> str:
        if not headers:
            return ""
        return "\n".join([f"{k}: {v}" for k, v in headers.items()])

    def _export_json(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export History", "history_session.json", "JSON Files (*.json)"
        )
        if not path:
            return
        data = []
        for fid in self._order:
            flow = self._flows.get(fid, {})
            resp = self._responses.get(fid, {})
            data.append({"flow": flow, "response": resp})
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=True)
        except Exception:
            pass

    def _import_json(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import History", "", "JSON Files (*.json)"
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
        self.clear_history()
        for idx, entry in enumerate(data, start=1):
            flow = entry.get("flow") if isinstance(entry, dict) else None
            resp = entry.get("response") if isinstance(entry, dict) else None
            if not isinstance(flow, dict):
                continue
            flow.setdefault("flow_id", f"import-{idx}")
            self.add_request(flow)
            if isinstance(resp, dict) and resp:
                resp["flow_id"] = flow["flow_id"]
                self.update_response(resp)

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export History", "history_session.csv", "CSV Files (*.csv)"
        )
        if not path:
            return
        fields = [
            "method", "url", "host", "path", "status", "length", "time_ms",
            "raw_request", "raw_response"
        ]
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                for fid in self._order:
                    flow = self._flows.get(fid, {})
                    resp = self._responses.get(fid, {})
                    raw_req = self._build_raw_request(flow)
                    raw_resp = self._build_raw_response(resp)
                    writer.writerow({
                        "method": flow.get("method", ""),
                        "url": flow.get("url", ""),
                        "host": flow.get("host", ""),
                        "path": flow.get("path", ""),
                        "status": resp.get("status_code", ""),
                        "length": resp.get("length", ""),
                        "time_ms": resp.get("elapsed_ms", ""),
                        "raw_request": raw_req,
                        "raw_response": raw_resp,
                    })
        except Exception:
            pass

    def _import_csv(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import History", "", "CSV Files (*.csv)"
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
        self.clear_history()
        for idx, row in enumerate(rows, start=1):
            raw_req = row.get("raw_request", "")
            flow = self._parse_raw_request(raw_req)
            flow.setdefault("flow_id", f"import-{idx}")
            flow.setdefault("url", row.get("url", ""))
            flow.setdefault("host", row.get("host", ""))
            flow.setdefault("path", row.get("path", "/"))
            self.add_request(flow)

            raw_resp = row.get("raw_response", "")
            resp = self._parse_raw_response(raw_resp)
            if resp:
                resp["flow_id"] = flow["flow_id"]
                self.update_response(resp)

    def _build_raw_request(self, flow: dict) -> str:
        if not flow:
            return ""
        raw = f"{flow.get('method','?')} {flow.get('path','/')} {flow.get('http_version','HTTP/1.1')}\n"
        for k, v in flow.get("headers", {}).items():
            raw += f"{k}: {v}\n"
        raw += "\n"
        raw += flow.get("body", "") or ""
        return raw

    def _build_raw_response(self, resp: dict) -> str:
        if not resp:
            return ""
        raw = f"HTTP/1.1 {resp.get('status_code','?')} {resp.get('reason','')}\n"
        for k, v in resp.get("headers", {}).items():
            raw += f"{k}: {v}\n"
        raw += "\n"
        raw += resp.get("body", "") or ""
        return raw

    def _parse_raw_request(self, raw: str) -> dict:
        if not raw:
            return {}
        text = raw.replace("\r\n", "\n")
        lines = text.split("\n")
        first = lines[0].strip().split()
        method = first[0] if len(first) > 0 else "GET"
        path = first[1] if len(first) > 1 else "/"
        http_version = first[2] if len(first) > 2 else "HTTP/1.1"
        headers = {}
        body_start = None
        for i, line in enumerate(lines[1:], start=1):
            if line.strip() == "":
                body_start = i + 1
                break
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
        body = "\n".join(lines[body_start:]) if body_start else ""
        host = headers.get("Host", "")
        url = f"http://{host}{path}" if host else path
        return {
            "method": method,
            "path": path,
            "http_version": http_version,
            "headers": headers,
            "body": body,
            "host": host,
            "url": url,
        }

    def _parse_raw_response(self, raw: str) -> dict:
        if not raw:
            return {}
        text = raw.replace("\r\n", "\n")
        lines = text.split("\n")
        first = lines[0].strip().split()
        status_code = 0
        reason = ""
        if len(first) >= 2 and first[1].isdigit():
            status_code = int(first[1])
            reason = " ".join(first[2:]) if len(first) > 2 else ""
        headers = {}
        body_start = None
        for i, line in enumerate(lines[1:], start=1):
            if line.strip() == "":
                body_start = i + 1
                break
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
        body = "\n".join(lines[body_start:]) if body_start else ""
        return {
            "status_code": status_code,
            "reason": reason,
            "headers": headers,
            "body": body,
            "length": len(body.encode("utf-8", errors="replace")),
        }