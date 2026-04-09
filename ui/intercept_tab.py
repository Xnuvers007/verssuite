"""
Vers Suite - Intercept Tab
Real-time request viewing, editing, forwarding and dropping.
Supports response interception and sensitive data detection.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QTextEdit, QLabel, QFrame, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QLineEdit,
    QMessageBox, QMenu, QAction, QApplication, QCheckBox
)
from PyQt5.QtCore import Qt, pyqtSignal
from core import load_config, save_config
from core.sensitive_patterns import scan_text, has_sensitive_data, get_severity_color
from PyQt5.QtGui import QFont, QColor, QTextCharFormat, QSyntaxHighlighter
import re
import socket


# ─────────────────────────────────────────────
# HTTP Syntax Highlighter
# ─────────────────────────────────────────────
class HttpHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self._rules = []

        def rule(pattern, color, bold=False):
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(color))
            if bold:
                fmt.setFontWeight(700)
            self._rules.append((re.compile(pattern), fmt))

        # HTTP method
        rule(r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|CONNECT|TRACE)\b", "#ea00ff", True)
        # HTTP version
        rule(r"HTTP/\d\.\d", "#00d4ff")
        # Status code
        rule(r"\b([1-5]\d{2})\b", "#ffab00", True)
        # Header name
        rule(r"^[A-Za-z-]+(?=:)", "#40c4ff")
        # Header value
        rule(r"(?<=:).+$", "#c8c8cc")
        # URL / path
        rule(r"https?://[^\s]+", "#00e676")
        rule(r"(/[^\s?#]*)", "#90ff90")
        # Query params
        rule(r"\?[^\s]*", "#ffd600")
        # JSON keys
        rule(r'"[\w-]+"(?=\s*:)', "#40c4ff")
        # JSON strings
        rule(r'"[^"]*"', "#c8ffc8")
        # JSON numbers/booleans
        rule(r'\b(true|false|null|\d+\.?\d*)\b', "#ffab00")

    def highlightBlock(self, text):
        for pattern, fmt in self._rules:
            for m in pattern.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)


# ─────────────────────────────────────────────
# Intercept Tab
# ─────────────────────────────────────────────
class InterceptTab(QWidget):
    """
    Shows intercepted requests and allows editing before forwarding/dropping.
    Emits forward_clicked(flow_id, modifications) or drop_clicked(flow_id).
    """
    forward_signal = pyqtSignal(str, dict)   # (flow_id, modifications)
    drop_signal    = pyqtSignal(str)          # flow_id
    forward_all_signal = pyqtSignal()
    drop_all_signal    = pyqtSignal()
    # Response intercept signals
    response_forward_signal = pyqtSignal(str, dict)   # (flow_id, modifications)
    response_drop_signal    = pyqtSignal(str)          # flow_id

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_flow_id: str | None = None
        self._flows: dict = {}
        self._responses: dict = {}
        self._intercepted_responses: dict = {}  # flow_id -> response data
        self._current_resp_flow_id: str | None = None
        self._dns_cache: dict = {}
        self._confirm_drop_all = True
        self._order: list = []
        self._load_settings()
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # ── Top action bar ─────────────────────
        top_bar = QHBoxLayout()
        top_bar.setSpacing(8)

        self.lbl_status = QLabel("⬤  Waiting for intercepted request…")
        self.lbl_status.setObjectName("status_intercept")
        top_bar.addWidget(self.lbl_status)
        top_bar.addStretch()

        self.btn_forward = QPushButton("▶  Forward")
        self.btn_forward.setObjectName("btn_forward")
        self.btn_forward.setToolTip("Forward request (with edits if any)")
        self.btn_forward.clicked.connect(self._on_forward)
        self.btn_forward.setEnabled(False)

        self.btn_drop = QPushButton("✖  Drop")
        self.btn_drop.setObjectName("btn_drop")
        self.btn_drop.setToolTip("Drop / kill this request")
        self.btn_drop.clicked.connect(self._on_drop)
        self.btn_drop.setEnabled(False)

        self.btn_to_repeater = QPushButton("↗  Send to Repeater")
        self.btn_to_repeater.setToolTip("Copy this request to the Repeater tab")
        self.btn_to_repeater.clicked.connect(self._on_send_to_repeater)
        self.btn_to_repeater.setEnabled(False)

        self.btn_forward_all = QPushButton("≫  Forward All")
        self.btn_forward_all.setToolTip("Forward all pending intercepted requests")
        self.btn_forward_all.clicked.connect(self._on_forward_all)
        self.btn_forward_all.setEnabled(False)

        self.btn_drop_all = QPushButton("✖  Drop All")
        self.btn_drop_all.setToolTip("Drop all pending intercepted requests")
        self.btn_drop_all.clicked.connect(self._on_drop_all)
        self.btn_drop_all.setEnabled(False)

        self.btn_to_intruder = QPushButton("⚡  Send to Intruder")
        self.btn_to_intruder.setToolTip("Copy this request to the Intruder tab")
        self.btn_to_intruder.clicked.connect(self._on_send_to_intruder)
        self.btn_to_intruder.setEnabled(False)

        # Sensitive data badge
        self.lbl_sensitive = QLabel("")
        self.lbl_sensitive.setStyleSheet("color: #ff5252; font-weight: bold; font-size: 11px;")
        self.lbl_sensitive.setVisible(False)

        for btn in [
            self.btn_forward, self.btn_drop, self.btn_forward_all, self.btn_drop_all,
            self.btn_to_repeater, self.btn_to_intruder
        ]:
            top_bar.addWidget(btn)
        top_bar.addWidget(self.lbl_sensitive)

        layout.addLayout(top_bar)

        # ── Divider ────────────────────────────
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #1e1e2e;")
        layout.addWidget(line)

        # ── Request list + editor ─────────────
        main_splitter = QSplitter(Qt.Horizontal)

        # Pending intercepts list
        list_panel = QWidget()
        list_layout = QVBoxLayout(list_panel)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(4)

        list_hdr = QLabel("PENDING INTERCEPTS")
        list_hdr.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        list_layout.addWidget(list_hdr)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Filter (host, path, url, method)")
        self.search_box.textChanged.connect(self._apply_filter)
        list_layout.addWidget(self.search_box)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["#", "Method", "Host", "Path"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setColumnWidth(0, 40)
        self.table.setColumnWidth(1, 70)
        self.table.setColumnWidth(2, 140)
        self.table.currentCellChanged.connect(self._on_row_select)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_table_menu)
        list_layout.addWidget(self.table)

        main_splitter.addWidget(list_panel)

        # Right side: request editor + metadata
        right_splitter = QSplitter(Qt.Vertical)

        # Request panel
        req_panel = QWidget()
        req_layout = QVBoxLayout(req_panel)
        req_layout.setContentsMargins(0, 0, 0, 0)
        req_layout.setSpacing(4)

        req_hdr = QLabel("REQUEST  —  edit freely before forwarding")
        req_hdr.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        req_layout.addWidget(req_hdr)

        self.request_edit = QTextEdit()
        self.request_edit.setObjectName("raw_request")
        self.request_edit.setPlaceholderText(
            "Intercepted request will appear here.\n"
            "Edit it, then click ▶ Forward."
        )
        font = QFont("Cascadia Code", 11)
        font.setStyleHint(QFont.Monospace)
        self.request_edit.setFont(font)
        self._hl_req = HttpHighlighter(self.request_edit.document())
        req_layout.addWidget(self.request_edit)

        right_splitter.addWidget(req_panel)

        # Info panel (read-only metadata)
        info_panel = QWidget()
        info_layout = QVBoxLayout(info_panel)
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(4)

        info_hdr = QLabel("REQUEST METADATA")
        info_hdr.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        info_layout.addWidget(info_hdr)

        self.info_view = QTextEdit()
        self.info_view.setReadOnly(True)
        self.info_view.setMaximumHeight(100)
        self.info_view.setObjectName("response_view")
        self.info_view.setPlaceholderText("Flow metadata…")
        info_layout.addWidget(self.info_view)

        right_splitter.addWidget(info_panel)
        right_splitter.setSizes([500, 100])

        main_splitter.addWidget(right_splitter)
        main_splitter.setSizes([260, 700])

        layout.addWidget(main_splitter, stretch=1)

        # ── Response Intercept Pane ───────────────
        resp_intercept_widget = QWidget()
        resp_layout = QVBoxLayout(resp_intercept_widget)
        resp_layout.setContentsMargins(0, 4, 0, 0)
        resp_layout.setSpacing(4)

        resp_bar = QHBoxLayout()
        resp_hdr = QLabel("INTERCEPTED RESPONSE  —  edit before forwarding to browser")
        resp_hdr.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        resp_bar.addWidget(resp_hdr)
        resp_bar.addStretch()

        self.btn_resp_forward = QPushButton("▶  Forward Response")
        self.btn_resp_forward.setObjectName("btn_forward")
        self.btn_resp_forward.clicked.connect(self._on_response_forward)
        self.btn_resp_forward.setEnabled(False)
        resp_bar.addWidget(self.btn_resp_forward)

        self.btn_resp_drop = QPushButton("✖  Drop Response")
        self.btn_resp_drop.setObjectName("btn_drop")
        self.btn_resp_drop.clicked.connect(self._on_response_drop)
        self.btn_resp_drop.setEnabled(False)
        resp_bar.addWidget(self.btn_resp_drop)

        resp_layout.addLayout(resp_bar)

        self.response_edit = QTextEdit()
        self.response_edit.setObjectName("response_view")
        self.response_edit.setPlaceholderText(
            "Intercepted response will appear here when Response Interception is enabled."
        )
        font2 = QFont("Cascadia Code", 11)
        font2.setStyleHint(QFont.Monospace)
        self.response_edit.setFont(font2)
        self.response_edit.setMaximumHeight(200)
        self._hl_resp = HttpHighlighter(self.response_edit.document())
        resp_layout.addWidget(self.response_edit)

        layout.addWidget(resp_intercept_widget)

    # ── Internal helpers ───────────────────────
    def _raw_text_to_modifications(self) -> dict:
        """Parse the edited request text back into modifications dict."""
        text = self.request_edit.toPlainText()
        lines = text.split("\n")
        mods = {}
        if not lines:
            return mods

        # First line: METHOD PATH HTTP/VERSION
        first = lines[0].strip().split()
        if len(first) >= 2:
            mods["method"] = first[0]
            mods["path"]   = first[1]

        # Headers
        headers = {}
        body_start = None
        for i, line in enumerate(lines[1:], start=1):
            if line.strip() == "":
                body_start = i + 1
                break
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()

        if headers:
            mods["headers"] = headers

        if body_start is not None:
            mods["body"] = "\n".join(lines[body_start:])

        return mods

    def _flow_to_raw(self, flow_data: dict) -> str:
        """Build a raw HTTP request string from a flow dict."""
        lines = []
        path = flow_data.get("path", "/")
        ver  = flow_data.get("http_version", "HTTP/1.1")
        lines.append(f"{flow_data['method']} {path} {ver}")
        for k, v in flow_data.get("headers", {}).items():
            lines.append(f"{k}: {v}")
        lines.append("")
        body = flow_data.get("body", "")
        if body:
            lines.append(body)
        return "\n".join(lines)

    # ── Public API ─────────────────────────────
    def show_intercepted(self, flow_data: dict):
        fid = flow_data["flow_id"]
        if fid in self._flows:
            return
        self._flows[fid] = flow_data
        self._order.append(fid)
        self._insert_row(flow_data, len(self._order))

        if self.table.currentRow() < 0:
            self.table.selectRow(self.table.rowCount() - 1)
        self._update_status()

    def show_intercepted_response(self, resp_data: dict):
        """Show an intercepted response for editing before forwarding to browser."""
        fid = resp_data.get("flow_id")
        if not fid:
            return
        self._intercepted_responses[fid] = resp_data
        self._current_resp_flow_id = fid

        # Build raw response text
        lines = []
        status = resp_data.get("status_code", "?")
        reason = resp_data.get("reason", "")
        lines.append(f"HTTP/1.1 {status} {reason}")
        for k, v in resp_data.get("headers", {}).items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(resp_data.get("body", ""))

        self.response_edit.setPlainText("\n".join(lines))
        self.btn_resp_forward.setEnabled(True)
        self.btn_resp_drop.setEnabled(True)

    def update_response_meta(self, resp_data: dict):
        fid = resp_data.get("flow_id")
        if not fid:
            return
        self._responses[fid] = resp_data
        if self._current_flow_id == fid:
            self._update_metadata_view()

    def clear(self):
        self._current_flow_id = None
        self.request_edit.clear()
        self.info_view.clear()
        self.lbl_status.setText("⬤  Waiting for intercepted request…")
        for btn in [
            self.btn_forward, self.btn_drop, self.btn_forward_all, self.btn_drop_all,
            self.btn_to_repeater, self.btn_to_intruder
        ]:
            btn.setEnabled(False)

    def get_raw_request(self) -> str:
        return self.request_edit.toPlainText()

    # ── Slots ──────────────────────────────────
    def _on_forward(self):
        if not self._current_flow_id:
            return
        mods = self._raw_text_to_modifications()
        self.forward_signal.emit(self._current_flow_id, mods)
        self._remove_current_flow()

    def _on_drop(self):
        if not self._current_flow_id:
            return
        self.drop_signal.emit(self._current_flow_id)
        self._remove_current_flow()

    def _on_forward_all(self):
        if not self._flows:
            return
        self.forward_all_signal.emit()
        self._clear_all_flows()

    def _on_drop_all(self):
        if not self._flows:
            return
        if self._confirm_drop_all:
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Warning)
            box.setWindowTitle("Drop All Pending Requests")
            box.setText("Drop all pending intercepted requests?")
            box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            box.setDefaultButton(QMessageBox.No)

            chk = QCheckBox("Don't ask again")
            box.setCheckBox(chk)

            resp = box.exec_()
            if resp != QMessageBox.Yes:
                return
            if chk.isChecked():
                self._confirm_drop_all = False
                self._save_settings()
        self.drop_all_signal.emit()
        self._clear_all_flows()

    def _insert_row(self, flow_data: dict, idx: int):
        row = self.table.rowCount()
        self.table.insertRow(row)

        fid = flow_data["flow_id"]
        items = [
            (str(idx), Qt.AlignCenter),
            (flow_data.get("method", "?"), Qt.AlignCenter),
            (flow_data.get("host", "?"), Qt.AlignLeft),
            (flow_data.get("path", "/"), Qt.AlignLeft),
        ]

        for col, (text, align) in enumerate(items):
            item = QTableWidgetItem(text)
            item.setTextAlignment(align | Qt.AlignVCenter)
            item.setData(Qt.UserRole, fid)
            self.table.setItem(row, col, item)

    def _on_row_select(self, row, col, prev_row, prev_col):
        item = self.table.item(row, 0)
        if not item:
            return
        fid = item.data(Qt.UserRole)
        flow = self._flows.get(fid)
        if not flow:
            return
        self._current_flow_id = fid
        raw = self._flow_to_raw(flow)
        self.request_edit.setPlainText(raw)
        self._update_metadata_view()
        for btn in [
            self.btn_forward, self.btn_drop, self.btn_forward_all, self.btn_drop_all,
            self.btn_to_repeater, self.btn_to_intruder
        ]:
            btn.setEnabled(True)
        self._update_status()

        # Sensitive data check
        raw_text = self.request_edit.toPlainText()
        if has_sensitive_data(raw_text):
            matches = scan_text(raw_text, max_matches=5)
            types = set(m.type for m in matches)
            self.lbl_sensitive.setText(f"⚠ Sensitive: {', '.join(types)}")
            self.lbl_sensitive.setVisible(True)
        else:
            self.lbl_sensitive.setVisible(False)

    def _remove_current_flow(self):
        fid = self._current_flow_id
        if not fid:
            return

        row_to_remove = None
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.data(Qt.UserRole) == fid:
                row_to_remove = row
                break

        if row_to_remove is not None:
            self.table.removeRow(row_to_remove)

        if fid in self._flows:
            del self._flows[fid]
        if fid in self._order:
            self._order.remove(fid)

        if self.table.rowCount() > 0:
            next_row = min(row_to_remove or 0, self.table.rowCount() - 1)
            self.table.selectRow(next_row)
        else:
            self.clear()
        self._update_status()

    def _update_status(self):
        total = len(self._flows)
        if total == 0:
            self.lbl_status.setText("⬤  Waiting for intercepted request…")
            return
        if self._current_flow_id and self._current_flow_id in self._flows:
            flow = self._flows[self._current_flow_id]
            self.lbl_status.setText(
                f"⬤  {flow.get('method','?')}  {flow.get('url','')}  |  Pending: {total}"
            )
        else:
            self.lbl_status.setText(f"⬤  Intercepts Pending: {total}")

    def _apply_filter(self):
        text_f = self.search_box.text().lower().strip()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if not item:
                continue
            fid = item.data(Qt.UserRole)
            flow = self._flows.get(fid, {})
            method = flow.get("method", "").lower()
            url = flow.get("url", "").lower()
            host = flow.get("host", "").lower()
            path = flow.get("path", "").lower()

            if not text_f:
                self.table.setRowHidden(row, False)
                continue

            visible = (
                text_f in method or text_f in url or text_f in host or text_f in path
            )
            self.table.setRowHidden(row, not visible)

    def _on_send_to_repeater(self):
        from PyQt5.QtCore import QCoreApplication
        app = QCoreApplication.instance()
        main_win = None
        for w in app.topLevelWidgets():
            if hasattr(w, "repeater_tab"):
                main_win = w
                break
        if main_win:
            main_win.repeater_tab.load_request(
                self.request_edit.toPlainText(),
                self._get_host_port()
            )
            if hasattr(main_win, "repeater_page"):
                main_win.tabs.setCurrentWidget(main_win.repeater_page)
            else:
                main_win.tabs.setCurrentIndex(1)

    def _on_send_to_intruder(self):
        from PyQt5.QtCore import QCoreApplication
        app = QCoreApplication.instance()
        for w in app.topLevelWidgets():
            if hasattr(w, "intruder_tab"):
                w.intruder_tab.load_request(self.request_edit.toPlainText())
                if hasattr(w, "intruder_page"):
                    w.tabs.setCurrentWidget(w.intruder_page)
                else:
                    w.tabs.setCurrentIndex(2)
                break

    def _get_host_port(self):
        text = self.info_view.toPlainText()
        for line in text.split("\n"):
            if line.startswith("Host"):
                parts = line.split(":")
                if len(parts) >= 3:
                    return parts[1].strip(), int(parts[2].strip())
        return "localhost", 80

    def _on_table_menu(self, pos):
        row = self.table.currentRow()
        if row < 0:
            return
        item = self.table.item(row, 0)
        if not item:
            return
        fid = item.data(Qt.UserRole)
        flow = self._flows.get(fid)
        if not flow:
            return

        menu = QMenu(self)
        act_copy_url = QAction("Copy URL", self)
        act_copy_headers = QAction("Copy Request Headers", self)
        act_copy_raw = QAction("Copy Raw Request", self)
        act_send_repeater = QAction("Send to Repeater", self)
        act_send_intruder = QAction("Send to Intruder", self)

        menu.addAction(act_copy_url)
        menu.addAction(act_copy_headers)
        menu.addSeparator()
        menu.addAction(act_copy_raw)
        menu.addSeparator()
        menu.addAction(act_send_repeater)
        menu.addAction(act_send_intruder)

        def to_clipboard(text: str):
            QApplication.clipboard().setText(text or "")

        act_copy_url.triggered.connect(lambda: to_clipboard(flow.get("url", "")))
        act_copy_headers.triggered.connect(
            lambda: to_clipboard(self._headers_to_text(flow.get("headers", {})))
        )
        act_copy_raw.triggered.connect(lambda: to_clipboard(self._flow_to_raw(flow)))
        act_send_repeater.triggered.connect(self._on_send_to_repeater)
        act_send_intruder.triggered.connect(self._on_send_to_intruder)

        menu.exec_(self.table.viewport().mapToGlobal(pos))

    def _headers_to_text(self, headers: dict) -> str:
        if not headers:
            return ""
        return "\n".join([f"{k}: {v}" for k, v in headers.items()])

    def _clear_all_flows(self):
        self._flows.clear()
        self._responses.clear()
        self._order.clear()
        self.table.setRowCount(0)
        self.clear()

    def _load_settings(self):
        cfg = load_config()
        self._confirm_drop_all = bool(cfg.get("confirm_drop_all", True))

    def _save_settings(self):
        cfg = load_config()
        cfg["confirm_drop_all"] = bool(self._confirm_drop_all)
        save_config(cfg)

    def _update_metadata_view(self):
        fid = self._current_flow_id
        flow = self._flows.get(fid, {}) if fid else {}
        resp = self._responses.get(fid, {}) if fid else {}

        host = flow.get("host", "?")
        port = flow.get("port", "?")
        scheme = flow.get("scheme", "?")
        time_s = flow.get("timestamp", "?")

        ip_addr = self._resolve_ip(host)
        cf_enabled = self._is_cloudflare(resp, host)
        waf_name = self._detect_waf(resp, host, cf_enabled)
        cf_ip = ip_addr if cf_enabled and ip_addr else "(unknown)"

        meta_lines = [
            f"Flow ID : {flow.get('flow_id','?')}",
            f"Host    : {host}:{port}",
            f"Scheme  : {scheme}",
            f"Time    : {time_s}",
            f"IP Addr : {ip_addr or '(unresolved)'}",
            f"WAF     : {waf_name or 'not detected'}",
            f"Cloudflare : {'yes' if cf_enabled else 'no'}",
            f"Cloudflare IP : {cf_ip if cf_enabled else '-'}",
            "",
            "HTTP Security Headers Check Tool - Security Headers Response",
        ]

        headers = {}
        for k, v in (resp.get("headers") or {}).items():
            key = k.decode("utf-8", "replace") if isinstance(k, (bytes, bytearray)) else str(k)
            val = v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)
            headers[key.lower()] = val

        def header_val(name: str) -> str:
            val = headers.get(name.lower())
            if val is None:
                return "(missing)"
            return val

        meta_lines.extend([
            f"Server               : {header_val('server')}",
            f"X-Frame-Options      : {header_val('x-frame-options')}",
            f"X-XSS-Protection     : {header_val('x-xss-protection')}",
            f"Content-Security-Policy : {header_val('content-security-policy')}",
            f"Strict-Transport-Security: {header_val('strict-transport-security')}",
            f"X-Content-Type-Options: {header_val('x-content-type-options')}",
            f"Referrer-Policy      : {header_val('referrer-policy')}",
            f"Permissions-Policy   : {header_val('permissions-policy')}",
        ])

        if resp.get("headers"):
            meta_lines.append("")
            meta_lines.append("Response Headers:")
            for k, v in resp.get("headers", {}).items():
                key = k.decode("utf-8", "replace") if isinstance(k, (bytes, bytearray)) else str(k)
                val = v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)
                meta_lines.append(f"{key}: {val}")
        else:
            meta_lines.append("")
            meta_lines.append("Response Headers: (not available yet)")
            meta_lines.append("Note: Forward the request to receive response headers.")

        self.info_view.setPlainText("\n".join(meta_lines))

    def _resolve_ip(self, host: str) -> str:
        if not host:
            return ""
        if host in self._dns_cache:
            return self._dns_cache[host]
        try:
            ip = socket.gethostbyname(host)
            self._dns_cache[host] = ip
            return ip
        except Exception:
            self._dns_cache[host] = ""
            return ""

    def _detect_waf(self, resp: dict, host: str, cf_enabled: bool) -> str:
        if cf_enabled:
            return "Cloudflare"
        if host and "cloudflare" in host.lower():
            return "Cloudflare"
        headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        server = headers.get("server", "")
        if any(h in headers for h in ["cf-ray", "cf-cache-status", "cf-request-id"]):
            return "Cloudflare"
        if "sucuri" in server.lower() or "x-sucuri-id" in headers:
            return "Sucuri"
        if "akamai" in server.lower() or "akamai" in headers.get("via", "").lower():
            return "Akamai"
        if "imperva" in server.lower() or "x-iinfo" in headers:
            return "Imperva"
        if "f5" in server.lower() or "big-ip" in server.lower():
            return "F5"
        if "aws" in server.lower() or "cloudfront" in server.lower() or "x-amz-cf-id" in headers:
            return "AWS CloudFront"
        if "fastly" in server.lower() or "x-served-by" in headers and "fastly" in headers.get("x-served-by", "").lower():
            return "Fastly"
        return ""

    def _is_cloudflare(self, resp: dict, host: str) -> bool:
        if host and "cloudflare" in host.lower():
            return True
        headers = {k.lower(): v for k, v in (resp.get("headers") or {}).items()}
        if any(h in headers for h in ["cf-ray", "cf-cache-status", "cf-request-id"]):
            return True
        server = headers.get("server", "")
        return "cloudflare" in str(server).lower()

    # ── Response intercept handlers ─────────────
    def _on_response_forward(self):
        fid = self._current_resp_flow_id
        if not fid:
            return
        mods = self._parse_response_edits()
        self.response_forward_signal.emit(fid, mods)
        self.response_edit.clear()
        self.btn_resp_forward.setEnabled(False)
        self.btn_resp_drop.setEnabled(False)
        self._current_resp_flow_id = None

    def _on_response_drop(self):
        fid = self._current_resp_flow_id
        if not fid:
            return
        self.response_drop_signal.emit(fid)
        self.response_edit.clear()
        self.btn_resp_forward.setEnabled(False)
        self.btn_resp_drop.setEnabled(False)
        self._current_resp_flow_id = None

    def _parse_response_edits(self) -> dict:
        """Parse edited response text into a modifications dict."""
        text = self.response_edit.toPlainText()
        lines = text.split("\n")
        mods = {}
        if not lines:
            return mods

        # First line: HTTP/VERSION STATUS REASON
        first = lines[0].strip().split(None, 2)
        if len(first) >= 2:
            try:
                mods["status_code"] = int(first[1])
            except ValueError:
                pass

        # Headers + body
        headers = {}
        body_start = None
        for i, line in enumerate(lines[1:], start=1):
            if line.strip() == "":
                body_start = i + 1
                break
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()

        if headers:
            mods["headers"] = headers
        if body_start is not None:
            mods["body"] = "\n".join(lines[body_start:])

        return mods