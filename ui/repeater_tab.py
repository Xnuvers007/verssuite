"""
Vers Suite - Repeater Tab
Send / re-send raw HTTP requests and inspect responses.
Supports HTTP and HTTPS (via socket + SSL).
"""

import socket
import ssl
import time
import threading
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QTextEdit, QLabel, QLineEdit, QSpinBox,
    QCheckBox, QFrame, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt5.QtGui import QFont
from .intercept_tab import HttpHighlighter


# ─────────────────────────────────────────────
# Worker thread for sending HTTP request
# ─────────────────────────────────────────────
class SendWorker(QObject):
    finished  = pyqtSignal(str, float)   # (raw_response, elapsed_ms)
    error_sig = pyqtSignal(str)

    def __init__(self, host, port, raw_request, use_ssl, timeout=15):
        super().__init__()
        self.host        = host
        self.port        = port
        self.raw_request = raw_request
        self.use_ssl     = use_ssl
        self.timeout     = timeout

    def run(self):
        try:
            t0 = time.time()
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if self.use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.host)

            # Ensure CRLF line endings
            raw = self.raw_request.replace("\r\n", "\n").replace("\n", "\r\n")
            if not raw.endswith("\r\n\r\n"):
                if "\r\n\r\n" not in raw:
                    raw += "\r\n\r\n"

            sock.sendall(raw.encode("utf-8", errors="replace"))

            # Read response
            chunks = []
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                chunks.append(chunk)
            sock.close()

            elapsed = (time.time() - t0) * 1000
            response = b"".join(chunks).decode("utf-8", errors="replace")
            self.finished.emit(response, elapsed)

        except Exception as e:
            self.error_sig.emit(str(e))


# ─────────────────────────────────────────────
# Repeater Tab
# ─────────────────────────────────────────────
class RepeaterTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._send_jobs: dict[int, tuple] = {}
        self._sessions: dict[int, dict] = {}
        self._order: list[int] = []
        self._session_seq = 1
        self._current_session_id: int | None = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # ── Session controls ──────────────────
        session_bar = QHBoxLayout()
        session_bar.setSpacing(8)

        self.btn_add = QPushButton("＋  Add")
        self.btn_add.clicked.connect(self._on_add_session)
        self.btn_dup = QPushButton("⧉  Duplicate")
        self.btn_dup.clicked.connect(self._on_duplicate_session)
        self.btn_remove = QPushButton("✖  Remove")
        self.btn_remove.clicked.connect(self._on_remove_session)

        session_bar.addWidget(self.btn_add)
        session_bar.addWidget(self.btn_dup)
        session_bar.addWidget(self.btn_remove)

        session_bar.addSpacing(8)

        session_bar.addWidget(QLabel("Group:"))
        self.group_input = QLineEdit("Default")
        self.group_input.setMaximumWidth(140)
        session_bar.addWidget(self.group_input)
        self.btn_set_group = QPushButton("Set Group")
        self.btn_set_group.clicked.connect(self._on_set_group)
        session_bar.addWidget(self.btn_set_group)

        self.btn_clear_group = QPushButton("Ungroup")
        self.btn_clear_group.clicked.connect(self._on_clear_group)
        session_bar.addWidget(self.btn_clear_group)

        session_bar.addStretch()

        self.btn_send_selected = QPushButton("⟳  Send Selected")
        self.btn_send_selected.clicked.connect(self._on_send_selected)
        self.btn_send_all = QPushButton("⚡  Send All")
        self.btn_send_all.clicked.connect(self._on_send_all)
        session_bar.addWidget(self.btn_send_selected)
        session_bar.addWidget(self.btn_send_all)

        layout.addLayout(session_bar)

        # ── Connection settings ────────────────
        conn_bar = QHBoxLayout()
        conn_bar.setSpacing(8)

        conn_bar.addWidget(QLabel("Host:"))
        self.host_input = QLineEdit("127.0.0.1")
        self.host_input.setMaximumWidth(200)
        conn_bar.addWidget(self.host_input)

        conn_bar.addWidget(QLabel("Port:"))
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(80)
        self.port_input.setMaximumWidth(80)
        conn_bar.addWidget(self.port_input)

        self.ssl_check = QCheckBox("HTTPS / SSL")
        self.ssl_check.stateChanged.connect(self._on_ssl_toggle)
        conn_bar.addWidget(self.ssl_check)

        conn_bar.addStretch()

        # History nav
        self.btn_prev = QPushButton("◀")
        self.btn_prev.setMaximumWidth(36)
        self.btn_prev.setToolTip("Previous request in history")
        self.btn_prev.clicked.connect(self._prev_history)
        self.btn_prev.setEnabled(False)

        self.btn_next = QPushButton("▶")
        self.btn_next.setMaximumWidth(36)
        self.btn_next.setToolTip("Next request in history")
        self.btn_next.clicked.connect(self._next_history)
        self.btn_next.setEnabled(False)

        self.lbl_history = QLabel("0/0")
        self.lbl_history.setStyleSheet("color:#505070; min-width:40px;")

        conn_bar.addWidget(self.btn_prev)
        conn_bar.addWidget(self.lbl_history)
        conn_bar.addWidget(self.btn_next)

        self.btn_send = QPushButton("▶  Send")
        self.btn_send.setObjectName("btn_send")
        self.btn_send.clicked.connect(self._on_send)
        conn_bar.addWidget(self.btn_send)

        layout.addLayout(conn_bar)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #1e1e2e;")
        layout.addWidget(line)

        # ── Sessions list + Request/Response ──
        splitter = QSplitter(Qt.Horizontal)

        list_panel = QWidget()
        list_layout = QVBoxLayout(list_panel)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(4)

        list_hdr = QLabel("SESSIONS")
        list_hdr.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        list_layout.addWidget(list_hdr)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Filter (host, path, group, method, name)")
        self.search_box.textChanged.connect(self._apply_session_filter)
        list_layout.addWidget(self.search_box)

        self.session_table = QTableWidget(0, 5)
        self.session_table.setHorizontalHeaderLabels(["#", "Name", "Host", "Group", "Status"])
        self.session_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.session_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.session_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.session_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.session_table.setAlternatingRowColors(True)
        self.session_table.verticalHeader().setVisible(False)
        self.session_table.setColumnWidth(0, 40)
        self.session_table.setColumnWidth(2, 140)
        self.session_table.setColumnWidth(3, 90)
        self.session_table.setColumnWidth(4, 70)
        self.session_table.currentCellChanged.connect(self._on_session_select)
        list_layout.addWidget(self.session_table)

        splitter.addWidget(list_panel)
        font = QFont("Cascadia Code", 11)
        font.setStyleHint(QFont.Monospace)

        # Request
        req_panel = QWidget()
        rq = QVBoxLayout(req_panel)
        rq.setContentsMargins(0, 0, 0, 0)
        rq.setSpacing(4)
        rq_hdr = QLabel("REQUEST")
        rq_hdr.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        rq.addWidget(rq_hdr)
        self.request_edit = QTextEdit()
        self.request_edit.setObjectName("raw_request")
        self.request_edit.setFont(font)
        self.request_edit.setPlaceholderText(
            "GET / HTTP/1.1\nHost: example.com\nUser-Agent: VersS Suite/1.0\n\n"
        )
        self._hl_req = HttpHighlighter(self.request_edit.document())
        rq.addWidget(self.request_edit)
        splitter.addWidget(req_panel)

        # Response
        resp_panel = QWidget()
        rp = QVBoxLayout(resp_panel)
        rp.setContentsMargins(0, 0, 0, 0)
        rp.setSpacing(4)

        resp_top = QHBoxLayout()
        rp_hdr = QLabel("RESPONSE")
        rp_hdr.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        resp_top.addWidget(rp_hdr)
        resp_top.addStretch()
        self.lbl_resp_meta = QLabel("")
        self.lbl_resp_meta.setStyleSheet("color:#505070; font-size:11px;")
        resp_top.addWidget(self.lbl_resp_meta)
        rp.addLayout(resp_top)

        self.response_view = QTextEdit()
        self.response_view.setObjectName("response_view")
        self.response_view.setReadOnly(True)
        self.response_view.setFont(font)
        self._hl_resp = HttpHighlighter(self.response_view.document())
        rp.addWidget(self.response_view)
        splitter.addWidget(resp_panel)

        splitter.setSizes([260, 520, 520])
        layout.addWidget(splitter, stretch=1)

        self._add_session(select=True)

    # ── Public API ─────────────────────────────
    def load_request(self, raw: str, host_port: tuple = None):
        host = "127.0.0.1"
        port = 80
        if host_port:
            host, port = host_port
        self._add_session(
            request=raw,
            host=str(host),
            port=int(port),
            use_ssl=int(port) == 443,
            select=True
        )

    # ── Slots ──────────────────────────────────
    def _on_ssl_toggle(self, state):
        if state and self.port_input.value() == 80:
            self.port_input.setValue(443)
        elif not state and self.port_input.value() == 443:
            self.port_input.setValue(80)

    def _on_send(self):
        self._sync_current_session()
        if not self._current_session_id:
            return
        self._send_session(self._current_session_id)

    def _on_response(self, session_id: int, raw_resp: str, elapsed: float):
        session = self._sessions.get(session_id)
        if not session:
            return
        session["response"] = raw_resp
        session["elapsed_ms"] = elapsed
        self._save_history(session)
        self._update_session_row(session_id)

        if self._current_session_id == session_id:
            self.response_view.setPlainText(raw_resp)
            first_line = raw_resp.split("\n")[0].strip()
            self.lbl_resp_meta.setText(
                f"{first_line}   |   {elapsed:.1f} ms   |   {len(raw_resp.encode())} bytes"
            )
        self._set_send_busy(session_id, False)

    def _on_error(self, session_id: int, msg: str):
        session = self._sessions.get(session_id)
        if not session:
            return
        session["response"] = f"[ERROR]\n{msg}"
        self._update_session_row(session_id)
        if self._current_session_id == session_id:
            self.response_view.setPlainText(f"[ERROR]\n{msg}")
            self.lbl_resp_meta.setText("ERROR")
        self._set_send_busy(session_id, False)

    def _save_history(self, session: dict):
        session["history"].append({
            "request":  session["request"],
            "response": session["response"],
            "host":     session["host"],
            "port":     session["port"],
            "ssl":      session["ssl"],
        })
        session["history_idx"] = len(session["history"]) - 1
        if self._current_session_id == session["id"]:
            self._update_history_nav(session)

    def _prev_history(self):
        session = self._get_current_session()
        if not session:
            return
        if session["history_idx"] > 0:
            session["history_idx"] -= 1
            self._load_history_entry(session)

    def _next_history(self):
        session = self._get_current_session()
        if not session:
            return
        if session["history_idx"] < len(session["history"]) - 1:
            session["history_idx"] += 1
            self._load_history_entry(session)

    def _load_history_entry(self, session: dict):
        entry = session["history"][session["history_idx"]]
        self.request_edit.setPlainText(entry["request"])
        self.response_view.setPlainText(entry["response"])
        self.host_input.setText(entry["host"])
        self.port_input.setValue(entry["port"])
        self.ssl_check.setChecked(entry.get("ssl", False))
        self._update_history_nav(session)

    def _update_history_nav(self, session: dict):
        n = len(session["history"])
        idx = session["history_idx"]
        label = f"{idx+1}/{n}" if n > 0 and idx >= 0 else "0/0"
        self.lbl_history.setText(label)
        self.btn_prev.setEnabled(idx > 0)
        self.btn_next.setEnabled(idx < n - 1)

    def _on_add_session(self):
        self._add_session(select=True)

    def _on_duplicate_session(self):
        session = self._get_current_session()
        if not session:
            return
        self._add_session(
            request=session["request"],
            host=session["host"],
            port=session["port"],
            use_ssl=session["ssl"],
            group=session.get("group", "Default"),
            name=session.get("name"),
            select=True
        )

    def _on_remove_session(self):
        rows = self.session_table.selectionModel().selectedRows()
        if not rows:
            return
        ids = [self.session_table.item(r.row(), 0).data(Qt.UserRole) for r in rows]
        for session_id in ids:
            self._remove_session(session_id)

    def _on_set_group(self):
        session = self._get_current_session()
        if not session:
            return
        group = self.group_input.text().strip() or "Default"
        session["group"] = group
        self._update_session_row(session["id"])

    def _on_clear_group(self):
        session = self._get_current_session()
        if not session:
            return
        session["group"] = "Default"
        self.group_input.setText("Default")
        self._update_session_row(session["id"])

    def _on_send_selected(self):
        self._sync_current_session()
        rows = self.session_table.selectionModel().selectedRows()
        if not rows:
            return
        for r in rows:
            session_id = self.session_table.item(r.row(), 0).data(Qt.UserRole)
            self._send_session(session_id)

    def _on_send_all(self):
        self._sync_current_session()
        for session_id in list(self._order):
            self._send_session(session_id)

    def _add_session(self, request: str = "", host: str = "127.0.0.1",
                     port: int = 80, use_ssl: bool = False,
                     group: str = "Default", name: str | None = None,
                     select: bool = False):
        session_id = self._session_seq
        self._session_seq += 1

        if not name:
            name = self._derive_name(request)

        session = {
            "id": session_id,
            "name": name,
            "group": group,
            "host": host,
            "port": port,
            "ssl": use_ssl,
            "request": request,
            "response": "",
            "elapsed_ms": 0.0,
            "history": [],
            "history_idx": -1,
        }
        self._sessions[session_id] = session
        self._order.append(session_id)
        self._insert_session_row(session)
        if select:
            self._select_session(session_id)

    def _remove_session(self, session_id: int):
        if session_id in self._send_jobs:
            return
        if session_id in self._sessions:
            del self._sessions[session_id]
        if session_id in self._order:
            self._order.remove(session_id)
        self._remove_session_row(session_id)
        if self._current_session_id == session_id:
            self._current_session_id = None
            if self._order:
                self._select_session(self._order[0])
            else:
                self._clear_editor()

    def _insert_session_row(self, session: dict):
        row = self.session_table.rowCount()
        self.session_table.insertRow(row)
        items = [
            (str(len(self._order)), Qt.AlignCenter),
            (session["name"], Qt.AlignLeft),
            (f"{session['host']}:{session['port']}", Qt.AlignLeft),
            (session.get("group", "Default"), Qt.AlignLeft),
            (self._status_from_response(session.get("response", "")), Qt.AlignCenter),
        ]
        for col, (text, align) in enumerate(items):
            item = QTableWidgetItem(text)
            item.setTextAlignment(align | Qt.AlignVCenter)
            item.setData(Qt.UserRole, session["id"])
            self.session_table.setItem(row, col, item)

    def _remove_session_row(self, session_id: int):
        for row in range(self.session_table.rowCount()):
            item = self.session_table.item(row, 0)
            if item and item.data(Qt.UserRole) == session_id:
                self.session_table.removeRow(row)
                break
        self._refresh_row_numbers()

    def _update_session_row(self, session_id: int):
        session = self._sessions.get(session_id)
        if not session:
            return
        for row in range(self.session_table.rowCount()):
            item = self.session_table.item(row, 0)
            if item and item.data(Qt.UserRole) == session_id:
                self.session_table.item(row, 1).setText(session["name"])
                self.session_table.item(row, 2).setText(f"{session['host']}:{session['port']}")
                self.session_table.item(row, 3).setText(session.get("group", "Default"))
                self.session_table.item(row, 4).setText(
                    self._status_from_response(session.get("response", ""))
                )
                break

    def _refresh_row_numbers(self):
        for row in range(self.session_table.rowCount()):
            item = self.session_table.item(row, 0)
            if item:
                item.setText(str(row + 1))

    def _select_session(self, session_id: int):
        for row in range(self.session_table.rowCount()):
            item = self.session_table.item(row, 0)
            if item and item.data(Qt.UserRole) == session_id:
                self.session_table.selectRow(row)
                return

    def _on_session_select(self, row, col, prev_row, prev_col):
        if self._current_session_id is not None:
            self._sync_current_session()
        item = self.session_table.item(row, 0)
        if not item:
            return
        session_id = item.data(Qt.UserRole)
        session = self._sessions.get(session_id)
        if not session:
            return
        self._current_session_id = session_id
        self.request_edit.setPlainText(session.get("request", ""))
        self.response_view.setPlainText(session.get("response", ""))
        self.host_input.setText(session.get("host", "127.0.0.1"))
        self.port_input.setValue(int(session.get("port", 80)))
        self.ssl_check.setChecked(bool(session.get("ssl", False)))
        self.group_input.setText(session.get("group", "Default"))
        self._update_history_nav(session)

    def _apply_session_filter(self):
        text_f = self.search_box.text().lower().strip()
        for row in range(self.session_table.rowCount()):
            item = self.session_table.item(row, 0)
            if not item:
                continue
            session_id = item.data(Qt.UserRole)
            session = self._sessions.get(session_id, {})

            if not text_f:
                self.session_table.setRowHidden(row, False)
                continue

            haystack = " ".join([
                session.get("name", ""),
                session.get("host", ""),
                str(session.get("port", "")),
                session.get("group", ""),
                self._extract_method(session.get("request", "")),
                self._extract_path(session.get("request", "")),
            ]).lower()

            self.session_table.setRowHidden(row, text_f not in haystack)

    def _sync_current_session(self):
        session = self._get_current_session()
        if not session:
            return
        session["request"] = self.request_edit.toPlainText().strip()
        session["host"] = self.host_input.text().strip() or "127.0.0.1"
        session["port"] = self.port_input.value()
        session["ssl"] = self.ssl_check.isChecked()
        session["group"] = self.group_input.text().strip() or "Default"
        self._update_session_row(session["id"])
        self._apply_session_filter()

    def _get_current_session(self) -> dict | None:
        if self._current_session_id is None:
            return None
        return self._sessions.get(self._current_session_id)

    def _clear_editor(self):
        self.request_edit.clear()
        self.response_view.clear()
        self.lbl_resp_meta.setText("")
        self.host_input.setText("127.0.0.1")
        self.port_input.setValue(80)
        self.ssl_check.setChecked(False)
        self.group_input.setText("Default")
        self.lbl_history.setText("0/0")
        self.btn_prev.setEnabled(False)
        self.btn_next.setEnabled(False)

    def _send_session(self, session_id: int):
        session = self._sessions.get(session_id)
        if not session:
            return
        raw = session.get("request", "").strip()
        if not raw:
            return

        if session_id in self._send_jobs:
            return

        self._set_send_busy(session_id, True)

        worker = SendWorker(
            session["host"],
            session["port"],
            raw,
            session.get("ssl", False)
        )
        thread = QThread()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(lambda resp, ms, sid=session_id: self._on_response(sid, resp, ms))
        worker.error_sig.connect(lambda msg, sid=session_id: self._on_error(sid, msg))
        worker.finished.connect(thread.quit)
        worker.error_sig.connect(thread.quit)
        thread.finished.connect(lambda sid=session_id: self._send_jobs.pop(sid, None))
        self._send_jobs[session_id] = (thread, worker)

        if self._current_session_id == session_id:
            self.btn_send.setEnabled(False)
            self.btn_send.setText("⏳  Sending…")
            self.response_view.setPlainText("Sending request…")

        thread.start()

    def _set_send_busy(self, session_id: int, busy: bool):
        if self._current_session_id != session_id:
            return
        if busy:
            self.btn_send.setEnabled(False)
            self.btn_send.setText("⏳  Sending…")
        else:
            self.btn_send.setEnabled(True)
            self.btn_send.setText("▶  Send")

    def _derive_name(self, raw: str) -> str:
        if not raw:
            return f"Request {self._session_seq}"
        first = raw.split("\n")[0].strip()
        parts = first.split()
        if len(parts) >= 2:
            return f"{parts[0]} {parts[1]}"
        return first[:30] or f"Request {self._session_seq}"

    def _extract_method(self, raw: str) -> str:
        if not raw:
            return ""
        first = raw.split("\n")[0].strip().split()
        return first[0] if first else ""

    def _extract_path(self, raw: str) -> str:
        if not raw:
            return ""
        first = raw.split("\n")[0].strip().split()
        return first[1] if len(first) >= 2 else ""

    def _status_from_response(self, raw_resp: str) -> str:
        if not raw_resp:
            return "—"
        first_line = raw_resp.split("\n")[0].strip()
        parts = first_line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            return parts[1]
        return "ERR"