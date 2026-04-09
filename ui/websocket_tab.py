"""
Vers Suite - WebSocket Tab
View and filter captured WebSocket messages.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QTextEdit, QLabel, QLineEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QComboBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor


class WebSocketTab(QWidget):
    """Displays captured WebSocket messages in a table with detail view."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._messages = []   # list of ws message dicts
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # ── Toolbar ───────────────────────────────
        tb = QHBoxLayout()
        tb.setSpacing(8)

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("🔍  Filter (URL, content…)")
        self.search_box.textChanged.connect(self._apply_filter)
        self.search_box.setMaximumWidth(300)
        tb.addWidget(self.search_box)

        self.direction_filter = QComboBox()
        self.direction_filter.addItems(["All Directions", "↑ Outgoing", "↓ Incoming"])
        self.direction_filter.currentTextChanged.connect(self._apply_filter)
        tb.addWidget(self.direction_filter)

        tb.addStretch()

        self.lbl_count = QLabel("0 messages")
        self.lbl_count.setStyleSheet("color:#505070; font-size:11px;")
        tb.addWidget(self.lbl_count)

        btn_clear = QPushButton("🗑  Clear")
        btn_clear.clicked.connect(self.clear_messages)
        btn_clear.setMaximumWidth(80)
        tb.addWidget(btn_clear)

        layout.addLayout(tb)

        # ── Splitter: table + detail ──────────────
        splitter = QSplitter(Qt.Vertical)

        # Message table
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["#", "Time", "Dir", "Host", "Length", "Content Preview"]
        )
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setColumnWidth(0, 40)
        self.table.setColumnWidth(1, 70)
        self.table.setColumnWidth(2, 40)
        self.table.setColumnWidth(3, 180)
        self.table.setColumnWidth(4, 70)
        self.table.currentCellChanged.connect(self._on_row_select)
        splitter.addWidget(self.table)

        # Detail view
        detail_panel = QWidget()
        dl = QVBoxLayout(detail_panel)
        dl.setContentsMargins(0, 0, 0, 0)
        dl.setSpacing(2)

        detail_hdr = QLabel("MESSAGE CONTENT")
        detail_hdr.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        dl.addWidget(detail_hdr)

        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setObjectName("response_view")
        font = QFont("Cascadia Code", 11)
        font.setStyleHint(QFont.Monospace)
        self.detail_view.setFont(font)
        self.detail_view.setPlaceholderText("Select a WebSocket message to view its content…")
        dl.addWidget(self.detail_view)

        splitter.addWidget(detail_panel)
        splitter.setSizes([350, 250])

        layout.addWidget(splitter, stretch=1)

    # ── Public API ─────────────────────────────
    def add_message(self, msg: dict):
        """Add a WebSocket message from the proxy event queue."""
        self._messages.append(msg)
        self._insert_row(msg, len(self._messages))
        self.lbl_count.setText(f"{len(self._messages)} messages")

    def clear_messages(self):
        self._messages.clear()
        self.table.setRowCount(0)
        self.detail_view.clear()
        self.lbl_count.setText("0 messages")

    # ── Private ────────────────────────────────
    def _insert_row(self, msg: dict, idx: int):
        row = self.table.rowCount()
        self.table.insertRow(row)

        direction = "↑" if msg.get("direction") == "outgoing" else "↓"
        dir_color = "#ffab00" if direction == "↑" else "#40c4ff"
        content_preview = (msg.get("content", "")[:80] or "(binary)")

        items = [
            (str(idx), Qt.AlignCenter, "#606080"),
            (msg.get("timestamp", ""), Qt.AlignCenter, "#a0a0b8"),
            (direction, Qt.AlignCenter, dir_color),
            (msg.get("host", ""), Qt.AlignLeft, "#c0c0cc"),
            (str(msg.get("length", 0)), Qt.AlignRight, "#a0a0b8"),
            (content_preview, Qt.AlignLeft, "#c8ffc8"),
        ]

        for col, (text, align, color) in enumerate(items):
            item = QTableWidgetItem(text)
            item.setTextAlignment(align | Qt.AlignVCenter)
            item.setForeground(QColor(color))
            item.setData(Qt.UserRole, len(self._messages) - 1)
            self.table.setItem(row, col, item)

    def _on_row_select(self, row, col, prev_row, prev_col):
        item = self.table.item(row, 0)
        if not item:
            return
        msg_idx = item.data(Qt.UserRole)
        if msg_idx is None or msg_idx >= len(self._messages):
            return
        msg = self._messages[msg_idx]
        direction = "Client → Server (Outgoing)" if msg.get("direction") == "outgoing" else "Server → Client (Incoming)"
        lines = [
            f"URL       : {msg.get('url', '?')}",
            f"Direction : {direction}",
            f"Type      : {'Text' if msg.get('is_text', True) else 'Binary'}",
            f"Length    : {msg.get('length', 0)} bytes",
            f"Time      : {msg.get('timestamp', '?')}",
            f"Flow ID   : {msg.get('flow_id', '?')}",
            "",
            "─── Content ───",
            "",
            msg.get("content", "(empty)"),
        ]
        self.detail_view.setPlainText("\n".join(lines))

    def _apply_filter(self):
        text_f = self.search_box.text().lower()
        dir_f = self.direction_filter.currentText()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if not item:
                continue
            msg_idx = item.data(Qt.UserRole)
            if msg_idx is None or msg_idx >= len(self._messages):
                continue
            msg = self._messages[msg_idx]

            visible = True

            # Direction filter
            if "Outgoing" in dir_f and msg.get("direction") != "outgoing":
                visible = False
            elif "Incoming" in dir_f and msg.get("direction") != "incoming":
                visible = False

            # Text filter
            if text_f and visible:
                haystack = f"{msg.get('url', '')} {msg.get('host', '')} {msg.get('content', '')}".lower()
                if text_f not in haystack:
                    visible = False

            self.table.setRowHidden(row, not visible)
