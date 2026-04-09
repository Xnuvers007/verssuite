"""
Vers Suite - Match & Replace Rules Dialog
Modal dialog for managing auto-modification rules.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QLineEdit,
    QLabel, QComboBox, QCheckBox, QFrame
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor


class MatchReplaceDialog(QDialog):
    """Dialog for editing match & replace rules."""

    def __init__(self, engine, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.setWindowTitle("⇄  Match & Replace Rules")
        self.setMinimumSize(750, 480)
        self._setup_ui()
        self._load_rules()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        # ── Master toggle ─────────────────────────
        toggle_bar = QHBoxLayout()
        self.chk_enabled = QCheckBox("Enable Match & Replace")
        self.chk_enabled.setChecked(self.engine.enabled)
        self.chk_enabled.stateChanged.connect(lambda s: setattr(self.engine, 'enabled', bool(s)))
        toggle_bar.addWidget(self.chk_enabled)
        toggle_bar.addStretch()
        layout.addLayout(toggle_bar)

        layout.addWidget(QLabel(
            "Rules are applied to every request/response passing through the proxy.\n"
            "Use this to auto-add headers, modify values, strip security headers, etc."
        ))

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #1e1e2e;")
        layout.addWidget(line)

        # ── Add rule bar ──────────────────────────
        add_bar = QHBoxLayout()
        add_bar.setSpacing(6)

        add_bar.addWidget(QLabel("Target:"))
        self.target_combo = QComboBox()
        self.target_combo.addItems([
            "request_header", "request_body",
            "response_header", "response_body"
        ])
        add_bar.addWidget(self.target_combo)

        add_bar.addWidget(QLabel("Match:"))
        self.match_input = QLineEdit()
        self.match_input.setPlaceholderText("User-Agent: Mozilla…")
        self.match_input.setMaximumWidth(200)
        add_bar.addWidget(self.match_input)

        add_bar.addWidget(QLabel("Replace:"))
        self.replace_input = QLineEdit()
        self.replace_input.setPlaceholderText("User-Agent: VersBot/1.0")
        self.replace_input.setMaximumWidth(200)
        add_bar.addWidget(self.replace_input)

        self.chk_regex = QCheckBox("Regex")
        add_bar.addWidget(self.chk_regex)

        self.btn_add = QPushButton("＋ Add")
        self.btn_add.clicked.connect(self._add_rule)
        add_bar.addWidget(self.btn_add)

        layout.addLayout(add_bar)

        # Comment
        comment_bar = QHBoxLayout()
        comment_bar.addWidget(QLabel("Comment:"))
        self.comment_input = QLineEdit()
        self.comment_input.setPlaceholderText("(optional description)")
        comment_bar.addWidget(self.comment_input)
        layout.addLayout(comment_bar)

        # ── Rules table ───────────────────────────
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "On", "Target", "Match", "Replace", "Regex", "Comment"
        ])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setColumnWidth(0, 35)
        self.table.setColumnWidth(1, 120)
        self.table.setColumnWidth(4, 50)
        layout.addWidget(self.table)

        # ── Bottom buttons ────────────────────────
        bottom_bar = QHBoxLayout()
        btn_remove = QPushButton("✖  Remove Selected")
        btn_remove.clicked.connect(self._remove_selected)
        btn_clear = QPushButton("🗑  Clear All")
        btn_clear.clicked.connect(self._clear_all)
        bottom_bar.addWidget(btn_remove)
        bottom_bar.addWidget(btn_clear)
        bottom_bar.addStretch()

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        bottom_bar.addWidget(btn_close)
        layout.addLayout(bottom_bar)

    def _load_rules(self):
        self.table.setRowCount(0)
        for rule in self.engine.get_rules():
            self._add_rule_row(
                rule.enabled, rule.target, rule.match,
                rule.replace, rule.is_regex, rule.comment
            )

    def _add_rule_row(self, enabled, target, match, replace, is_regex, comment):
        row = self.table.rowCount()
        self.table.insertRow(row)

        chk = QTableWidgetItem()
        chk.setCheckState(Qt.Checked if enabled else Qt.Unchecked)
        self.table.setItem(row, 0, chk)

        target_colors = {
            "request_header": "#00e676",
            "request_body": "#40c4ff",
            "response_header": "#ffab00",
            "response_body": "#ea00ff",
        }
        target_item = QTableWidgetItem(target)
        target_item.setForeground(QColor(target_colors.get(target, "#c0c0cc")))
        self.table.setItem(row, 1, target_item)

        self.table.setItem(row, 2, QTableWidgetItem(match))
        self.table.setItem(row, 3, QTableWidgetItem(replace))

        regex_item = QTableWidgetItem("✔" if is_regex else "")
        regex_item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 4, regex_item)

        self.table.setItem(row, 5, QTableWidgetItem(comment))

    def _add_rule(self):
        match = self.match_input.text().strip()
        replace = self.replace_input.text().strip()
        if not match:
            return
        target = self.target_combo.currentText()
        is_regex = self.chk_regex.isChecked()
        comment = self.comment_input.text().strip()

        self.engine.add_rule(target, match, replace, is_regex, comment)
        self._add_rule_row(True, target, match, replace, is_regex, comment)

        self.match_input.clear()
        self.replace_input.clear()
        self.comment_input.clear()

    def _remove_selected(self):
        rows = sorted(set(idx.row() for idx in self.table.selectedIndexes()), reverse=True)
        for row in rows:
            self.engine.remove_rule(row)
            self.table.removeRow(row)

    def _clear_all(self):
        self.engine.clear_rules()
        self.table.setRowCount(0)
