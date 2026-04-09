"""
Vers Suite - Scope Configuration Dialog
Modal dialog for managing scope include/exclude rules.
"""

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QLineEdit,
    QLabel, QComboBox, QCheckBox, QFrame, QGroupBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor


class ScopeDialog(QDialog):
    """Dialog for editing scope rules."""

    def __init__(self, scope_manager, parent=None):
        super().__init__(parent)
        self.scope_manager = scope_manager
        self.setWindowTitle("🎯  Scope — Target Filter")
        self.setMinimumSize(600, 480)
        self._setup_ui()
        self._load_rules()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        # ── Master toggle ─────────────────────────
        toggle_bar = QHBoxLayout()
        self.chk_enabled = QCheckBox("Enable Scope Filter")
        self.chk_enabled.setChecked(self.scope_manager.enabled)
        self.chk_enabled.stateChanged.connect(self._on_toggle)
        toggle_bar.addWidget(self.chk_enabled)
        toggle_bar.addStretch()
        layout.addLayout(toggle_bar)

        layout.addWidget(QLabel(
            "When enabled, only requests matching Include rules will be intercepted.\n"
            "Exclude rules take priority over Include rules.\n"
            "Patterns use glob syntax: *.example.com, api.*.com, exact.host.com"
        ))

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #1e1e2e;")
        layout.addWidget(line)

        # ── Add rule bar ──────────────────────────
        add_bar = QHBoxLayout()
        add_bar.setSpacing(6)

        add_bar.addWidget(QLabel("Pattern:"))
        self.pattern_input = QLineEdit()
        self.pattern_input.setPlaceholderText("*.example.com")
        self.pattern_input.setMaximumWidth(250)
        add_bar.addWidget(self.pattern_input)

        add_bar.addWidget(QLabel("Type:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["include", "exclude"])
        add_bar.addWidget(self.type_combo)

        self.btn_add = QPushButton("＋  Add Rule")
        self.btn_add.clicked.connect(self._add_rule)
        add_bar.addWidget(self.btn_add)
        add_bar.addStretch()
        layout.addLayout(add_bar)

        # ── Rules table ───────────────────────────
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Enabled", "Type", "Pattern"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setColumnWidth(0, 60)
        self.table.setColumnWidth(1, 80)
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

        # ── Test URL ──────────────────────────────
        test_group = QGroupBox("TEST URL")
        tl = QHBoxLayout(test_group)
        self.test_input = QLineEdit()
        self.test_input.setPlaceholderText("https://example.com/path")
        tl.addWidget(self.test_input)
        btn_test = QPushButton("Test")
        btn_test.clicked.connect(self._test_url)
        tl.addWidget(btn_test)
        self.test_result = QLabel("")
        tl.addWidget(self.test_result)
        layout.addWidget(test_group)

    def _load_rules(self):
        self.table.setRowCount(0)
        for rule in self.scope_manager.get_rules():
            self._add_rule_row(rule.pattern, rule.rule_type, rule.enabled)

    def _add_rule_row(self, pattern: str, rule_type: str, enabled: bool):
        row = self.table.rowCount()
        self.table.insertRow(row)

        chk = QTableWidgetItem()
        chk.setCheckState(Qt.Checked if enabled else Qt.Unchecked)
        self.table.setItem(row, 0, chk)

        type_item = QTableWidgetItem(rule_type)
        type_item.setForeground(QColor("#00e676" if rule_type == "include" else "#ff5252"))
        type_item.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 1, type_item)

        self.table.setItem(row, 2, QTableWidgetItem(pattern))

    def _add_rule(self):
        pattern = self.pattern_input.text().strip()
        if not pattern:
            return
        rule_type = self.type_combo.currentText()
        self.scope_manager.add_rule(pattern, rule_type, True)
        self._add_rule_row(pattern, rule_type, True)
        self.pattern_input.clear()

    def _remove_selected(self):
        rows = sorted(set(idx.row() for idx in self.table.selectedIndexes()), reverse=True)
        for row in rows:
            self.scope_manager.remove_rule(row)
            self.table.removeRow(row)

    def _clear_all(self):
        self.scope_manager.clear_rules()
        self.table.setRowCount(0)

    def _on_toggle(self, state):
        self.scope_manager.enabled = bool(state)

    def _test_url(self):
        url = self.test_input.text().strip()
        if not url:
            return
        in_scope = self.scope_manager.is_in_scope(url)
        if in_scope:
            self.test_result.setText("✔ IN SCOPE")
            self.test_result.setStyleSheet("color: #00e676; font-weight: bold;")
        else:
            self.test_result.setText("✖ OUT OF SCOPE")
            self.test_result.setStyleSheet("color: #ff5252; font-weight: bold;")
