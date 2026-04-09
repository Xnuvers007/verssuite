"""
Vers Suite - Comparer Tab
Side-by-side diff comparison of requests/responses.
"""

import difflib
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QPushButton, QTextEdit, QLabel, QFrame, QApplication
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor, QTextCursor, QTextCharFormat


class ComparerTab(QWidget):
    """Side-by-side diff viewer with line-level highlighting."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # ── Top buttons ───────────────────────────
        top_bar = QHBoxLayout()
        top_bar.setSpacing(8)

        self.btn_paste_left = QPushButton("📋  Paste Left")
        self.btn_paste_left.clicked.connect(lambda: self._paste_clipboard(self.left_edit))
        self.btn_paste_right = QPushButton("📋  Paste Right")
        self.btn_paste_right.clicked.connect(lambda: self._paste_clipboard(self.right_edit))
        self.btn_compare = QPushButton("⇄  Compare")
        self.btn_compare.setObjectName("btn_send")
        self.btn_compare.clicked.connect(self._run_compare)
        self.btn_clear = QPushButton("🗑  Clear All")
        self.btn_clear.clicked.connect(self._clear_all)
        self.btn_swap = QPushButton("⇆  Swap")
        self.btn_swap.clicked.connect(self._swap_sides)

        top_bar.addWidget(self.btn_paste_left)
        top_bar.addWidget(self.btn_paste_right)
        top_bar.addWidget(self.btn_swap)
        top_bar.addWidget(self.btn_compare)
        top_bar.addStretch()
        top_bar.addWidget(self.btn_clear)

        layout.addLayout(top_bar)

        # ── Stats bar ─────────────────────────────
        self.lbl_stats = QLabel("")
        self.lbl_stats.setStyleSheet("color:#505070; font-size:11px;")
        layout.addWidget(self.lbl_stats)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("color: #1e1e2e;")
        layout.addWidget(line)

        # ── Diff views ────────────────────────────
        font = QFont("Cascadia Code", 11)
        font.setStyleHint(QFont.Monospace)

        splitter = QSplitter(Qt.Horizontal)

        # Left panel
        left_panel = QWidget()
        ll = QVBoxLayout(left_panel)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(2)
        left_hdr = QLabel("LEFT  (original)")
        left_hdr.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        ll.addWidget(left_hdr)
        self.left_edit = QTextEdit()
        self.left_edit.setObjectName("raw_request")
        self.left_edit.setFont(font)
        self.left_edit.setPlaceholderText("Paste or type the first text here…")
        ll.addWidget(self.left_edit)
        splitter.addWidget(left_panel)

        # Right panel
        right_panel = QWidget()
        rl = QVBoxLayout(right_panel)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(2)
        right_hdr = QLabel("RIGHT  (modified)")
        right_hdr.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px;")
        rl.addWidget(right_hdr)
        self.right_edit = QTextEdit()
        self.right_edit.setObjectName("response_view")
        self.right_edit.setFont(font)
        self.right_edit.setPlaceholderText("Paste or type the second text here…")
        rl.addWidget(self.right_edit)
        splitter.addWidget(right_panel)

        layout.addWidget(splitter, stretch=1)

        # ── Unified diff output ───────────────────
        diff_label = QLabel("UNIFIED DIFF")
        diff_label.setStyleSheet("color:#505070; font-size:10px; font-weight:600; letter-spacing:1px; margin-top:4px;")
        layout.addWidget(diff_label)

        self.diff_view = QTextEdit()
        self.diff_view.setReadOnly(True)
        self.diff_view.setFont(font)
        self.diff_view.setMaximumHeight(200)
        self.diff_view.setPlaceholderText("Diff output will appear here after comparing…")
        layout.addWidget(self.diff_view)

    # ── Public API ─────────────────────────────
    def load_left(self, text: str):
        self.left_edit.setPlainText(text)

    def load_right(self, text: str):
        self.right_edit.setPlainText(text)

    # ── Actions ────────────────────────────────
    def _paste_clipboard(self, target: QTextEdit):
        clipboard = QApplication.clipboard()
        target.setPlainText(clipboard.text() or "")

    def _swap_sides(self):
        left = self.left_edit.toPlainText()
        right = self.right_edit.toPlainText()
        self.left_edit.setPlainText(right)
        self.right_edit.setPlainText(left)

    def _clear_all(self):
        self.left_edit.clear()
        self.right_edit.clear()
        self.diff_view.clear()
        self.lbl_stats.setText("")

    def _run_compare(self):
        left_text = self.left_edit.toPlainText()
        right_text = self.right_edit.toPlainText()

        left_lines = left_text.splitlines(keepends=True)
        right_lines = right_text.splitlines(keepends=True)

        # Highlight in-place on the text edits
        self._highlight_diffs(self.left_edit, self.right_edit, left_lines, right_lines)

        # Generate unified diff
        diff = difflib.unified_diff(
            left_lines, right_lines,
            fromfile="Left", tofile="Right",
            lineterm=""
        )
        diff_text = "\n".join(diff)
        self._highlight_unified_diff(diff_text)

        # Stats
        matcher = difflib.SequenceMatcher(None, left_text, right_text)
        ratio = matcher.ratio()
        added = sum(1 for l in right_lines if l not in left_lines)
        removed = sum(1 for l in left_lines if l not in right_lines)

        self.lbl_stats.setText(
            f"Similarity: {ratio*100:.1f}%   |   "
            f"Lines: {len(left_lines)} → {len(right_lines)}   |   "
            f"+{added} added   −{removed} removed"
        )

    def _highlight_diffs(self, left_edit: QTextEdit, right_edit: QTextEdit,
                         left_lines, right_lines):
        """Highlight changed lines in both editors."""
        differ = difflib.SequenceMatcher(None, left_lines, right_lines)

        # Removed lines (in left)
        fmt_removed = QTextCharFormat()
        fmt_removed.setBackground(QColor("#3d0000"))

        # Added lines (in right)
        fmt_added = QTextCharFormat()
        fmt_added.setBackground(QColor("#003d20"))

        # Clear previous formatting
        for edit in (left_edit, right_edit):
            cursor = edit.textCursor()
            cursor.select(QTextCursor.Document)
            fmt_clear = QTextCharFormat()
            cursor.setCharFormat(fmt_clear)

        for tag, i1, i2, j1, j2 in differ.get_opcodes():
            if tag == "replace" or tag == "delete":
                self._apply_format_to_lines(left_edit, i1, i2, fmt_removed)
            if tag == "replace" or tag == "insert":
                self._apply_format_to_lines(right_edit, j1, j2, fmt_added)

    def _apply_format_to_lines(self, edit: QTextEdit, start_line: int,
                               end_line: int, fmt: QTextCharFormat):
        cursor = edit.textCursor()
        doc = edit.document()
        for line_idx in range(start_line, end_line):
            block = doc.findBlockByNumber(line_idx)
            if not block.isValid():
                continue
            cursor.setPosition(block.position())
            cursor.movePosition(QTextCursor.EndOfBlock, QTextCursor.KeepAnchor)
            cursor.mergeCharFormat(fmt)

    def _highlight_unified_diff(self, diff_text: str):
        self.diff_view.clear()
        cursor = self.diff_view.textCursor()

        fmt_normal = QTextCharFormat()
        fmt_normal.setForeground(QColor("#c8c8cc"))

        fmt_added = QTextCharFormat()
        fmt_added.setForeground(QColor("#00e676"))

        fmt_removed = QTextCharFormat()
        fmt_removed.setForeground(QColor("#ff5252"))

        fmt_header = QTextCharFormat()
        fmt_header.setForeground(QColor("#40c4ff"))

        for line in diff_text.split("\n"):
            if line.startswith("@@"):
                cursor.insertText(line + "\n", fmt_header)
            elif line.startswith("+"):
                cursor.insertText(line + "\n", fmt_added)
            elif line.startswith("-"):
                cursor.insertText(line + "\n", fmt_removed)
            else:
                cursor.insertText(line + "\n", fmt_normal)
