"""
Vers Suite - Dark Theme Stylesheet
Professional hacker-tool aesthetic.
"""

DARK_STYLESHEET = """
/* ═══════════════════════════════════════════
   VERS SUITE — Dark Pro Theme
   ═══════════════════════════════════════════ */

QMainWindow, QDialog {
    background-color: #0d0d0f;
    color: #e0e0e0;
}

QWidget {
    background-color: #0d0d0f;
    color: #c8c8cc;
    font-family: 'Segoe UI', 'SF Pro Display', 'Ubuntu', sans-serif;
    font-size: 13px;
}

/* ── Tab Bar ────────────────────────────────*/
QTabWidget::pane {
    border: 1px solid #1e1e2e;
    background: #0d0d0f;
    border-radius: 4px;
}

QTabBar::tab {
    background: #13131a;
    color: #6e6e8a;
    padding: 8px 20px;
    border: none;
    border-bottom: 2px solid transparent;
    margin-right: 2px;
    font-weight: 500;
    min-width: 90px;
}

QTabBar::tab:selected {
    color: #00d4ff;
    border-bottom: 2px solid #00d4ff;
    background: #0d0d0f;
}

QTabBar::tab:hover:!selected {
    color: #a0a0c0;
    background: #161620;
}

/* ── Buttons ────────────────────────────────*/
QPushButton {
    background-color: #1a1a2e;
    color: #c0c0d0;
    border: 1px solid #2a2a3e;
    border-radius: 5px;
    padding: 6px 14px;
    font-weight: 500;
}

QPushButton:hover {
    background-color: #242440;
    color: #e0e0f0;
    border: 1px solid #3a3a5e;
}

QPushButton:pressed {
    background-color: #0f0f20;
}

QPushButton#btn_start {
    background-color: #003d20;
    color: #00e676;
    border: 1px solid #005c2e;
    font-weight: 700;
    padding: 7px 18px;
}
QPushButton#btn_start:hover {
    background-color: #005c30;
    border-color: #00e676;
}

QPushButton#btn_stop {
    background-color: #3d0000;
    color: #ff5252;
    border: 1px solid #5c0000;
    font-weight: 700;
    padding: 7px 18px;
}
QPushButton#btn_stop:hover {
    background-color: #5c0000;
    border-color: #ff5252;
}

QPushButton#btn_forward {
    background-color: #003d20;
    color: #00e676;
    border: 1px solid #00c853;
    font-weight: 600;
}
QPushButton#btn_forward:hover {
    background-color: #005c30;
}

QPushButton#btn_drop {
    background-color: #3d0000;
    color: #ff5252;
    border: 1px solid #b71c1c;
    font-weight: 600;
}
QPushButton#btn_drop:hover {
    background-color: #5c0000;
}

QPushButton#btn_intercept_on {
    background-color: #1a0033;
    color: #ea00ff;
    border: 1px solid #7b00a8;
    font-weight: 700;
    padding: 7px 18px;
}
QPushButton#btn_intercept_on:hover {
    background-color: #280047;
    border-color: #ea00ff;
}

QPushButton#btn_attack {
    background-color: #1a1a00;
    color: #ffd600;
    border: 1px solid #a07800;
    font-weight: 700;
    padding: 7px 18px;
}
QPushButton#btn_attack:hover {
    background-color: #2a2a00;
    border-color: #ffd600;
}

QPushButton#btn_send {
    background-color: #001a33;
    color: #40c4ff;
    border: 1px solid #0066a0;
    font-weight: 700;
    padding: 7px 18px;
}
QPushButton#btn_send:hover {
    background-color: #002244;
    border-color: #40c4ff;
}

QPushButton#btn_cert {
    background-color: #1a1a00;
    color: #ffab00;
    border: 1px solid #8a6000;
    font-weight: 600;
}
QPushButton#btn_cert:hover {
    background-color: #2a2a00;
    border-color: #ffab00;
}

/* ── Text Inputs ────────────────────────────*/
QLineEdit, QSpinBox {
    background-color: #13131a;
    color: #d0d0e0;
    border: 1px solid #2a2a3e;
    border-radius: 4px;
    padding: 5px 8px;
    selection-background-color: #00d4ff44;
}

QLineEdit:focus, QSpinBox:focus {
    border: 1px solid #00d4ff66;
}

QTextEdit, QPlainTextEdit {
    background-color: #0a0a0f;
    color: #c8ffc8;
    border: 1px solid #1e1e2e;
    border-radius: 4px;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', 'Courier New', monospace;
    font-size: 12px;
    selection-background-color: #00d4ff33;
    padding: 4px;
}

QTextEdit#response_view {
    color: #aad4ff;
}

QTextEdit#raw_request {
    color: #c8ffc8;
}

/* ── Tables ─────────────────────────────────*/
QTableWidget {
    background-color: #0d0d0f;
    color: #c0c0cc;
    border: 1px solid #1e1e2e;
    gridline-color: #1a1a2a;
    selection-background-color: #1a1a3a;
    alternate-background-color: #0f0f15;
}

QTableWidget::item {
    padding: 4px 8px;
    border: none;
}

QTableWidget::item:selected {
    background-color: #1a1a3a;
    color: #00d4ff;
}

QHeaderView::section {
    background-color: #13131a;
    color: #7070a0;
    border: none;
    border-right: 1px solid #1e1e2e;
    border-bottom: 1px solid #1e1e2e;
    padding: 5px 8px;
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

/* ── Splitter ────────────────────────────────*/
QSplitter::handle {
    background-color: #1e1e2e;
    width: 2px;
    height: 2px;
}

/* ── Labels ─────────────────────────────────*/
QLabel {
    color: #a0a0b8;
    background: transparent;
}

QLabel#title_label {
    color: #00d4ff;
    font-size: 18px;
    font-weight: 700;
    letter-spacing: 1px;
}

QLabel#subtitle_label {
    color: #444466;
    font-size: 11px;
}

QLabel#status_ok {
    color: #00e676;
    font-weight: 600;
}

QLabel#status_err {
    color: #ff5252;
    font-weight: 600;
}

QLabel#status_intercept {
    color: #ea00ff;
    font-weight: 600;
}

/* ── ComboBox ────────────────────────────────*/
QComboBox {
    background-color: #13131a;
    color: #c0c0d0;
    border: 1px solid #2a2a3e;
    border-radius: 4px;
    padding: 5px 8px;
    min-width: 120px;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox QAbstractItemView {
    background-color: #13131a;
    color: #c0c0d0;
    border: 1px solid #2a2a3e;
    selection-background-color: #1a1a3a;
}

/* ── CheckBox ────────────────────────────────*/
QCheckBox {
    color: #a0a0b8;
    spacing: 6px;
}

QCheckBox::indicator {
    width: 14px;
    height: 14px;
    border: 1px solid #3a3a5e;
    border-radius: 3px;
    background: #13131a;
}

QCheckBox::indicator:checked {
    background: #00d4ff;
    border-color: #00d4ff;
}

/* ── Scroll bars ─────────────────────────────*/
QScrollBar:vertical {
    background: #0d0d0f;
    width: 8px;
    border: none;
}
QScrollBar::handle:vertical {
    background: #2a2a3e;
    border-radius: 4px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover { background: #3a3a5e; }
QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical { height: 0px; }

QScrollBar:horizontal {
    background: #0d0d0f;
    height: 8px;
    border: none;
}
QScrollBar::handle:horizontal {
    background: #2a2a3e;
    border-radius: 4px;
    min-width: 20px;
}
QScrollBar::handle:horizontal:hover { background: #3a3a5e; }
QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal { width: 0px; }

/* ── Toolbar / GroupBox ──────────────────────*/
QGroupBox {
    color: #606080;
    border: 1px solid #1e1e2e;
    border-radius: 5px;
    margin-top: 8px;
    padding-top: 8px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 6px;
    color: #505070;
    left: 10px;
}

/* ── Status Bar ──────────────────────────────*/
QStatusBar {
    background: #0a0a0f;
    color: #505070;
    border-top: 1px solid #1e1e2e;
    font-size: 11px;
}

QStatusBar::item { border: none; }

/* ── Progress Bar ────────────────────────────*/
QProgressBar {
    background-color: #13131a;
    border: 1px solid #2a2a3e;
    border-radius: 3px;
    text-align: center;
    color: #a0a0b8;
    height: 14px;
}
QProgressBar::chunk {
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 #0066a0, stop:1 #00d4ff
    );
    border-radius: 3px;
}

/* ── List Widget ─────────────────────────────*/
QListWidget {
    background-color: #0d0d0f;
    color: #c0c0cc;
    border: 1px solid #1e1e2e;
    border-radius: 4px;
}
QListWidget::item:selected {
    background-color: #1a1a3a;
    color: #00d4ff;
}
QListWidget::item:hover {
    background-color: #13131a;
}

/* ── Tooltip ─────────────────────────────────*/
QToolTip {
    background-color: #13131a;
    color: #c0c0d0;
    border: 1px solid #2a2a3e;
    padding: 4px 8px;
    border-radius: 3px;
}
"""

# Color constants for programmatic use
COLORS = {
    "bg":         "#0d0d0f",
    "bg2":        "#13131a",
    "border":     "#1e1e2e",
    "accent":     "#00d4ff",
    "green":      "#00e676",
    "red":        "#ff5252",
    "purple":     "#ea00ff",
    "yellow":     "#ffd600",
    "blue":       "#40c4ff",
    "orange":     "#ffab00",
    "text":       "#c8c8cc",
    "text_dim":   "#606080",
    "text_code":  "#c8ffc8",
}

STATUS_COLORS = {
    "2xx": "#00e676",
    "3xx": "#40c4ff",
    "4xx": "#ffab00",
    "5xx": "#ff5252",
}

def status_color(code: int) -> str:
    if 200 <= code < 300: return STATUS_COLORS["2xx"]
    if 300 <= code < 400: return STATUS_COLORS["3xx"]
    if 400 <= code < 500: return STATUS_COLORS["4xx"]
    if 500 <= code < 600: return STATUS_COLORS["5xx"]
    return COLORS["text_dim"]