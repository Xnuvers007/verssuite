"""
Vers Suite - Sensitive Data Scanner
Detects tokens, passwords, API keys, JWTs, and other sensitive information.
"""

import re
from typing import List, NamedTuple


class SensitiveMatch(NamedTuple):
    """A detected sensitive data match."""
    type: str       # Category name
    value: str      # Matched text (truncated)
    start: int      # Start position in text
    end: int        # End position in text
    severity: str   # "high", "medium", "low"


# ── Pattern Definitions ────────────────────────────────────
_PATTERNS = [
    # JWT tokens
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "high",
    ),
    # Bearer tokens
    (
        "Bearer Token",
        re.compile(r"[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}"),
        "high",
    ),
    # AWS Access Key
    (
        "AWS Access Key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "high",
    ),
    # AWS Secret Key
    (
        "AWS Secret Key",
        re.compile(r"(?i)aws[_\-]?secret[_\-]?(?:access[_\-]?)?key[\s:=\"']+([A-Za-z0-9/+=]{40})"),
        "high",
    ),
    # Google API Key
    (
        "Google API Key",
        re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        "high",
    ),
    # GitHub Token
    (
        "GitHub Token",
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        "high",
    ),
    # Generic API Key patterns
    (
        "API Key",
        re.compile(r"(?i)(?:api[_\-]?key|apikey|api_secret)[\s:=\"']+([A-Za-z0-9_\-]{16,64})"),
        "medium",
    ),
    # Password in URL or body
    (
        "Password Field",
        re.compile(r"(?i)(?:password|passwd|pwd|pass)[\s:=]+[^\s&\"']{4,}"),
        "high",
    ),
    # Credit card (basic Luhn-plausible patterns)
    (
        "Credit Card",
        re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
        "high",
    ),
    # Private key markers
    (
        "Private Key",
        re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
        "high",
    ),
    # Authorization header
    (
        "Authorization Header",
        re.compile(r"(?i)^Authorization:\s+\S+", re.MULTILINE),
        "medium",
    ),
    # Session/Cookie tokens
    (
        "Session Token",
        re.compile(r"(?i)(?:session[_\-]?id|sess[_\-]?token|PHPSESSID|JSESSIONID|ASP\.NET_SessionId)[\s:=]+[^\s;&\"']{8,}"),
        "medium",
    ),
    # Email addresses
    (
        "Email Address",
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "low",
    ),
    # IP addresses (private ranges)
    (
        "Internal IP",
        re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"),
        "low",
    ),
]


def scan_text(text: str, max_matches: int = 50) -> List[SensitiveMatch]:
    """
    Scan text for sensitive data patterns.

    Returns a list of SensitiveMatch objects, limited to max_matches.
    """
    if not text:
        return []

    matches = []
    seen_positions = set()

    for name, pattern, severity in _PATTERNS:
        for m in pattern.finditer(text):
            pos_key = (m.start(), m.end())
            if pos_key in seen_positions:
                continue
            seen_positions.add(pos_key)

            value = m.group(0)
            # Truncate long matches for display
            display_value = value[:60] + "…" if len(value) > 60 else value

            matches.append(SensitiveMatch(
                type=name,
                value=display_value,
                start=m.start(),
                end=m.end(),
                severity=severity,
            ))

            if len(matches) >= max_matches:
                return matches

    return matches


def has_sensitive_data(text: str) -> bool:
    """Quick check if text contains any sensitive data (stops at first match)."""
    if not text:
        return False
    for _, pattern, _ in _PATTERNS:
        if pattern.search(text):
            return True
    return False


def get_severity_color(severity: str) -> str:
    """Return hex color for a severity level."""
    return {
        "high": "#ff5252",
        "medium": "#ffab00",
        "low": "#40c4ff",
    }.get(severity, "#606080")
