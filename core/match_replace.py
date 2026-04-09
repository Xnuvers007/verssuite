"""
Vers Suite - Match & Replace Engine
Automatically modifies requests/responses on the fly based on user-defined rules.
"""

import re
from typing import List, Dict, Any, Optional


class MatchReplaceRule:
    """A single match & replace rule."""

    TARGETS = ("request_header", "request_body", "response_header", "response_body")

    def __init__(self, target: str, match: str, replace: str,
                 is_regex: bool = False, enabled: bool = True, comment: str = ""):
        self.target = target      # One of TARGETS
        self.match = match        # String or regex pattern to find
        self.replace = replace    # Replacement string
        self.is_regex = is_regex
        self.enabled = enabled
        self.comment = comment

    def apply_to_headers(self, headers: dict) -> dict:
        """Apply this rule to a headers dict. Returns modified copy."""
        if not self.enabled:
            return headers
        if self.target not in ("request_header", "response_header"):
            return headers

        new_headers = {}
        for k, v in headers.items():
            header_line = f"{k}: {v}"
            if self.is_regex:
                try:
                    new_line = re.sub(self.match, self.replace, header_line)
                except re.error:
                    new_line = header_line
            else:
                new_line = header_line.replace(self.match, self.replace)

            if ": " in new_line:
                nk, _, nv = new_line.partition(": ")
                new_headers[nk] = nv
            else:
                new_headers[k] = v
        return new_headers

    def apply_to_body(self, body: str) -> str:
        """Apply this rule to a body string. Returns modified string."""
        if not self.enabled:
            return body
        if self.target not in ("request_body", "response_body"):
            return body

        if self.is_regex:
            try:
                return re.sub(self.match, self.replace, body)
            except re.error:
                return body
        else:
            return body.replace(self.match, self.replace)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "match": self.match,
            "replace": self.replace,
            "is_regex": self.is_regex,
            "enabled": self.enabled,
            "comment": self.comment,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MatchReplaceRule":
        return cls(
            target=d.get("target", "request_header"),
            match=d.get("match", ""),
            replace=d.get("replace", ""),
            is_regex=d.get("is_regex", False),
            enabled=d.get("enabled", True),
            comment=d.get("comment", ""),
        )


class MatchReplaceEngine:
    """Manages and applies match & replace rules."""

    def __init__(self):
        self._rules: List[MatchReplaceRule] = []
        self.enabled = False  # Master toggle

    def add_rule(self, target: str, match: str, replace: str,
                 is_regex: bool = False, comment: str = "") -> MatchReplaceRule:
        rule = MatchReplaceRule(target, match, replace, is_regex, True, comment)
        self._rules.append(rule)
        return rule

    def remove_rule(self, index: int):
        if 0 <= index < len(self._rules):
            self._rules.pop(index)

    def get_rules(self) -> List[MatchReplaceRule]:
        return list(self._rules)

    def clear_rules(self):
        self._rules.clear()

    def apply_request(self, headers: dict, body: str) -> tuple:
        """Apply all request rules. Returns (modified_headers, modified_body)."""
        if not self.enabled:
            return headers, body
        for rule in self._rules:
            if rule.target == "request_header":
                headers = rule.apply_to_headers(headers)
            elif rule.target == "request_body":
                body = rule.apply_to_body(body)
        return headers, body

    def apply_response(self, headers: dict, body: str) -> tuple:
        """Apply all response rules. Returns (modified_headers, modified_body)."""
        if not self.enabled:
            return headers, body
        for rule in self._rules:
            if rule.target == "response_header":
                headers = rule.apply_to_headers(headers)
            elif rule.target == "response_body":
                body = rule.apply_to_body(body)
        return headers, body

    def to_list(self) -> List[dict]:
        return [r.to_dict() for r in self._rules]

    def load_from_list(self, rules_list: List[dict]):
        self._rules.clear()
        for d in rules_list:
            self._rules.append(MatchReplaceRule.from_dict(d))
