"""
Vers Suite - Scope Manager
Filters which hosts/URLs are in-scope for interception and history logging.
"""

import re
import fnmatch
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse


class ScopeRule:
    """A single scope rule (include or exclude)."""

    __slots__ = ("pattern", "rule_type", "enabled", "_regex")

    def __init__(self, pattern: str, rule_type: str = "include", enabled: bool = True):
        self.pattern = pattern          # e.g. "*.example.com", "api.target.com"
        self.rule_type = rule_type      # "include" or "exclude"
        self.enabled = enabled
        self._regex: Optional[re.Pattern] = None
        self._compile()

    def _compile(self):
        """Convert the glob pattern to a compiled regex."""
        try:
            regex_str = fnmatch.translate(self.pattern)
            self._regex = re.compile(regex_str, re.IGNORECASE)
        except re.error:
            self._regex = None

    def matches(self, host: str) -> bool:
        if not self.enabled or not self._regex:
            return False
        return bool(self._regex.match(host))

    def to_dict(self) -> dict:
        return {
            "pattern": self.pattern,
            "rule_type": self.rule_type,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScopeRule":
        return cls(
            pattern=d.get("pattern", "*"),
            rule_type=d.get("rule_type", "include"),
            enabled=d.get("enabled", True),
        )


class ScopeManager:
    """
    Manages scope rules for filtering intercepted traffic.

    When no include rules exist, everything is in-scope (open scope).
    When include rules exist, only matching hosts are in-scope.
    Exclude rules always take priority over include rules.
    """

    def __init__(self):
        self._rules: List[ScopeRule] = []
        self.enabled = False  # Master toggle

    def is_in_scope(self, url_or_host: str) -> bool:
        """Check if a URL or host is within the defined scope."""
        if not self.enabled:
            return True  # Scope disabled = everything in scope

        if not self._rules:
            return True  # No rules = everything in scope

        # Extract host from URL if needed
        host = self._extract_host(url_or_host)

        # Check exclude rules first (they take priority)
        for rule in self._rules:
            if rule.rule_type == "exclude" and rule.matches(host):
                return False

        # Check include rules
        include_rules = [r for r in self._rules if r.rule_type == "include" and r.enabled]
        if not include_rules:
            return True  # No include rules = everything in scope

        for rule in include_rules:
            if rule.matches(host):
                return True

        return False  # Has include rules but none matched

    def add_rule(self, pattern: str, rule_type: str = "include",
                 enabled: bool = True) -> ScopeRule:
        rule = ScopeRule(pattern, rule_type, enabled)
        self._rules.append(rule)
        return rule

    def remove_rule(self, index: int):
        if 0 <= index < len(self._rules):
            self._rules.pop(index)

    def update_rule(self, index: int, pattern: str = None,
                    rule_type: str = None, enabled: bool = None):
        if 0 <= index < len(self._rules):
            rule = self._rules[index]
            if pattern is not None:
                rule.pattern = pattern
                rule._compile()
            if rule_type is not None:
                rule.rule_type = rule_type
            if enabled is not None:
                rule.enabled = enabled

    def get_rules(self) -> List[ScopeRule]:
        return list(self._rules)

    def clear_rules(self):
        self._rules.clear()

    def to_list(self) -> List[dict]:
        return [r.to_dict() for r in self._rules]

    def load_from_list(self, rules_list: List[dict]):
        self._rules.clear()
        for d in rules_list:
            self._rules.append(ScopeRule.from_dict(d))

    @staticmethod
    def _extract_host(url_or_host: str) -> str:
        if "://" in url_or_host:
            parsed = urlparse(url_or_host)
            return parsed.hostname or url_or_host
        # Remove port if present
        if ":" in url_or_host:
            return url_or_host.split(":")[0]
        return url_or_host
