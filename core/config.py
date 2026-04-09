"""
Vers Suite - Simple config persistence
"""

import json
import os
from typing import Dict, Any

CONFIG_PATH = os.environ.get(
    "VERSSUITE_CONFIG_PATH",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json"),
)

DEFAULT_CONFIG: Dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 8080,
    "intercept_enabled": False,
    "response_intercept_enabled": False,
    "confirm_drop_all": True,
    "scope_enabled": False,
    "scope_rules": [],
    "match_replace_enabled": False,
    "match_replace_rules": [],
}


def load_config() -> Dict[str, Any]:
    if not os.path.exists(CONFIG_PATH):
        return dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return dict(DEFAULT_CONFIG)
        merged = dict(DEFAULT_CONFIG)
        merged.update(data)
        return merged
    except Exception:
        return dict(DEFAULT_CONFIG)


def save_config(cfg: Dict[str, Any]) -> None:
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=True)
    except Exception:
        pass
