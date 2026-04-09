"""
Vers Suite - Session Manager
Save and load entire project sessions to/from .verssuite files.
"""

import json
import gzip
import os
from typing import Dict, Any, Optional


SESSION_VERSION = 1
SESSION_EXTENSION = ".verssuite"


def save_session(path: str, data: Dict[str, Any]) -> bool:
    """
    Save a session to a .verssuite file (gzipped JSON).

    data should contain:
        - history_flows: list of flow dicts
        - history_responses: dict of flow_id -> response
        - history_notes: dict of flow_id -> note string
        - repeater_sessions: list of session dicts
        - intruder_results: list of result dicts
        - scope_rules: list of scope rule dicts
        - scope_enabled: bool
        - match_replace_rules: list of rule dicts
        - match_replace_enabled: bool
        - config: dict
    """
    try:
        envelope = {
            "version": SESSION_VERSION,
            "app": "verssuite",
            "data": data,
        }
        json_bytes = json.dumps(envelope, ensure_ascii=True, indent=None).encode("utf-8")
        with gzip.open(path, "wb", compresslevel=6) as f:
            f.write(json_bytes)
        return True
    except Exception:
        return False


def load_session(path: str) -> Optional[Dict[str, Any]]:
    """
    Load a session from a .verssuite file.
    Returns the data dict, or None on error.
    """
    try:
        with gzip.open(path, "rb") as f:
            json_bytes = f.read()
        envelope = json.loads(json_bytes.decode("utf-8"))
        if not isinstance(envelope, dict):
            return None
        if envelope.get("app") != "verssuite":
            return None
        return envelope.get("data", {})
    except Exception:
        return None
