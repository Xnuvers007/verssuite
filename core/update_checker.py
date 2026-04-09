"""
Vers Suite - Update checker.
Checks the latest version from GitHub with release/tag fallback.
"""

from __future__ import annotations

import re
from typing import Dict, Optional, Tuple

import requests

from .version import REPO_NAME, REPO_OWNER, REPO_URL


GITHUB_API_BASE = "https://api.github.com"


def _normalize_version(version: str) -> str:
    return version.strip().lstrip("vV")


def _version_tuple(version: str) -> Tuple[int, ...]:
    cleaned = _normalize_version(version)
    match = re.match(r"^(\d+(?:\.\d+)*)", cleaned)
    if not match:
        return tuple()
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return tuple()


def _is_newer(latest: str, current: str) -> bool:
    latest_tuple = _version_tuple(latest)
    current_tuple = _version_tuple(current)

    if latest_tuple and current_tuple:
        max_len = max(len(latest_tuple), len(current_tuple))
        padded_latest = latest_tuple + (0,) * (max_len - len(latest_tuple))
        padded_current = current_tuple + (0,) * (max_len - len(current_tuple))
        return padded_latest > padded_current

    return _normalize_version(latest) != _normalize_version(current)


def _github_get_json(url: str, timeout_sec: float) -> Optional[dict]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "verssuite-update-checker",
    }
    response = requests.get(url, headers=headers, timeout=timeout_sec)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


def _fetch_latest_version(owner: str, repo: str, timeout_sec: float) -> Tuple[str, str]:
    release_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/releases/latest"
    release_json = _github_get_json(release_url, timeout_sec)
    if release_json:
        tag = release_json.get("tag_name") or release_json.get("name")
        html_url = release_json.get("html_url") or f"https://github.com/{owner}/{repo}/releases"
        if tag:
            return str(tag), str(html_url)

    tags_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/tags?per_page=1"
    tags_json = _github_get_json(tags_url, timeout_sec)
    if isinstance(tags_json, list) and tags_json:
        first = tags_json[0] or {}
        tag = first.get("name")
        if tag:
            return str(tag), f"https://github.com/{owner}/{repo}/releases"

    raise RuntimeError("Latest version not found on GitHub releases/tags")


def check_for_updates(
    current_version: str,
    owner: str = REPO_OWNER,
    repo: str = REPO_NAME,
    timeout_sec: float = 6.0,
) -> Dict[str, str]:
    """
    Returns dict with keys: status, current_version, latest_version, url, message.
    status values: up-to-date | update-available | error
    """
    try:
        latest_version, latest_url = _fetch_latest_version(owner, repo, timeout_sec)
        if _is_newer(latest_version, current_version):
            return {
                "status": "update-available",
                "current_version": current_version,
                "latest_version": _normalize_version(latest_version),
                "url": latest_url,
                "message": "A newer version is available.",
            }

        return {
            "status": "up-to-date",
            "current_version": current_version,
            "latest_version": _normalize_version(latest_version),
            "url": latest_url,
            "message": "You are already using the latest version.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "current_version": current_version,
            "latest_version": "",
            "url": REPO_URL,
            "message": f"Failed to check updates: {exc}",
        }
