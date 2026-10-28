"""Screenshot store for the dashboard — PNGs the agent captures, served by id."""
from __future__ import annotations

import secrets
from pathlib import Path

SHOT_DIR = Path(".metsec_cache/shots")


def save(png: bytes) -> str:
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    sid = secrets.token_hex(6)
    (SHOT_DIR / f"{sid}.png").write_bytes(png)
    return sid


def path(sid: str):
    if not sid or not sid.isalnum():   # no traversal
        return None
    p = SHOT_DIR / f"{sid}.png"
    return p if p.exists() else None


if __name__ == "__main__":  # self-check: python -m metsec.shots
    sid = save(b"\x89PNG\r\n\x1a\n_fake_")
    assert path(sid) and path(sid).read_bytes().startswith(b"\x89PNG")
    assert path("../etc/passwd") is None and path("nope") is None
    print("shots self-check ok")
