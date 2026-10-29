"""Tiny JSON cache for recon inventories, keyed by target + mode + depth.

Avoids re-fingerprinting/re-crawling on repeat assess runs. Bypass with --fresh;
entries expire after max_age seconds.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

CACHE_DIR = Path(".watson_cache/recon")


def _key(parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:16]


def get(parts, max_age: float = 3600) -> dict | None:
    f = CACHE_DIR / (_key(parts) + ".json")
    if f.exists() and (time.time() - f.stat().st_mtime) < max_age:
        try:
            return json.loads(f.read_text())
        except (ValueError, OSError):
            return None
    return None


def put(data: dict, parts) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (CACHE_DIR / (_key(parts) + ".json")).write_text(json.dumps(data, default=str))


if __name__ == "__main__":  # self-check: python -m watson.cache
    import tempfile

    CACHE_DIR = Path(tempfile.mkdtemp())
    k = ("http://t/", "dev", True)
    assert get(k) is None
    put({"techs": [1, 2]}, k)
    assert get(k) == {"techs": [1, 2]}
    assert get(k, max_age=-1) is None        # expired
    assert get(("other", "static", False)) is None
    print("cache self-check ok")
