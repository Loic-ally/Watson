"""Audit log — a persistent JSONL record of every tool call (requests, commands),
for engagement traceability. Written to its own file per run.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

_lock = threading.Lock()
_path: Path | None = None


def start(path: str | Path) -> None:
    global _path
    _path = Path(path)
    _path.parent.mkdir(parents=True, exist_ok=True)
    _path.write_text("")


def log(etype: str, **data) -> None:
    if _path is None:
        return
    rec = {"ts": round(time.time(), 3), "type": etype, **data}
    with _lock:
        with open(_path, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")


def path() -> str | None:
    return str(_path) if _path else None


if __name__ == "__main__":  # self-check: python -m metsec.audit
    import tempfile

    f = Path(tempfile.mkdtemp()) / "audit.jsonl"
    start(f)
    log("call", tool="http_probe", args={"url": "http://x/"}, status=200)
    log("call", tool="run_command", args={"command": "id"})
    lines = f.read_text().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["tool"] == "http_probe" and first["status"] == 200 and "ts" in first
    assert path() == str(f)
    print("audit self-check ok")
