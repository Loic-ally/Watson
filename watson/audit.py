"""Audit log — a persistent JSONL record of every tool call (requests, commands).

Path is per-context (ContextVar) so parallel runs each write their own file, while
single runs keep one file.
"""
from __future__ import annotations

import contextvars
import json
import threading
import time
from pathlib import Path

_lock = threading.Lock()
_path: contextvars.ContextVar = contextvars.ContextVar("watson_audit", default=None)


def start(path: str | Path) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("")
    _path.set(str(p))


def log(etype: str, **data) -> None:
    pth = _path.get()
    if pth is None:
        return
    rec = {"ts": round(time.time(), 3), "type": etype, **data}
    with _lock:
        with open(pth, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")


def path() -> str | None:
    return _path.get()


if __name__ == "__main__":  # self-check: python -m watson.audit
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
