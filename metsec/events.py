"""Event bus for the live dashboard.

Default: one global buffer, shared across threads — the web dashboard (which reads
from a different thread than the run) relies on this. Parallel runs call
`new_stream()` to get an ISOLATED per-run buffer (via a ContextVar), so their feeds
don't interleave.
"""
from __future__ import annotations

import contextvars
import threading
import time

_global: list[dict] = []
_cur: contextvars.ContextVar = contextvars.ContextVar("metsec_events", default=None)
_lock = threading.Lock()


def _buf() -> list:
    b = _cur.get()
    return _global if b is None else b


def new_stream() -> list:
    """Isolate this context's events into a fresh buffer (for a parallel run)."""
    b: list[dict] = []
    _cur.set(b)
    return b


def emit(etype: str, **data) -> None:
    b = _buf()
    with _lock:
        b.append({"i": len(b), "ts": time.time(), "type": etype, **data})


def since(idx: int) -> list[dict]:
    b = _buf()
    with _lock:
        return list(b[idx:])


def count() -> int:
    with _lock:
        return len(_buf())


def reset() -> None:
    b = _buf()
    with _lock:
        b.clear()


if __name__ == "__main__":  # self-check: python -m metsec.events
    import threading as _t

    reset()
    emit("tool", name="http_probe", detail="/login")
    emit("finding", severity="high", title="SQLi")
    assert count() == 2 and since(0)[0]["type"] == "tool" and since(1)[0]["severity"] == "high"
    assert since(2) == []
    reset()
    assert count() == 0

    # isolation: a thread with new_stream() has its own buffer, global untouched
    emit("start", target="main")
    seen = {}

    def worker():
        new_stream()
        emit("tool", name="isolated")
        seen["n"] = count()            # only its own event

    t = _t.Thread(target=worker)
    t.start()
    t.join()
    assert seen["n"] == 1 and count() == 1 and since(0)[0]["target"] == "main"  # global intact
    print("events self-check ok")
