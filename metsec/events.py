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

# Cooperative cancellation. A global flag (process-wide stop, e.g. on SIGTERM) plus an
# optional per-run flag (ContextVar) so a parallel run can be stopped on its own. The agent
# loop checks stop_requested() between turns and wraps up with the findings already recorded.
_stop_global = threading.Event()
_stop_cur: contextvars.ContextVar = contextvars.ContextVar("metsec_stop", default=None)


def _buf() -> list:
    b = _cur.get()
    return _global if b is None else b


def arm_stop() -> "threading.Event":
    """Give this context its own cancel flag (for an isolated parallel run)."""
    ev = threading.Event()
    _stop_cur.set(ev)
    return ev


def request_stop() -> None:
    """Ask the current run (and the process) to stop gracefully after the current turn."""
    _stop_global.set()
    ev = _stop_cur.get()
    if ev is not None:
        ev.set()


def stop_requested() -> bool:
    ev = _stop_cur.get()
    return _stop_global.is_set() or (ev is not None and ev.is_set())


def clear_stop() -> None:
    _stop_global.clear()
    ev = _stop_cur.get()
    if ev is not None:
        ev.clear()


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
    clear_stop()   # a fresh run starts with no pending cancel


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

    # cancellation: request_stop trips stop_requested; reset()/clear_stop clears it
    reset()
    assert not stop_requested()
    request_stop()
    assert stop_requested()
    clear_stop()
    assert not stop_requested()
    print("events self-check ok")
