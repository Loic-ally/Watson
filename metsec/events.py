"""In-process event bus for the live dashboard. The agent emits; the web UI tails.

Thread-safe: the agent runs in one thread and the Flask SSE stream reads from
another. Events are kept in memory for the life of the process.
"""
from __future__ import annotations

import threading
import time

_events: list[dict] = []
_lock = threading.Lock()


def emit(etype: str, **data) -> None:
    with _lock:
        _events.append({"i": len(_events), "ts": time.time(), "type": etype, **data})


def since(idx: int) -> list[dict]:
    with _lock:
        return list(_events[idx:])


def count() -> int:
    with _lock:
        return len(_events)


def reset() -> None:
    with _lock:
        _events.clear()


if __name__ == "__main__":  # self-check: python -m metsec.events
    reset()
    emit("tool", name="http_probe", detail="/login")
    emit("finding", severity="high", title="SQLi")
    assert count() == 2
    evs = since(0)
    assert evs[0]["type"] == "tool" and evs[0]["i"] == 0
    assert evs[1]["severity"] == "high"
    assert since(1)[0]["type"] == "finding" and since(2) == []
    reset()
    assert count() == 0
    print("events self-check ok")
