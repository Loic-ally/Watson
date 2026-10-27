"""Active recon — port/service scanning (nmap wrapper, socket fallback).

Mode-gated by the caller: static never reaches here; dev is aggressive; prod is
rate-limited and opt-in. All targets must already be scope-checked.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from .tools import have, run

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 2375,
    3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017,
]


def _socket_scan(host: str, ports: list[int], timeout: float = 0.5) -> list[dict]:
    def check(p: int) -> int | None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return p if s.connect_ex((host, p)) == 0 else None

    with ThreadPoolExecutor(max_workers=50) as ex:
        found = [p for p in ex.map(check, ports) if p]
    return [{"port": p, "service": "", "source": "socket"} for p in sorted(found)]


def _nmap_scan(host: str, ports: list[int]) -> list[dict]:
    code, out, _ = run(
        ["nmap", "-Pn", "-sV", "-p", ",".join(map(str, ports)), "-oG", "-", host], 300)
    if code != 0:
        return []
    res = []
    for line in out.splitlines():
        if "Ports:" not in line:
            continue
        for entry in line.split("Ports:")[1].split(","):
            f = entry.strip().split("/")  # port/state/proto//service//version
            if len(f) >= 5 and f[1] == "open":
                res.append({"port": int(f[0]), "service": f[4] or f[2], "source": "nmap"})
    return res


def port_scan(host: str, ports: list[int] | None = None, prefer_nmap: bool = True) -> list[dict]:
    ports = ports or COMMON_PORTS
    if prefer_nmap and have("nmap"):
        hits = _nmap_scan(host, ports)
        if hits:
            return hits
    return _socket_scan(host, ports)


if __name__ == "__main__":  # self-check: python -m metsec.active (socket scan, deterministic)
    import threading

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]

    def accept_loop():
        while True:
            try:
                srv.accept()
            except OSError:
                return

    threading.Thread(target=accept_loop, daemon=True).start()

    other = port + 1 if port < 65535 else port - 1
    hits = _socket_scan("127.0.0.1", [port, other])
    assert [h["port"] for h in hits] == [port], hits  # only the listening port open
    srv.close()
    print("active self-check ok")
