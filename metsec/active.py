"""Active recon — port scanning, crawling, content discovery.

Mode-gated by the caller: static never reaches here; dev is aggressive; prod is
rate-limited and opt-in. All targets must already be scope-checked.
"""
from __future__ import annotations

import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

from .tools import have, run

UA = {"User-Agent": "Mozilla/5.0 (MetSec active)"}

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


class _Crawl(HTMLParser):
    """Collect same-origin links, asset URLs, and forms+inputs from a page."""

    def __init__(self, base: str):
        super().__init__()
        self.base = base
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and d.get("href"):
            self.links.append(urljoin(self.base, d["href"]))
        elif tag in ("script", "link") and (d.get("src") or d.get("href")):
            self.links.append(urljoin(self.base, d.get("src") or d["href"]))
        elif tag == "form":
            self._form = {"action": urljoin(self.base, d.get("action", "")) or self.base,
                          "method": (d.get("method") or "get").lower(), "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            self._form["inputs"].append({"name": d.get("name", ""),
                                         "type": d.get("type", "text")})

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


_JS_PATH = re.compile(r"""["'`](/[A-Za-z0-9_./\-]{1,80})["'`]""")


def _mine_js(session, js_urls: list[str], limit: int = 20) -> set[str]:
    """Pull path-like strings (API routes etc.) out of JS files."""
    eps: set[str] = set()
    for u in js_urls[:limit]:
        try:
            eps.update(_JS_PATH.findall(session.get(u, headers=UA, timeout=15).text))
        except requests.RequestException:
            continue
    return eps


def crawl(base_url: str, scope, max_pages: int = 50, rate: float = 0.0,
          session: requests.Session | None = None) -> dict:
    """Scope-gated same-origin BFS crawl → pages, endpoints, forms (+ JS routes)."""
    from .scope import OutOfScope

    sess = session or requests.Session()
    origin = urlparse(base_url).netloc
    seen: set[str] = set()
    queue = [base_url]
    pages: list[str] = []
    endpoints: set[str] = set()
    forms: list[dict] = []
    js_urls: list[str] = []

    while queue and len(pages) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            scope.require(url)
        except OutOfScope:
            continue
        try:
            r = sess.get(url, headers=UA, timeout=15)
        except requests.RequestException:
            continue
        pages.append(url)
        if rate:
            time.sleep(rate)
        if "html" not in r.headers.get("content-type", "").lower():
            continue
        p = _Crawl(url)
        p.feed(r.text)
        forms += p.forms
        for link in p.links:
            endpoints.add(link)
            if link.endswith(".js") and urlparse(link).netloc == origin:
                js_urls.append(link)
            if urlparse(link).netloc == origin and link not in seen:
                queue.append(link)
    endpoints.update(_mine_js(sess, js_urls))
    return {"pages": pages, "endpoints": sorted(endpoints), "forms": forms}


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

    # crawl: links, forms, JS endpoint mining
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from .scope import Scope

    PAGES = {
        "/": b'<a href="/page2">p2</a><script src="/app.js"></script>'
             b'<form action="/login" method="post"><input name="user"></form>',
        "/page2": b"<html>nothing</html>",
        "/app.js": b'fetch("/api/secret"); const u="/api/users";',
    }

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = PAGES.get(self.path.split("?")[0])
            self.send_response(200 if body is not None else 404)
            self.send_header("Content-Type",
                             "application/javascript" if self.path.endswith(".js") else "text/html")
            self.end_headers()
            self.wfile.write(body or b"")

        def log_message(self, *a):
            pass

    web = HTTPServer(("127.0.0.1", 0), H)
    wport = web.server_address[1]
    threading.Thread(target=web.serve_forever, daemon=True).start()
    scope = Scope(ips=["127.0.0.1"], authorized_by="test", mode="dev")
    out = crawl(f"http://127.0.0.1:{wport}/", scope)
    assert f"http://127.0.0.1:{wport}/page2" in out["endpoints"], out["endpoints"]
    assert any(f["action"].endswith("/login") and f["method"] == "post"
               and f["inputs"][0]["name"] == "user" for f in out["forms"]), out["forms"]
    assert "/api/secret" in out["endpoints"] and "/api/users" in out["endpoints"], out["endpoints"]
    web.shutdown()
    print("active self-check ok")
