"""Phase 2 recon — passive fingerprinting of a target (dev/prod modes).

One GET of the target yields a tech inventory (name + version + evidence) that
feeds the retriever and research(). Passive only here: no active scanning.
Version detection is heuristic (CDN/filename/header patterns).
ponytail: regex heuristics, known ceiling — swap in a wappalyzer-style
fingerprint DB if coverage matters.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlparse

import requests

UA = {"User-Agent": "Mozilla/5.0 (MetSec recon)"}

SECURITY_HEADERS = [
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
]
HEADER_TECH = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]

_VERSION = r"(\d+\.\d+(?:\.\d+)?)"


@dataclass
class Tech:
    name: str
    version: str = ""
    source: str = ""      # header | script | meta
    evidence: str = ""


class _Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets: list[str] = []
        self.generators: list[str] = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag in ("script", "link") and (d.get("src") or d.get("href")):
            self.assets.append(d.get("src") or d["href"])
        elif tag == "meta" and d.get("name", "").lower() == "generator" and d.get("content"):
            self.generators.append(d["content"])


def _from_header(name: str, value: str) -> list[Tech]:
    out = []
    for part in re.split(r"[ ,;]+", value.strip()):
        m = re.match(r"([A-Za-z][\w\-]*)/(\d[\w.]*)", part)
        if m:
            out.append(Tech(m.group(1).lower(), m.group(2), "header", f"{name}: {value}"[:120]))
    return out


def _from_asset(url: str) -> Tech | None:
    path = urlparse(url).path.lower()
    m = re.search(r"(?:libs/|npm/|/)([a-z][a-z0-9\-.]{1,30}?)[-@/]" + _VERSION, path)
    if not m:
        return None
    name = m.group(1).strip("-.").split("/")[-1]
    if name in ("ajax", "npm", "libs", ""):
        return None
    return Tech(name, m.group(2), "script", url[:120])


def _from_generator(content: str) -> Tech | None:
    content = content.strip()
    if not content:
        return None
    m = re.match(r"([A-Za-z][\w .\-]*?)\s*v?" + _VERSION, content)
    if m:
        return Tech(m.group(1).strip().lower(), m.group(2), "meta", content[:80])
    return Tech(content.lower(), "", "meta", content[:80])


def _dedup(techs: list[Tech]) -> list[Tech]:
    seen: dict[tuple, Tech] = {}
    for t in techs:
        seen.setdefault((t.name, t.version), t)
    return list(seen.values())


def fingerprint(url: str) -> dict:
    """Passive fingerprint of one URL → inventory dict."""
    r = requests.get(url, headers=UA, timeout=20, allow_redirects=True)
    present = {k.lower() for k in r.headers}
    techs: list[Tech] = []
    for h in HEADER_TECH:
        if h in r.headers:
            techs += _from_header(h, r.headers[h])
    if "html" in r.headers.get("content-type", "").lower():
        p = _Assets()
        p.feed(r.text)
        techs += [t for s in p.assets if (t := _from_asset(s))]
        techs += [t for g in p.generators if (t := _from_generator(g))]
    return {
        "url": url,
        "status": r.status_code,
        "server": r.headers.get("server", ""),
        "techs": _dedup(techs),
        "cookies": list(r.cookies.keys()),
        "missing_security_headers": [h for h in SECURITY_HEADERS if h not in present],
    }


if __name__ == "__main__":  # self-check: python -m metsec.recon (in-process local server)
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    HTML = (
        b"<html><head>"
        b'<meta name="generator" content="WordPress 4.1">'
        b'<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.7.2/jquery.min.js"></script>'
        b'<link href="/css/bootstrap-3.3.7.min.css" rel="stylesheet">'
        b"</head><body>hi</body></html>"
    )

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            self.end_headers()
            self.wfile.write(HTML)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    inv = fingerprint(f"http://127.0.0.1:{srv.server_address[1]}/")
    found = {t.name: t.version for t in inv["techs"]}
    assert found.get("jquery") == "1.7.2", found
    assert found.get("wordpress") == "4.1", found
    assert found.get("php") == "7.4.3", found
    assert found.get("bootstrap") == "3.3.7", found
    assert "content-security-policy" in inv["missing_security_headers"]
    srv.shutdown()
    print("recon self-check ok")
