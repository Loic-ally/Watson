"""Re-validation — replay verified findings to re-confirm them and cut false positives.

For each VERIFIED finding whose `affected` points at an in-scope URL, re-probe it
(reflection re-check for reflected/XSS findings, else reachability). Anything that no
longer reproduces is downgraded to `potential` with a note.
ponytail: reachability/reflection replay — not a full re-exploitation of every class.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import parse_qs, urlparse

import requests

UA = {"User-Agent": "Mozilla/5.0 (MetSec revalidate)"}
_URL = re.compile(r"https?://[^\s'\"]+")


def _get(f, k):
    return f.get(k, "") if isinstance(f, dict) else (getattr(f, k, "") or "")


def _downgrade(f, note):
    ev = (_get(f, "evidence") + f" [re-validation: {note}]").strip()
    if isinstance(f, dict):
        f["status"], f["evidence"] = "potential", ev
    else:
        f.status, f.evidence = "potential", ev


def _reproduces(url: str, f, sess: requests.Session) -> bool:
    low = (_get(f, "title") + " " + _get(f, "evidence")).lower()
    p = urlparse(url)
    qs = parse_qs(p.query)
    try:
        if ("reflect" in low or "xss" in low) and qs:   # re-send a fresh marker
            param = next(iter(qs))
            nonce = "MSEC" + secrets.token_hex(4)
            r = sess.get(f"{p.scheme}://{p.netloc}{p.path}", params={param: nonce},
                         headers=UA, timeout=10)
            return nonce in r.text
        r = sess.get(url, headers=UA, timeout=10, allow_redirects=False)
        return r.status_code not in (404, 410) and r.status_code < 500
    except requests.RequestException:
        return False


def revalidate(findings: list, scope, session: requests.Session | None = None) -> dict:
    """Mutates findings in place. Returns {reproduced, downgraded, skipped}."""
    from .scope import OutOfScope

    sess = session or requests.Session()
    repro = down = skipped = 0
    for f in findings:
        if _get(f, "status") != "verified":
            continue
        m = _URL.search(_get(f, "affected"))
        if not m:
            skipped += 1
            continue
        url = m.group(0).rstrip(".,)")
        try:
            scope.require(url)
        except OutOfScope:
            skipped += 1
            continue
        if _reproduces(url, f, sess):
            repro += 1
        else:
            _downgrade(f, "not reproduced")
            down += 1
    return {"reproduced": repro, "downgraded": down, "skipped": skipped}


if __name__ == "__main__":  # self-check: python -m metsec.revalidate
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from .scope import Scope

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            from urllib.parse import parse_qs as pq
            from urllib.parse import urlparse as up
            u = up(self.path)
            if u.path == "/.env":
                body, code = b"SECRET=1", 200
            elif u.path == "/search":
                q = pq(u.query).get("q", [""])[0]
                body, code = ("<h1>" + q + "</h1>").encode(), 200     # reflects
            else:
                body, code = b"gone", 404
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    scope = Scope(ips=["127.0.0.1"], authorized_by="t", mode="prod")
    fs = [
        {"title": "Exposed .env", "status": "verified", "affected": f"{base}/.env", "evidence": ""},
        {"title": "Reflected XSS", "status": "verified", "affected": f"{base}/search?q=", "evidence": ""},
        {"title": "Gone endpoint", "status": "verified", "affected": f"{base}/old", "evidence": ""},
        {"title": "Potential CVE", "status": "potential", "affected": f"{base}/.env", "evidence": ""},
    ]
    stats = revalidate(fs, scope)
    srv.shutdown()
    assert stats["reproduced"] == 2 and stats["downgraded"] == 1, stats   # .env + xss repro; /old gone
    assert fs[2]["status"] == "potential" and "not reproduced" in fs[2]["evidence"]
    assert fs[0]["status"] == "verified" and fs[3]["status"] == "potential"  # potential untouched
    print("revalidate self-check ok")
