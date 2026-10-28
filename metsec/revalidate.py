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


def _replay_probe(probe: dict, scope, sess: requests.Session):
    """Re-send the exact proving request and check `expect`. None if not replayable."""
    from .scope import OutOfScope

    url = probe.get("url", "")
    if not url:
        return None
    try:
        scope.require(url)
    except OutOfScope:
        return None
    method = (probe.get("method") or "GET").upper()
    param, value, cookie = probe.get("param"), probe.get("value"), probe.get("cookie")
    expect = str(probe.get("expect", "") or "")
    headers = dict(UA)
    if cookie:
        headers["Cookie"] = cookie
    params = {param: value} if (param and value is not None and method == "GET") else None
    data = {param: value} if (param and value is not None and method != "GET") else None
    try:
        r = sess.request(method, url, params=params, data=data, headers=headers,
                         timeout=12, allow_redirects=False)
    except requests.RequestException:
        return False
    if not expect:
        return r.status_code < 500 and r.status_code not in (404, 410)
    return str(r.status_code) == expect if expect.isdigit() else expect in r.text


def revalidate(findings: list, scope, session: requests.Session | None = None) -> dict:
    """Mutates findings in place. Returns {reproduced, downgraded, skipped, replayed}."""
    from .scope import OutOfScope

    sess = session or requests.Session()
    repro = down = skipped = replayed = 0
    for f in findings:
        if _get(f, "status") != "verified":
            continue
        probe = _get(f, "probe")
        if isinstance(probe, dict) and probe.get("url"):   # full replay of the proving request
            ok = _replay_probe(probe, scope, sess)
            if ok is not None:
                replayed += 1
        else:                                              # heuristic reachability/reflection
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
            ok = _reproduces(url, f, sess)
        if ok is None:
            skipped += 1
        elif ok:
            repro += 1
        else:
            _downgrade(f, "not reproduced")
            down += 1
    return {"reproduced": repro, "downgraded": down, "skipped": skipped, "replayed": replayed}


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
        # full-replay findings (carry the exact proving request)
        {"title": "SQLi marker", "status": "verified", "affected": f"{base}/search", "evidence": "",
         "probe": {"url": f"{base}/search", "param": "q", "value": "MARK42", "expect": "MARK42"}},
        {"title": "Stale verified", "status": "verified", "affected": f"{base}/search", "evidence": "",
         "probe": {"url": f"{base}/search", "param": "q", "value": "x", "expect": "ZZZNOPE"}},
    ]
    stats = revalidate(fs, scope)
    srv.shutdown()
    assert stats["reproduced"] == 3 and stats["downgraded"] == 2, stats   # .env, xss, replayed-SQLi
    assert stats["replayed"] == 2, stats                                  # the two probe-based ones
    assert fs[2]["status"] == "potential" and "not reproduced" in fs[2]["evidence"]
    assert fs[3]["status"] == "potential"                                 # potential untouched
    assert fs[4]["status"] == "verified" and fs[5]["status"] == "potential"  # replay OK vs failed
    print("revalidate self-check ok")
