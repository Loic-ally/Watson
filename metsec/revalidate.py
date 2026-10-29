"""Re-validation — replay verified findings to re-confirm them and cut false positives.

Replaying a proving request only COUNTS as a reproduction when there is a proof criterion
adapted to the finding. In particular:
  - an HTTP 200 or 403 does NOT, on its own, prove a vulnerability;
  - reflecting a string does NOT prove XSS *execution* (reflection ≠ execution);
  - an unavailable target, an auth wall (401/403), a 5xx, or a test we cannot adapt a proof
    to yields INDETERMINATE — the finding's status and history are left untouched, never
    silently promoted or erased;
  - scope and mode gate the replay (static = no network; prod detection-first blocks
    mutating/injection replays unless exploitation is authorized), including on redirects
    (we never follow a redirect to an out-of-scope host).

Outcome of one replay is a tri-state: True (reproduced), False (clearly not reproduced →
downgrade), or None (indeterminate → leave as-is, annotate).
ponytail: criterion-based replay — not a full re-exploitation of every vuln class.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import parse_qs, urlparse

import requests

UA = {"User-Agent": "Mozilla/5.0 (MetSec revalidate)"}
_URL = re.compile(r"https?://[^\s'\"]+")
# a replay request carrying any of these in its value/url is a mutating/injection probe
_INJECT = re.compile(r"""[;|&<>`'"$]|\{\{|\.\./|\$\(|<script""", re.I)


def _get(f, k):
    return f.get(k, "") if isinstance(f, dict) else (getattr(f, k, "") or "")


def _set(f, **kw):
    for k, v in kw.items():
        if isinstance(f, dict):
            f[k] = v
        else:
            setattr(f, k, v)


def _annotate(f, note):
    _set(f, evidence=(_get(f, "evidence") + f" [re-validation: {note}]").strip())


def _downgrade(f, note):
    _annotate(f, note)
    _set(f, status="potential", confidence="unconfirmed")


def _mode_blocks(mode: str, exploit: bool, *payloads: str) -> bool:
    """Detection-first in prod: an injection/mutating replay is blocked unless exploit."""
    if mode == "prod" and not exploit:
        return any(p and _INJECT.search(str(p)) for p in payloads)
    return False


def _reproduces(url: str, f, scope, sess: requests.Session, exploit: bool):
    """Heuristic path (no proving request stored). Reachability alone is NOT proof, so it
    returns None (indeterminate) except for a reflection re-check, which proves reflection
    (annotated as NOT proof of execution)."""
    low = (_get(f, "title") + " " + _get(f, "evidence")).lower()
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    if ("reflect" in low or "xss" in low) and qs:   # re-send a fresh marker
        param = next(iter(qs))
        nonce = "MSEC" + secrets.token_hex(4)
        if _mode_blocks(scope.mode, exploit, nonce):
            return None
        try:
            r = sess.get(f"{p.scheme}://{p.netloc}{p.path}", params={param: nonce},
                         headers=UA, timeout=10, allow_redirects=False)
        except requests.RequestException:
            return None                              # unavailable → indeterminate
        if nonce in r.text:
            _annotate(f, "reflection reproduced — NOT a confirmation of script execution")
            return True
        return False
    # no adapted proof criterion → reachability is not evidence either way
    return None


def _replay_probe(probe: dict, scope, sess: requests.Session, exploit: bool):
    """Re-send the exact proving request and check `expect`. Tri-state; None if we cannot
    adapt a verdict (not replayable, out of scope, mode-gated, unavailable, auth wall, 5xx,
    or no proof criterion)."""
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
    if method != "GET" or _mode_blocks(scope.mode, exploit, value, url):
        return None                                  # detection-first: don't replay payloads
    headers = dict(UA)
    if cookie:
        headers["Cookie"] = cookie
    params = {param: value} if (param and value is not None and method == "GET") else None
    data = {param: value} if (param and value is not None and method != "GET") else None
    try:
        r = sess.request(method, url, params=params, data=data, headers=headers,
                         timeout=12, allow_redirects=False)
    except requests.RequestException:
        return None                                  # unavailable → indeterminate
    # a redirect to an out-of-scope host must never be followed/trusted
    if r.is_redirect:
        loc = r.headers.get("Location", "")
        try:
            if loc:
                scope.require(urlparse(loc).scheme and loc or f"{url.rsplit('/', 1)[0]}/{loc}")
        except OutOfScope:
            return None
    if r.status_code in (401, 403) or r.status_code >= 500:
        return None                                  # auth wall / unavailable → indeterminate
    if not expect:
        return None                                  # no adapted proof criterion → indeterminate
    if expect.isdigit():
        return str(r.status_code) == expect
    return expect in r.text


def revalidate(findings: list, scope, session: requests.Session | None = None,
               exploit: bool = False) -> dict:
    """Mutates findings in place. Returns {reproduced, downgraded, indeterminate, replayed}.
    Scope/mode are enforced; static mode does no network and leaves everything indeterminate."""
    from .scope import OutOfScope

    sess = session or requests.Session()
    repro = down = indet = replayed = 0
    static = getattr(scope, "mode", "") == "static"
    for f in findings:
        if _get(f, "status") != "verified":
            continue
        if static:                                   # no network in static mode
            indet += 1
            _annotate(f, "indeterminate — static mode, no network re-validation")
            continue
        probe = _get(f, "probe")
        if isinstance(probe, dict) and probe.get("url"):   # full replay of the proving request
            ok = _replay_probe(probe, scope, sess, exploit)
            if ok is not None:
                replayed += 1
        else:                                              # heuristic reflection / reachability
            m = _URL.search(_get(f, "affected"))
            if not m:
                indet += 1
                continue
            url = m.group(0).rstrip(".,)")
            try:
                scope.require(url)
            except OutOfScope:
                indet += 1
                continue
            ok = _reproduces(url, f, scope, sess, exploit)
        if ok is None:
            indet += 1
            if not _get(f, "evidence").endswith("]"):
                _annotate(f, "indeterminate — no adapted proof criterion / unavailable")
        elif ok:
            repro += 1
        else:
            _downgrade(f, "not reproduced")
            down += 1
    # 'downgraded' kept as the historical key name; 'skipped' retained as an alias of indeterminate
    return {"reproduced": repro, "downgraded": down, "indeterminate": indet,
            "skipped": indet, "replayed": replayed}


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
            elif u.path == "/admin":
                body, code = b"forbidden", 403                        # auth wall
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
        # reachability-only, no proof criterion → INDETERMINATE (200 alone proves nothing)
        {"title": "Exposed .env", "status": "verified", "affected": f"{base}/.env", "evidence": ""},
        # reflection re-check reproduces reflection (annotated: NOT execution proof)
        {"title": "Reflected XSS", "status": "verified", "affected": f"{base}/search?q=", "evidence": ""},
        {"title": "Potential CVE", "status": "potential", "affected": f"{base}/.env", "evidence": ""},
        # replay with a matching proof criterion → reproduced
        {"title": "SQLi marker", "status": "verified", "affected": f"{base}/search", "evidence": "",
         "probe": {"url": f"{base}/search", "param": "q", "value": "MARK42", "expect": "MARK42"}},
        # replay whose proof criterion fails → clearly NOT reproduced → downgraded
        {"title": "Stale verified", "status": "verified", "affected": f"{base}/search", "evidence": "",
         "probe": {"url": f"{base}/search", "param": "q", "value": "x", "expect": "ZZZNOPE"}},
        # HTTP 403 must NOT count as a reproduction → indeterminate, status untouched
        {"title": "Admin 403", "status": "verified", "affected": f"{base}/admin", "evidence": "",
         "probe": {"url": f"{base}/admin", "expect": "anything"}},
    ]
    stats = revalidate(fs, scope)
    assert stats["reproduced"] == 2, stats          # reflection + SQLi marker only
    assert stats["downgraded"] == 1, stats          # the stale one
    assert stats["indeterminate"] == 2, stats       # .env (no criterion) + 403 admin
    assert fs[0]["status"] == "verified" and "indeterminate" in fs[0]["evidence"]  # .env not erased
    assert fs[1]["status"] == "verified" and "reflection reproduced" in fs[1]["evidence"]
    assert fs[2]["status"] == "potential"           # a non-verified finding is left alone
    assert fs[3]["status"] == "verified"            # reproduced
    assert fs[4]["status"] == "potential" and "not reproduced" in fs[4]["evidence"]
    assert fs[5]["status"] == "verified" and "indeterminate" in fs[5]["evidence"]  # 403 ≠ repro

    # mode gating: an injection replay is blocked in prod detection-first (indeterminate),
    # and allowed once exploitation is authorized
    inj = [{"title": "SSTI", "status": "verified", "affected": f"{base}/search", "evidence": "",
            "probe": {"url": f"{base}/search", "param": "q", "value": "{{7*7}}", "expect": "49"}}]
    assert revalidate([dict(inj[0])], scope)["indeterminate"] == 1       # prod blocks payload replay

    # static mode does no network → everything indeterminate, nothing erased
    stat_scope = Scope(code_path=".", authorized_by="t", mode="static")
    sf = [{"title": "x", "status": "verified", "affected": f"{base}/.env", "evidence": ""}]
    assert revalidate(sf, stat_scope)["indeterminate"] == 1 and sf[0]["status"] == "verified"
    srv.shutdown()
    print("revalidate self-check ok")
