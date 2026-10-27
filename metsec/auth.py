"""Authenticated scanning — log in a test account and reuse the session.

Credentials come from .env via the env-var names in scope.auth (never stored in
the scope file). The login form is discovered so field names + CSRF/hidden
inputs are preserved. Enables testing the authenticated surface (IDOR, access
control) in later phases.
"""
from __future__ import annotations

import os
from html.parser import HTMLParser
from urllib.parse import urljoin

import requests

from .active import UA, crawl
from .scope import OutOfScope


class _FormParser(HTMLParser):
    def __init__(self, base: str):
        super().__init__()
        self.base = base
        self.forms: list[dict] = []
        self._cur: dict | None = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "form":
            self._cur = {"action": urljoin(self.base, d.get("action", "")) or self.base,
                         "method": (d.get("method") or "post").lower(), "fields": []}
            self.forms.append(self._cur)
        elif tag == "input" and self._cur is not None:
            self._cur["fields"].append((d.get("name"), (d.get("type") or "text").lower(),
                                        d.get("value", "")))

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def _pick_login_form(html: str, base: str) -> dict | None:
    forms = _FormParser(base)
    forms.feed(html)
    for f in forms.forms:
        if any(t == "password" for _, t, _ in f["fields"]):
            return f
    return forms.forms[0] if forms.forms else None


def _build_credentials(form: dict, user: str, pw: str) -> dict:
    """Map user/pass onto the form's fields, preserving hidden CSRF/defaults."""
    data: dict[str, str] = {}
    username_set = False
    for name, typ, val in form["fields"]:
        if not name:
            continue
        if typ == "password":
            data[name] = pw
        elif typ in ("text", "email", "tel") and not username_set:
            data[name], username_set = user, True
        else:  # hidden, checkbox, radio, tokens — keep their defaults
            data.setdefault(name, val)
    return data


def _cred(env_name: str) -> str:
    v = os.environ.get(env_name)
    if not v:
        raise OutOfScope(f"credential env var {env_name!r} not set")
    return v


def login(scope, account: dict | None = None) -> requests.Session:
    """Log in a test account from scope.auth → authenticated requests.Session."""
    auth = scope.auth or {}
    accounts = auth.get("accounts") or []
    login_url = auth.get("login_url")
    if not accounts or not login_url:
        raise OutOfScope("scope.auth needs login_url and at least one account")
    scope.require(login_url)
    acct = account or accounts[0]
    user, pw = _cred(acct["user_env"]), _cred(acct["pass_env"])

    sess = requests.Session()
    form = _pick_login_form(sess.get(login_url, headers=UA, timeout=20).text, login_url)
    if not form:
        raise OutOfScope(f"no login form found at {login_url}")
    data = _build_credentials(form, user, pw)
    send = sess.post if form["method"] == "post" else sess.get
    send(form["action"], data=data, headers=UA, timeout=20, allow_redirects=True)
    # ponytail: success = a session cookie was set; tighten with an app-specific
    # authenticated-only marker if false positives show.
    if not len(sess.cookies):
        raise OutOfScope("login set no session cookie — check credentials/fields")
    return sess


def authenticated_crawl(scope, start_url: str, account: dict | None = None,
                        max_pages: int = 50, rate: float = 0.0) -> dict:
    return crawl(start_url, scope, max_pages=max_pages, rate=rate, session=login(scope, account))


if __name__ == "__main__":  # self-check: python -m metsec.auth (in-process login flow)
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from .scope import Scope

    os.environ["T_USER"], os.environ["T_PASS"] = "alice", "s3cret"
    LOGIN = (b'<form action="/login" method="post">'
             b'<input name="csrf" type="hidden" value="tok123">'
             b'<input name="email" type="text">'
             b'<input name="pw" type="password"></form>')

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/login":
                body, code = LOGIN, 200
            elif self.path == "/secret":
                ok = "sid=ok" in self.headers.get("Cookie", "")
                body, code = (b"TOP SECRET" if ok else b"nope"), (200 if ok else 401)
            else:
                body, code = b'<a href="/secret">s</a>', 200
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            ok = "email=alice" in body and "pw=s3cret" in body and "csrf=tok123" in body
            self.send_response(302 if ok else 403)
            if ok:
                self.send_header("Set-Cookie", "sid=ok")
            self.send_header("Location", "/")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    scope = Scope(ips=["127.0.0.1"], authorized_by="test", mode="dev",
                  auth={"login_url": f"{base}/login",
                        "accounts": [{"user_env": "T_USER", "pass_env": "T_PASS"}]})
    sess = login(scope)
    assert sess.get(f"{base}/secret", headers=UA).text == "TOP SECRET"  # authenticated
    out = authenticated_crawl(scope, f"{base}/")
    assert f"{base}/secret" in out["endpoints"], out["endpoints"]
    srv.shutdown()
    print("auth self-check ok")
