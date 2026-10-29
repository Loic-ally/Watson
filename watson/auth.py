"""Authenticated scanning — log in a test account and reuse the session.

Credentials come from .env via the env-var names in scope.auth (never stored in
the scope file). The login form is discovered so field names + CSRF/hidden
inputs are preserved. Enables testing the authenticated surface (IDOR, access
control) in later phases.
"""
from __future__ import annotations

import os
import re
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
    """Log in a test account from scope.auth → authenticated requests.Session.

    Dispatches on scope.auth['type']:
      'form'   (default) — HTML form POST + cookie session (static recon, no JS);
      'token'/'bearer'/'supabase'/'jwt' — JSON login → JWT sent as Authorization: Bearer;
      'browser' — drive the REAL login form in Playwright with the creds from .env, capture
                  the full storage_state (cookies + localStorage), and reuse it everywhere.
                  The universal path for any SPA — no need to reverse-engineer its auth API,
                  and the password is typed by this code, never placed in the model's context.
    """
    kind = (scope.auth or {}).get("type", "form").lower()
    if kind == "browser":
        return login_browser(scope, account)
    if kind in ("token", "bearer", "supabase", "jwt"):
        return login_token(scope, account)
    return login_form(scope, account)


def _token_url(auth: dict) -> str | None:
    if auth.get("token_url"):
        return auth["token_url"]
    if auth.get("supabase_url"):   # shorthand: derive the GoTrue password-grant endpoint
        return auth["supabase_url"].rstrip("/") + "/auth/v1/token?grant_type=password"
    return None


def _apikey(auth: dict) -> str:
    return (os.environ.get(auth["apikey_env"], "") if auth.get("apikey_env")
            else auth.get("apikey", ""))


def login_token(scope, account: dict | None = None) -> requests.Session:
    """JSON credential login → bearer-token session (Supabase GoTrue and similar).

    Posts {email, password} to the token endpoint (with the public apikey header when given),
    reads the access token, and returns a Session that sends `Authorization: Bearer <jwt>`
    (+ apikey) on every subsequent request — so the agent's probes are authenticated."""
    import json as _json

    auth = scope.auth or {}
    accounts = auth.get("accounts") or []
    token_url = _token_url(auth)
    if not accounts or not token_url:
        raise OutOfScope("token auth needs token_url (or supabase_url) and at least one account")
    scope.require(token_url)   # the token endpoint must itself be in scope
    acct = account or accounts[0]
    user, pw = _cred(acct["user_env"]), _cred(acct["pass_env"])
    apikey = _apikey(auth)

    sess = requests.Session()
    headers = {**UA, "Content-Type": "application/json"}
    if apikey:
        headers["apikey"] = apikey
    body = {auth.get("user_field", "email"): user, auth.get("pass_field", "password"): pw}
    try:
        r = sess.post(token_url, data=_json.dumps(body), headers=headers, timeout=20)
    except requests.RequestException as e:
        raise OutOfScope(f"token login request failed: {str(e)[:120]}") from e
    if r.status_code != 200:
        raise OutOfScope(f"token login rejected ({r.status_code}) — check credentials/apikey")
    try:
        data = r.json()
    except ValueError as e:
        raise OutOfScope("token login response was not JSON") from e
    token = (data.get(auth.get("token_field", "access_token"))
             or data.get("token") or data.get("jwt") or data.get("id_token"))
    if not token:
        raise OutOfScope("no access token in the login response")
    sess.headers.update({"Authorization": f"Bearer {token}"})   # rides every request
    if apikey:
        sess.headers["apikey"] = apikey
    # Also expose the session for the VISION browser: Supabase-js keeps the session in
    # localStorage under sb-<ref>-auth-token, so injecting it makes headless Chromium render
    # the authenticated app (http_probe already carries the bearer header).
    from urllib.parse import urlparse as _up
    ref = (_up(token_url).hostname or "").split(".")[0]
    if ref:
        sess.browser_storage = [{"name": f"sb-{ref}-auth-token", "value": _json.dumps(data)}]
    return sess


# default selectors for the real login form (overridable via scope.auth)
_USER_SEL = ("input[type=email], input[name=email], input[name=username], input[name=user], "
             "input[type=text]")
_PASS_SEL = "input[type=password]"
_SUBMIT_SELS = ("button[type=submit]", "input[type=submit]")
_AUTH_COOKIE = re.compile(r"sess|auth|sb-|token|jwt|\bsid\b|csrf", re.I)


def login_browser(scope, account: dict | None = None) -> requests.Session:
    """Drive the REAL login form in Playwright with creds from .env, then reuse the session.

    Types the credentials into the live form (this code types them — they never enter the
    model's context), submits, captures the full storage_state (cookies + localStorage), and
    returns a requests.Session carrying the cookies (plus a bearer lifted from localStorage
    when present) with .browser_storage set so the vision browser renders the logged-in app.
    Works for any SPA without knowing its auth API. Selectors/success checks are overridable
    via scope.auth: user_selector, pass_selector, submit_selector, success_url."""
    import json as _json

    auth = scope.auth or {}
    accounts = auth.get("accounts") or []
    login_url = auth.get("login_url")
    if not accounts or not login_url:
        raise OutOfScope("browser auth needs login_url and at least one account")
    if scope.mode == "static":
        raise OutOfScope("browser login needs network/JS — not available in static mode")
    scope.require(login_url)
    acct = account or accounts[0]
    user, pw = _cred(acct["user_env"]), _cred(acct["pass_env"])
    user_sel = auth.get("user_selector") or _USER_SEL
    pass_sel = auth.get("pass_selector") or _PASS_SEL
    submit_sel = auth.get("submit_selector")
    success_url = auth.get("success_url")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError as e:
        raise OutOfScope("browser login needs: pip install playwright && playwright install "
                         "chromium") from e

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        try:
            ctx = browser.new_context()
            page = ctx.new_page()
            auth_calls: list[int] = []   # statuses of login/token API calls, for diagnostics
            page.on("response", lambda r: auth_calls.append(r.status)
                    if re.search(r"/auth/v1/token|/login|/signin|/session", r.url, re.I)
                    and r.request.method == "POST" else None)
            page.goto(login_url, timeout=25000, wait_until="domcontentloaded")
            # wait for the SPA to hydrate: the password field must be present AND React must
            # have attached its handlers, else a submit before hydration is a silent no-op
            try:
                page.wait_for_selector(pass_sel, state="visible", timeout=15000)
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:  # noqa: BLE001 — best-effort; fills below still auto-wait
                pass
            try:
                # type into the fields (triggers React onChange reliably), not just set .value
                page.fill(user_sel, "", timeout=10000)
                page.type(user_sel, user, delay=15)
                page.fill(pass_sel, "", timeout=10000)
                page.type(pass_sel, pw, delay=15)
            except Exception as e:  # noqa: BLE001 — form not where we expect
                raise OutOfScope(f"could not fill the login form ({str(e)[:80]}) — set "
                                 "user_selector/pass_selector in scope.auth") from e
            page.wait_for_timeout(300)   # let React commit the input state before submit
            if submit_sel:
                page.click(submit_sel, timeout=10000)
            else:
                if not any(_try_click(page, s) for s in _SUBMIT_SELS):
                    page.press(pass_sel, "Enter")   # fall back to submitting via Enter
            # wait for the login to actually complete: the URL leaves the login page
            try:
                page.wait_for_url(lambda u: not re.search(r"log[_-]?in|sign[_-]?in", u, re.I),
                                  timeout=12000)
            except Exception:  # noqa: BLE001 — SPA may stay on the same URL; fall through
                pass
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:  # noqa: BLE001 — networkidle best-effort
                pass
            page.wait_for_timeout(1000)   # let a client-side login settle its storage
            state = ctx.storage_state()
            final_url = page.url
            statuses = list(auth_calls)
        finally:
            browser.close()

    cookies = state.get("cookies", [])
    ls = [{"name": i["name"], "value": i["value"]}
          for o in state.get("origins", []) for i in o.get("localStorage", [])]
    moved = final_url.rstrip("/") != login_url.rstrip("/") and not re.search(
        r"log[_-]?in|sign[_-]?in", final_url, re.I)
    token_ls = any(("access_token" in i["value"] or _AUTH_COOKIE.search(i["name"])) for i in ls)
    auth_cookie = any(_AUTH_COOKIE.search(c.get("name", "")) for c in cookies)
    ok = bool((success_url and success_url in final_url) or moved or token_ls or auth_cookie)
    if not ok:
        why = ""
        if 429 in statuses:
            why = " — the auth API returned 429 (rate-limited); wait a few minutes and retry"
        elif any(400 <= s < 500 for s in statuses):
            why = f" — the auth API rejected the login (HTTP {statuses}); check the credentials"
        elif not statuses:
            why = " — no login API call was observed; the form selectors may be wrong"
        raise OutOfScope("browser login did not appear to succeed (still on the login page, no "
                         "session cookie/token)" + why + ". Override user_selector/pass_selector/"
                         "submit_selector/success_url in scope.auth if the form was missed.")

    sess = requests.Session()
    for c in cookies:   # same-origin app routes are now authenticated via these cookies
        try:
            sess.cookies.set(c["name"], c["value"], domain=c.get("domain"),
                             path=c.get("path", "/"))
        except Exception:  # noqa: BLE001 — skip a cookie requests can't represent
            pass
    # Lift a bearer out of the captured session (cookie or localStorage) so CROSS-ORIGIN API
    # probes (e.g. Supabase REST) are authenticated too — same-domain cookies don't reach them.
    if (tok := _extract_bearer(cookies, ls)):
        sess.headers["Authorization"] = f"Bearer {tok}"
    if (apikey := _apikey(auth)):
        sess.headers["apikey"] = apikey
    sess.browser_storage = ls      # legacy localStorage-only seed
    sess.browser_state = state     # full state (cookies+localStorage) → authenticated vision browser
    return sess


def _try_click(page, selector: str) -> bool:
    try:
        page.click(selector, timeout=3000)
        return True
    except Exception:  # noqa: BLE001
        return False


def _extract_bearer(cookies: list, localstorage: list) -> str | None:
    """Find an access_token in a captured session. Handles Supabase's cookie/localStorage
    formats, incl. the @supabase/ssr `base64-<b64 json>` value and chunked/array shapes.
    Secrets are returned for in-process use only — never logged or printed."""
    import base64
    import json

    raws = [c.get("value", "") for c in cookies
            if "auth-token" in c.get("name", "") or c.get("name", "").startswith("sb-")]
    raws += [c.get("value", "") for c in cookies if c.get("value", "") not in raws]
    raws += [i.get("value", "") for i in localstorage]
    for raw in raws:
        if not isinstance(raw, str) or not raw:
            continue
        val = raw
        if val.startswith("base64-"):
            for dec in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    val = dec(val[7:] + "===").decode("utf-8", "ignore")
                    break
                except Exception:  # noqa: BLE001
                    continue
        try:
            data = json.loads(val)
        except (ValueError, TypeError):
            continue
        if isinstance(data, list) and data:          # chunked/array session
            data = data[0] if isinstance(data[0], dict) else {}
        if isinstance(data, dict):
            tok = data.get("access_token") or (data.get("currentSession") or {}).get("access_token")
            if tok:
                return tok
    return None


def login_form(scope, account: dict | None = None) -> requests.Session:
    """Log in a test account via an HTML form → cookie-session requests.Session."""
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


if __name__ == "__main__":  # self-check: python -m watson.auth (in-process login flow)
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

    # --- token/bearer login (Supabase-style): JSON creds → JWT → Authorization: Bearer ---
    import json as _json

    os.environ["TK_USER"], os.environ["TK_PASS"] = "bob@example.com", "pw"

    class TH(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = _json.loads(self.rfile.read(n).decode() or "{}")
            ok = (self.path.startswith("/auth/v1/token")
                  and body.get("email") == "bob@example.com" and body.get("password") == "pw"
                  and self.headers.get("apikey") == "anon-key-123")
            self.send_response(200 if ok else 400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(_json.dumps({"access_token": "good-jwt"} if ok
                                         else {"error": "bad"}).encode())

        def do_GET(self):  # a protected API resource: needs the bearer token
            bearer = self.headers.get("Authorization") == "Bearer good-jwt"
            self.send_response(200 if bearer else 401)
            self.end_headers()
            self.wfile.write(b"PRIVATE ROWS" if bearer else b"no")

        def log_message(self, *a):
            pass

    tsrv = HTTPServer(("127.0.0.1", 0), TH)
    tport = tsrv.server_address[1]
    threading.Thread(target=tsrv.serve_forever, daemon=True).start()
    tbase = f"http://127.0.0.1:{tport}"
    tscope = Scope(ips=["127.0.0.1"], authorized_by="test", mode="dev",
                   auth={"type": "supabase", "supabase_url": tbase, "apikey": "anon-key-123",
                         "accounts": [{"user_env": "TK_USER", "pass_env": "TK_PASS"}]})
    tsess = login(tscope)
    assert tsess.headers.get("Authorization") == "Bearer good-jwt"
    assert tsess.headers.get("apikey") == "anon-key-123"
    assert tsess.get(f"{tbase}/rest/v1/notes").text == "PRIVATE ROWS"  # bearer rides the request
    # wrong apikey / creds are rejected, not silently accepted
    bad = Scope(ips=["127.0.0.1"], authorized_by="t", mode="dev",
                auth={"type": "supabase", "supabase_url": tbase, "apikey": "WRONG",
                      "accounts": [{"user_env": "TK_USER", "pass_env": "TK_PASS"}]})
    try:
        login(bad)
        raise AssertionError("bad apikey should be rejected")
    except OutOfScope:
        pass
    tsrv.shutdown()

    # --- browser login: drive the real form in Playwright, reuse cookies in requests ---
    os.environ["BU"], os.environ["BP"] = "carol@example.com", "pw9"
    LOGINPAGE = (b'<html><body><form method="post" action="/login">'
                 b'<input type="email" name="email"><input type="password" name="pw">'
                 b'<button type="submit">Log in</button></form></body></html>')

    class BH(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/app":
                ok = "sid=ok" in self.headers.get("Cookie", "")
                body, code = (b"DASHBOARD" if ok else b"login required"), (200 if ok else 302)
            else:
                body, code = LOGINPAGE, 200
            self.send_response(code)
            if code == 302:
                self.send_header("Location", "/login")
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n).decode()
            ok = "email=carol%40example.com" in body and "pw=pw9" in body
            self.send_response(302)
            if ok:
                self.send_header("Set-Cookie", "sid=ok; Path=/")
            self.send_header("Location", "/app" if ok else "/login")
            self.end_headers()

        def log_message(self, *a):
            pass

    try:
        from playwright.sync_api import sync_playwright as _sp  # noqa: F401
        _have_pw = True
    except ImportError:
        _have_pw = False
    if _have_pw:
        bsrv = HTTPServer(("127.0.0.1", 0), BH)
        bport = bsrv.server_address[1]
        threading.Thread(target=bsrv.serve_forever, daemon=True).start()
        bbase = f"http://127.0.0.1:{bport}"
        bscope = Scope(ips=["127.0.0.1"], authorized_by="test", mode="dev",
                       auth={"type": "browser", "login_url": f"{bbase}/login",
                             "accounts": [{"user_env": "BU", "pass_env": "BP"}]})
        bsess = login_browser(bscope)
        # the cookie captured in Chromium now rides the requests session
        assert bsess.get(f"{bbase}/app").text == "DASHBOARD", "browser-login cookie not reused"
        bsrv.shutdown()
        print("  browser-login path ok")
    else:
        print("  browser-login path skipped (playwright not installed)")

    print("auth self-check ok")
