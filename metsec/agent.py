"""Phase 3 — the agent loop.

Muse Wonder reasons over real recon + RAG evidence and calls a small DEFENSIVE
toolset to investigate, recording only grounded findings. The model plans and
correlates; the tools do the probing. Mode-gated: static blocks network,
prod is detection-first (safe GET only), dev may send payloads.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import requests

from .scope import OutOfScope

UA = {"User-Agent": "Mozilla/5.0 (MetSec agent)"}


@dataclass
class Finding:
    title: str
    severity: str = "info"       # info | low | medium | high | critical
    status: str = "potential"    # potential | verified
    affected: str = ""
    evidence: str = ""
    remediation: str = ""
    refs: list = field(default_factory=list)


class Agent:
    """Holds scan state and exposes the tools the model may call."""

    def __init__(self, scope, target: str, budget: int = 16):
        self.scope = scope
        self.target = target
        self.budget = budget
        self.session = requests.Session()
        self.findings: list[Finding] = []

    def search_vulns(self, tech: str, version: str = "") -> list[dict]:
        """Known vulns for a tech+version (OSV/web research + the CVE index)."""
        from .research import research

        hits = research(tech, version) if version else []
        try:
            from .rag import CveIndex
            hits += CveIndex().search(f"{tech} {version}".strip(), k=5)
        except Exception:  # noqa: BLE001 — index may be absent; research still works
            pass
        out, seen = [], set()
        for h in hits:
            if h["id"] in seen:
                continue
            seen.add(h["id"])
            out.append({"id": h["id"], "summary": h["summary"][:200],
                        "severity": h.get("severity", "")})
        return out[:12]

    def http_probe(self, url: str, method: str = "GET",
                   param: str | None = None, value: str | None = None) -> dict:
        """Send one request (scope- and mode-gated). Reports status/length/reflection."""
        self.scope.require(url)
        if self.scope.mode == "static":
            return {"error": "static mode: no network probes"}
        method = method.upper()
        payloaded = bool(param and value is not None)
        if self.scope.mode == "prod" and (method != "GET" or payloaded):
            return {"error": "prod mode: only safe GET probes (no payloads) allowed"}
        params = {param: value} if payloaded and method == "GET" else None
        data = {param: value} if payloaded and method != "GET" else None
        try:
            r = self.session.request(method, url, params=params, data=data,
                                     headers=UA, timeout=15, allow_redirects=False)
        except requests.RequestException as e:
            return {"error": str(e)[:120]}
        body = r.text[:2000]
        return {"status": r.status_code, "length": len(r.content),
                "reflected": bool(value and value in body), "snippet": body[:400]}

    def record_finding(self, title: str, severity: str = "info",
                       status: str = "potential", affected: str = "",
                       evidence: str = "", remediation: str = "",
                       refs: list | None = None) -> dict:
        self.findings.append(Finding(title, severity, status, affected,
                                     evidence, remediation, refs or []))
        return {"recorded": True, "count": len(self.findings)}

    def dispatch(self, name: str, args: dict) -> dict:
        fn = {"search_vulns": self.search_vulns, "http_probe": self.http_probe,
              "record_finding": self.record_finding}.get(name)
        if not fn:
            return {"error": f"unknown tool {name}"}
        try:
            return fn(**args)
        except OutOfScope as e:
            return {"error": f"out of scope: {e}"}
        except TypeError as e:
            return {"error": f"bad args: {e}"}


if __name__ == "__main__":  # self-check: python -m metsec.agent (tool gating, offline)
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from .scope import Scope

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"echo:" + self.path.encode())

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"

    dev = Agent(Scope(ips=["127.0.0.1"], authorized_by="t", mode="dev"), base)
    r = dev.http_probe(f"{base}/search", "GET", "q", "XSSMARK")
    assert r["status"] == 200 and r["reflected"], r  # payload reflected back

    prod = Agent(Scope(ips=["127.0.0.1"], authorized_by="t", mode="prod"), base)
    assert "error" in prod.http_probe(f"{base}/x", "POST", "a", "b"), "prod must block payloads"
    assert prod.http_probe(f"{base}/x")["status"] == 200, "prod allows safe GET"
    assert "out of scope" in dev.dispatch("http_probe", {"url": "http://evil.com/"})["error"]

    dev.record_finding("Reflected input", "medium", "verified", evidence="XSSMARK echoed")
    assert len(dev.findings) == 1 and dev.findings[0].status == "verified"
    srv.shutdown()
    print("agent self-check ok")
