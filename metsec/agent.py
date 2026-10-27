"""Phase 3 — the agent loop.

Muse Wonder reasons over real recon + RAG evidence and calls a small DEFENSIVE
toolset to investigate, recording only grounded findings. The model plans and
correlates; the tools do the probing. Mode-gated: static blocks network,
prod is detection-first (safe GET only), dev may send payloads.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import unquote

import requests

from .scope import OutOfScope

UA = {"User-Agent": "Mozilla/5.0 (MetSec agent)"}

# Injection metacharacters that mark an exploitation payload (cmd/XSS/SSTI/SQLi/
# path traversal). Blocked in prod so detection-first is actually enforced — even
# when the payload is baked into the URL rather than passed as param/value.
_PROD_BLOCK = re.compile(r"""[;|&<>`'"$]|\{\{|\.\./|\$\(""")


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
        if self.scope.mode == "prod":
            probe = unquote(url) + " " + (unquote(str(value)) if value is not None else "")
            if method != "GET" or _PROD_BLOCK.search(probe):
                return {"error": "prod mode: detection-first — mutating or injection "
                                 "probes are blocked (use dev mode to exploit)"}
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


TOOLS = [
    {"type": "function", "function": {
        "name": "search_vulns",
        "description": "Known vulnerabilities for a technology and optional version "
                       "(OSV + web research + the local CVE index).",
        "parameters": {"type": "object", "properties": {
            "tech": {"type": "string"}, "version": {"type": "string"}},
            "required": ["tech"]}}},
    {"type": "function", "function": {
        "name": "http_probe",
        "description": "Send ONE HTTP request to an in-scope URL and observe the response "
                       "(status, length, whether `value` is reflected in the body). "
                       "Mode-gated: prod allows only safe GET without payloads.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string"},
            "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"]},
            "param": {"type": "string"}, "value": {"type": "string"}},
            "required": ["url"]}}},
    {"type": "function", "function": {
        "name": "record_finding",
        "description": "Record ONE grounded security finding backed by evidence you gathered.",
        "parameters": {"type": "object", "properties": {
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
            "status": {"type": "string", "enum": ["potential", "verified"]},
            "affected": {"type": "string"}, "evidence": {"type": "string"},
            "remediation": {"type": "string"},
            "refs": {"type": "array", "items": {"type": "string"}}},
            "required": ["title", "severity"]}}},
]

SYSTEM = (
    "You are MetSec, an authorized defensive security agent pentesting the operator's OWN "
    "site (authorization is already verified via scope). Investigate the recon inventory "
    "using the tools: look up vulnerabilities for detected tech+versions, and probe "
    "in-scope URLs to confirm conditions. Record a finding ONLY when backed by concrete "
    "evidence — a version match, a tool result, an exposed path, a reflected payload, or a "
    "missing security header. Mark status 'verified' only if you confirmed it, else "
    "'potential'. Prefer detection over exploitation. Never invent vulnerabilities. "
    "Stop calling tools when the investigation is complete."
)


def _inventory_json(inv: dict) -> dict:
    from dataclasses import asdict, is_dataclass

    out = dict(inv)
    if "techs" in out:
        out["techs"] = [asdict(t) if is_dataclass(t) else t for t in out["techs"]]
    if "crawl" in out:  # trim heavy fields for the prompt
        c = out["crawl"]
        out["crawl"] = {"forms": c.get("forms", [])[:20],
                        "endpoints": c.get("endpoints", [])[:40]}
    return out


def run_agent(agent: Agent, inventory: dict) -> list[Finding]:
    import json

    from . import config

    msgs = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": f"Recon inventory for {agent.target}:\n"
         + json.dumps(inventory, default=str)[:7000]
         + "\n\nInvestigate with the tools and record grounded findings. Stop when done."},
    ]
    for _ in range(agent.budget):
        m = config.client().chat.completions.create(
            model=config.BRAIN, messages=msgs, tools=TOOLS, tool_choice="auto"
        ).choices[0].message
        assistant: dict = {"role": "assistant", "content": m.content or ""}
        if m.tool_calls:
            assistant["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in m.tool_calls]
        msgs.append(assistant)
        if not m.tool_calls:
            break
        for tc in m.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            result = agent.dispatch(tc.function.name, args)
            msgs.append({"role": "tool", "tool_call_id": tc.id,
                         "content": json.dumps(result, default=str)[:2000]})
    return agent.findings


def assess(target: str | None, scope, active: bool = False, budget: int = 16) -> list[Finding]:
    """Full assessment: gather evidence (mode-appropriate) → agent loop → findings."""
    if scope.mode == "static":
        from .static import analyze
        inv = analyze(scope.code_path)
        target = scope.code_path
    else:
        from .recon import recon
        inv = recon(target, scope)
        if active:
            from .active import active_recon
            inv.update(active_recon(target, scope))
    agent = Agent(scope, target or scope.code_path, budget)
    run_agent(agent, _inventory_json(inv))
    return agent.findings


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
    assert "error" in prod.http_probe(f"{base}/x", "POST", "a", "b"), "prod blocks non-GET"
    assert "error" in prod.http_probe(f"{base}/ping?host=1;id"), "prod blocks URL injection"
    assert "error" in prod.http_probe(f"{base}/ping?host=1%3Bid"), "prod blocks encoded injection"
    assert "error" in prod.http_probe(f"{base}/s?q=<script>"), "prod blocks XSS payload"
    assert prod.http_probe(f"{base}/x")["status"] == 200, "prod allows safe GET"
    assert prod.http_probe(f"{base}/profile?id=1")["status"] == 200, "prod allows benign param"
    assert "out of scope" in dev.dispatch("http_probe", {"url": "http://evil.com/"})["error"]

    dev.record_finding("Reflected input", "medium", "verified", evidence="XSSMARK echoed")
    assert len(dev.findings) == 1 and dev.findings[0].status == "verified"
    srv.shutdown()
    print("agent self-check ok")
