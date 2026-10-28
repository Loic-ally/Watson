"""Phase 3 — the agent loop.

Muse Wonder reasons over real recon + RAG evidence and calls a small DEFENSIVE
toolset to investigate, recording only grounded findings. The model plans and
correlates; the tools do the probing. Mode-gated: static blocks network,
prod is detection-first (safe GET only), dev may send payloads.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from urllib.parse import unquote

import requests

from . import events
from .scope import OutOfScope

UA = {"User-Agent": "Mozilla/5.0 (MetSec agent)"}

# Injection metacharacters that mark an exploitation payload (cmd/XSS/SSTI/SQLi/
# path traversal). Blocked in prod so detection-first is actually enforced — even
# when the payload is baked into the URL rather than passed as param/value.
_PROD_BLOCK = re.compile(r"""[;|&<>`'"$]|\{\{|\.\./|\$\(""")

# Commands refused even in exploit mode — box-destroyers, not pentest actions.
# Guards against the model accidentally wrecking the (often the operator's own) host.
_CATASTROPHIC = re.compile(
    r"\brm\s+-[rf]*\s+(/|~|\*)|\bmkfs\b|\bdd\b.*\bof=/dev/|>\s*/dev/sd|\bwipefs\b|"
    r"\bshutdown\b|\breboot\b|\bhalt\b|\bpoweroff\b|:\(\)\s*\{\s*:\|:", re.I)


@dataclass
class Finding:
    title: str
    severity: str = "info"       # info | low | medium | high | critical
    status: str = "potential"    # potential | verified
    affected: str = ""           # WHERE the flaw is (endpoint/param/file:line)
    evidence: str = ""
    remediation: str = ""
    refs: list = field(default_factory=list)
    exploitation: str = ""       # HOW it is exploited (technique + steps)


@dataclass
class Hypothesis:
    """A reasoned link between observations → a possible attack path."""
    statement: str
    based_on: list = field(default_factory=list)
    test: str = ""
    status: str = "untested"     # untested | confirmed | refuted


class Agent:
    """Holds scan state and exposes the tools the model may call."""

    def __init__(self, scope, target: str, budget: int = 16, exploit: bool = False):
        self.scope = scope
        self.target = target
        self.budget = budget
        self.exploit = exploit  # authorized aggressive exploitation (lifts prod gate)
        self.session = requests.Session()
        self.findings: list[Finding] = []
        self.hypotheses: list[Hypothesis] = []
        self.channel = None  # exec foothold once established

    def search_vulns(self, tech: str, version: str = "") -> list[dict]:
        """Known vulns for a tech+version (OSV/web research + the CVE index)."""
        from .research import research

        hits = research(tech, version) if version else []
        try:
            from .rag import CveIndex
            hits += CveIndex().search(f"{tech} {version}".strip(), k=5)
        except Exception:  # noqa: BLE001 — index may be absent; research still works
            pass
        from .exploitdb import exploits_for

        out, seen = [], set()
        for h in hits:
            if h["id"] in seen:
                continue
            seen.add(h["id"])
            item = {"id": h["id"], "summary": h["summary"][:200],
                    "severity": h.get("severity", "")}
            ex = exploits_for(h["id"])  # public exploit available? (big prioritization signal)
            if ex:
                item["public_exploits"] = [{"id": e["id"], "url": e["url"],
                                            "metasploit": e["metasploit"]} for e in ex[:3]]
            out.append(item)
        return out[:12]

    def http_probe(self, url: str, method: str = "GET", param: str | None = None,
                   value: str | None = None, cookie: str | None = None) -> dict:
        """Send one request (scope- and mode-gated). Reports status/length/reflection.

        `cookie` sets a raw Cookie header (e.g. to test forged sessions). In prod,
        injection payloads are blocked unless exploitation is enabled.
        """
        self.scope.require(url)
        if self.scope.mode == "static":
            return {"error": "static mode: no network probes"}
        method = method.upper()
        payloaded = bool(param and value is not None)
        if self.scope.mode == "prod" and not self.exploit:
            probe = unquote(url) + " " + (unquote(str(value)) if value is not None else "")
            if method != "GET" or _PROD_BLOCK.search(probe):
                return {"error": "prod mode: detection-first — mutating or injection probes "
                                 "are blocked (enable exploitation or use dev mode)"}
        params = {param: value} if payloaded and method == "GET" else None
        data = {param: value} if payloaded and method != "GET" else None
        headers = {**UA, "Cookie": cookie} if cookie else UA
        try:
            r = self.session.request(method, url, params=params, data=data,
                                     headers=headers, timeout=15, allow_redirects=False)
        except requests.RequestException as e:
            return {"error": str(e)[:120]}
        body = r.text[:2000]
        return {"status": r.status_code, "length": len(r.content),
                "reflected": bool(value and value in body), "snippet": body[:400]}

    def record_finding(self, title: str, severity: str = "info",
                       status: str = "potential", affected: str = "",
                       evidence: str = "", remediation: str = "",
                       refs: list | None = None, exploitation: str = "") -> dict:
        self.findings.append(Finding(title, severity, status, affected, evidence,
                                     remediation, refs or [], exploitation))
        events.emit("finding", severity=severity, status=status, title=title[:120])
        return {"recorded": True, "count": len(self.findings)}

    def establish_foothold(self, url: str, param: str, kind: str = "auto",
                           base: str = "127.0.0.1") -> dict:
        """Turn a confirmed web RCE (cmd injection / SSTI) into command execution."""
        if not self.exploit:
            return {"error": "foothold requires exploitation to be enabled (--exploit)"}
        self.scope.require(url)
        if self.scope.mode == "static":
            return {"error": "static mode: no network"}
        from .exec_channel import establish
        ch, proof = establish(self.session, url, param, kind, base)
        if not ch:
            return {"error": "no working exec vector at this url/param"}
        self.channel = ch
        events.emit("foothold", kind=ch.kind, whoami=proof[:120])
        return {"foothold": ch.kind, "url": url, "param": param, "whoami": proof[:300]}

    def run_command(self, command: str) -> dict:
        """Run a shell command through the established foothold (enumeration/privesc)."""
        if not self.exploit:
            return {"error": "run_command requires exploitation to be enabled (--exploit)"}
        if self.channel is None:
            return {"error": "no foothold — call establish_foothold first"}
        if _CATASTROPHIC.search(command):
            return {"error": "refused: destructive command blocked"}
        out = self.channel.run(command)[:3000]
        events.emit("command", cmd=command[:160], output=out[:400])
        if "uid=0(root)" in out:
            events.emit("root")
        return {"output": out}

    def privesc_scan(self) -> dict:
        """Enumerate the host and return GTFOBins-matched privilege-escalation candidates."""
        if not self.exploit:
            return {"error": "requires exploitation to be enabled (--exploit)"}
        if self.channel is None:
            return {"error": "no foothold — call establish_foothold first"}
        from .privesc import candidates, enumerate_host
        profile = enumerate_host(self.channel.run)
        return {"id": profile.get("id", "")[:200], "uname": profile.get("uname", "")[:150],
                "sudo": profile.get("sudo", "")[:500],
                "suid_sample": "\n".join(profile.get("suid", "").splitlines()[:15]),
                "privesc_candidates": candidates(profile)[:12]}

    def loot(self) -> dict:
        """Capture credentials, keys, and proof files through the foothold."""
        if not self.exploit:
            return {"error": "requires exploitation to be enabled (--exploit)"}
        if self.channel is None:
            return {"error": "no foothold — call establish_foothold first"}
        from .privesc import loot as _loot
        return _loot(self.channel.run) or {"info": "no readable secrets as current user"}

    def browse(self, url: str,
               question: str = "Identify login forms, inputs, notable features, and the tech stack.") -> dict:
        """Load the page in a real browser and SEE it (screenshot + vision) — catches JS-rendered
        forms/features static recon misses."""
        if self.scope.mode == "static":
            return {"error": "static mode: no browser"}
        self.scope.require(url)
        try:
            from .browser import snapshot, vision_analyze
            snap = snapshot(url)
        except ImportError:
            return {"error": "browser needs: pip install playwright && playwright install chromium"}
        except Exception as e:  # noqa: BLE001 — navigation can fail many ways
            return {"error": f"browser: {str(e)[:140]}"}
        vision = vision_analyze(snap["png"], f"You are a pentester viewing {url}. {question}")
        return {"title": snap["title"], "vision": vision[:1500],
                "links": snap["links"][:40], "forms": snap["forms"][:10]}

    def hypothesize(self, statement: str, based_on: list | None = None,
                    test: str = "", status: str = "untested") -> dict:
        """Record a link between observations → a possible attack path, and how to test it."""
        self.hypotheses.append(Hypothesis(statement, based_on or [], test, status))
        events.emit("hypothesis", statement=statement[:160], status=status)
        return {"recorded": True, "hypotheses": len(self.hypotheses)}

    def dispatch(self, name: str, args: dict) -> dict:
        fn = {"search_vulns": self.search_vulns, "http_probe": self.http_probe,
              "record_finding": self.record_finding,
              "establish_foothold": self.establish_foothold,
              "run_command": self.run_command, "privesc_scan": self.privesc_scan,
              "loot": self.loot, "hypothesize": self.hypothesize,
              "browse": self.browse}.get(name)
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
            "param": {"type": "string"}, "value": {"type": "string"},
            "cookie": {"type": "string", "description": "raw Cookie header, e.g. to test a forged session"}},
            "required": ["url"]}}},
    {"type": "function", "function": {
        "name": "record_finding",
        "description": "Record ONE grounded security finding backed by evidence you gathered.",
        "parameters": {"type": "object", "properties": {
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
            "status": {"type": "string", "enum": ["potential", "verified"]},
            "affected": {"type": "string", "description": "WHERE: endpoint/param/file:line"},
            "evidence": {"type": "string"},
            "exploitation": {"type": "string",
                             "description": "HOW it is exploited: the technique and concrete steps"},
            "remediation": {"type": "string"},
            "refs": {"type": "array", "items": {"type": "string"}}},
            "required": ["title", "severity"]}}},
    {"type": "function", "function": {
        "name": "establish_foothold",
        "description": "After confirming a web RCE (command injection or SSTI), turn it into "
                       "command execution on the host. Give the vulnerable url and parameter; "
                       "returns the foothold type and id/whoami. Requires exploitation enabled.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string"}, "param": {"type": "string"},
            "kind": {"type": "string", "enum": ["auto", "cmd-injection", "ssti", "webshell"]},
            "base": {"type": "string", "description": "benign base value, e.g. 127.0.0.1"}},
            "required": ["url", "param"]}}},
    {"type": "function", "function": {
        "name": "run_command",
        "description": "Run ONE shell command on the target through the established foothold "
                       "(host enumeration and privilege escalation). Destructive commands are "
                       "refused.",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}},
                       "required": ["command"]}}},
    {"type": "function", "function": {
        "name": "privesc_scan",
        "description": "Enumerate the compromised host (sudo rights, SUID, capabilities, cron, "
                       "secrets) and return GTFOBins-matched privilege-escalation candidates. "
                       "Then confirm a candidate with run_command and check for uid=0.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "browse",
        "description": "Load a URL in a real headless Chromium and SEE it: returns a vision "
                       "analysis of the screenshot plus rendered links and forms. Use for recon, "
                       "especially JS-heavy pages where static fetch misses forms/features.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string"},
            "question": {"type": "string", "description": "what to look for on the page"}},
            "required": ["url"]}}},
    {"type": "function", "function": {
        "name": "hypothesize",
        "description": "Record a hypothesis that LINKS findings/observations into a possible "
                       "attack path (credential reuse across services, an exposed config that "
                       "unlocks auth, a version with a known exploit chain, one vuln that lets "
                       "you reach another). Say what would confirm or refute it, then test it.",
        "parameters": {"type": "object", "properties": {
            "statement": {"type": "string", "description": "the link between observations"},
            "based_on": {"type": "array", "items": {"type": "string"},
                         "description": "the findings/facts it connects"},
            "test": {"type": "string", "description": "what action confirms or refutes it"},
            "status": {"type": "string", "enum": ["untested", "confirmed", "refuted"]}},
            "required": ["statement"]}}},
    {"type": "function", "function": {
        "name": "loot",
        "description": "Capture readable credentials, SSH keys, .env secrets, and proof files "
                       "(root.txt/user.txt) through the foothold. Call after foothold and again "
                       "after escalating to root. Record notable captures as findings.",
        "parameters": {"type": "object", "properties": {}}}},
]

SYSTEM = (
    "You are MetSec, an authorized security agent pentesting the operator's OWN site "
    "(authorization is already verified via scope). Investigate the recon inventory using "
    "the tools: look up vulnerabilities for detected tech+versions, and probe in-scope URLs "
    "to confirm conditions. For recon you can call browse(url) to load a page in a real "
    "browser and SEE it (screenshot + vision), catching forms/features static recon misses. "
    "Record a finding ONLY when backed by concrete evidence — a "
    "version match, a tool result, an exposed path, a reflected payload, or a missing "
    "security header. Call record_finding IMMEDIATELY each time you confirm an issue — do "
    "not batch recording for the end. For every finding fill `affected` (WHERE: the exact "
    "endpoint/param/file:line), `exploitation` (HOW it is exploited: the technique and the "
    "concrete steps/payload you used), `evidence`, and `remediation` (the fix). Actively "
    "connect the dots: when two observations might relate, call hypothesize to record the link "
    "and what would test it, then test it. Never invent vulnerabilities. Stop when done."
)
DETECTION_NOTE = (" Prefer detection over exploitation. Mark a finding 'verified' only when a "
                  "probe confirmed it, otherwise 'potential'.")
EXPLOIT_NOTE = (" EXPLOITATION IS AUTHORIZED AND ENABLED. Actively try to break the target: "
                "send injection payloads (SQLi, XSS, SSTI, command injection), test IDOR by "
                "enumerating ids, forge/replay session cookies, and chain requests to prove "
                "impact. Report 'verified' ONLY for issues you concretely exploited or "
                "confirmed; DROP anything you could not confirm rather than reporting it as "
                "potential — do not pad the report with speculation. When you confirm a remote "
                "code execution vuln, call establish_foothold to get command execution, then "
                "run_command to enumerate the host. Then call privesc_scan to get GTFOBins-"
                "matched escalation candidates, pick one, run it with run_command, and confirm "
                "root with `id` (uid=0). Reason beyond the candidates — kernel/cron/writable-path "
                "escalation won't always be listed. Keep going until you are root or out of leads. "
                "After the foothold, and again once root, call loot to capture credentials, keys, "
                "and proof files (root.txt/user.txt) and record notable captures as findings.")


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

    def turn(msgs: list) -> bool:
        """One model turn. Returns True if it called tools (should continue)."""
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
            return False
        for tc in m.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            hint = (args.get("title") or args.get("command") or args.get("url")
                    or args.get("tech") or "")
            print(f"  → {tc.function.name} {str(hint)[:72]}", file=sys.stderr, flush=True)
            events.emit("tool", name=tc.function.name, detail=str(hint)[:100])
            msgs.append({"role": "tool", "tool_call_id": tc.id,
                         "content": json.dumps(agent.dispatch(tc.function.name, args),
                                               default=str)[:2000]})
        return True

    msgs = [
        {"role": "system", "content": SYSTEM + (EXPLOIT_NOTE if agent.exploit else DETECTION_NOTE)},
        {"role": "user", "content": f"Recon inventory for {agent.target}:\n"
         + json.dumps(inventory, default=str)[:7000]
         + "\n\nInvestigate with the tools and record grounded findings. Stop when done."},
    ]
    exhausted = all(turn(msgs) for _ in range(agent.budget))
    if exhausted:  # hit budget mid-investigation — force a wrap-up so findings aren't lost
        msgs.append({"role": "user", "content": "Probing budget reached. Call record_finding "
                     "now for every vulnerability you confirmed or have concrete evidence for, "
                     "then stop."})
        for _ in range(3):
            if not turn(msgs):
                break
    return agent.findings


def assess(target: str | None, scope, active: bool = False, budget: int = 16,
           exploit: bool = False, fresh: bool = False) -> "Agent":
    """Full assessment: gather evidence → agent loop. Returns the Agent (.findings/.hypotheses)."""
    from . import cache

    target = target or scope.code_path
    ckey = (target, scope.mode, active)
    inv = None if fresh else cache.get(ckey)
    if inv is None:
        if scope.mode == "static":
            from .static import analyze
            raw = analyze(scope.code_path)
        else:
            from .recon import recon
            raw = recon(target, scope)
            if active:
                from .active import active_recon
                raw.update(active_recon(target, scope))
        inv = _inventory_json(raw)
        cache.put(inv, ckey)
    agent = Agent(scope, target, budget, exploit=exploit)
    run_agent(agent, inv)
    return agent


if __name__ == "__main__":  # self-check: python -m metsec.agent (tool gating, offline)
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from .scope import Scope

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"echo:" + self.path.encode()
                             + b" cookie:" + self.headers.get("Cookie", "").encode())

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

    exp = Agent(Scope(ips=["127.0.0.1"], authorized_by="t", mode="prod"), base, exploit=True)
    assert exp.http_probe(f"{base}/ping?host=1;id")["status"] == 200, "exploit lifts prod gate"
    r = dev.http_probe(f"{base}/p", cookie="session=forged")
    assert "session=forged" in r["snippet"], "cookie sent"

    # foothold tools: gated by exploit, need a channel, destructive commands refused
    assert "requires exploitation" in dev.run_command("id")["error"]
    assert "no foothold" in exp.run_command("id")["error"]
    assert "requires exploitation" in dev.privesc_scan()["error"]
    assert "no foothold" in exp.privesc_scan()["error"]
    assert "requires exploitation" in dev.loot()["error"]
    assert "no foothold" in exp.loot()["error"]

    class _Dummy:
        kind = "test"

        def run(self, c):
            return "ran:" + c

    exp.channel = _Dummy()
    assert exp.run_command("sudo -l")["output"] == "ran:sudo -l"
    assert "destructive" in exp.run_command("rm -rf /")["error"]
    assert "destructive" in exp.run_command("mkfs.ext4 /dev/sda1")["error"]

    dev.record_finding("Reflected input", "medium", "verified", evidence="XSSMARK echoed",
                       exploitation="GET /search?q=<payload>, reflected unescaped")
    assert len(dev.findings) == 1 and dev.findings[0].status == "verified"
    assert dev.findings[0].exploitation.startswith("GET /search")

    dev.hypothesize("looted creds may unlock admin", ["f1", "f2"], "replay creds", "confirmed")
    assert len(dev.hypotheses) == 1 and dev.hypotheses[0].status == "confirmed"
    assert dev.hypotheses[0].based_on == ["f1", "f2"]

    stat = Agent(Scope(code_path=".", authorized_by="t", mode="static"), "x")
    assert "static mode" in stat.browse("http://127.0.0.1/")["error"]  # no browser in static
    srv.shutdown()
    print("agent self-check ok")
