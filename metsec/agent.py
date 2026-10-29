"""Phase 3 — the agent loop.

The reasoning model (Muse Spark) reasons over real recon + RAG evidence and calls
a small DEFENSIVE toolset to investigate, recording only grounded findings. It plans and
correlates; the tools do the probing. Mode-gated: static blocks network,
prod is detection-first (safe GET only), dev may send payloads.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from urllib.parse import unquote

import requests

from . import audit, events, redact
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


# Finding status — a small state machine, enforced in record_finding():
#   potential : reported, not yet backed by a collected observation (default)
#   verified  : backed by a real Observation the agent itself collected (not model text)
#   refuted   : a test showed the condition does NOT hold
# (a *hypothesis* — an unproven idea — is a separate object, Hypothesis.)
FINDING_STATUSES = ("potential", "verified", "refuted")
# Confidence in the EVIDENCE, kept separate from qualitative severity and from CVSS.
STATUS_CONFIDENCE = {"verified": "confirmed", "potential": "unconfirmed",
                     "refuted": "refuted"}


# Tools whose successful result is real, target-touching evidence (→ an Observation the
# agent can cite to verify a finding). Knowledge/planning tools (search_vulns, hypothesize,
# make_payload, get_evidence) are NOT evidence of a condition on the target.
EVIDENCE_TOOLS = {"http_probe", "run_command", "establish_foothold", "upload_shell",
                  "privesc_scan", "pivot_scan", "loot", "browse", "browser_action"}

_CVSS_VECTOR = re.compile(r"^CVSS:(2\.0|3\.0|3\.1|4\.0)/", re.I)


def _clean_cvss(c: dict | None) -> dict:
    """Keep a CVSS only when it is authentic: a version, a provenance, and (when a score
    is given) a valid vector. Otherwise drop it — never fabricate a number. Returns {} for
    'not available' (reports render that as null / n/a, never an implicit 0)."""
    if not isinstance(c, dict) or not c:
        return {}
    vector = str(c.get("vector", "") or "")
    version = str(c.get("version", "") or "")
    prov = str(c.get("provenance", "") or c.get("source", "") or "")
    if vector and _CVSS_VECTOR.match(vector):
        version = version or vector.split("/", 1)[0].split(":", 1)[1]
    elif vector:
        return {}  # a vector was claimed but it is malformed → reject the whole score
    score = c.get("base_score", c.get("score"))
    try:
        score = round(float(score), 1) if score is not None and score != "" else None
    except (TypeError, ValueError):
        score = None
    if not version or not prov or (score is None and not vector):
        return {}
    return {"version": version, "base_score": score, "vector": vector, "provenance": prov}


@dataclass
class Observation:
    """One fact the agent actually collected from the target — the evidence a
    `verified` finding must point at. System-generated, never free model text."""
    id: str                       # stable: OBS-1, OBS-2, …
    tool: str                     # the tool that produced it (http_probe, run_command, …)
    asset: str                    # WHAT it concerns: url / host / target
    result: str                   # short result summary (status code, output head)
    ts: float = 0.0               # epoch seconds
    audit: str = ""               # audit-log file this run wrote to (traceability)
    source: str = "agent"         # observation source (tool class)
    detail: dict = field(default_factory=dict)  # structured raw (status, length, …)


@dataclass
class Finding:
    title: str
    severity: str = "info"       # info | low | medium | high | critical (qualitative)
    status: str = "potential"    # potential | verified | refuted (see FINDING_STATUSES)
    affected: str = ""           # WHERE the flaw is (endpoint/param/file:line)
    evidence: str = ""
    remediation: str = ""
    refs: list = field(default_factory=list)
    exploitation: str = ""       # HOW it is exploited (technique + steps)
    probe: dict = field(default_factory=dict)   # the exact proving request, for re-validation
    observations: list = field(default_factory=list)  # ids of the Observations that back it
    confidence: str = "unconfirmed"   # evidence confidence (derived from status)
    cvss: dict = field(default_factory=dict)  # authentic CVSS only: {version,base_score,vector,provenance}


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
        self.shots: list[dict] = []  # screenshots captured this run → embedded in the report
        self.channel = None  # exec foothold once established
        self.proxies = None  # SOCKS tunnel through the foothold, once opened
        self.done = False    # the agent declares the assessment complete
        self.cancelled = False  # set when a graceful stop was requested mid-run
        self.authed = False  # an authenticated session is loaded (self.session carries it)
        self.auth_role = ""  # the role of the logged-in test account
        self.auth_storage = []  # localStorage to seed the vision browser (SPA session token)
        self._calls: dict = {}  # repeat guard
        self.observations: list[Observation] = []  # evidence the agent actually collected
        self._obs_by_id: dict[str, Observation] = {}

    def search_vulns(self, tech: str, version: str = "") -> list[dict]:
        """Known vulns for a tech+version (OSV/web research + the CVE index).

        Preserves the fields analysis needs — canonical id + aliases, source/provenance,
        references, KEV, CVSS score AND vector (kept distinct from the qualitative severity
        label), product, searched version, applicability (affected/fixed ranges) and dates.
        Web-sourced hits are marked candidate=True (not yet substantiated)."""
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
            hid = h.get("id", "")
            if not hid or hid in seen:
                continue
            seen.add(hid)
            item = {"id": hid, "summary": (h.get("summary") or "")[:300],
                    "source": h.get("source", ""),
                    "aliases": h.get("aliases") or [],
                    "severity": h.get("severity", ""),           # qualitative label
                    "cvss": h.get("cvss") or None,               # numeric base score (may be None)
                    "cvss_vector": h.get("cvss_vector", ""),     # the vector, kept separate
                    "kev": bool(h.get("kev", False)),
                    "product": h.get("products", ""),
                    "searched_version": version,
                    "applicability": {"affected_ranges": h.get("affected_ranges") or [],
                                      "fixed_versions": h.get("fixed_versions") or []},
                    "cwe_ids": h.get("cwe_ids") or ([h["cwe"]] if h.get("cwe") else []),
                    "references": h.get("references") or [],
                    "published": h.get("published", ""), "modified": h.get("modified", "")}
            if h.get("candidate"):
                item["candidate"] = True   # web-sourced, not yet substantiated
            ex = exploits_for(hid)  # public exploit available? (big prioritization signal)
            if ex:
                item["public_exploits"] = [{"id": e["id"], "url": e["url"],
                                            "metasploit": e["metasploit"]} for e in ex[:3]]
            out.append(item)
        out = out[:12]
        try:  # EPSS: likelihood-of-exploitation signal (best-effort, dated, never fabricated)
            from .epss import enrich
            scores = enrich([i["id"] for i in out])
            for i in out:
                if (e := scores.get(i["id"])):
                    i["epss"] = {"score": e["score"], "percentile": e["percentile"],
                                 "date": e["date"]}
        except Exception:  # noqa: BLE001 — enrichment is optional
            pass
        return out

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
            r = self.session.request(method, url, params=params, data=data, headers=headers,
                                     timeout=15, allow_redirects=False, proxies=self.proxies)
        except requests.RequestException as e:
            return {"error": str(e)[:120]}
        body = r.text[:2000]
        return {"status": r.status_code, "length": len(r.content),
                "reflected": bool(value and value in body), "snippet": body[:400]}

    def record_finding(self, title: str, severity: str = "info",
                       status: str = "potential", affected: str = "",
                       evidence: str = "", remediation: str = "",
                       refs: list | None = None, exploitation: str = "",
                       probe: dict | None = None, observations: list | None = None,
                       cvss: dict | None = None) -> dict:
        """Record a finding. `verified` is EARNED, not asserted: it requires at least one
        `observations` id that references a real Observation this agent collected. A
        model claiming `verified` with only free text is clamped to `potential`."""
        status = status if status in FINDING_STATUSES else "potential"
        linked = [o for o in (observations or []) if o in self._obs_by_id]
        downgraded = False
        if status == "verified" and not linked:
            status, downgraded = "potential", True
        confidence = STATUS_CONFIDENCE[status]
        if downgraded:
            evidence = (evidence + " [status: reported as verified but no collected "
                        "observation was linked — kept as potential]").strip()
        f = Finding(title, severity, status, affected, evidence, remediation,
                    refs or [], exploitation, probe or {}, linked, confidence,
                    _clean_cvss(cvss))
        self.findings.append(f)
        events.emit("finding", severity=severity, status=status, title=title[:120])
        return {"recorded": True, "count": len(self.findings), "status": status,
                "linked_observations": linked,
                **({"note": "verified requires a linked observation id; recorded as potential"}
                   if downgraded else {})}

    def get_evidence(self, id: str) -> dict:
        """Look up the full detail of an observation or an indexed vuln by stable id —
        so heavy evidence can be inspected on demand instead of bloating every prompt."""
        if id in self._obs_by_id:
            o = self._obs_by_id[id]
            return {"kind": "observation", "id": o.id, "tool": o.tool, "asset": o.asset,
                    "result": o.result, "ts": o.ts, "audit": o.audit, "detail": o.detail}
        try:
            from .rag import CveIndex
            hit = CveIndex().get(id)
            if hit:
                return {"kind": "vuln", **hit}
        except Exception:  # noqa: BLE001 — index optional
            pass
        return {"error": f"no observation or vuln with id {id!r}"}

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

    def upload_shell(self, upload_url: str, uploads_base: str, field: str = "file",
                     lang: str = "php") -> dict:
        """Foothold via file upload: upload a webshell, then exec through where it's served."""
        if not self.exploit:
            return {"error": "requires exploitation to be enabled (--exploit)"}
        if self.scope.mode == "static":
            return {"error": "static mode: no network"}
        self.scope.require(upload_url)
        self.scope.require(uploads_base)
        from .exec_channel import upload_webshell
        ch, proof = upload_webshell(self.session, upload_url, uploads_base, field, lang)
        if not ch:
            return {"error": proof}
        self.channel = ch
        events.emit("foothold", kind=ch.kind, whoami=proof[:120])
        return {"foothold": "webshell", "whoami": proof[:300]}

    def make_payload(self, kind: str, command: str) -> dict:
        """Generate a serialized RCE payload to send to a deserialization sink via http_probe."""
        from .exec_channel import pickle_payload
        if kind in ("python", "pickle"):
            return {"payload": pickle_payload(command),
                    "note": "base64 Python pickle; send to a pickle.loads() sink (blind RCE)"}
        return {"error": f"kind {kind!r} unsupported (java/php gadgets are app-specific)"}

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
        return {"output": out}  # root is detected centrally in the loop (any tool)

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

    def open_tunnel(self, host: str = "", port: int = 1080) -> dict:
        """Open a SOCKS tunnel through the foothold; http_probe then routes through it."""
        if not self.exploit:
            return {"error": "requires exploitation to be enabled (--exploit)"}
        if self.channel is None:
            return {"error": "no foothold — call establish_foothold first"}
        from urllib.parse import urlparse
        from .pivot import open_socks
        h = host or urlparse(self.target).hostname or "127.0.0.1"
        self.proxies = open_socks(self.channel, h, port)
        return {"tunnel": self.proxies,
                "note": "http_probe now routes through the foothold — probe IN-SCOPE internal hosts"}

    def pivot_scan(self) -> dict:
        """Map the internal network from the foothold (interfaces, neighbors, services)."""
        if not self.exploit:
            return {"error": "requires exploitation to be enabled (--exploit)"}
        if self.channel is None:
            return {"error": "no foothold — call establish_foothold first"}
        from .privesc import pivot
        return {k: (v or "")[:600] for k, v in pivot(self.channel.run).items()}

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
            snap = snapshot(url, storage=self.auth_storage)
        except ImportError:
            return {"error": "browser needs: pip install playwright && playwright install chromium"}
        except Exception as e:  # noqa: BLE001 — navigation can fail many ways
            return {"error": f"browser: {str(e)[:140]}"}
        vision = vision_analyze(snap["png"], f"You are a pentester viewing {url}. {question}")
        from . import shots
        sid = shots.save(snap["png"])
        events.emit("screenshot", id=sid, url=url, caption=vision[:140])
        self.shots.append({"id": sid, "url": url, "caption": vision[:140]})
        return {"title": snap["title"], "vision": vision[:1500], "screenshot": sid,
                "links": snap["links"][:40], "forms": snap["forms"][:10]}

    def browser_action(self, url: str, steps: list) -> dict:
        """Drive the page by vision: SAM locates each element, Playwright clicks/fills it."""
        if self.scope.mode == "static":
            return {"error": "static mode: no browser"}
        self.scope.require(url)
        if not isinstance(steps, list) or not steps:
            return {"error": "steps must be a non-empty list of {find, fill?}"}
        try:
            from .browser import interact
            res = interact(url, steps, storage=self.auth_storage)
        except ImportError:
            return {"error": "browser needs: pip install playwright && playwright install chromium"}
        except Exception as e:  # noqa: BLE001
            return {"error": f"browser: {str(e)[:140]}"}
        if isinstance(res, dict) and res.get("png"):
            from . import shots
            sid = shots.save(res.pop("png"))
            events.emit("screenshot", id=sid, url=url, caption=res.get("vision", "")[:140])
            self.shots.append({"id": sid, "url": url, "caption": res.get("vision", "")[:140]})
            res["screenshot"] = sid
        return res

    def hypothesize(self, statement: str, based_on: list | None = None,
                    test: str = "", status: str = "untested") -> dict:
        """Record a link between observations → a possible attack path, and how to test it."""
        self.hypotheses.append(Hypothesis(statement, based_on or [], test, status))
        events.emit("hypothesis", statement=statement[:160], status=status)
        return {"recorded": True, "hypotheses": len(self.hypotheses)}

    def finish(self, summary: str = "") -> dict:
        """Declare the assessment complete — ends the run (you decide when you're done)."""
        self.done = True
        events.emit("finish", summary=summary[:200])
        return {"done": True}

    def dispatch(self, name: str, args: dict) -> dict:
        import json as _json
        key = (name, _json.dumps(args, sort_keys=True, default=str)[:200])
        self._calls[key] = self._calls.get(key, 0) + 1
        if self._calls[key] > 4 and name not in ("finish", "record_finding", "hypothesize"):
            result = {"note": "identical call repeated — test something new, or call finish if done"}
        else:
            fn = {"search_vulns": self.search_vulns, "http_probe": self.http_probe,
                  "finish": self.finish,
                  "record_finding": self.record_finding, "get_evidence": self.get_evidence,
                  "establish_foothold": self.establish_foothold,
                  "run_command": self.run_command, "privesc_scan": self.privesc_scan,
                  "loot": self.loot, "hypothesize": self.hypothesize,
                  "browse": self.browse, "browser_action": self.browser_action,
                  "upload_shell": self.upload_shell, "make_payload": self.make_payload,
                  "pivot_scan": self.pivot_scan, "open_tunnel": self.open_tunnel}.get(name)
            if not fn:
                result = {"error": f"unknown tool {name}"}
            else:
                try:
                    result = fn(**args)
                except OutOfScope as e:
                    result = {"error": f"out of scope: {e}"}
                except TypeError as e:
                    result = {"error": f"bad args: {e}"}
        if name in EVIDENCE_TOOLS and isinstance(result, dict) and "error" not in result:
            obs = self._record_observation(name, args, result)
            result = {**result, "observation_id": obs.id}  # the model cites this to verify
        audit.log("call", tool=name, args=args, result=_json.dumps(result, default=str)[:300])
        return result

    def _record_observation(self, tool: str, args: dict, result: dict) -> "Observation":
        import time
        oid = f"OBS-{len(self.observations) + 1}"
        asset = str(args.get("url") or args.get("upload_url") or self.target)
        summary = result.get("whoami") or result.get("output") or result.get("vision") \
            or (f"status={result.get('status')} len={result.get('length')} "
                f"reflected={result.get('reflected')}" if "status" in result else "")
        o = Observation(id=oid, tool=tool, asset=asset, result=str(summary)[:300],
                        ts=round(time.time(), 3), audit=audit.path() or "",
                        source=tool, detail={k: v for k, v in result.items()
                                             if k in ("status", "length", "reflected", "kind")})
        self.observations.append(o)
        self._obs_by_id[oid] = o
        return o


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
        "description": "Record ONE grounded security finding backed by evidence you gathered. "
                       "status 'verified' is ONLY accepted when you link at least one "
                       "`observations` id returned by a probing tool — you cannot mark a finding "
                       "verified from text alone (it will be kept as 'potential'). Use 'refuted' "
                       "when a test showed the condition does not hold.",
        "parameters": {"type": "object", "properties": {
            "title": {"type": "string"},
            "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"],
                         "description": "qualitative risk — NOT a CVSS number"},
            "status": {"type": "string", "enum": ["potential", "verified", "refuted"]},
            "affected": {"type": "string", "description": "WHERE: endpoint/param/file:line"},
            "evidence": {"type": "string"},
            "exploitation": {"type": "string",
                             "description": "HOW it is exploited: the technique and concrete steps"},
            "remediation": {"type": "string"},
            "refs": {"type": "array", "items": {"type": "string"}},
            "observations": {"type": "array", "items": {"type": "string"},
                             "description": "ids (OBS-N) of the probing-tool results that back this "
                             "finding — REQUIRED to mark it 'verified'"},
            "cvss": {"type": "object", "description": "ONLY an authentic CVSS from a source "
                     "(NVD/OSV/vendor): {version, base_score, vector, provenance}. Omit it rather "
                     "than inventing a number — severity already carries qualitative risk."},
            "probe": {"type": "object", "description": "for a VERIFIED finding, the exact request "
                      "that proves it so it can be re-validated: {url, method, param, value, "
                      "cookie, expect} where expect is a status code or a substring the response "
                      "must contain"}},
            "required": ["title", "severity"]}}},
    {"type": "function", "function": {
        "name": "get_evidence",
        "description": "Fetch the full detail of an observation (OBS-N) you collected, or of an "
                       "indexed vulnerability by its exact id (CVE/GHSA), without bloating the "
                       "conversation. Use it to inspect evidence before recording a finding.",
        "parameters": {"type": "object", "properties": {"id": {"type": "string"}},
                       "required": ["id"]}}},
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
        "name": "pivot_scan",
        "description": "Map the internal network from the foothold (interfaces, routes, ARP "
                       "neighbors, /etc/hosts, listening services). Use it to find in-scope "
                       "internal hosts, then reach them with run_command (curl/nc through the "
                       "foothold) for lateral movement.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "open_tunnel",
        "description": "Open a SOCKS tunnel through the foothold. Afterwards http_probe routes "
                       "through the compromised host, so you can probe/exploit IN-SCOPE internal "
                       "web hosts the foothold can reach. Requires a foothold.",
        "parameters": {"type": "object", "properties": {
            "host": {"type": "string", "description": "foothold host reachable from here (default: target)"},
            "port": {"type": "integer"}}}}},
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
        "name": "browser_action",
        "description": "Drive the page by VISION: SAM locates each element from a noun phrase and "
                       "Playwright clicks/fills it. Use to interact with the real UI (log in, "
                       "multi-step flows) when selectors are unknown.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string"},
            "steps": {"type": "array", "items": {"type": "object", "properties": {
                "find": {"type": "string", "description": "noun phrase, e.g. 'username field'"},
                "fill": {"type": "string", "description": "text to type; omit to click"}},
                "required": ["find"]}}},
            "required": ["url", "steps"]}}},
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
        "name": "upload_shell",
        "description": "Foothold via file upload: upload a webshell to upload_url, then execute "
                       "through uploads_base/<file> (where uploaded files are served).",
        "parameters": {"type": "object", "properties": {
            "upload_url": {"type": "string"}, "uploads_base": {"type": "string"},
            "field": {"type": "string", "description": "form file field name (default 'file')"},
            "lang": {"type": "string", "description": "webshell language (php, …)"}},
            "required": ["upload_url", "uploads_base"]}}},
    {"type": "function", "function": {
        "name": "make_payload",
        "description": "Generate a serialized RCE payload (e.g. base64 Python pickle) to send to "
                       "a deserialization sink via http_probe. kind: python/pickle.",
        "parameters": {"type": "object", "properties": {
            "kind": {"type": "string"}, "command": {"type": "string"}},
            "required": ["kind", "command"]}}},
    {"type": "function", "function": {
        "name": "finish",
        "description": "Declare the assessment COMPLETE and end the run. Call this once you have "
                       "reached the objective (e.g. root) or exhausted productive leads — do not "
                       "keep re-probing. YOU decide when you are done.",
        "parameters": {"type": "object", "properties": {
            "summary": {"type": "string", "description": "one line: what you achieved"}}}}},
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
    "browser and SEE it (screenshot + vision), catching forms/features static recon misses, "
    "and browser_action(url, steps) to interact by vision (SAM locates elements to click/fill, "
    "e.g. to log in through the real UI). "
    "Record a finding ONLY when backed by concrete evidence — a "
    "version match, a tool result, an exposed path, a reflected payload, or a missing "
    "security header. Call record_finding IMMEDIATELY each time you confirm an issue — do "
    "not batch recording for the end. For every finding fill `affected` (WHERE: the exact "
    "endpoint/param/file:line), `exploitation` (HOW it is exploited: the technique and the "
    "concrete steps/payload you used), `evidence`, and `remediation` (the fix). For a VERIFIED "
    "finding, also pass `probe` = the exact request that proves it ({url, method, param, value, "
    "cookie, expect}) so it can be re-validated. Actively "
    "connect the dots: when two observations might relate, call hypothesize to record the link "
    "and what would test it, then test it. Never invent vulnerabilities. To mark a finding "
    "'verified' you MUST pass `observations` = the id(s) (OBS-N) returned by the probing tool(s) "
    "that proved it — a claim without a linked observation is kept as 'potential'. Do NOT put a "
    "CVSS number in `severity`; pass a `cvss` object only when a source (NVD/OSV/vendor) gives a "
    "real vector. YOU decide when the "
    "assessment is complete: call finish(summary) once you have reached the objective (e.g. "
    "root) or exhausted productive leads. Do NOT re-probe what you already tested — each call "
    "should test something new."
)
DETECTION_NOTE = (" Prefer detection over exploitation. Mark a finding 'verified' only when a "
                  "probe confirmed it, otherwise 'potential'.")
EXPLOIT_NOTE = (" EXPLOITATION IS AUTHORIZED AND ENABLED. Actively try to break the target: "
                "send injection payloads (SQLi, XSS, SSTI, command injection), test IDOR by "
                "enumerating ids, forge/replay session cookies, and chain requests to prove "
                "impact. Report 'verified' ONLY for issues you concretely exploited or "
                "confirmed; DROP anything you could not confirm rather than reporting it as "
                "potential — do not pad the report with speculation. When you confirm a remote "
                "code execution vuln, call establish_foothold to get command execution (or "
                "upload_shell for a file-upload webshell, or make_payload for a deserialization "
                "sink), then "
                "run_command to enumerate the host. Then call privesc_scan to get GTFOBins-"
                "matched escalation candidates, pick one, run it with run_command, and confirm "
                "root with `id` (uid=0). Reason beyond the candidates — kernel/cron/writable-path "
                "escalation won't always be listed. Keep going until you are root or out of leads. "
                "Once you have a foothold, call pivot_scan to map the internal network and reach "
                "other IN-SCOPE internal hosts via run_command (curl/nc through the foothold), or "
                "open_tunnel to route http_probe through the foothold and attack internal web hosts. "
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


def _select_inventory(inv) -> dict:
    """Trim a recon inventory to a prompt-sized BUT structurally-valid subset — cap the
    long lists by count, never by slicing the serialized JSON mid-structure (which would
    corrupt ids/refs). Keeps the fields the model needs to act: tech+versions, endpoints/
    forms, deps, and the strongest code findings (with file:line/rule/refs intact)."""
    if not isinstance(inv, dict):
        return inv
    out = dict(inv)
    if isinstance(out.get("techs"), list):
        out["techs"] = out["techs"][:40]
    if isinstance(out.get("crawl"), dict):
        c = out["crawl"]
        out["crawl"] = {"forms": c.get("forms", [])[:20], "endpoints": c.get("endpoints", [])[:40]}
    if isinstance(out.get("deps"), list):
        out["deps"] = out["deps"][:80]
    if isinstance(out.get("code_findings"), list):
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        out["code_findings"] = sorted(
            out["code_findings"], key=lambda f: rank.get(f.get("severity"), 9))[:60]
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
            rtext = json.dumps(agent.dispatch(tc.function.name, args), default=str)
            if "uid=0(root)" in rtext:  # root reached via ANY tool (http_probe, run_command, …)
                events.emit("root")
            # scrub secrets before the result (fetched pages, command output, loot) reaches
            # the model — raw output stays only in the operator-local audit log
            msgs.append({"role": "tool", "tool_call_id": tc.id,
                         "content": redact.redact(rtext[:2000])})
        return True

    mem = inventory.get("_memory", "") if isinstance(inventory, dict) else ""
    inv_dump = {k: v for k, v in inventory.items() if k != "_memory"} if isinstance(inventory, dict) else inventory
    user = (f"Recon inventory for {agent.target}:\n"
            + redact.redact(json.dumps(_select_inventory(inv_dump), default=str))
            + "\n\nInvestigate with the tools and record grounded findings. Stop when done.")
    if getattr(agent, "authed", False):
        user = (f"AUTHENTICATED SESSION: you are logged in as a '{agent.auth_role}' test account; "
                "every http_probe you send carries that session automatically. Prioritise the "
                "AUTHENTICATED attack surface — broken access control, IDOR (enumerate object "
                "ids), privilege escalation, and functions only reachable once logged in — not "
                "just the public pages.\n\n") + user
    if mem:
        user = mem + "\n\n" + user
    msgs = [
        {"role": "system", "content": SYSTEM + (EXPLOIT_NOTE if agent.exploit else DETECTION_NOTE)},
        {"role": "user", "content": user},
    ]
    exhausted = True
    for _ in range(agent.budget):  # budget is a safety cap; the agent stops itself via finish()
        if events.stop_requested():  # graceful cancel: halt now, keep findings already recorded
            agent.cancelled, exhausted = True, False
            events.emit("stopped", reason="cancelled by operator",
                        findings=len(agent.findings))
            print("  ⏹ stop requested — halting", file=sys.stderr, flush=True)
            break
        if not turn(msgs) or agent.done:
            exhausted = False
            break
    if exhausted:  # hit budget mid-investigation — force a wrap-up so findings aren't lost
        msgs.append({"role": "user", "content": "Probing budget reached. Call record_finding "
                     "now for every vulnerability you confirmed or have concrete evidence for, "
                     "then stop."})
        for _ in range(3):
            if not turn(msgs):
                break
    return agent.findings


def assess(target: str | None, scope, active: bool = False, budget: int = 16,
           exploit: bool = False, fresh: bool = False, revalidate: bool = False) -> "Agent":
    """Full assessment: gather evidence → agent loop. Returns the Agent (.findings/.hypotheses)."""
    import time

    from . import cache

    from . import memory

    target = target or scope.code_path
    project = getattr(scope, "authorized_by", "") or "default"   # groups audits of one owner
    audit_path = f".metsec_cache/audit/metsec-{int(time.time())}.jsonl"
    audit.start(audit_path)
    audit.log("start", target=target, mode=scope.mode, exploit=exploit, project=project)
    # cache key carries project + asset (scheme/host/PORT) so runs of different projects or of
    # apps on different ports never share a recon inventory
    ckey = (project, memory.asset_id(target), scope.mode, active)
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
    note = memory.context(target, project)
    if note:
        inv = {**inv, "_memory": note}
    agent = Agent(scope, target, budget, exploit=exploit)
    if scope.mode != "static" and scope.auth:   # log in so the agent's probes are authenticated
        from . import auth as _auth
        try:
            agent.session = _auth.login(scope)   # session cookies now ride every http_probe
            agent.auth_storage = getattr(agent.session, "browser_storage", [])  # for vision browser
            agent.authed = True
            acct = (scope.auth.get("accounts") or [{}])[0]
            agent.auth_role = acct.get("role", "user")
            events.emit("tool", name="auth", detail=f"logged in as {agent.auth_role} test account")
            audit.log("auth", role=agent.auth_role, login_url=scope.auth.get("login_url"),
                      accounts=len(scope.auth.get("accounts") or []))
        except OutOfScope as e:
            events.emit("error", msg=f"authentication failed: {e}")
    run_agent(agent, inv)
    if revalidate:
        from .revalidate import revalidate as _reval
        st = _reval(agent.findings, scope, exploit=exploit)
        events.emit("tool", name="revalidate",
                    detail=f"{st['reproduced']} reproduced, {st['downgraded']} downgraded, "
                           f"{st['indeterminate']} indeterminate")
    from dataclasses import asdict as _asdict
    memory.remember(target, [_asdict(f) for f in agent.findings], inv,
                    foothold=agent.channel.kind if agent.channel else "",
                    project=project, audit=audit_path)
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
    assert "requires exploitation" in dev.pivot_scan()["error"]
    assert "no foothold" in exp.pivot_scan()["error"]
    assert "requires exploitation" in dev.open_tunnel()["error"]
    assert "no foothold" in exp.open_tunnel()["error"]
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

    # 'verified' with NO linked observation is clamped to 'potential' (no self-confirm via text)
    r = dev.record_finding("Reflected input", "medium", "verified", evidence="XSSMARK echoed",
                           exploitation="GET /search?q=<payload>, reflected unescaped")
    assert dev.findings[-1].status == "potential" and "note" in r, r
    assert dev.findings[-1].confidence == "unconfirmed"
    # a probe through dispatch records an Observation; linking it earns 'verified'
    pr = dev.dispatch("http_probe", {"url": f"{base}/search", "method": "GET",
                                     "param": "q", "value": "XSSMARK"})
    oid = pr["observation_id"]
    dev.record_finding("Reflected input (confirmed)", "medium", "verified",
                       evidence="XSSMARK echoed", observations=[oid])
    assert dev.findings[-1].status == "verified" and dev.findings[-1].observations == [oid]
    assert dev.get_evidence(oid)["tool"] == "http_probe"
    assert "error" in dev.get_evidence("OBS-999")
    # a fabricated CVSS (no provenance/vector) is dropped; an authentic one is kept
    dev.record_finding("x", "high", cvss={"base_score": 9.8})
    assert dev.findings[-1].cvss == {}
    dev.record_finding("y", "high", cvss={"version": "3.1", "base_score": 9.8,
                       "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                       "provenance": "NVD"})
    assert dev.findings[-1].cvss["base_score"] == 9.8 and dev.findings[-1].cvss["provenance"] == "NVD"
    # refuted is a valid terminal state
    dev.record_finding("not vulnerable after all", "low", "refuted")
    assert dev.findings[-1].status == "refuted" and dev.findings[-1].confidence == "refuted"

    dev.hypothesize("looted creds may unlock admin", ["f1", "f2"], "replay creds", "confirmed")
    assert len(dev.hypotheses) == 1 and dev.hypotheses[0].status == "confirmed"
    assert dev.hypotheses[0].based_on == ["f1", "f2"]

    stat = Agent(Scope(code_path=".", authorized_by="t", mode="static"), "x")
    assert "static mode" in stat.browse("http://127.0.0.1/")["error"]  # no browser in static
    assert "static mode" in stat.browser_action("http://127.0.0.1/", [{"find": "x"}])["error"]
    assert dev.make_payload("pickle", "id").get("payload"), "pickle payload"
    assert "unsupported" in dev.make_payload("java", "id").get("error", "")
    assert "error" in stat.upload_shell("http://127.0.0.1/u", "http://127.0.0.1/up")  # gated

    assert dev.finish("rooted the box")["done"] is True and dev.done is True  # self-termination
    g = Agent(Scope(ips=["127.0.0.1"], authorized_by="t", mode="dev"), base)
    for _ in range(4):
        g.dispatch("http_probe", {"url": f"{base}/x"})
    assert "repeated" in g.dispatch("http_probe", {"url": f"{base}/x"}).get("note", ""), "repeat guard"
    srv.shutdown()
    print("agent self-check ok")
