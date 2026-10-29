"""Persistent per-ASSET memory — the agent remembers a target across runs.

Memory is scoped by explicit identifiers so runs never bleed into each other:
  - project id : groups audits that belong together (derived from who authorized the scope)
  - asset id   : the specific application = scheme + host + PORT (so two apps on different
                 ports of the same host are kept apart — they are different assets)
  - audit id   : the individual run (the audit-log filename carries it)

Stored at .watson_cache/memory/<project>/<asset>.json. Old flat <host>.json files from
before this layout are still read as a fallback (prudent migration, never overwritten).
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urlparse

MEM_DIR = Path(".watson_cache/memory")


def _slug(s: str) -> str:
    return "".join(c if c.isalnum() or c in ".-" else "_" for c in (s or "")) or "x"


def asset_id(target: str) -> str:
    """scheme_host_port — the port is part of the identity (distinct apps per port)."""
    u = urlparse(target if "://" in (target or "") else "//" + (target or ""))
    host = u.hostname or target or "target"
    port = u.port or {"https": 443, "http": 80}.get(u.scheme, "")
    return _slug(f"{u.scheme or 'http'}_{host}_{port}")


def project_id(project: str | None) -> str:
    # ponytail: project = who authorized it (slug). Per-scope project names if teams collide.
    return _slug(project or "default")


def _dir(project: str | None) -> Path:
    return MEM_DIR / project_id(project)


def _legacy_file(target: str) -> Path:
    host = urlparse(target).hostname or target
    return MEM_DIR / (_slug(host) + ".json")


def recall(target: str, project: str | None = None) -> dict:
    f = _dir(project) / (asset_id(target) + ".json")
    if not f.exists():
        f = _legacy_file(target)          # migrate-on-read: fall back to the old flat layout
    if f.exists():
        try:
            return json.loads(f.read_text())
        except (ValueError, OSError):
            return {}
    return {}


def remember(target: str, findings: list, inventory: dict | None = None,
             foothold: str = "", project: str | None = None, audit: str = "") -> dict:
    d = _dir(project)
    d.mkdir(parents=True, exist_ok=True)
    mem = recall(target, project)
    mem["target"] = target
    mem["project"] = project_id(project)
    mem["asset"] = asset_id(target)
    if audit:
        mem["last_audit"] = audit
    mem["last_seen"] = time.strftime("%Y-%m-%d %H:%M")
    mem["runs"] = mem.get("runs", 0) + 1
    mem["findings"] = [{"title": f.get("title"), "severity": f.get("severity"),
                        "status": f.get("status"), "affected": f.get("affected")}
                       for f in findings[:15]]
    if foothold:
        mem["foothold"] = foothold
    if inventory:
        techs = inventory.get("techs", [])
        mem["tech"] = [(t.get("name") if isinstance(t, dict) else getattr(t, "name", ""))
                       for t in techs][:20]
    (d / (asset_id(target) + ".json")).write_text(json.dumps(mem, indent=2, default=str))
    return mem


def context(target: str, project: str | None = None) -> str:
    """A short note about what we already know, to prime the agent. '' if nothing."""
    mem = recall(target, project)
    if not mem.get("findings") and not mem.get("tech"):
        return ""
    out = [f"MEMORY — you have assessed {target} before "
           f"({mem.get('runs', 1)} run(s), last {mem.get('last_seen', '?')}). Known:"]
    out += [f"- {f.get('severity')}/{f.get('status')}: {f.get('title')} @ {f.get('affected', '')}"
            for f in mem.get("findings", [])[:10]]
    if mem.get("foothold"):
        out.append(f"- prior foothold: {mem['foothold']}")
    if mem.get("tech"):
        out.append("- tech: " + ", ".join(t for t in mem["tech"][:12] if t))
    out.append("Use this to go faster; re-confirm before relying on it.")
    return "\n".join(out)


if __name__ == "__main__":  # self-check: python -m watson.memory
    import tempfile

    MEM_DIR = Path(tempfile.mkdtemp())
    t = "http://10.0.0.5:8080/"
    assert recall(t) == {} and context(t) == ""
    remember(t, [{"title": "SQLi", "severity": "critical", "status": "verified",
                  "affected": "/login"}],
             inventory={"techs": [{"name": "nginx"}, {"name": "php"}]}, foothold="cmd-injection")
    m = recall(t)
    assert m["runs"] == 1 and m["findings"][0]["title"] == "SQLi" and m["foothold"] == "cmd-injection"
    assert "nginx" in m["tech"]
    ctx = context(t)
    assert "assessed http://10.0.0.5:8080/ before" in ctx and "SQLi" in ctx and "cmd-injection" in ctx
    remember(t, [])  # a later run increments and refreshes the summary
    assert recall(t)["runs"] == 2

    # two apps on DIFFERENT PORTS of the same host are distinct assets (not merged)
    remember(t, [{"title": "SQLi", "severity": "critical", "status": "verified", "affected": "/login"}])
    other = "http://10.0.0.5:9090/"
    remember(other, [{"title": "XSS", "severity": "low", "status": "potential", "affected": "/q"}])
    assert asset_id(t) != asset_id(other), "port is part of asset identity"
    assert recall(other)["findings"][0]["title"] == "XSS"
    assert recall(t)["findings"][0]["title"] == "SQLi", "port 8080 memory untouched by 9090"

    # two audits in DIFFERENT PROJECTS stay isolated
    remember(t, [{"title": "ProjB only", "severity": "info", "status": "potential", "affected": "/"}],
             project="team-b")
    assert recall(t, project="team-b")["findings"][0]["title"] == "ProjB only"
    assert recall(t)["findings"][0]["title"] == "SQLi", "default project not affected by team-b"
    print("memory self-check ok")
