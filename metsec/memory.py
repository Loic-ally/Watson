"""Persistent per-target memory — the agent remembers a target across runs.

Stored per host in .metsec_cache/memory/<host>.json: a compact summary of past
findings, detected tech, and foothold. Recalled into the agent's context so repeat
runs start informed.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import urlparse

MEM_DIR = Path(".metsec_cache/memory")


def _key(target: str) -> str:
    host = urlparse(target).hostname or target
    return "".join(c if c.isalnum() or c in ".-" else "_" for c in host) or "target"


def recall(target: str) -> dict:
    f = MEM_DIR / (_key(target) + ".json")
    if f.exists():
        try:
            return json.loads(f.read_text())
        except (ValueError, OSError):
            return {}
    return {}


def remember(target: str, findings: list, inventory: dict | None = None,
             foothold: str = "") -> dict:
    MEM_DIR.mkdir(parents=True, exist_ok=True)
    mem = recall(target)
    mem["target"] = target
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
    (MEM_DIR / (_key(target) + ".json")).write_text(json.dumps(mem, indent=2, default=str))
    return mem


def context(target: str) -> str:
    """A short note about what we already know, to prime the agent. '' if nothing."""
    mem = recall(target)
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


if __name__ == "__main__":  # self-check: python -m metsec.memory
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
    print("memory self-check ok")
