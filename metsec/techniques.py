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
    print("techniques self-check ok")
