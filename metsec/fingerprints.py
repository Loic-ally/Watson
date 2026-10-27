"""Wappalyzer-format fingerprint engine.

Consumes the standard `technologies.json` pattern format (thousands of maintained
app signatures) instead of hand-rolled regexes. A pattern is a regex optionally
followed by `\\;version:<tmpl>` and `\\;confidence:<n>`; version templates use
backrefs (`\\1`) and the ternary form `\\1?a:b`.

Matched fields: headers, cookies, meta, scriptSrc, html, url, plus `implies`.
ponytail: js/dom/dns/certIssuer fields need a JS runtime / extra probes — skipped
(known ceiling); add them if detection gaps show. Scan is O(techs × patterns) per page.
"""
from __future__ import annotations

import re
from functools import lru_cache


def _aslist(x) -> list:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


@lru_cache(maxsize=20000)
def _compile(pattern: str):
    parts = pattern.split("\\;")
    meta = {}
    for p in parts[1:]:
        if ":" in p:
            k, v = p.split(":", 1)
            meta[k] = v
    try:
        rx = re.compile(parts[0], re.I)
    except re.error:
        rx = None  # Wappalyzer uses JS regex; skip the few Python can't compile
    return rx, meta


def _resolve_version(tmpl: str, m: re.Match) -> str:
    def grp(i: str) -> str:
        try:
            return m.group(int(i)) or ""
        except IndexError:
            return ""

    tern = re.match(r"\\(\d)\?([^:]*):(.*)$", tmpl)  # \1?present:absent
    if tern:
        return tern.group(2) if grp(tern.group(1)) else tern.group(3)
    return re.sub(r"\\(\d)", lambda x: grp(x.group(1)), tmpl)


def _match(pattern: str, value: str):
    rx, meta = _compile(pattern)
    if rx is None:
        return None
    m = rx.search(value)
    if not m:
        return None
    version = _resolve_version(meta["version"], m) if "version" in meta else ""
    return version, int(meta.get("confidence", 100))


def detect(evidence: dict, db: dict) -> list[dict]:
    """evidence: {url, headers(lower), cookies, metas(lower), scripts[list], html}."""
    found: dict[str, dict] = {}

    def add(name, version="", confidence=100, cats=None, cpe=""):
        cur = found.get(name)
        if cur:
            cur["version"] = cur["version"] or version
            cur["confidence"] = min(100, cur["confidence"] + confidence)
        else:
            found[name] = {"name": name, "version": version,
                           "confidence": min(confidence, 100),
                           "cats": cats or [], "cpe": cpe}

    def scan(pats, value, state):
        for pat in _aslist(pats):
            r = _match(pat, value)
            if r:
                state[0] = True
                state[1] = state[1] or r[0]
                state[2] = max(state[2], r[1])

    for name, tech in db.items():
        st = [False, "", 0]  # matched, version, confidence
        for hname, pats in (tech.get("headers") or {}).items():
            if (v := evidence["headers"].get(hname.lower())) is not None:
                scan(pats, v, st)
        for cname, pats in (tech.get("cookies") or {}).items():
            if (v := evidence["cookies"].get(cname)) is not None:
                scan(pats, v, st)
        for mname, pats in (tech.get("meta") or {}).items():
            if (v := evidence["metas"].get(mname.lower())) is not None:
                scan(pats, v, st)
        for pat in _aslist(tech.get("scriptSrc")):
            for s in evidence["scripts"]:
                scan(pat, s, st)
        scan(tech.get("html"), evidence["html"], st)
        scan(tech.get("url"), evidence["url"], st)
        if st[0]:
            add(name, st[1], st[2] or 100, tech.get("cats"), tech.get("cpe", ""))

    for name in list(found):  # implied technologies
        for imp in _aslist(db.get(name, {}).get("implies")):
            iname = imp.split("\\;")[0]
            if iname and iname not in found:
                it = db.get(iname, {})
                add(iname, "", 50, it.get("cats"), it.get("cpe", ""))

    return sorted(found.values(), key=lambda t: -t["confidence"])


if __name__ == "__main__":  # offline self-check: python -m metsec.fingerprints
    db = {
        "jQuery": {"scriptSrc": [r"/jquery-([\d.]+)\.js\;version:\1"],
                   "cats": [59], "cpe": "cpe:2.3:a:jquery:jquery"},
        "Nginx": {"headers": {"Server": r"nginx(?:/([\d.]+))?\;version:\1"},
                  "implies": ["Linux"]},
        "Linux": {"cats": [28]},
        "WordPress": {"meta": {"generator": r"WordPress ?([\d.]+)?\;version:\1"}},
    }
    ev = {"url": "http://x/", "headers": {"server": "nginx/1.18.0"}, "cookies": {},
          "metas": {"generator": "WordPress 6.4"}, "scripts": ["/jquery-3.4.1.js"], "html": ""}
    got = {t["name"]: t["version"] for t in detect(ev, db)}
    assert got.get("jQuery") == "3.4.1", got
    assert got.get("Nginx") == "1.18.0", got
    assert got.get("WordPress") == "6.4", got
    assert "Linux" in got, got  # implied by Nginx

    assert _resolve_version(r"\1?yes:no", re.match(r"(x)?", "x")) == "yes"
    assert _resolve_version(r"\1?yes:no", re.match(r"(x)?", "")) == "no"
    print("fingerprints self-check ok")
