"""Active vulnerability research — look beyond the static CVE index.

Given a detected technology + version, find vulnerabilities via:
  1. OSV.dev  — free, no-key, exact-version lookup for open-source packages (npm, PyPI, …).
  2. web search — DuckDuckGo snippets → Muse extracts structured vulns (runtimes, GHSAs,
     advisories, long tail OSV/KEV miss, e.g. "node v18.12").

Findings use the same record schema as the RAG index, so `--save` can fold them back
into LanceDB — the agent "learns" what it researches.
"""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser

import requests

from . import config
from .rag import _record

OSV_API = "https://api.osv.dev/v1/query"
# Tried in order when the caller doesn't know the ecosystem (recon will usually know it).
GUESS_ECOSYSTEMS = ["npm", "PyPI", "Go", "Maven", "crates.io", "RubyGems", "Packagist"]


# ------------------------------- OSV ----------------------------------------

def _osv_cvss(sev_list: list) -> tuple[float, str]:
    """OSV `severity[].score` holds the CVSS *vector*, not a label. Return (base_score, vector),
    deriving the numeric base score from the vector when a library is available (else 0.0)."""
    vector = next((s.get("score", "") for s in sev_list
                   if s.get("score", "").startswith("CVSS:")), "")
    if not vector:
        vector = next((s.get("score", "") for s in sev_list if s.get("score")), "")
    score = 0.0
    if vector.startswith("CVSS:"):
        try:
            from cvss import CVSS3
            score = float(CVSS3(vector).base_score)
        except Exception:  # noqa: BLE001 — no cvss lib / malformed; keep the vector, score stays 0
            pass
    return score, vector


def _osv_affected(v: dict, name: str) -> tuple[list[str], list[str]]:
    """Preserve OSV applicability: affected version ranges AND the versions that fix them."""
    ranges, fixed = [], []
    for aff in v.get("affected", []):
        pkg = aff.get("package", {}).get("name", "") or name
        for rng in aff.get("ranges", []):
            intro = fx = ""
            for ev in rng.get("events", []):
                if ev.get("introduced"):
                    intro = ev["introduced"]
                if ev.get("fixed"):
                    fx = ev["fixed"]
                    fixed.append(fx)
            ranges.append(f"{pkg} introduced {intro or '0'}"
                          + (f", fixed {fx}" if fx else ", no fix"))
    # de-dup preserving order
    return list(dict.fromkeys(ranges)), list(dict.fromkeys(fixed))


def _parse_osv(data: dict, name: str, version: str) -> list[dict]:
    out = []
    for v in data.get("vulns", []):
        score, vector = _osv_cvss(v.get("severity", []))
        refs = [r["url"] for r in v.get("references", []) if r.get("url")][:5]
        ranges, fixed = _osv_affected(v, name)
        out.append(_record(
            id=v.get("id", ""), source="osv",
            summary=(v.get("summary") or v.get("details", ""))[:300],
            products=f"{name} {version}",
            aliases=v.get("aliases", []) or [],
            cwe_ids=v.get("database_specific", {}).get("cwe_ids", []) or [],
            cwe=",".join(v.get("database_specific", {}).get("cwe_ids", []) or []),
            cvss=score, cvss_vector=vector, severity="",  # OSV gives a vector, not a label
            affected_ranges=ranges, fixed_versions=fixed,
            published=v.get("published", ""), modified=v.get("modified", ""),
            references=refs or None,
        ))
    return out


class SourceError(Exception):
    """The source could not be reached — distinct from 'the source returned no results'."""


def osv_query(name: str, version: str, ecosystem: str) -> list[dict]:
    """Returns the (possibly empty) list of vulns. Raises SourceError on a transport failure,
    so callers can tell 'nothing known' apart from 'we could not ask'."""
    payload = {"version": version, "package": {"name": name, "ecosystem": ecosystem}}
    try:
        resp = requests.post(OSV_API, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        raise SourceError(f"OSV unreachable: {str(e)[:120]}") from e
    return _parse_osv(data, name, version)


# ------------------------------- web ----------------------------------------

def _tavily_parse(data: dict) -> list[dict]:
    return [{"title": r.get("title", ""), "body": r.get("content", ""), "url": r.get("url", "")}
            for r in data.get("results", [])]


def _brave_parse(data: dict) -> list[dict]:
    return [{"title": r.get("title", ""), "body": r.get("description", ""), "url": r.get("url", "")}
            for r in ((data.get("web") or {}).get("results") or [])]


def web_search(query: str, k: int = 6) -> list[dict]:
    # Prefer a keyed provider when configured (reliable); fall back to DuckDuckGo.
    import os
    import time

    if (key := os.environ.get("TAVILY_API_KEY")):
        try:
            data = requests.post("https://api.tavily.com/search", timeout=20,
                                 json={"api_key": key, "query": query, "max_results": k}).json()
            if (hits := _tavily_parse(data)):
                return hits
        except requests.RequestException:
            pass
    if (key := os.environ.get("BRAVE_API_KEY")):
        try:
            data = requests.get("https://api.search.brave.com/res/v1/web/search", timeout=20,
                                headers={"X-Subscription-Token": key, "Accept": "application/json"},
                                params={"q": query, "count": k}).json()
            if (hits := _brave_parse(data)):
                return hits
        except requests.RequestException:
            pass
    # DDG fallback: rate-limits bursts and returns empty; one retry smooths it.
    for attempt in range(2):
        try:
            from ddgs import DDGS
            with DDGS() as ddg:
                hits = [{"title": r.get("title", ""), "body": r.get("body", ""),
                         "url": r.get("href", "")}
                        for r in ddg.text(query, max_results=k)]
            if hits:
                return hits
        except Exception:  # noqa: BLE001 — search is best-effort; degrade to OSV-only
            pass
        time.sleep(2)
    return []


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: list[str] = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self._skip = True

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript"):
            self._skip = False

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.parts.append(data.strip())


def fetch_text(url: str, limit: int = 3000) -> str:
    """Readable text from a page (stdlib HTML strip). Snippets are too thin alone."""
    try:
        html = requests.get(url, timeout=20,
                            headers={"User-Agent": "Mozilla/5.0 (Watson research)"}).text
    except requests.RequestException:
        return ""
    p = _TextExtractor()
    p.feed(html)
    return " ".join(p.parts)[:limit]


def _json_array(raw: str) -> list:
    m = re.search(r"\[.*\]", raw, re.DOTALL)
    try:
        return json.loads(m.group(0)) if m else []
    except json.JSONDecodeError:
        return []


def web_research(name: str, version: str, k: int = 6, fetch_pages: int = 3) -> list[dict]:
    results = web_search(f"{name} {version} vulnerability CVE security advisory")
    if not results:
        return []
    blocks = [f"- {r['title']}: {r['body']} ({r['url']})" for r in results]
    # Enrich with real page text from the top results — snippets miss the CVE lists
    # that live in advisory/release-note bodies.
    for r in results[:fetch_pages]:
        txt = fetch_text(r["url"])
        if txt:
            blocks.append(f"\nPAGE {r['url']}:\n{txt}")
    ctx = "\n".join(blocks)
    prompt = (
        f"You are a security analyst. Web search results about {name} {version}:\n{ctx}\n\n"
        f"From these, list DISTINCT security vulnerabilities relevant to {name} {version}. "
        f"INCLUDE vulnerabilities fixed in a later patch of the same line (e.g. a {version}.x "
        "release or advisory shown above), since the queried version is affected by them. "
        'Return a JSON array; each item: {"id": CVE/GHSA id or "", "summary": one line, '
        '"severity": "low|medium|high|critical or "", "url": source}. '
        "Output JSON only, no prose. Use [] only if the results truly show no vulnerabilities."
    )
    out = []
    for it in _json_array(config.chat(prompt, model=config.FAST)):
        if not isinstance(it, dict):
            continue
        vid = (it.get("id") or "").strip()
        summary = (it.get("summary") or "").strip()
        if not summary:
            continue
        out.append(_record(
            id=vid or f"WEB-{name}-{abs(hash(summary)) % 10**8}",
            source="web", summary=summary, products=f"{name} {version}",
            severity=it.get("severity", ""), candidate=True,  # web-sourced → not yet substantiated
            references=[it["url"]] if it.get("url") else None,
        ))
    return out


# ----------------------------- orchestrate ----------------------------------

def research(name: str, version: str, ecosystem: str | None = None,
             use_web: bool = True) -> list[dict]:
    """Combine OSV + web research for one tech+version. Deduped by id/alias.

    A source that is unreachable (SourceError) is reported via a synthetic record with
    source='error' rather than silently looking like 'no vulnerabilities' — the caller can
    then tell 'nothing known' apart from 'could not ask'. A later fixed version is preserved
    as applicability data, NOT treated as proof the queried version is exploitable."""
    findings: list[dict] = []
    errors: list[str] = []
    for eco in ([ecosystem] if ecosystem else GUESS_ECOSYSTEMS):
        try:
            hits = osv_query(name, version, eco)
        except SourceError as e:
            errors.append(str(e))
            continue
        if hits:
            findings += hits
            break
    if use_web:
        findings += web_research(name, version)
    if not findings and errors:
        findings.append(_record(id=f"ERROR-{name}", source="error",
                                summary="; ".join(errors)[:300], products=f"{name} {version}"))

    seen, deduped = set(), []
    for f in findings:
        ids = {f["id"], *(f.get("aliases") or [])}
        if seen & ids:
            continue
        seen |= ids
        deduped.append(f)
    return deduped


def from_inventory(inv: dict, use_web: bool = True) -> dict[str, list[dict]]:
    """Research every versioned tech in a recon inventory → {`name version`: findings}."""
    out: dict[str, list[dict]] = {}
    for t in inv.get("techs", []):
        name, version = getattr(t, "name", ""), getattr(t, "version", "")
        if name and version:
            out[f"{name} {version}"] = research(name, version, use_web=use_web)
    return out


if __name__ == "__main__":  # offline self-check: python -m watson.research
    sample = {"vulns": [{
        "id": "GHSA-jf85-cpcp-j695",
        "summary": "Prototype Pollution in lodash",
        "aliases": ["CVE-2019-10744"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "references": [{"url": "https://github.com/advisories/GHSA-jf85-cpcp-j695"}],
        "database_specific": {"cwe_ids": ["CWE-1321"]},
        "published": "2019-07-19T00:00:00Z",
        "affected": [{"package": {"name": "lodash", "ecosystem": "npm"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"},
                                                               {"fixed": "4.17.12"}]}]}],
    }]}
    recs = _parse_osv(sample, "lodash", "4.17.4")
    assert len(recs) == 1
    r = recs[0]
    assert r["id"] == "GHSA-jf85-cpcp-j695" and r["source"] == "osv"
    assert r["cwe"] == "CWE-1321" and r["cwe_ids"] == ["CWE-1321"]
    # vector kept distinct from the (absent) qualitative label; applicability preserved
    assert r["cvss_vector"].startswith("CVSS:3.1/") and r["severity"] == ""
    assert r["aliases"] == ["CVE-2019-10744"]
    assert "4.17.12" in r["fixed_versions"] and any("fixed 4.17.12" in x for x in r["affected_ranges"])
    assert r["published"].startswith("2019") and "lodash 4.17.4" in r["products"]

    assert _json_array('junk [{"id":"CVE-1"}] tail') == [{"id": "CVE-1"}]
    assert _json_array("not json") == []

    p = _TextExtractor()
    p.feed("<html><style>x{}</style><body>Node 18 fixes <b>CVE-2022-43548</b>"
           "<script>bad()</script></body></html>")
    text = " ".join(p.parts)
    assert "CVE-2022-43548" in text and "bad()" not in text and "x{}" not in text

    tav = _tavily_parse({"results": [{"title": "T", "content": "body", "url": "http://t/"}]})
    assert tav == [{"title": "T", "body": "body", "url": "http://t/"}], tav
    brv = _brave_parse({"web": {"results": [{"title": "B", "description": "d", "url": "http://b/"}]}})
    assert brv == [{"title": "B", "body": "d", "url": "http://b/"}], brv
    assert _brave_parse({}) == [] and _tavily_parse({}) == []
    print("research self-check ok")
