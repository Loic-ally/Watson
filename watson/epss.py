"""FIRST EPSS — Exploit Prediction Scoring System.

EPSS gives, per CVE, the probability it will be exploited in the wild in the next 30 days
(score 0–1) plus the percentile among all CVEs, dated. It is a prioritisation signal that
complements CVSS (severity) and KEV (known-exploited) — "how likely", not "how bad".

Two access modes, matching the data's shape:
  - lookup(cves)      : ad-hoc, keyless JSON API (api.first.org) for a handful of CVEs.
  - sync(date)        : the full daily CSV (epss.cyentia.com) cached locally for bulk/global
                        enrichment, read back with bulk_get().

EPSS numbers are DATA: a date is always carried so a stale score is never mistaken for a
current one. No license key required (CC BY 4.0, attribution: FIRST.org).
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import time
from pathlib import Path

import requests

API = "https://api.first.org/data/v1/epss"
DAILY = "https://epss.cyentia.com/epss_scores-{date}.csv.gz"
CACHE = Path(".watson_cache/epss")


def _rec(cve: str, epss, percentile, date: str) -> dict:
    return {"cve": cve, "score": float(epss or 0.0),
            "percentile": float(percentile or 0.0), "date": date}


def _parse_api(data: dict) -> dict[str, dict]:
    return {r["cve"]: _rec(r["cve"], r.get("epss"), r.get("percentile"), r.get("date", ""))
            for r in data.get("data", []) if r.get("cve")}


def lookup(cves: list[str]) -> dict[str, dict]:
    """Ad-hoc EPSS for specific CVEs via the keyless API. Best-effort: {} on failure."""
    cves = [c for c in cves if c.upper().startswith("CVE-")]
    if not cves:
        return {}
    try:
        data = requests.get(API, params={"cve": ",".join(cves[:100])}, timeout=20).json()
    except (requests.RequestException, ValueError):
        return {}
    return _parse_api(data)


def parse_bulk_csv(text: str) -> dict[str, dict]:
    """Parse the daily EPSS CSV. First line is a `#model_version...,score_date=YYYY-MM-DD`
    comment; the next line is the header `cve,epss,percentile`."""
    date = ""
    lines = text.splitlines()
    if lines and lines[0].startswith("#"):
        for part in lines[0].lstrip("#").split(","):
            if "score_date" in part:
                date = part.split("=", 1)[-1].strip().split("T")[0]
        lines = lines[1:]
    out = {}
    for row in csv.DictReader(lines):
        cve = (row.get("cve") or "").strip()
        if cve:
            out[cve] = _rec(cve, row.get("epss"), row.get("percentile"), date)
    return out


def sync(date: str | None = None) -> int:
    """Download + cache the full daily EPSS CSV for global enrichment. Returns row count.
    `date` is YYYY-MM-DD (default: today, UTC)."""
    date = date or time.strftime("%Y-%m-%d", time.gmtime())
    resp = requests.get(DAILY.format(date=date), timeout=120)
    resp.raise_for_status()
    text = gzip.decompress(resp.content).decode("utf-8", "ignore") \
        if resp.content[:2] == b"\x1f\x8b" else resp.text
    scores = parse_bulk_csv(text)
    CACHE.mkdir(parents=True, exist_ok=True)
    (CACHE / f"{date}.json").write_text(json.dumps(scores))
    (CACHE / "latest.json").write_text(json.dumps({"date": date, "count": len(scores)}))
    return len(scores)


def bulk_get(cve: str, date: str | None = None) -> dict | None:
    """Read a CVE's EPSS from a synced daily snapshot (latest if no date). None if absent."""
    if date is None:
        meta = CACHE / "latest.json"
        if not meta.exists():
            return None
        date = json.loads(meta.read_text()).get("date", "")
    f = CACHE / f"{date}.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text()).get(cve)
    except (ValueError, OSError):
        return None


def enrich(ids: list[str], use_api: bool = True) -> dict[str, dict]:
    """EPSS for a set of ids — local synced snapshot first, API for any still missing."""
    out: dict[str, dict] = {}
    for cve in ids:
        hit = bulk_get(cve)
        if hit:
            out[cve] = hit
    missing = [c for c in ids if c not in out and c.upper().startswith("CVE-")]
    if use_api and missing:
        out.update(lookup(missing))
    return out


if __name__ == "__main__":  # self-check: python -m watson.epss (offline; fixtures only)
    api_fixture = {"status": "OK", "data": [
        {"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99998",
         "date": "2026-10-28"}]}
    got = _parse_api(api_fixture)
    assert got["CVE-2021-44228"]["score"] > 0.9 and got["CVE-2021-44228"]["date"] == "2026-10-28"
    assert got["CVE-2021-44228"]["percentile"] > 0.99

    csv_fixture = (
        "#model_version:v2025.03.14,score_date=2026-10-28T00:00:00Z\n"
        "cve,epss,percentile\n"
        "CVE-2021-44228,0.975650000,0.999980000\n"
        "CVE-2020-0001,0.000430000,0.100000000\n")
    rows = parse_bulk_csv(csv_fixture)
    assert len(rows) == 2 and rows["CVE-2020-0001"]["date"] == "2026-10-28"
    assert rows["CVE-2021-44228"]["score"] > 0.9 and rows["CVE-2020-0001"]["score"] < 0.01
    print("epss self-check ok")
