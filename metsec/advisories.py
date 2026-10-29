"""Vendor advisories — CSAF 2.0 / VEX connector.

CSAF (Common Security Advisory Framework) 2.0 is the vendor-neutral JSON standard that
security advisories and VEX (Vulnerability Exploitability eXchange) statements are published
in. One parser therefore covers many vendors' advisories for the stack.

What we preserve per vulnerability in an advisory:
  - applicability  : which products are known_affected / known_not_affected / fixed /
                     under_investigation (VEX status) — so a "not affected" statement is NOT
                     mistaken for a vulnerability;
  - justification  : why a product is not affected (VEX flag/justification);
  - fixed versions : the versions a vendor_fix remediation points at;
  - provenance     : the publishing vendor;
  - dates          : initial + current release dates;
  - references.

VEX status is DATA: a vendor saying "not affected (vulnerable_code_not_in_execute_path)" is
recorded as applicability, never as an instruction or a permission change.
"""
from __future__ import annotations

import json
from pathlib import Path

import requests

from .rag import _record

# CSAF product_status keys → our normalized applicability labels
_STATUS = {"known_affected": "affected", "known_not_affected": "not_affected",
           "fixed": "fixed", "first_fixed": "fixed", "under_investigation": "under_investigation",
           "recommended": "fixed"}


def _product_names(tree: dict) -> dict[str, str]:
    """Flatten a CSAF product_tree → {product_id: full product name}."""
    names: dict[str, str] = {}
    for fpn in tree.get("full_product_names", []):
        if fpn.get("product_id"):
            names[fpn["product_id"]] = fpn.get("name", fpn["product_id"])

    def walk(branches):
        for b in branches or []:
            p = b.get("product")
            if p and p.get("product_id"):
                names[p["product_id"]] = p.get("name", p["product_id"])
            walk(b.get("branches"))
    walk(tree.get("branches"))
    return names


def parse_csaf(doc: dict) -> list[dict]:
    """Parse a CSAF 2.0 document (advisory or VEX) into RAG-compatible advisory records."""
    d = doc.get("document", {})
    publisher = (d.get("publisher") or {}).get("name", "") or "vendor"
    tracking = d.get("tracking", {})
    initial = tracking.get("initial_release_date", "")
    current = tracking.get("current_release_date", "")
    is_vex = (d.get("category", "") or "").lower() == "csaf_vex"
    names = _product_names(doc.get("product_tree", {}))

    out = []
    for v in doc.get("vulnerabilities", []):
        cve = v.get("cve", "") or (v.get("ids", [{}])[0].get("text", "") if v.get("ids") else "")
        cwe = v.get("cwe", {}) or {}
        # applicability per product status
        applic: dict[str, list[str]] = {}
        fixed_products: list[str] = []
        for key, pids in (v.get("product_status") or {}).items():
            label = _STATUS.get(key, key)
            for pid in pids or []:
                applic.setdefault(label, []).append(names.get(pid, pid))
                if label == "fixed":
                    fixed_products.append(names.get(pid, pid))
        # VEX justification for not-affected products (flags) + remediation fixed versions
        justification = ""
        for flag in v.get("flags", []) or []:
            if flag.get("label"):
                justification = flag["label"]
        fixed_versions: list[str] = []
        refs = [r["url"] for r in (v.get("references") or []) if r.get("url")][:5]
        for rem in v.get("remediations", []) or []:
            if rem.get("category") in ("vendor_fix", "mitigation") and rem.get("details"):
                fixed_versions.append(rem["details"][:120])
            if rem.get("url"):
                refs.append(rem["url"])
        summary = (v.get("title") or d.get("title") or cve or "advisory")[:300]
        out.append(_record(
            id=cve or f"ADV-{tracking.get('id', publisher)}", source=publisher,
            provenance=publisher, rtype="advisory", summary=summary,
            cwe_ids=[cwe["id"]] if cwe.get("id") else [],
            cwe=cwe.get("id", ""),
            fixed_versions=list(dict.fromkeys(fixed_versions + fixed_products)),
            applicability=json.dumps({"vex": is_vex, "status": applic,
                                      "justification": justification}),
            published=initial, modified=current, candidate=False,
            references=refs or None,
        ))
    return out


def vex_status(doc: dict, cve: str, product: str) -> str:
    """Resolve the VEX status of (cve, product) from a CSAF doc: affected / not_affected /
    fixed / under_investigation / unknown. Lets the agent skip a product a vendor cleared."""
    names = _product_names(doc.get("product_tree", {}))
    for v in doc.get("vulnerabilities", []):
        if v.get("cve") != cve:
            continue
        for key, pids in (v.get("product_status") or {}).items():
            for pid in pids or []:
                if product in (pid, names.get(pid, "")):
                    return _STATUS.get(key, key)
    return "unknown"


def fetch_csaf(url: str) -> list[dict]:
    """Fetch and parse a CSAF JSON document from a vendor's CSAF directory. Best-effort."""
    try:
        doc = requests.get(url, timeout=30,
                           headers={"User-Agent": "MetSec advisories"}).json()
    except (requests.RequestException, ValueError):
        return []
    return parse_csaf(doc)


def load_file(path: str | Path) -> list[dict]:
    return parse_csaf(json.loads(Path(path).read_text()))


if __name__ == "__main__":  # self-check: python -m metsec.advisories (offline; fixture)
    # A CSAF VEX doc: one product affected+fixed, one explicitly NOT affected (with justification)
    fixture = {
        "document": {
            "category": "csaf_vex", "title": "ACME HTTP Server advisory",
            "publisher": {"name": "ACME PSIRT"},
            "tracking": {"id": "ACME-2026-001", "initial_release_date": "2026-10-01",
                         "current_release_date": "2026-10-20"}},
        "product_tree": {"full_product_names": [
            {"product_id": "P1", "name": "ACME HTTP Server 1.2.3"},
            {"product_id": "P2", "name": "ACME HTTP Server 1.2.9"},
            {"product_id": "P3", "name": "ACME Lite 0.1"}]},
        "vulnerabilities": [{
            "cve": "CVE-2026-9999", "title": "Heap overflow in request parser",
            "cwe": {"id": "CWE-122", "name": "Heap overflow"},
            "product_status": {"known_affected": ["P1"], "fixed": ["P2"],
                               "known_not_affected": ["P3"]},
            "flags": [{"label": "vulnerable_code_not_in_execute_path", "product_ids": ["P3"]}],
            "remediations": [{"category": "vendor_fix", "details": "Upgrade to 1.2.9",
                              "product_ids": ["P2"], "url": "https://acme.example/fix"}],
            "references": [{"url": "https://acme.example/CVE-2026-9999"}]}]}

    recs = parse_csaf(fixture)
    assert len(recs) == 1
    r = recs[0]
    assert r["id"] == "CVE-2026-9999" and r["source"] == "ACME PSIRT" and r["rtype"] == "advisory"
    assert r["cwe"] == "CWE-122" and r["published"] == "2026-10-01" and r["modified"] == "2026-10-20"
    applic = json.loads(r["applicability"])
    assert applic["vex"] is True
    assert "ACME HTTP Server 1.2.3" in applic["status"]["affected"]
    assert "ACME Lite 0.1" in applic["status"]["not_affected"]
    assert applic["justification"] == "vulnerable_code_not_in_execute_path"
    assert any("1.2.9" in x for x in r["fixed_versions"])

    # VEX resolution: a vendor "not affected" is surfaced, not treated as vulnerable
    assert vex_status(fixture, "CVE-2026-9999", "ACME Lite 0.1") == "not_affected"
    assert vex_status(fixture, "CVE-2026-9999", "ACME HTTP Server 1.2.3") == "affected"
    assert vex_status(fixture, "CVE-2026-9999", "Unknown Product") == "unknown"
    print("advisories self-check ok")
