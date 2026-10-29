"""Security control catalogs + a coverage tracker.

Two distinct things, kept apart from the structured vuln data (CVE/EPSS/advisories):

1. Control CATALOGS — versioned requirement/procedure sets (OWASP ASVS, OWASP WSTG, CIS
   Benchmarks). Each control carries: id, title, requirement, references, preconditions,
   expected_evidence and limits. Loaded from a documented, VALIDATED JSON "pack" format so a
   malformed or unversioned pack is rejected rather than half-trusted. Catalog text is DATA:
   it never grants permissions or instructs the agent.

2. A COVERAGE tracker — per audit, each control is in exactly one state:
   compliant | non-compliant | not-applicable | not-verified (default). A control is NEVER
   promoted to `compliant` without linked evidence (observation/finding ids) — an untested
   control stays `not-verified`, mirroring the finding-status rule.

CWE / OWASP Cheat Sheet Series give classification + remediation guidance, exposed via
remediation_for(cwe_id). CIS content is license-gated: the import interface + a fixture are
provided; real CIS corpora are imported only where the operator holds the rights.
"""
from __future__ import annotations

import json
from pathlib import Path

STATES = ("compliant", "non-compliant", "not-applicable", "not-verified")
_PACK_DIR = Path(__file__).resolve().parent / "data" / "controls"
_REQUIRED = ("id", "title", "requirement")


class InvalidPack(ValueError):
    """A controls pack is missing a framework/version or a required control field."""


def _control(c: dict) -> dict:
    missing = [k for k in _REQUIRED if not c.get(k)]
    if missing:
        raise InvalidPack(f"control missing {missing}: {c.get('id') or c}")
    return {"id": c["id"], "title": c["title"], "requirement": c["requirement"],
            "references": list(c.get("references") or []),
            "preconditions": list(c.get("preconditions") or []),
            "expected_evidence": list(c.get("expected_evidence") or []),
            "limits": c.get("limits", ""),
            "level": c.get("level", ""),          # optional (e.g. ASVS L1/L2/L3)
            "cwe": list(c.get("cwe") or [])}      # CWE ids this control maps to


def load_pack(data: dict) -> dict:
    """Validate a controls pack {framework, version, controls:[...]} → normalized pack."""
    fw, ver = data.get("framework"), str(data.get("version", ""))
    if not fw or not ver:
        raise InvalidPack("pack needs an explicit framework and version")
    controls = [_control(c) for c in data.get("controls", [])]
    if not controls:
        raise InvalidPack("pack has no controls")
    return {"framework": fw, "version": ver, "controls": controls}


def load_pack_file(path: str | Path) -> dict:
    return load_pack(json.loads(Path(path).read_text()))


def available_packs() -> list[str]:
    return sorted(p.name for p in _PACK_DIR.glob("*.json")) if _PACK_DIR.exists() else []


def load_builtin(name: str) -> dict:
    """Load a shipped pack by file stem (e.g. 'asvs-4.0.3', 'wstg-4.2', 'cis-fixture')."""
    return load_pack_file(_PACK_DIR / f"{name}.json")


def import_cis(path: str | Path) -> dict:
    """Import a CIS Benchmark pack the operator is licensed to use (same validated format).

    CIS Benchmark content is distributed under terms that forbid redistribution, so no real
    CIS corpus ships here. Provide a pack exported under your own CIS membership/agreement;
    this validates and loads it. Without it, only the fixture (cis-fixture) is available —
    clearly marked as a sample, not the real benchmark.
    """
    return load_pack_file(path)


# ------------------------------- coverage -----------------------------------

class Coverage:
    """Tracks the status of each control for one audit. Default = not-verified; a control is
    only `compliant` when evidence is linked (never silently from 'not tested')."""

    def __init__(self, pack: dict):
        self.pack = pack
        self.controls = {c["id"]: dict(c) for c in pack["controls"]}
        self.status = {cid: "not-verified" for cid in self.controls}
        self.evidence: dict[str, list] = {cid: [] for cid in self.controls}

    def mark(self, control_id: str, state: str, evidence: list | None = None) -> dict:
        if control_id not in self.controls:
            return {"error": f"unknown control {control_id!r}"}
        if state not in STATES:
            return {"error": f"state must be one of {STATES}"}
        ev = list(evidence or [])
        if state == "compliant" and not ev:
            # cannot declare a control met without evidence — stays not-verified
            return {"error": "compliant requires linked evidence (observation/finding ids)",
                    "control": control_id, "status": self.status[control_id]}
        self.status[control_id] = state
        self.evidence[control_id] = ev
        return {"control": control_id, "status": state, "evidence": ev}

    def summary(self) -> dict:
        counts = {s: 0 for s in STATES}
        for s in self.status.values():
            counts[s] += 1
        return {"framework": self.pack["framework"], "version": self.pack["version"],
                "total": len(self.controls), "counts": counts,
                # an untested control is NEVER counted as compliant
                "verified_compliant": counts["compliant"]}

    def to_dict(self) -> dict:
        return {"framework": self.pack["framework"], "version": self.pack["version"],
                "summary": self.summary(),
                "controls": [{"id": cid, "title": self.controls[cid]["title"],
                              "status": self.status[cid], "evidence": self.evidence[cid]}
                             for cid in self.controls]}


# ---------------------------- CWE remediation -------------------------------
# Minimal CWE → (name, OWASP Cheat Sheet, remediation) map. Documentary guidance, not a score.
_CWE = {
    "CWE-89": ("SQL Injection", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
               "Use parameterized queries / prepared statements; never concatenate input into SQL."),
    "CWE-79": ("Cross-site Scripting", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
               "Context-aware output encoding; a strict Content-Security-Policy; avoid raw innerHTML."),
    "CWE-78": ("OS Command Injection", "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
               "Avoid the shell; pass args as a list; allow-list inputs; never interpolate into commands."),
    "CWE-502": ("Deserialization of Untrusted Data", "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
                "Do not deserialize untrusted data; use safe formats (JSON) and signed/validated payloads."),
    "CWE-22": ("Path Traversal", "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
               "Canonicalize and confine paths to an allow-listed base directory."),
    "CWE-918": ("SSRF", "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                "Allow-list destinations; block internal ranges and redirects to them."),
}


_CWE_CATALOG: dict | None = None


def _cwe_catalog() -> dict:
    """The full MITRE CWE list (id → {name, description}), loaded once from data/cwe.json."""
    global _CWE_CATALOG
    if _CWE_CATALOG is None:
        f = Path(__file__).resolve().parent / "data" / "cwe.json"
        try:
            _CWE_CATALOG = json.loads(f.read_text()).get("weaknesses", {})
        except (OSError, ValueError):
            _CWE_CATALOG = {}
    return _CWE_CATALOG


def remediation_for(cwe_id: str) -> dict | None:
    """Classification + remediation for a CWE. A curated OWASP Cheat Sheet is returned when
    one exists; otherwise the real CWE name/description from the MITRE catalog is returned, so
    any of the ~950 weaknesses is at least classified."""
    key = (cwe_id or "").upper().strip()
    cs = _CWE.get(key)
    cat = _cwe_catalog().get(key)
    if not cs and not cat:
        return None
    out = {"cwe": key, "name": cs[0] if cs else cat["name"]}
    if cs:
        out["cheat_sheet"] = cs[1]
        out["remediation"] = cs[2]
    if cat:
        out["description"] = cat["description"]
        out.setdefault("name", cat["name"])
    return out


if __name__ == "__main__":  # self-check: python -m metsec.controls (offline)
    pack = load_pack({
        "framework": "ASVS", "version": "4.0.3",
        "controls": [
            {"id": "V2.1.1", "title": "Password length", "requirement": "Allow >= 12 chars.",
             "references": ["ASVS-2.1.1"], "preconditions": ["an auth flow exists"],
             "expected_evidence": ["registration accepts a 64-char password"],
             "limits": "does not assess password storage (see V2.4)"},
            {"id": "V5.3.4", "title": "SQLi defense", "requirement": "Use parameterized queries."},
        ]})
    assert pack["version"] == "4.0.3" and len(pack["controls"]) == 2
    assert pack["controls"][0]["expected_evidence"] == ["registration accepts a 64-char password"]

    # a pack without a version or with a control missing a required field is rejected
    for bad in ({"framework": "ASVS", "controls": [{"id": "x", "title": "t", "requirement": "r"}]},
                {"framework": "ASVS", "version": "1", "controls": [{"id": "x"}]}):
        try:
            load_pack(bad); raise AssertionError("should reject")
        except InvalidPack:
            pass

    cov = Coverage(pack)
    assert cov.summary()["counts"]["not-verified"] == 2        # default: nothing assumed
    # compliant without evidence is refused → stays not-verified
    assert "error" in cov.mark("V5.3.4", "compliant")
    assert cov.status["V5.3.4"] == "not-verified"
    assert cov.mark("V5.3.4", "compliant", evidence=["OBS-3"])["status"] == "compliant"
    assert cov.mark("V2.1.1", "non-compliant", ["OBS-5"])["status"] == "non-compliant"
    s = cov.summary()
    assert s["counts"] == {"compliant": 1, "non-compliant": 1, "not-applicable": 0,
                           "not-verified": 0} and s["verified_compliant"] == 1
    assert "unknown control" in cov.mark("NOPE", "compliant", ["x"])["error"]

    r = remediation_for("CWE-89")
    assert r["name"] == "SQL Injection" and "parameterized" in r["remediation"].lower()
    # any MITRE CWE is at least classified from the full catalog (if data/cwe.json shipped)
    if _cwe_catalog():
        assert remediation_for("CWE-502")["name"]            # curated
        assert (r312 := remediation_for("CWE-312")) and r312.get("description")  # catalog-only
    assert remediation_for("CWE-0000") is None

    # the shipped catalogs load and validate (full ASVS / WSTG, plus the CIS sample)
    for name in ("asvs-4.0.3", "wstg-4.2", "cis-fixture"):
        pk = load_builtin(name)
        assert pk["controls"], name
    asvs = load_builtin("asvs-4.0.3")
    assert len(asvs["controls"]) > 200 and asvs["version"] == "4.0.3"
    assert any(c["id"] == "V5.3.4" for c in asvs["controls"])
    print("controls self-check ok")
