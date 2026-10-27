"""Phase 4 — reporting. Dedup + rank findings, write findings.json + Markdown.

A run's findings become two artifacts: a machine-readable findings.json (meta +
summary + findings) and a shareable report.md, both ranked critical→info and
verified-before-potential.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _rank(f) -> tuple:
    return (SEV_ORDER.get(f.severity, 9), 0 if f.status == "verified" else 1)


def dedup_rank(findings: list) -> list:
    """Collapse duplicate (title, affected) findings, keeping the strongest; then rank."""
    best: dict[tuple, object] = {}
    for f in findings:
        key = (f.title.strip().lower(), f.affected.strip().lower())
        if key not in best or _rank(f) < _rank(best[key]):
            best[key] = f
    return sorted(best.values(), key=_rank)


def summarize(findings: list) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {s: counts[s] for s in SEV_ORDER if s in counts}


def _markdown(findings: list, meta: dict) -> str:
    counts = summarize(findings)
    badge = " · ".join(f"{n} {s}" for s, n in counts.items())
    out = [
        f"# MetSec report — {meta.get('target', '')}", "",
        f"- **Mode:** {meta.get('mode', '')}",
        f"- **Exploitation:** {'enabled' if meta.get('exploit') else 'disabled'}",
        f"- **Authorized by:** {meta.get('authorized_by', '')}",
        f"- **Date:** {meta.get('date', '')}",
        f"- **Findings:** {len(findings)} ({badge})" if findings else "- **Findings:** 0",
        "", "---", "",
    ]
    for f in findings:
        out.append(f"## [{f.severity.upper()} · {f.status}] {f.title}")
        if f.affected:
            out.append(f"- **Affected:** {f.affected}")
        if f.evidence:
            out.append(f"- **Evidence:** {f.evidence}")
        if f.remediation:
            out.append(f"- **Remediation:** {f.remediation}")
        if f.refs:
            out.append(f"- **References:** {', '.join(str(r) for r in f.refs)}")
        out.append("")
    if not findings:
        out.append("_No findings._")
    return "\n".join(out)


def write_reports(findings: list, meta: dict, out_dir: str) -> tuple[Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ranked = dedup_rank(findings)
    data = {"meta": meta, "summary": summarize(ranked),
            "findings": [asdict(f) for f in ranked]}
    jpath, mpath = out / "findings.json", out / "report.md"
    jpath.write_text(json.dumps(data, indent=2))
    mpath.write_text(_markdown(ranked, meta))
    return jpath, mpath


if __name__ == "__main__":  # self-check: python -m metsec.report (offline)
    import tempfile

    from .agent import Finding

    fs = [
        Finding("Reflected XSS", "medium", "potential", affected="/search"),
        Finding("Reflected XSS", "medium", "verified", affected="/search"),  # dup, stronger
        Finding("Exposed .env", "critical", "verified", affected="/.env"),
        Finding("Missing headers", "low", "verified"),
    ]
    ranked = dedup_rank(fs)
    assert [f.title for f in ranked] == ["Exposed .env", "Reflected XSS", "Missing headers"], ranked
    assert ranked[1].status == "verified", "kept the stronger duplicate"
    assert summarize(ranked) == {"critical": 1, "medium": 1, "low": 1}

    with tempfile.TemporaryDirectory() as d:
        meta = {"target": "http://x/", "mode": "dev", "exploit": True,
                "authorized_by": "owner", "date": "2026-10-27"}
        j, m = write_reports(fs, meta, d)
        data = json.loads(j.read_text())
        assert len(data["findings"]) == 3 and data["meta"]["exploit"] is True
        assert "Exposed .env" in m.read_text() and "Exploitation:** enabled" in m.read_text()
    print("report self-check ok")
