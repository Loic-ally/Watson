"""Phase 4 — reporting. Dedup + rank findings, write findings.json + Markdown.

A run's findings become two artifacts: a machine-readable findings.json (meta +
summary + findings) and a shareable report.md, both ranked critical→info and
verified-before-potential.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# A consistent CVSS band per severity (verified findings score at the top of the band).
SEV_CVSS = {"critical": (9.0, 10.0), "high": (7.0, 8.9), "medium": (4.0, 6.9),
            "low": (0.1, 3.9), "info": (0.0, 0.0)}


def cvss(f) -> float:
    lo, hi = SEV_CVSS.get(f.severity, (0.0, 0.0))
    return round(hi if f.status == "verified" else (lo + hi) / 2, 1)


def overall_score(findings: list) -> float:
    return max((cvss(f) for f in findings), default=0.0)


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


def _markdown(findings: list, meta: dict, hypotheses: list | None = None,
              shots: list | None = None) -> str:
    counts = summarize(findings)
    badge = " · ".join(f"{n} {s}" for s, n in counts.items())
    out = [
        f"# MetSec report — {meta.get('target', '')}", "",
        f"- **Mode:** {meta.get('mode', '')}",
        f"- **Exploitation:** {'enabled' if meta.get('exploit') else 'disabled'}",
        f"- **Authorized by:** {meta.get('authorized_by', '')}",
        f"- **Date:** {meta.get('date', '')}",
        *([f"- **Audit log:** {meta['audit']}"] if meta.get("audit") else []),
        f"- **Findings:** {len(findings)} ({badge})" if findings else "- **Findings:** 0",
        f"- **Overall risk (CVSS):** {overall_score(findings)}",
        "", "---", "",
    ]
    if meta.get("narrative"):
        out += ["## Attack narrative", "", meta["narrative"], "", "---", ""]
    if hypotheses:
        out += ["## Hypotheses & attack chain", ""]
        for h in hypotheses:
            mark = {"confirmed": "✅", "refuted": "❌"}.get(h.status, "🔎")
            out.append(f"- {mark} **{h.statement}**")
            if h.based_on:
                out.append(f"  - links: {', '.join(str(b) for b in h.based_on)}")
            if h.test:
                out.append(f"  - test: {h.test}")
        out += ["", "---", ""]
    for f in findings:
        out.append(f"## [{f.severity.upper()} · {f.status}] {f.title}")
        out.append(f"- **CVSS:** {cvss(f)}")
        if f.affected:
            out.append(f"- **Where:** {f.affected}")
        if getattr(f, "exploitation", ""):
            out.append(f"- **How it's exploited:** {f.exploitation}")
        if f.evidence:
            out.append(f"- **Evidence:** {f.evidence}")
        if f.remediation:
            out.append(f"- **Fix:** {f.remediation}")
        if f.refs:
            out.append(f"- **References:** {', '.join(str(r) for r in f.refs)}")
        out.append("")
    if not findings:
        out.append("_No findings._")
    if shots:
        out += ["", "---", "", "## Screenshots", ""]
        for s in shots:
            cap = s.get("caption") or s.get("url") or s["id"]
            out.append(f"![{cap}](shots/{s['id']}.png)")
            out.append(f"*{cap}*")
            out.append("")
    return "\n".join(out)


def narrative(findings: list, hypotheses: list | None = None) -> str:
    """LLM-written attack-chain narrative (one paragraph). Empty string on failure."""
    from . import config

    if not findings:
        return ""
    fs = "\n".join(f"- [{f.severity}/{f.status}] {f.title} @ {f.affected}" for f in findings[:20])
    hy = "\n".join(f"- {h.statement}" for h in (hypotheses or [])[:10])
    prompt = ("Write a concise one-paragraph attack-chain narrative for this authorized pentest: "
              "how the findings connect from entry point to impact. Prose only.\n\n"
              f"Findings:\n{fs}\n\nHypotheses:\n{hy}")
    try:
        return config.chat(prompt, model=config.FAST).strip()
    except Exception:  # noqa: BLE001 — narrative is best-effort
        return ""


def _html(findings: list, meta: dict, hypotheses: list, narr: str, shots: list | None = None) -> str:
    import html as _h

    def esc(s):
        return _h.escape(str(s or ""))

    color = {"critical": "#f87272", "high": "#fb7185", "medium": "#fbbd23",
             "low": "#3b82f6", "info": "#6b7689"}
    cards = []
    for f in findings:
        c = color.get(f.severity, "#6b7689")
        rows = [f'<div class="r"><b>{lbl}:</b> {esc(val)}</div>' for lbl, val in (
            ("Where", f.affected), ("How exploited", getattr(f, "exploitation", "")),
            ("Evidence", f.evidence), ("Fix", f.remediation)) if val]
        cards.append(f'<div class="f" style="border-left-color:{c}"><div class="hd">'
                     f'<span class="sev" style="background:{c}">{esc(f.severity.upper())} · {esc(f.status)}</span>'
                     f'<b>{esc(f.title)}</b><span class="cv">CVSS {cvss(f)}</span></div>'
                     + "".join(rows) + "</div>")
    hyps = "".join(f"<li>{esc(h.statement)} <i>({esc(h.status)})</i></li>" for h in hypotheses)
    gallery = ""
    if shots:
        figs = "".join(
            f'<figure class="shot"><a href="shots/{esc(s["id"])}.png" target="_blank">'
            f'<img src="shots/{esc(s["id"])}.png" loading="lazy"></a>'
            f'<figcaption>{esc(s.get("caption") or s.get("url"))}</figcaption></figure>'
            for s in shots)
        gallery = f"<h2>Screenshots</h2><div class='gal'>{figs}</div>"
    badge = " · ".join(f"{n} {s}" for s, n in summarize(findings).items())
    return (
        "<!doctype html><html><head><meta charset='utf-8'><title>MetSec Report</title><style>"
        "body{background:#0b0e14;color:#c9d4e3;font:14px/1.6 ui-sans-serif,system-ui,sans-serif;"
        "max-width:900px;margin:0 auto;padding:24px}h1{color:#36d399}h2{color:#8aa0bd;"
        "border-bottom:1px solid #1f2633;padding-bottom:6px;margin-top:28px}.meta{color:#6b7689;font-size:13px}"
        ".f{background:#121722;border-left:4px solid;border-radius:0 6px 6px 0;padding:12px 16px;margin:10px 0}"
        ".hd{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.sev{color:#0b0e14;font-weight:700;"
        "font-size:11px;padding:2px 8px;border-radius:4px}.cv{margin-left:auto;color:#6b7689;font-size:12px}"
        ".r{font-size:13px;margin-top:6px;color:#aab6c6}.r b{color:#c9d4e3}.score{font-size:22px;color:#f87272;"
        "font-weight:700}li{margin:4px 0}"
        ".gal{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}"
        ".shot{margin:0;background:#121722;border:1px solid #1f2633;border-radius:6px;padding:8px}"
        ".shot img{width:100%;border-radius:4px;display:block}"
        ".shot figcaption{color:#6b7689;font-size:12px;margin-top:6px;word-break:break-word}"
        "</style></head><body><h1>⬢ MetSec Report</h1>"
        f"<p class='meta'>{esc(meta.get('target'))} · mode {esc(meta.get('mode'))} · exploitation "
        f"{'on' if meta.get('exploit') else 'off'} · {esc(meta.get('date'))}<br>authorized by "
        f"{esc(meta.get('authorized_by'))}</p>"
        f"<p>Overall risk (CVSS): <span class='score'>{overall_score(findings)}</span> — "
        f"{len(findings)} findings ({esc(badge)})</p>"
        + (f"<h2>Attack narrative</h2><p>{esc(narr)}</p>" if narr else "")
        + (f"<h2>Hypotheses &amp; attack chain</h2><ul>{hyps}</ul>" if hyps else "")
        + "<h2>Findings</h2>" + ("".join(cards) if cards else "<p>No findings.</p>")
        + gallery
        + "</body></html>")


def _copy_shots(shots: list, out: Path) -> list:
    """Copy each captured screenshot into <out>/shots/ so the report is self-contained."""
    import shutil

    from . import shots as store

    saved = []
    if not shots:
        return saved
    dest = out / "shots"
    dest.mkdir(exist_ok=True)
    for s in shots:
        sid = s.get("id")
        src = store.path(sid) if sid else None
        if not src:
            continue
        try:
            shutil.copyfile(src, dest / f"{sid}.png")
            saved.append({"id": sid, "url": s.get("url", ""), "caption": s.get("caption", "")})
        except OSError:
            continue
    return saved


def write_reports(findings: list, meta: dict, out_dir: str, hypotheses: list | None = None,
                  narrative: str = "", shots: list | None = None) -> tuple[Path, Path, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    ranked = dedup_rank(findings)
    shots = _copy_shots(shots or [], out)
    meta = {**meta, "narrative": narrative, "overall_cvss": overall_score(ranked)}
    data = {"meta": meta, "summary": summarize(ranked),
            "findings": [{**asdict(f), "cvss": cvss(f)} for f in ranked],
            "hypotheses": [asdict(h) for h in (hypotheses or [])],
            "shots": shots}
    jpath, mpath, hpath = out / "findings.json", out / "report.md", out / "report.html"
    jpath.write_text(json.dumps(data, indent=2))
    mpath.write_text(_markdown(ranked, meta, hypotheses or [], shots))
    hpath.write_text(_html(ranked, meta, hypotheses or [], narrative, shots))
    return jpath, mpath, hpath


def _template_html() -> str | None:
    for p in (Path("template.html"), Path(__file__).resolve().parent.parent / "template.html"):
        if p.exists():
            return p.read_text()
    return None


def _fallback_html(data: dict) -> str:
    from .agent import Finding, Hypothesis

    fs = [Finding(title=f.get("title", ""), severity=f.get("severity", "info"),
                  status=f.get("status", "potential"), affected=f.get("affected", ""),
                  evidence=f.get("evidence", ""), remediation=f.get("remediation", ""),
                  refs=f.get("refs", []), exploitation=f.get("exploitation", ""))
          for f in data.get("findings", [])]
    hs = [Hypothesis(**{k: h.get(k) for k in ("statement", "based_on", "test", "status")})
          for h in data.get("hypotheses", [])]
    meta = data.get("meta", {})
    return _html(fs, meta, hs, meta.get("narrative", ""), data.get("shots", []))


def craft_template_html(data: dict) -> str:
    """Spark Contributor fills template.html with the findings; falls back to the built-in report."""
    from . import config

    tpl = _template_html()
    if tpl:
        meta, findings = data.get("meta", {}), data.get("findings", [])
        prompt = (
            "You produce a penetration-test report by FILLING an HTML template. Replace EVERY "
            "[ ... ] placeholder with real content from the data. Rules:\n"
            "- Map severity to priority: critical/high → HIGH PRIORITY (var(--high)); medium → "
            "MEDIUM PRIORITY (var(--medium)); low → LOW PRIORITY (var(--low)); info → GENERAL "
            "IMPROVEMENT (var(--general)). Set the 4 count cards and the OVERVIEW table (one row "
            "per finding).\n"
            "- Create ONE finding slide per finding by duplicating the finding <section> pattern "
            "(slides 4–7): keep the EXACT css classes and --x/--y/--w/--h coords; change only the "
            "text, the priority label+color, 'FINDING N / TOTAL', and the page number. Description "
            "= what/why (from title+evidence+how-exploited); Action Required = the fix.\n"
            "- NEXT STEPS = top remediation priorities. Title/scope/date/auth from meta.\n"
            "Output ONLY the complete HTML document.\n\n"
            f"=== TEMPLATE ===\n{tpl}\n\n=== DATA ===\n"
            + json.dumps({"meta": meta, "findings": findings[:14]}, default=str)[:7000])
        try:
            out = config.chat(prompt, model=config.FAST)
            m = re.search(r"<!doctype html.*</html>", out, re.DOTALL | re.IGNORECASE) \
                or re.search(r"<html.*</html>", out, re.DOTALL | re.IGNORECASE)
            html = m.group(0) if m else out
            if "<html" in html.lower() and "slide" in html:
                return html
        except Exception:  # noqa: BLE001 — fall back to the built-in report
            pass
    return _fallback_html(data)


def to_pdf(html: str, out_path: str) -> str:
    """Render HTML → PDF with headless Chromium (respects the template's @page size)."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        b = p.chromium.launch(headless=True, args=["--no-sandbox"])
        try:
            page = b.new_page()
            page.set_content(html, wait_until="networkidle")
            page.pdf(path=out_path, prefer_css_page_size=True, print_background=True)
        finally:
            b.close()
    return out_path


def make_pdf(report_dir: str) -> str | None:
    """Craft the template report for a report dir's findings.json and render it to report.pdf."""
    d = Path(report_dir)
    f = d / "findings.json"
    if not f.exists():
        return None
    data = json.loads(f.read_text())
    html = craft_template_html(data)
    (d / "report_filled.html").write_text(html)
    return to_pdf(html, str(d / "report.pdf"))


if __name__ == "__main__":  # self-check: python -m metsec.report (offline)
    import tempfile

    from .agent import Finding, Hypothesis

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
        hyps = [Hypothesis("looted DB password may unlock the admin login",
                           ["Exposed .env", "admin login form"], "replay creds", "confirmed")]
        j, m, h = write_reports(fs, meta, d, hypotheses=hyps, narrative="chained .env creds to admin")
        data = json.loads(j.read_text())
        assert len(data["findings"]) == 3 and data["meta"]["exploit"] is True
        assert data["findings"][0]["cvss"] == 10.0 and data["meta"]["overall_cvss"] == 10.0
        assert data["hypotheses"][0]["status"] == "confirmed"
        md = m.read_text()
        assert "Exposed .env" in md and "CVSS:" in md and "Attack narrative" in md
        assert "Hypotheses & attack chain" in md and "looted DB password" in md
        html = h.read_text()
        assert "<html" in html and "Exposed .env" in html and "CVSS 10.0" in html
    print("report self-check ok")
