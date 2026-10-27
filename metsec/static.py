"""Static analysis (mode: static) — code + dependency review, no traffic.

Two signals, both grounded in the source tree at scope.code_path:
  - dependency lockfiles (requirements*.txt, package.json) → {name, version, ecosystem}
    for OSV lookup by the agent/research.
  - a pattern-based source scan for risky sinks (SQLi, command injection, SSTI,
    open redirect, SSRF, hardcoded secrets, eval/pickle, debug).

ponytail: regex rules, not full AST dataflow (known ceiling) — enough to surface
candidates a reviewer/agent then confirms; add AST/semgrep rules if precision matters.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_SKIP_DIRS = {".venv", "venv", "node_modules", ".git", "__pycache__", "dist", "build"}

# (id, severity, pattern, message)
RULES = [
    ("sql-injection", "high",
     re.compile(r"(SELECT|INSERT|UPDATE|DELETE)\b.*(%s|%d|['\"]\s*%\s|\.format\(|['\"]\s*\+|f['\"])", re.I),
     "SQL query built with string formatting/concatenation"),
    ("command-injection", "high",
     re.compile(r"(os\.system|subprocess\.(getoutput|call|run|Popen|check_output))\s*\([^)]*(\+|%|\.format|f['\"])"),
     "Shell command built from a variable"),
    ("command-injection", "high", re.compile(r"shell\s*=\s*True"),
     "subprocess called with shell=True"),
    ("ssti", "high",
     re.compile(r"render_template_string\s*\([^)]*(\+|%|\.format|f['\"])"),
     "Template rendered from concatenated/interpolated input (SSTI)"),
    ("open-redirect", "medium", re.compile(r"redirect\s*\(\s*request\."),
     "Redirect to a user-controlled destination"),
    ("ssrf", "medium",
     re.compile(r"requests\.(get|post|put|head)\s*\(\s*[A-Za-z_][\w.]*\b"),
     "Outbound request to a non-literal URL (possible SSRF)"),
    ("deserialization", "high", re.compile(r"(pickle\.loads|yaml\.load)\s*\((?!.*Safe)"),
     "Unsafe deserialization"),
    ("code-exec", "high", re.compile(r"\b(eval|exec)\s*\("),
     "Dynamic code execution"),
    ("hardcoded-secret", "medium",
     re.compile(r"(secret_key|password|passwd|api_key|token)\s*=\s*['\"][^'\"]{6,}['\"]", re.I),
     "Hardcoded secret"),
    ("hardcoded-secret", "high", re.compile(r"AKIA[0-9A-Z]{16}"),
     "Hardcoded AWS access key id"),
    ("debug-enabled", "medium", re.compile(r"debug\s*=\s*True"),
     "Debug mode enabled"),
    ("weak-hash", "low", re.compile(r"hashlib\.(md5|sha1)\s*\("),
     "Weak hash algorithm"),
]


def _scan_source(root: str) -> list[dict]:
    findings = []
    for path in Path(root).rglob("*.py"):
        if _SKIP_DIRS & set(path.parts):
            continue
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            for rid, sev, rx, msg in RULES:
                if rx.search(line):
                    findings.append({"file": str(path), "line": n, "rule": rid,
                                     "severity": sev, "message": msg,
                                     "snippet": line.strip()[:160]})
    return findings


def _parse_deps(root: str) -> list[dict]:
    deps = []
    for rf in Path(root).rglob("requirements*.txt"):
        if _SKIP_DIRS & set(rf.parts):
            continue
        for line in rf.read_text(errors="ignore").splitlines():
            m = re.match(r"([A-Za-z0-9_.\-]+)\s*==\s*([0-9][\w.\-]*)", line.split("#")[0].strip())
            if m:
                deps.append({"name": m.group(1).lower(), "version": m.group(2), "ecosystem": "PyPI"})
    for pj in Path(root).rglob("package.json"):
        if _SKIP_DIRS & set(pj.parts):
            continue
        try:
            data = json.loads(pj.read_text(errors="ignore"))
        except ValueError:
            continue
        for sec in ("dependencies", "devDependencies"):
            for name, ver in (data.get(sec) or {}).items():
                deps.append({"name": name, "ecosystem": "npm",
                             "version": re.sub(r"[^0-9.].*$", "", str(ver).lstrip("^~"))})
    return deps


def analyze(code_path: str) -> dict:
    return {"mode": "static", "code_path": code_path,
            "deps": _parse_deps(code_path), "code_findings": _scan_source(code_path)}


if __name__ == "__main__":  # self-check: python -m metsec.static (offline)
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "app.py").write_text(
            'q = "SELECT * FROM t WHERE u=\'%s\'" % u\n'
            'import subprocess; subprocess.getoutput("ping " + host)\n'
            'render_template_string("Hi " + name)\n'
            'redirect(request.args.get("next"))\n'
            'SECRET_KEY = "dev-secret-key-change-me"\n'
            'app.run(debug=True)\n')
        (Path(d) / "requirements.txt").write_text("requests==2.19.1\nJinja2==2.10\n")
        out = analyze(d)
        rules = {f["rule"] for f in out["code_findings"]}
        assert {"sql-injection", "command-injection", "ssti", "open-redirect",
                "hardcoded-secret", "debug-enabled"} <= rules, rules
        names = {dep["name"] for dep in out["deps"]}
        assert names == {"requests", "jinja2"} and out["deps"][0]["version"] == "2.19.1", out["deps"]
    print("static self-check ok")
