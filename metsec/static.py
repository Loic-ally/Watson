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

import ast
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


def _scan_regex(path: str, lines: list[str]) -> list[dict]:
    out = []
    for n, line in enumerate(lines, 1):
        for rid, sev, rx, msg in RULES:
            if rx.search(line):
                out.append({"file": path, "line": n, "rule": rid, "severity": sev,
                            "message": msg, "snippet": line.strip()[:160]})
    return out


def _callname(func) -> str:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _callname(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return ""


def _kw_true(node, name: str) -> bool:
    return any(k.arg == name and isinstance(k.value, ast.Constant) and k.value.value is True
               for k in node.keywords)


def _refs_request(node) -> bool:
    return any(isinstance(n, ast.Name) and n.id == "request" for n in ast.walk(node))


class _PyVisitor(ast.NodeVisitor):
    """AST sinks — precise: ignores parameterized queries / literal commands."""

    def __init__(self, path: str):
        self.path = path
        self.out: list[dict] = []

    def _add(self, node, rule, sev, msg):
        self.out.append({"file": self.path, "line": getattr(node, "lineno", 0),
                         "rule": rule, "severity": sev, "message": msg, "snippet": ""})

    def _nonliteral_arg(self, node) -> bool:
        return bool(node.args) and not isinstance(node.args[0], ast.Constant)

    def visit_Call(self, node):
        name = _callname(node.func)
        if _kw_true(node, "shell"):
            self._add(node, "command-injection", "high", "subprocess called with shell=True")
        if name in ("os.system", "os.popen"):
            self._add(node, "command-injection", "high", f"{name} runs a shell command")
        if name.startswith("subprocess.") and self._nonliteral_arg(node):
            self._add(node, "command-injection", "high", f"{name} with a non-literal command")
        if name in ("eval", "exec"):
            self._add(node, "code-exec", "high", "dynamic code execution")
        if name == "pickle.loads":
            self._add(node, "deserialization", "high", "unsafe pickle deserialization")
        if name == "yaml.load" and not any(k.arg == "Loader" for k in node.keywords):
            self._add(node, "deserialization", "high", "yaml.load without a safe Loader")
        if name.endswith("render_template_string") and self._nonliteral_arg(node):
            self._add(node, "ssti", "high", "template rendered from a non-literal (SSTI)")
        if name.endswith("redirect") and node.args and _refs_request(node.args[0]):
            self._add(node, "open-redirect", "medium", "redirect to a user-controlled value")
        if name in ("requests.get", "requests.post", "requests.put", "requests.head") \
                and self._nonliteral_arg(node):
            self._add(node, "ssrf", "medium", "outbound request to a non-literal URL")
        if _kw_true(node, "debug"):
            self._add(node, "debug-enabled", "medium", "debug mode enabled")
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executescript") \
                and self._nonliteral_arg(node):
            self._add(node, "sql-injection", "high", "SQL query from a non-literal (injection risk)")
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and re.search(r"AKIA[0-9A-Z]{16}", node.value):
            self._add(node, "hardcoded-secret", "high", "hardcoded AWS access key id")

    def visit_Assign(self, node):
        if (isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
                and len(node.value.value) >= 6):
            for t in node.targets:
                nm = ast.unparse(t).lower()
                if any(s in nm for s in ("secret", "password", "passwd", "api_key",
                                         "apikey", "token")):
                    self._add(node, "hardcoded-secret", "medium", f"hardcoded secret in {nm}")
        self.generic_visit(node)


def _scan_python(path: str, tree, lines: list[str]) -> list[dict]:
    v = _PyVisitor(path)
    v.visit(tree)
    for f in v.out:
        ln = f["line"]
        f["snippet"] = lines[ln - 1].strip()[:160] if 0 < ln <= len(lines) else ""
    return v.out


def _scan_source(root: str) -> list[dict]:
    findings = []
    for path in Path(root).rglob("*.py"):
        if _SKIP_DIRS & set(path.parts):
            continue
        try:
            src = path.read_text(errors="ignore")
        except OSError:
            continue
        lines = src.splitlines()
        try:
            tree = ast.parse(src)
        except SyntaxError:
            findings += _scan_regex(str(path), lines)  # fall back if it won't parse
            continue
        findings += _scan_python(str(path), tree, lines)
    return findings


# ---------------------------- dependencies ----------------------------------
# Three distinct notions, never conflated (a range in a manifest is NOT an installed version):
#   declared : the CONSTRAINT written in a manifest  (package.json "^1.2.3", requirements ">=1")
#   resolved : the exact version pinned by a LOCKFILE (package-lock.json, a == pin)
#   observed : a version actually seen in an environment (SBOM / runtime) — rarely available here
# `version` is the best exact version for an OSV lookup: resolved first, else an exact pin,
# else "" (a bare range can't be looked up exactly and must NOT be guessed).

def _dep(name, ecosystem, declared="", resolved="", observed="", source=""):
    return {"name": name, "ecosystem": ecosystem, "declared": declared,
            "resolved": resolved, "observed": observed,
            "version": resolved or observed or (declared if _is_exact(declared, ecosystem) else ""),
            "source_file": source}


def _is_exact(spec: str, ecosystem: str) -> bool:
    """True if a declared spec already pins one exact version (per the ecosystem's grammar)."""
    s = (spec or "").strip()
    if not s:
        return False
    if ecosystem == "npm":
        return bool(re.fullmatch(r"\d+\.\d+\.\d+(?:[-+].*)?", s))  # no ^ ~ > < || x *
    if ecosystem == "PyPI":
        return s.startswith("==") and "*" not in s
    return bool(re.fullmatch(r"\d[\w.\-]*", s))


def _npm_lock(path: Path) -> dict:
    """{name: resolved version} from a package-lock.json (v1 'dependencies' or v2/v3 'packages')."""
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except ValueError:
        return {}
    out = {}
    for key, node in (data.get("packages") or {}).items():       # v2/v3
        if key.startswith("node_modules/") and node.get("version"):
            out[key.rsplit("node_modules/", 1)[-1]] = node["version"]
    for name, node in (data.get("dependencies") or {}).items():  # v1
        if isinstance(node, dict) and node.get("version"):
            out.setdefault(name, node["version"])
    return out


def _parse_deps(root: str) -> list[dict]:
    deps: list[dict] = []
    # resolve npm lockfiles first, so a package.json range can be married to its locked version
    npm_locked: dict[str, str] = {}
    for lf in Path(root).rglob("package-lock.json"):
        if not (_SKIP_DIRS & set(lf.parts)):
            npm_locked.update(_npm_lock(lf))

    for rf in Path(root).rglob("requirements*.txt"):
        if _SKIP_DIRS & set(rf.parts):
            continue
        for line in rf.read_text(errors="ignore").splitlines():
            s = line.split("#")[0].strip()
            m = re.match(r"([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|!=|>|<)?\s*([0-9][\w.\-]*)?", s)
            if not m or not m.group(1) or not m.group(3):
                continue
            op, ver = m.group(2) or "", m.group(3)
            declared = f"{op}{ver}"
            # a == pin is exact → it IS the resolved version; a range stays declared-only
            resolved = ver if op == "==" else ""
            deps.append(_dep(m.group(1).lower(), "PyPI", declared=declared,
                             resolved=resolved, source=str(rf)))

    for pj in Path(root).rglob("package.json"):
        if _SKIP_DIRS & set(pj.parts):
            continue
        try:
            data = json.loads(pj.read_text(errors="ignore"))
        except ValueError:
            continue
        for sec in ("dependencies", "devDependencies"):
            for name, spec in (data.get(sec) or {}).items():
                deps.append(_dep(name, "npm", declared=str(spec),
                                 resolved=npm_locked.get(name, ""), source=str(pj)))
    deps += _parse_sbom(root)
    return deps


def _parse_sbom(root: str) -> list[dict]:
    """Import an SBOM — CycloneDX (1.4/1.5 JSON) or SPDX (2.2/2.3 JSON) — as OBSERVED components.
    Format versions are read explicitly; an unsupported one is skipped (not silently trusted)."""
    _ECO = {"pypi": "PyPI", "npm": "npm", "cargo": "crates.io", "golang": "Go",
            "maven": "Maven", "gem": "RubyGems", "composer": "Packagist", "nuget": "NuGet"}

    def eco_from_purl(purl: str) -> str:
        m = re.match(r"pkg:([^/]+)/", purl or "")
        return _ECO.get(m.group(1).lower(), "") if m else ""

    out = []
    for f in list(Path(root).rglob("*.cdx.json")) + list(Path(root).rglob("bom.json")) \
            + list(Path(root).rglob("*.spdx.json")):
        if _SKIP_DIRS & set(f.parts):
            continue
        try:
            data = json.loads(f.read_text(errors="ignore"))
        except ValueError:
            continue
        fmt = str(data.get("bomFormat", "") or data.get("spdxVersion", ""))
        spec = str(data.get("specVersion", "") or data.get("spdxVersion", ""))
        if data.get("bomFormat") == "CycloneDX" and spec in ("1.4", "1.5", "1.6"):
            for c in data.get("components", []):
                eco = eco_from_purl(c.get("purl", ""))
                if c.get("name") and c.get("version"):
                    out.append(_dep(c["name"], eco or "", observed=c["version"], source=str(f)))
        elif str(data.get("spdxVersion", "")) in ("SPDX-2.2", "SPDX-2.3"):
            for p in data.get("packages", []):
                if p.get("name") and p.get("versionInfo"):
                    out.append(_dep(p["name"], "", observed=p["versionInfo"], source=str(f)))
        # else: unsupported SBOM version → skipped, not trusted
        _ = fmt
    return out


def _sem_sev(s: str) -> str:
    return {"ERROR": "high", "WARNING": "medium", "INFO": "low"}.get((s or "").upper(), "info")


def _parse_semgrep(data: dict) -> list[dict]:
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        out.append({"file": r.get("path", ""), "line": r.get("start", {}).get("line", 0),
                    "rule": "semgrep:" + (r.get("check_id", "") or "rule").split(".")[-1][:40],
                    "severity": _sem_sev(extra.get("severity")),
                    "message": (extra.get("message", "") or "")[:160],
                    "snippet": (extra.get("lines", "") or "").strip()[:160]})
    return out


def _scan_semgrep(root: str) -> list[dict]:
    """Multi-language SAST via Semgrep (host or Exegol). ponytail: AST covers Python
    precisely; Semgrep adds JS/PHP/Java/Go/… coverage."""
    from .tools import have, run_with_path

    if not have("semgrep"):
        return []
    _, out, _ = run_with_path(
        ["semgrep", "--config", "auto", "--json", "--quiet", "--timeout", "60", root],
        root, timeout=300)
    try:
        return _parse_semgrep(json.loads(out)) if out else []
    except ValueError:
        return []


def analyze(code_path: str) -> dict:
    return {"mode": "static", "code_path": code_path, "deps": _parse_deps(code_path),
            "code_findings": _scan_source(code_path) + _scan_semgrep(code_path)}


if __name__ == "__main__":  # self-check: python -m metsec.static (offline)
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "app.py").write_text(
            "import subprocess, pickle\n"
            "def f(u, host, name, cur):\n"
            "    cur.execute('SELECT * FROM t WHERE u=' + u)\n"       # sqli (concatenated)
            "    cur.execute('SELECT * FROM t WHERE id=?', (u,))\n"   # safe: parameterized
            "    subprocess.getoutput('ping ' + host)\n"
            "    subprocess.run(['ls'], shell=True)\n"
            "    render_template_string('Hi ' + name)\n"
            "    redirect(request.args.get('next'))\n"
            "    requests.get(host)\n"
            "    eval(name)\n"
            "    pickle.loads(name)\n"
            "SECRET_KEY = 'dev-secret-key-change-me'\n"
            "app.run(debug=True)\n")
        (Path(d) / "requirements.txt").write_text("requests==2.19.1\nurllib3>=1.0\n")
        # npm: a RANGE in the manifest must not be read as an installed version — the lockfile is
        (Path(d) / "package.json").write_text(json.dumps(
            {"dependencies": {"lodash": "^4.17.4"}}))
        (Path(d) / "package-lock.json").write_text(json.dumps(
            {"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.21"}}}))
        out = analyze(d)
        fs = out["code_findings"]
        rules = {f["rule"] for f in fs}
        assert {"sql-injection", "command-injection", "ssti", "open-redirect", "ssrf",
                "code-exec", "deserialization", "hardcoded-secret", "debug-enabled"} <= rules, rules
        # precision win: the parameterized execute is NOT flagged, only the concatenated one
        assert sum(f["rule"] == "sql-injection" for f in fs) == 1, fs
        deps = {d["name"]: d for d in out["deps"]}
        # a == pin is exact → resolved; a range is declared-only, no guessed version
        assert deps["requests"]["resolved"] == "2.19.1" and deps["requests"]["version"] == "2.19.1"
        assert deps["urllib3"]["declared"] == ">=1.0" and deps["urllib3"]["resolved"] == ""
        assert deps["urllib3"]["version"] == "", "a bare range must not become an exact version"
        # npm: declared range preserved, resolved comes from the lockfile (NOT from '^4.17.4')
        assert deps["lodash"]["declared"] == "^4.17.4"
        assert deps["lodash"]["resolved"] == "4.17.21" and deps["lodash"]["version"] == "4.17.21"

    # SBOM import: CycloneDX components land as OBSERVED versions with the right ecosystem
    with tempfile.TemporaryDirectory() as d2:
        (Path(d2) / "bom.json").write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"name": "flask", "version": "2.0.1", "purl": "pkg:pypi/flask@2.0.1"}]}))
        sbom = {c["name"]: c for c in analyze(d2)["deps"]}
        assert sbom["flask"]["observed"] == "2.0.1" and sbom["flask"]["ecosystem"] == "PyPI"

    sg = {"results": [{"path": "a.js", "check_id": "javascript.lang.security.audit.xss",
          "start": {"line": 12}, "extra": {"severity": "ERROR", "message": "XSS sink",
                                            "lines": "res.send(x)"}}]}
    ps = _parse_semgrep(sg)
    assert ps[0]["rule"] == "semgrep:xss" and ps[0]["severity"] == "high" and ps[0]["line"] == 12
    print("static self-check ok")
