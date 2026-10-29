"""Run manager for the web UI — launch the agent from the browser, track state,
stream events, keep history, and turn natural-language instructions into scans.

One active run at a time (the event bus is a global singleton); extra launches are
rejected while one is running.
"""
from __future__ import annotations

import ipaddress
import json
import re
import threading
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlparse

from . import events

_runs: dict[str, dict] = {}
_active: str | None = None
_lock = threading.Lock()


def scope_for(target: str, mode: str, authorized_by: str):
    """Build a Scope from a target URL/host. The logged-in user asserts authorization.

    If a scope.yaml in the project root already covers this target, reuse it — crucially its
    `auth` block — so configured test credentials are actually used (only the mode is
    overridden to what the operator asked for). Otherwise fall back to a bare scope.
    """
    import dataclasses
    from pathlib import Path

    from .scope import OutOfScope, Scope

    host = urlparse(target).hostname or target
    for p in (Path("scope.yaml"), Path("scope.yml")):
        if not p.exists():
            continue
        try:
            configured = Scope.load(p)
        except (OutOfScope, OSError, ValueError):
            break
        if configured.contains(target):           # reuse its targets + auth, honor chosen mode
            return dataclasses.replace(configured, mode=mode,
                                       authorized_by=configured.authorized_by or authorized_by)
        break  # a scope.yaml exists but doesn't cover this target → bare scope below
    try:
        ipaddress.ip_address(host)
        return Scope(ips=[host], authorized_by=authorized_by, mode=mode)
    except ValueError:
        return Scope(domains=[host], authorized_by=authorized_by, mode=mode)


def parse_instruction(text: str) -> dict:
    """LLM-extract scan params from an instruction. {"target": None} if not a scan."""
    from . import config

    prompt = (
        "You turn a user's instruction into pentest scan parameters. Output JSON only: "
        '{"target": "<url or null>", "mode": "dev|prod|static", "exploit": true|false, '
        '"budget": <int 20-60>}. Default mode prod, exploit false, budget 40. If the message is '
        "NOT a request to scan/pentest/attack a specific target, return {\"target\": null}.\n\n"
        f"Instruction: {text}")
    try:
        raw = config.chat(prompt, model=config.FAST)
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        return json.loads(m.group(0)) if m else {"target": None}
    except Exception:  # noqa: BLE001
        return {"target": None}


def answer(text: str) -> str:
    """Answer a non-scan chat message, using the latest run's findings as context."""
    from . import config

    ctx = ""
    last = latest()
    if last and last.get("findings"):
        ctx = "Latest findings:\n" + "\n".join(
            f"- [{f['severity']}/{f['status']}] {f['title']}" for f in last["findings"][:20])
    try:
        return config.chat(
            "You are Watson, an autonomous pentest agent's assistant. Answer concisely for the "
            f"operator.\n{ctx}\n\nQuestion: {text}", model=config.FAST)
    except Exception as e:  # noqa: BLE001
        return f"(model error: {e})"


def launch(instruction: str, authorized_by: str) -> tuple[str | None, str | None]:
    global _active
    with _lock:
        if _active and _runs.get(_active, {}).get("status") == "running":
            return None, "a scan is already running — wait for it to finish"
    params = parse_instruction(instruction)
    target = params.get("target")
    if not target:
        return None, None  # not a scan instruction → caller will treat as chat
    rid = uuid.uuid4().hex[:8]
    run = {"id": rid, "instruction": instruction, "target": target,
           "mode": params.get("mode", "prod"), "exploit": bool(params.get("exploit")),
           "status": "running", "started": time.time(), "findings": [], "report": None}
    with _lock:
        _runs[rid] = run
        _active = rid
    threading.Thread(target=_run, args=(run, params, authorized_by), daemon=True).start()
    return rid, None


def _run(run: dict, params: dict, authorized_by: str) -> None:
    from .agent import assess
    from .report import dedup_rank, narrative, write_reports

    events.reset()
    events.emit("start", target=run["target"], mode=run["mode"])
    try:
        scope = scope_for(run["target"], run["mode"], authorized_by)
        result = assess(run["target"], scope, active=True, exploit=run["exploit"],
                        budget=int(params.get("budget", 40)))
        findings = dedup_rank(result.findings)
        run["findings"] = [asdict(f) for f in findings]
        outdir = f"watson-report-{time.strftime('%Y%m%d-%H%M%S')}"
        meta = {"target": run["target"], "mode": run["mode"], "exploit": run["exploit"],
                "authorized_by": authorized_by, "date": time.strftime("%Y-%m-%d %H:%M")}
        write_reports(findings, meta, outdir, hypotheses=result.hypotheses,
                      narrative=narrative(findings, result.hypotheses), shots=result.shots)
        run["report"] = outdir
        run["status"] = "done"
    except Exception as e:  # noqa: BLE001
        run["status"] = "error"
        run["error"] = str(e)[:300]
        events.emit("error", msg=str(e)[:200])
    run["ended"] = time.time()
    events.emit("done")


def latest() -> dict | None:
    return _runs.get(_active) if _active else None


def history() -> list[dict]:
    return sorted(_runs.values(), key=lambda r: r.get("started", 0), reverse=True)


def list_reports() -> list[dict]:
    """Past reports on disk (watson-report-*/findings.json), newest first."""
    out = []
    for d in sorted(Path(".").glob("watson-report-*"), reverse=True):
        f = d / "findings.json"
        if not f.exists():
            continue
        try:
            data = json.loads(f.read_text())
        except (ValueError, OSError):
            continue
        meta = data.get("meta", {})
        out.append({"name": d.name, "target": meta.get("target", "?"),
                    "date": meta.get("date", ""), "cvss": meta.get("overall_cvss", 0),
                    "count": len(data.get("findings", [])),
                    "has_html": (d / "report.html").exists()})
    return out


def read_report(name: str) -> dict | None:
    if not re.fullmatch(r"watson-report-[\w\-]+", name):   # no path traversal
        return None
    d = Path(name)
    f = d / "findings.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text())
    except (ValueError, OSError):
        return None


if __name__ == "__main__":  # self-check: python -m watson.runs (offline bits)
    s = scope_for("http://127.0.0.1:5001/x", "dev", "me")
    assert s.ips == ["127.0.0.1"] and s.mode == "dev" and s.authorized_by == "me"
    s2 = scope_for("http://shop.example.com/", "prod", "me")
    assert s2.domains == ["shop.example.com"] and not s2.ips
    assert read_report("../etc/passwd") is None            # traversal blocked
    assert read_report("watson-report-does-not-exist") is None
    assert isinstance(list_reports(), list) and isinstance(history(), list)
    print("runs self-check ok")
