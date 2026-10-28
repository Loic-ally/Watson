"""NDJSON/JSON bridge for the Rust backend.

The Rust server (backend/) owns HTTP, auth, SSE and static serving; it shells out
to this module for the four things that need Python: classify a chat message,
run a scan (streaming events as NDJSON on stdout), search the CVE/RAG index, and
transcribe audio. Agent code (agent.py, rag.py, …) is untouched — this only
re-uses the web helpers that already live in runs.py.

Subcommands (one JSON object per line on stdout):
  classify <msg>        -> {"type":"reply","text":...} | {"type":"scan",<params>}
  scan <params-json>    -> stream of agent events, one per line, ending with {"type":"done"}
  knowledge <query>     -> {"hits":[...]}
  transcribe            -> reads WAV from stdin -> {"text":...}
  pdf <report-name>     -> {"path":...} | {"error":...}
"""
from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path


def _out(obj) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def classify(msg: str) -> None:
    from . import runs
    params = runs.parse_instruction(msg)
    if params.get("target"):
        _out({"type": "scan", "target": params["target"],
              "mode": params.get("mode", "prod"), "exploit": bool(params.get("exploit")),
              "budget": int(params.get("budget", 40))})
    else:
        _out({"type": "reply", "text": runs.answer(msg)})


def scan(params: dict) -> None:
    """Run the assessment and stream its event bus to stdout as NDJSON."""
    from . import events
    from .agent import assess
    from .report import dedup_rank, narrative, write_reports
    from .runs import scope_for

    target = params["target"]
    mode = params.get("mode", "prod")
    exploit = bool(params.get("exploit"))
    authorized_by = params.get("authorized_by", "operator")

    done = threading.Event()
    result_box: dict = {}

    def work():
        try:
            scope = scope_for(target, mode, authorized_by)
            res = assess(target, scope, active=True, exploit=exploit,
                         budget=int(params.get("budget", 40)))
            findings = dedup_rank(res.findings)
            outdir = f"metsec-report-{time.strftime('%Y%m%d-%H%M%S')}"
            meta = {"target": target, "mode": mode, "exploit": exploit,
                    "authorized_by": authorized_by, "date": time.strftime("%Y-%m-%d %H:%M")}
            write_reports(findings, meta, outdir, hypotheses=res.hypotheses,
                          narrative=narrative(findings, res.hypotheses))
            result_box["report"] = outdir
            result_box["findings"] = [asdict(f) for f in findings]
        except Exception as e:  # noqa: BLE001
            result_box["error"] = str(e)[:300]
            events.emit("error", msg=str(e)[:200])
        finally:
            done.set()

    events.reset()
    events.emit("start", target=target, mode=mode)
    threading.Thread(target=work, daemon=True).start()

    idx = 0
    while not done.is_set() or events.count() > idx:
        for e in events.since(idx):
            _out(e)
            idx += 1
        if not done.is_set():
            time.sleep(0.25)
    _out({"type": "done", "report": result_box.get("report"),
          "findings": result_box.get("findings", []), "error": result_box.get("error")})


def knowledge(query: str) -> None:
    try:
        from .rag import CveIndex
        hits = CveIndex().search(query, k=12)
        _out({"hits": [{"id": h["id"], "source": h["source"],
                        "summary": h.get("summary", ""),
                        "severity": h.get("severity", ""),
                        "cvss": h.get("cvss", 0.0),
                        "cwe": h.get("cwe", ""),
                        "products": h.get("products", ""),
                        "kev": bool(h.get("kev", False)),
                        "references": list(h.get("references") or [])}
                       for h in hits]})
    except Exception as e:  # noqa: BLE001
        _out({"hits": [], "error": str(e)[:160]})


def transcribe() -> None:
    from . import config
    audio = sys.stdin.buffer.read()
    try:
        _out({"text": config.transcribe(audio, sample_rate=16000)})
    except Exception as e:  # noqa: BLE001
        _out({"text": "", "error": str(e)[:160]})


def pdf(name: str) -> None:
    from .runs import read_report
    if not read_report(name):   # validates name (no traversal) + existence
        _out({"error": "not found"})
        return
    p = Path(name) / "report.pdf"
    if not p.exists():
        from .report import make_pdf
        make_pdf(name)
    _out({"path": str(p.resolve())} if p.exists() else {"error": "render failed"})


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: python -m metsec.bridge <classify|scan|knowledge|transcribe|pdf> [arg]",
              file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "classify":
        classify(rest[0] if rest else "")
    elif cmd == "scan":
        scan(json.loads(rest[0]))
    elif cmd == "knowledge":
        knowledge(rest[0] if rest else "")
    elif cmd == "transcribe":
        transcribe()
    elif cmd == "pdf":
        pdf(rest[0] if rest else "")
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
