"""MetSec CLI. Phase 0: `metsec smoke` and `metsec scope <file>`."""
from __future__ import annotations

import sys

from . import config
from .scope import OutOfScope, Scope


def smoke() -> int:
    """Confirm META_API_KEY + model routing work against the Meta API."""
    try:
        ids = {m.id for m in config.client().models.list().data}
    except Exception as e:  # noqa: BLE001 — surface any auth/network failure plainly
        print(f"FAIL: could not list models: {e}")
        return 1
    print(f"ok: {len(ids)} models visible "
          f"(brain={config.BRAIN in ids}, fast={config.FAST in ids})")
    try:
        reply = config.chat("Reply with exactly: MetSec online", model=config.FAST)
    except Exception as e:  # noqa: BLE001
        print(f"FAIL: chat call failed: {e}")
        return 1
    print(f"{config.FAST} says: {reply!r}")
    return 0


def check_scope(path: str) -> int:
    try:
        s = Scope.load(path)
    except (OutOfScope, FileNotFoundError) as e:
        print(f"invalid scope: {e}")
        return 1
    accounts = len(s.auth.get("accounts", [])) if s.auth else 0
    auth = f", {accounts} test account(s)" if accounts else " (unauthenticated)"
    print(f"scope ok — mode={s.mode}, authorized_by={s.authorized_by!r}, "
          f"{len(s.domains)} domains, {len(s.ips)} ips{auth}")
    return 0


def rag_build(args: list[str]) -> int:
    """Build the CVE index. Default source = CISA KEV; --nvd-keyword adds NVD hits."""
    import os

    from .rag import CveIndex, fetch_kev, fetch_nvd

    records = list(fetch_kev())
    print(f"fetched {len(records)} KEV records")
    if "--nvd-keyword" in args:
        kw = args[args.index("--nvd-keyword") + 1]
        nvd = list(fetch_nvd(keyword=kw, api_key=os.environ.get("NVD_API_KEY")))
        print(f"fetched {len(nvd)} NVD records for {kw!r}")
        records += nvd
    n = CveIndex().build(records)
    print(f"indexed {n} CVEs → .metsec_cache/lancedb")
    return 0


def rag_search(args: list[str]) -> int:
    from .rag import CveIndex

    if not args:
        print("usage: metsec rag search \"<query>\" [--kev] [--min-cvss X] [-k N]")
        return 2
    query = args[0]
    kev = "--kev" in args
    k = int(args[args.index("-k") + 1]) if "-k" in args else 5
    min_cvss = float(args[args.index("--min-cvss") + 1]) if "--min-cvss" in args else None
    hits = CveIndex().search(query, k=k, min_cvss=min_cvss, kev_only=kev)
    for h in hits:
        tag = "KEV" if h["kev"] else (f"CVSS {h['cvss']}" if h["cvss"] else "—")
        print(f"\n[{tag}] {h['id']}  ({h['source']})")
        print(f"  {h['summary'][:160]}")
    if not hits:
        print("no matches")
    return 0


def research_cmd(args: list[str]) -> int:
    """Research a detected tech+version: OSV + web → vulns, optionally saved to the index."""
    from .rag import CveIndex
    from .research import research

    if len(args) < 2:
        print("usage: metsec research <name> <version> [--ecosystem E] [--no-web] [--save]")
        return 2
    name, version = args[0], args[1]
    eco = args[args.index("--ecosystem") + 1] if "--ecosystem" in args else None
    findings = research(name, version, ecosystem=eco, use_web="--no-web" not in args)
    for f in findings:
        src = f["source"].upper()
        sev = f["severity"] or "—"
        print(f"\n[{src} {sev}] {f['id']}")
        print(f"  {f['summary'][:160]}")
        if f["references"]:
            print(f"  {f['references'][0]}")
    print(f"\n{len(findings)} finding(s) for {name} {version}")
    if "--save" in args and findings:
        added = CveIndex().add(findings)
        print(f"saved {added} into the CVE index")
    return 0


def recon_cmd(args: list[str]) -> int:
    """Scope-gated passive recon of a target URL."""
    from .recon import recon

    if not args or "--scope" not in args:
        print("usage: metsec recon <url> --scope <file> "
              "[--active [--ports|--no-ports] [--nuclei] [--rate S]] [--research [--no-web]]")
        return 2
    target = args[0]
    scope_path = args[args.index("--scope") + 1]
    try:
        s = Scope.load(scope_path)
        inv = recon(target, s)
    except (OutOfScope, FileNotFoundError) as e:
        print(f"refused: {e}")
        return 1
    print(f"{inv['url']} → HTTP {inv['status']}  server={inv['server'] or '—'}")
    print(f"\ntech ({len(inv['techs'])}):")
    for t in inv["techs"]:
        print(f"  {t.name} {t.version or '?'}  [{t.source}]")
    if inv["missing_security_headers"]:
        print(f"\nmissing security headers: {', '.join(inv['missing_security_headers'])}")
    if inv["paths"]:
        print(f"\ndisclosed paths ({len(inv['paths'])}): {', '.join(inv['paths'][:10])}")
    if "--active" in args:
        from .active import active_recon

        # ports default on in dev, opt-in in prod; both honor --ports/--no-ports
        ports = "--ports" in args or (s.mode == "dev" and "--no-ports" not in args)
        rate = float(args[args.index("--rate") + 1]) if "--rate" in args else 0.0
        act = active_recon(target, s, ports=ports, nuclei="--nuclei" in args, rate=rate)
        c = act["crawl"]
        auth = " (authenticated)" if s.auth else ""
        print(f"\ncrawl{auth}: {len(c['pages'])} pages, {len(c['endpoints'])} endpoints, "
              f"{len(c['forms'])} forms")
        print(f"content discovery: {len(act['discovery'])} hits — "
              f"{', '.join(h['path'] for h in act['discovery'][:12])}")
        if "ports" in act:
            ports_str = ", ".join(f"{p['port']}/{p['service'] or '?'}" for p in act["ports"])
            print(f"open ports: {ports_str}")
        if "nuclei" in act:
            print(f"nuclei: {len(act['nuclei'])} findings")
    if "--research" in args:
        from .research import from_inventory

        print("\n=== vulnerabilities (OSV + web) ===")
        for tech, findings in from_inventory(inv, use_web="--no-web" not in args).items():
            print(f"\n{tech}: {len(findings)} finding(s)")
            for f in findings[:5]:
                print(f"  [{f['source']}] {f['id']}: {f['summary'][:90]}")
    return 0


def fingerprints_cmd(args: list[str]) -> int:
    from .fingerprints import load_db, update_db

    if args and args[0] == "update":
        print(f"downloaded {update_db()} technology fingerprints")
        return 0
    db = load_db()
    print(f"{len(db)} fingerprints cached" if db
          else "no fingerprints — run: metsec fingerprints update")
    return 0


def assess_cmd(args: list[str]) -> int:
    """Full assessment: recon + agent loop → prioritized findings."""
    from datetime import datetime, timezone

    from .agent import assess
    from .report import dedup_rank, write_reports

    if "--scope" not in args:
        print("usage: metsec assess [<url>] --scope <file> "
              "[--active] [--exploit] [--budget N] [--out <dir>]")
        return 2
    budget = int(args[args.index("--budget") + 1]) if "--budget" in args else 16
    out_dir = args[args.index("--out") + 1] if "--out" in args else None
    target = args[0] if args and not args[0].startswith("--") else None
    exploit = "--exploit" in args
    if exploit:
        print("⚠️  exploitation ENABLED — the agent will actively attack in-scope targets. "
              "Only use on systems you own/are authorized to break.")
    try:
        s = Scope.load(args[args.index("--scope") + 1])
        if s.mode != "static" and not target:
            print("non-static mode needs a target url")
            return 2
        findings = assess(target, s, active="--active" in args, budget=budget, exploit=exploit)
    except (OutOfScope, FileNotFoundError) as e:
        print(f"refused: {e}")
        return 1
    findings = dedup_rank(findings)
    for f in findings:
        print(f"\n[{f.severity.upper()} · {f.status}] {f.title}")
        if f.affected:
            print(f"  affected: {f.affected}")
        if f.evidence:
            print(f"  evidence: {f.evidence[:160]}")
        if f.remediation:
            print(f"  fix: {f.remediation[:160]}")
        if f.refs:
            print(f"  refs: {', '.join(str(r) for r in f.refs[:3])}")
    print(f"\n{len(findings)} finding(s)" if findings else "no findings")
    if out_dir:
        meta = {"target": target or s.code_path, "mode": s.mode, "exploit": exploit,
                "authorized_by": s.authorized_by,
                "date": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        j, m = write_reports(findings, meta, out_dir)
        print(f"\nwrote {j}  and  {m}")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    usage = ("usage: metsec {smoke | scope <file> | rag build [--nvd-keyword K] | "
             "rag search \"<q>\" | research <name> <version> | recon <url> --scope <file> | "
             "assess <url> --scope <file>}")
    if not argv:
        print(usage)
        return 2
    cmd, *rest = argv
    if cmd == "smoke":
        return smoke()
    if cmd == "scope" and rest:
        return check_scope(rest[0])
    if cmd == "rag" and rest:
        sub, *sargs = rest
        if sub == "build":
            return rag_build(sargs)
        if sub == "search":
            return rag_search(sargs)
    if cmd == "research":
        return research_cmd(rest)
    if cmd == "recon":
        return recon_cmd(rest)
    if cmd == "fingerprints":
        return fingerprints_cmd(rest)
    if cmd == "assess":
        return assess_cmd(rest)
    print(usage)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
