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


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    usage = ("usage: metsec {smoke | scope <file> | rag build [--nvd-keyword K] | "
             "rag search \"<q>\" | research <name> <version>}")
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
    print(usage)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
