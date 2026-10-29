"""Parallel multi-target assessment — one agent per target, run concurrently.

Each target gets its own Agent (independent session/findings/foothold); they share
the global event bus (one combined live feed) and audit log. Findings are merged.
ponytail: shared event bus = interleaved feed; per-run isolation if it matters later.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor


def targets_from_scope(scope) -> list[str]:
    """Base URLs for every concrete host in scope (CIDRs skipped)."""
    out = [f"http://{d}/" for d in getattr(scope, "domains", [])]
    out += [f"http://{ip}/" for ip in getattr(scope, "ips", []) if "/" not in ip]
    return out


def parallel_assess(targets: list[str], scope, active: bool = True, budget: int = 30,
                    exploit: bool = False, workers: int = 3) -> dict:
    """Assess each target with its own agent, in parallel. → {target: Agent | Exception}.

    Each run gets an isolated event stream + audit file (per-thread context)."""
    from . import audit, events
    from .agent import assess

    def one(t):
        try:
            events.new_stream()          # isolated feed, not interleaved with others
            agent = assess(t, scope, active=active, budget=budget, exploit=exploit)
            agent.run_events = events.since(0)   # this run's own feed
            agent.run_audit = audit.path()       # this run's own audit file
            return t, agent
        except Exception as e:  # noqa: BLE001 — isolate per-target failures
            return t, e

    results: dict = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as ex:
        for t, r in ex.map(one, targets):
            results[t] = r
    return results


def merge_findings(results: dict) -> list:
    """All findings across successful targets, in one list."""
    out = []
    for agent in results.values():
        if not isinstance(agent, Exception):
            out += getattr(agent, "findings", [])
    return out


if __name__ == "__main__":  # self-check: python -m watson.parallel (offline)
    from .scope import Scope

    s = Scope(domains=["a.example.com"], ips=["10.0.0.5", "10.0.0.0/24"],
              authorized_by="t", mode="prod")
    tg = targets_from_scope(s)
    assert "http://a.example.com/" in tg and "http://10.0.0.5/" in tg
    assert all("/24" not in t for t in tg), tg   # CIDR skipped

    class _A:
        def __init__(self, fs):
            self.findings = fs

    results = {"http://a/": _A([1, 2]), "http://b/": _A([3]), "http://c/": ValueError("x")}
    assert sorted(merge_findings(results)) == [1, 2, 3]   # failed target excluded
    print("parallel self-check ok")
