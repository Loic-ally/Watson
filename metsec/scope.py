"""Scope enforcement — the safety boundary.

No target is ever touched unless it is declared in a scope file that names who
authorized it. `require()` is called at every tool boundary, not just startup.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import yaml


class OutOfScope(Exception):
    """Raised when a target is not covered by the authorized scope."""


MODES = ("static", "dev", "prod")  # static proposes → dev confirms → prod validates


@dataclass
class Scope:
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)      # plain IPs or CIDRs
    authorized_by: str = ""
    mode: str = "static"                               # static | dev | prod
    code_path: str = ""                                # source dir (static mode)
    auth: dict = field(default_factory=dict)           # optional: login_url + accounts

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        data = yaml.safe_load(Path(path).read_text()) or {}
        s = cls(
            domains=[str(d).lower().lstrip("*.") for d in data.get("domains", [])],
            ips=[str(i) for i in data.get("ips", [])],
            authorized_by=str(data.get("authorized_by", "")).strip(),
            mode=str(data.get("mode", "static")).lower(),
            code_path=str(data.get("code_path", "")).strip(),
            auth=data.get("auth") or {},
        )
        if not s.authorized_by:
            raise OutOfScope("scope missing 'authorized_by' — refusing to run")
        if s.mode not in MODES:
            raise OutOfScope(f"mode {s.mode!r} invalid — must be one of {MODES}")
        if s.mode in ("dev", "prod") and not (s.domains or s.ips):
            raise OutOfScope(f"{s.mode} mode needs domains or ips")
        if s.mode == "static" and not s.code_path:
            raise OutOfScope("static mode needs a code_path")
        return s

    def contains(self, target: str) -> bool:
        host = (urlparse(target).hostname or target).lower()
        try:  # IP / CIDR match
            ip = ipaddress.ip_address(host)
            return any(ip in ipaddress.ip_network(e, strict=False) for e in self.ips)
        except ValueError:
            pass
        # domain or subdomain match
        return any(host == d or host.endswith("." + d) for d in self.domains)

    def require(self, target: str) -> str:
        if not self.contains(target):
            raise OutOfScope(f"{target!r} is not in scope — refusing")
        return target


if __name__ == "__main__":  # self-check: python -m metsec.scope
    import os
    import tempfile

    def write(text: str) -> str:
        f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
        f.write(text)
        f.close()
        return f.name

    dev = write(
        "authorized_by: owner\nmode: prod\n"
        "domains:\n  - example.com\n  - '*.test.io'\n"
        "ips:\n  - 10.0.0.0/24\n  - 192.168.1.5\n"
        "auth:\n  login_url: https://example.com/login\n"
        "  accounts:\n    - {user_env: TEST_USER1, pass_env: TEST_PASS1, role: user}\n"
    )
    s = Scope.load(dev)
    assert s.mode == "prod"
    assert s.auth["accounts"][0]["user_env"] == "TEST_USER1"  # names only, not secrets
    assert s.contains("https://example.com/login")
    assert s.contains("api.test.io")            # subdomain of wildcard
    assert s.contains("http://10.0.0.42:8080")  # inside CIDR
    assert s.contains("192.168.1.5")
    assert not s.contains("evil.com")
    assert not s.contains("notexample.com")      # suffix trick
    assert not s.contains("10.0.1.1")            # outside CIDR
    os.unlink(dev)

    static = write("authorized_by: owner\nmode: static\ncode_path: ./src\n")
    assert Scope.load(static).mode == "static"
    os.unlink(static)

    bad = {
        "no authorizer": "domains:\n  - a.com\n",
        "bad mode": "authorized_by: x\nmode: nuke\ndomains:\n  - a.com\n",
        "prod no targets": "authorized_by: x\nmode: prod\n",
        "static no code_path": "authorized_by: x\nmode: static\n",
    }
    for why, text in bad.items():
        g = write(text)
        try:
            Scope.load(g)
            raise AssertionError(f"expected OutOfScope ({why})")
        except OutOfScope:
            pass
        os.unlink(g)

    print("scope self-check ok")
