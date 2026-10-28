"""External security-tool wrappers — host, then Exegol, then pure-Python fallback.

A tool runs on the host if installed; otherwise, if an Exegol container is running,
it runs inside it (so nothing has to be installed on the host — nuclei/ffuf/semgrep/
nxc/bloodhound/impacket all live in Exegol). Set EXEGOL_CONTAINER to pin one.

Note: a tool running inside Exegol reaches a *host-local* target (127.0.0.1) only via
host.docker.internal — rewrite localhost targets, or run the container with host net.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from functools import lru_cache


@lru_cache(maxsize=1)
def exegol_container() -> str | None:
    """Name of a running Exegol container to run tools in, or None."""
    name = os.environ.get("EXEGOL_CONTAINER")
    if name:
        return name
    try:
        out = subprocess.run(["docker", "ps", "--filter", "name=exegol", "--format", "{{.Names}}"],
                             capture_output=True, text=True, timeout=10).stdout.split()
        return out[0] if out else None
    except (OSError, subprocess.SubprocessError):
        return None


@lru_cache(maxsize=256)
def have(tool: str) -> bool:
    if shutil.which(tool):
        return True
    c = exegol_container()
    if not c:
        return False
    try:
        return subprocess.run(["docker", "exec", c, "sh", "-lc", f"command -v {shlex.quote(tool)}"],
                             capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def run(argv: list[str], timeout: int = 300) -> tuple[int, str, str]:
    """Run a tool and capture (returncode, stdout, stderr). Host → Exegol → not found."""
    try:
        if shutil.which(argv[0]):
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        c = exegol_container()
        if c:  # run inside Exegol with a login shell so ~/.local/bin tools are on PATH
            cmd = ["docker", "exec", c, "sh", "-lc", " ".join(shlex.quote(a) for a in argv)]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        return 127, "", "not found (no host tool, no exegol container)"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not found"


if __name__ == "__main__":  # self-check: python -m metsec.tools
    assert exegol_container() is None or isinstance(exegol_container(), str)
    code, out, _ = run(["echo", "metsec_tools_ok"])   # host path (echo always present)
    assert code == 0 and "metsec_tools_ok" in out, (code, out)
    assert have("echo") is True
    print("tools self-check ok  (exegol:", exegol_container() or "none", ")")
