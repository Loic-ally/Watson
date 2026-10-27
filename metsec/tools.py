"""External security-tool wrappers with pure-Python fallbacks.

Wrap best-in-class tools (nmap/nuclei/ffuf) when installed; fall back to
self-contained Python when they're absent, so MetSec runs anywhere. Tools are
always invoked as an argv list (never a shell string) — the target is a value,
not interpolated into a command line.
"""
from __future__ import annotations

import shutil
import subprocess


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def run(argv: list[str], timeout: int = 300) -> tuple[int, str, str]:
    """Run a tool and capture (returncode, stdout, stderr). No shell."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not found"
