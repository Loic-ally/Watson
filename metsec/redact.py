"""Secret redaction — scrub credentials BEFORE text reaches the model or the index.

Trust boundary: recon output, tool results, fetched pages and researched web content are
DATA. Before any of it is sent to the reasoning model or written into the RAG index, it is
passed through redact() so secrets (keys, tokens, passwords, connection strings) are replaced
with a `[REDACTED:<kind>]` marker. This shrinks blast radius if the model, the index, or a
report is ever shared, and keeps secrets out of embeddings.

Retention policy for raw evidence:
  - The model and the LanceDB index only ever see REDACTED text.
  - Raw, un-redacted tool output lives only in the per-run audit log on disk
    (.metsec_cache/audit/), which is operator-local, excluded from reports, and the
    operator's to retain or purge. No raw secret is persisted anywhere else.
ponytail: regex scrubber with a known ceiling (misses bespoke/obfuscated secrets); it is a
defence-in-depth net, not a guarantee — never feed it attacker-controlled regexes.
"""
from __future__ import annotations

import re

MARK = "[REDACTED:{}]"

# (kind, pattern). Order matters: multi-line blocks first, then specific, then generic.
_RULES: list[tuple[str, re.Pattern]] = [
    ("private-key", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL)),
    ("aws-key-id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    # URL embedded credentials:  scheme://user:password@host
    ("url-cred", re.compile(r"(?P<pre>[a-zA-Z][\w+.-]*://[^\s:@/]+:)[^\s@/]+(?P<at>@)")),
    # HTTP Authorization / Bearer
    ("bearer", re.compile(r"(?i)\b(?:authorization|bearer)\b\s*[:=]?\s*[A-Za-z0-9._\-]{12,}")),
    # generic key=value / key: "value" secrets
    ("secret", re.compile(
        r"""(?ix)
        (?P<lead>\b(?:password|passwd|pwd|secret(?:_key)?|api[_-]?key|access[_-]?key|
             auth[_-]?token|token|client[_-]?secret|private[_-]?key)\b
        \s*[:=]\s*)
        ['"]?(?P<val>[^\s'"&,;}{]{4,})['"]?
        """)),
]


def redact(value):
    """Redact secrets in a string, or recursively in a dict/list (string leaves). Other
    scalars pass through. Keys are never redacted (so structure/labels stay readable)."""
    if isinstance(value, str):
        return _redact_str(value)
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact(v) for v in value)
    return value


def _redact_str(s: str) -> str:
    for kind, rx in _RULES:
        if kind == "url-cred":
            s = rx.sub(lambda m: m.group("pre") + MARK.format(kind) + m.group("at"), s)
        elif kind == "secret":
            s = rx.sub(lambda m: m.group("lead") + MARK.format(kind), s)
        else:
            s = rx.sub(MARK.format(kind), s)
    return s


if __name__ == "__main__":  # self-check: python -m metsec.redact (offline)
    assert redact("AKIA1234567890ABCDEF") == "[REDACTED:aws-key-id]"
    assert "[REDACTED:private-key]" == redact(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----")
    assert redact("password=hunter2!") == "password=[REDACTED:secret]"
    assert redact('API_KEY: "sk-live-abcdef123456"') == 'API_KEY: [REDACTED:secret]'
    assert redact("postgres://admin:s3cr3t@db:5432/app") == \
        "postgres://admin:[REDACTED:url-cred]@db:5432/app"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
    assert redact(jwt) == "[REDACTED:jwt]"
    # structure/labels survive; only values are scrubbed
    out = redact({"url": "http://x/", "env": ["SECRET=abcdef", "PORT=80"]})
    assert out["url"] == "http://x/" and out["env"] == ["SECRET=[REDACTED:secret]", "PORT=80"]
    # benign text is untouched (no false positives on short/plain values)
    assert redact("status=200 length=42 reflected=True") == "status=200 length=42 reflected=True"
    print("redact self-check ok")
