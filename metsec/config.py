"""Meta Muse API client + model routing.

The Meta Model API is OpenAI-compatible, so we point the openai SDK at it.
Key comes from META_API_KEY in .env (never hard-coded).
"""
from __future__ import annotations

import os
from functools import lru_cache

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

BASE_URL = "https://api.meta.ai/v1"

# Model routing. Wonder dropped per user; Spark 1.3 Contributor runs both roles
# (supports tool calling + vision). Contributor = cheaper, but inputs/outputs are
# used to train Meta models — keep that in mind for sensitive engagements.
# Note: SAM 3.1 is a segmentation model (boxes/masks) and cannot run the agent.
BRAIN = "muse-spark-1.3-contributor"   # planning, reasoning, vision, tool calling
FAST = "muse-spark-1.3-contributor"    # triage, classification, tool loops


@lru_cache(maxsize=1)
def client() -> OpenAI:
    key = os.environ.get("META_API_KEY")
    if not key:
        raise RuntimeError("META_API_KEY not set — add it to .env")
    return OpenAI(base_url=BASE_URL, api_key=key)


def chat(prompt, model: str = FAST, reasoning_effort: str | None = None, **kw) -> str:
    """One-shot chat. `prompt` is a string or a messages list."""
    msgs = prompt if isinstance(prompt, list) else [{"role": "user", "content": prompt}]
    if reasoning_effort:
        kw["reasoning_effort"] = reasoning_effort
    resp = client().chat.completions.create(model=model, messages=msgs, **kw)
    return resp.choices[0].message.content
