"""Headless-browser recon with vision (Playwright + Muse).

Drives a real Chromium so Watson sees JS-rendered pages the static fetch misses:
a screenshot fed to the vision model, plus the rendered links and forms.

Optional: needs `pip install playwright && playwright install chromium`.
"""
from __future__ import annotations

import base64
import json
import re


def _ctx(browser, storage=None, storage_state=None, viewport=None):
    """A browser context that restores an authenticated session so the app renders logged-in.

    `storage_state` is a full Playwright state dict (cookies + localStorage) — the robust path
    (handles cookie-based SSR sessions). `storage` is a plain [{name, value}] localStorage list
    seeded via an init script (used when only a token is known). Either may be None."""
    kw = {}
    if viewport:
        kw["viewport"] = viewport
    if storage_state:
        kw["storage_state"] = storage_state
    ctx = browser.new_context(**kw)
    if storage and not storage_state:
        items = {s["name"]: s["value"] for s in storage if s.get("name")}
        ctx.add_init_script(
            "(()=>{try{const m=" + json.dumps(items)
            + ";for(const k in m)localStorage.setItem(k,m[k]);}catch(e){}})()")
    return ctx

# SAM 3.1 encodes each detection as <|box;x1=..;y1=..;x2=..;y2=..;w=..;h=..|> + a mask.
_BOX = re.compile(r"<\|box;x1=(\d+);y1=(\d+);x2=(\d+);y2=(\d+);w=(\d+);h=(\d+)\|>")

_LINKS_JS = "els => els.map(e => e.href)"
_FORMS_JS = """els => els.map(f => ({
  action: f.action, method: f.method,
  inputs: [...f.querySelectorAll('input,select,textarea')].map(i => ({name: i.name, type: i.type}))
}))"""


def snapshot(url: str, timeout: int = 20000, storage: list | None = None,
             storage_state: dict | None = None) -> dict:
    """Navigate headless Chromium → {png, title, links, forms, text}.

    `storage`/`storage_state` restore an authenticated session so the SPA renders logged-in."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        try:
            page = _ctx(browser, storage, storage_state).new_page()
            page.goto(url, timeout=timeout, wait_until="domcontentloaded")
            try:
                page.wait_for_load_state("networkidle", timeout=4000)
            except Exception:  # noqa: BLE001 — networkidle is best-effort
                pass
            return {
                "png": page.screenshot(full_page=True),
                "title": page.title(),
                "links": page.eval_on_selector_all("a[href]", _LINKS_JS),
                "forms": page.eval_on_selector_all("form", _FORMS_JS),
                "text": page.inner_text("body")[:4000],
            }
        finally:
            browser.close()


def vision_analyze(png: bytes, prompt: str) -> str:
    """Ask Muse (multimodal) to describe/assess a page screenshot."""
    from . import config

    b64 = base64.b64encode(png).decode()
    messages = [{"role": "user", "content": [
        {"type": "text", "text": prompt},
        {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{b64}"}},
    ]}]
    return config.chat(messages, model=config.BRAIN)


def _parse_boxes(text: str) -> list[dict]:
    out = []
    for m in _BOX.finditer(text or ""):
        x1, y1, x2, y2, w, h = map(int, m.groups())
        out.append({"box": [x1, y1, x2, y2], "center": [(x1 + x2) // 2, (y1 + y2) // 2],
                    "w": w, "h": h})
    return out


def segment(png: bytes, phrase: str) -> list[dict]:
    """SAM 3.1: locate everything matching a noun phrase → boxes + centers."""
    from . import config

    b64 = base64.b64encode(png).decode()
    r = config.client().responses.create(model=config.SEGMENT, input=[{"role": "user", "content": [
        {"type": "input_text", "text": phrase},
        {"type": "input_image", "image_url": f"data:image/png;base64,{b64}"}]}])
    text = ""
    for o in getattr(r, "output", []) or []:
        for c in getattr(o, "content", []) or []:
            text += getattr(c, "text", "") or ""
    return _parse_boxes(text)


_FILL_JS = """([x, y, text]) => {
  let el = document.elementFromPoint(x, y);
  if (el && !['INPUT','TEXTAREA'].includes(el.tagName))
    el = el.closest('input,textarea') || el.querySelector('input,textarea') || el;
  if (el && ['INPUT','TEXTAREA'].includes(el.tagName)) {
    el.focus(); el.value = text;
    el.dispatchEvent(new Event('input', {bubbles:true}));
    el.dispatchEvent(new Event('change', {bubbles:true}));
    return true;
  }
  return false;
}"""
_CLICK_JS = """([x, y]) => {
  let el = document.elementFromPoint(x, y);
  if (!el) return false;
  (el.closest('button,a,input[type=submit],[role=button]') || el).click();
  return true;
}"""


def interact(url: str, steps: list[dict], timeout: int = 20000, storage: list | None = None,
             storage_state: dict | None = None) -> dict:
    """Drive the page by VISION: SAM locates each element, Playwright clicks/fills it.

    steps: [{"find": "<noun phrase>", "fill": "<text>"?}] — fill present ⇒ type into it,
    else click. Viewport is fixed so SAM coordinates map 1:1 to clicks. `storage`/`storage_state`
    restore an authenticated session.
    """
    from playwright.sync_api import sync_playwright

    log = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        try:
            page = _ctx(browser, storage, storage_state,
                        viewport={"width": 1280, "height": 720}).new_page()
            page.goto(url, timeout=timeout, wait_until="domcontentloaded")
            for st in steps:
                boxes = segment(page.screenshot(), st["find"])
                if not boxes:
                    log.append(f"{st['find']}: not located")
                    continue
                cx, cy = boxes[0]["center"]
                if st.get("fill") is not None:
                    # snap the SAM box to the real DOM input for a reliable fill
                    ok = page.evaluate(_FILL_JS, [cx, cy, str(st["fill"])])
                    if not ok:
                        page.mouse.click(cx, cy)
                        page.keyboard.type(str(st["fill"]))
                    log.append(f"filled '{st['find']}' @({cx},{cy})" + ("" if ok else " [coord]"))
                else:
                    ok = page.evaluate(_CLICK_JS, [cx, cy])
                    if not ok:
                        page.mouse.click(cx, cy)
                    log.append(f"clicked '{st['find']}' @({cx},{cy})" + ("" if ok else " [coord]"))
                page.wait_for_timeout(600)
            try:  # let any navigation settle before the final capture
                page.wait_for_load_state("networkidle", timeout=4000)
            except Exception:  # noqa: BLE001
                pass
            final = page.screenshot()
            vision = vision_analyze(final, "After these actions, what does the page show now "
                                    "(errors, success, authenticated state)?")
            return {"log": log, "url": page.url, "title": page.title(),
                    "vision": vision[:1200], "png": final}
        finally:
            browser.close()


if __name__ == "__main__":  # self-check: python -m watson.browser (local page, no vision call)
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    HTML = (b"<html><head><title>Login</title></head><body><h1>Portal</h1>"
            b'<form action="/auth" method="post"><input name="user">'
            b'<input name="pw" type="password"></form>'
            b'<a href="/admin">admin</a>'
            b"<script>window.onload=()=>{document.body.innerHTML+=' AUTH:'"
            b"+(localStorage.getItem('sb')||'none')}</script></body></html>")

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(HTML)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    snap = snapshot(f"http://127.0.0.1:{srv.server_address[1]}/")
    assert snap["png"][:8] == b"\x89PNG\r\n\x1a\n", "got a PNG screenshot"
    assert snap["title"] == "Login"
    assert any(f["inputs"] and f["inputs"][-1]["type"] == "password" for f in snap["forms"]), snap["forms"]
    assert any(l.endswith("/admin") for l in snap["links"]), snap["links"]
    assert "AUTH:none" in snap["text"], snap["text"][-80:]       # no session injected

    # authenticated browse: localStorage is seeded before the app's JS runs
    base = f"http://127.0.0.1:{srv.server_address[1]}/"
    snap2 = snapshot(base, storage=[{"name": "sb", "value": "TOKEN123"}])
    assert "AUTH:TOKEN123" in snap2["text"], snap2["text"][-80:]
    srv.shutdown()

    # SAM box parsing (real output shape)
    sam = ("<0f>0<|box;x1=50;y1=98;x2=214;y2=132;w=1280;h=720|><|mask;x=0;data=35|>,"
           "1<|box;x1=50;y1=143;x2=214;y2=177;w=1280;h=720|><|mask;x=0;data=9|>")
    boxes = _parse_boxes(sam)
    assert len(boxes) == 2 and boxes[0]["center"] == [132, 115], boxes
    assert boxes[1]["box"] == [50, 143, 214, 177] and boxes[1]["center"] == [132, 160]
    print("browser self-check ok")
