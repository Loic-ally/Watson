"""Headless-browser recon with vision (Playwright + Muse).

Drives a real Chromium so MetSec sees JS-rendered pages the static fetch misses:
a screenshot fed to the vision model, plus the rendered links and forms.

Optional: needs `pip install playwright && playwright install chromium`.
"""
from __future__ import annotations

import base64

_LINKS_JS = "els => els.map(e => e.href)"
_FORMS_JS = """els => els.map(f => ({
  action: f.action, method: f.method,
  inputs: [...f.querySelectorAll('input,select,textarea')].map(i => ({name: i.name, type: i.type}))
}))"""


def snapshot(url: str, timeout: int = 20000) -> dict:
    """Navigate headless Chromium → {png, title, links, forms, text}."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        try:
            page = browser.new_page()
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


if __name__ == "__main__":  # self-check: python -m metsec.browser (local page, no vision call)
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    HTML = (b"<html><head><title>Login</title></head><body><h1>Portal</h1>"
            b'<form action="/auth" method="post"><input name="user">'
            b'<input name="pw" type="password"></form>'
            b'<a href="/admin">admin</a></body></html>')

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
    srv.shutdown()
    print("browser self-check ok")
