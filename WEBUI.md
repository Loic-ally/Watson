# Watson web UI — Rust backend + TypeScript frontend

The browser control panel is a **React/TypeScript SPA** (Vite + Tailwind +
shadcn/ui) served by a **thin Rust (Axum) backend**. The Python agent is
untouched — the Rust server shells out to `python -m watson.bridge` for the four
jobs that need Python (classify a chat message, run a scan + stream events,
search the RAG index, transcribe audio). Reports and screenshots are plain files
on disk, served directly by Rust.

```
TS SPA (Vite/React)  ──HTTP + SSE──►  Rust (Axum)  ──spawn──►  python -m watson.bridge  ──►  watson agent
                                         │ reads watson-report-*/ , .watson_cache/shots/ directly
```

## Features

- **Chat** — drive the agent in natural language; it classifies the message,
  launches a scan, and streams the kill-chain live in the conversation.
- **Persistent history** — conversations are kept in the browser (localStorage),
  so you can leave and reopen a previous chat. Finished scan feeds are folded
  into the saved history; mid-scan reloads reconnect to the live stream.
- **Dashboard** — real-time kill-chain tracker (Recon → Exploit → Foothold →
  Privesc → ROOT) with the agent's activity feed.
- **Reports** — summary stat cards + every past assessment; open the styled HTML
  report or download a PDF.
- **Knowledge** — CVE/technique search showing full detail per hit: CVSS,
  severity/KEV, affected products, CWE and clickable references.
- **Voice input** — speak an instruction; transcribed via Muse Voice Transcribe.
- **Design** — monochrome dark theme; colour is reserved for danger only.

## Run (dev)

Two terminals, from the repo root:

```bash
# 1. backend (serves API + SSE on :8787)
cd backend && cargo run

# 2. frontend (Vite dev server, proxies /api,/stream,/shot to :8787)
cd frontend && npm install && npm run dev
# open the URL Vite prints (login: admin / watson)
```

## Run (single server)

Build the SPA; the Rust server then serves it too — one process on :8787:

```bash
cd frontend && npm run build        # -> frontend/dist
cd ../backend && cargo run          # http://127.0.0.1:8787
```

## Config (env)

| var | default | meaning |
|-----|---------|---------|
| `WATSON_WEB_USER` / `WATSON_WEB_PASS` | `admin` / `watson` | login (change the password!) |
| `WATSON_PORT` | `8787` | backend port |
| `WATSON_PYTHON` | `.venv/bin/python` else `python3` | python used for the bridge |
| `WATSON_ROOT` | this crate's parent | project dir (reports, venv, SPA) |

The agent still needs its Muse API credentials (`.env`) for chat, scans,
knowledge search and transcription.

The legacy Flask control panel (`watson web`) still works and shares the same
report/screenshot files; this Rust/TS UI supersedes it.
