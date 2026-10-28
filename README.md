# MetSec

Autonomous AI pentest agent for your **own** web apps. It recons a target, correlates
against a live vulnerability knowledge base, exploits to *confirm* (not guess), chains
**web → foothold → Linux root**, loots, and writes a report — with a **live web
dashboard** to watch its path. Reasoning runs on Meta Muse (Spark) with SAM 3.1 vision.

> ⚠️ MetSec only runs against targets you own or are authorized to test. Every run
> starts from a `scope.yaml` naming who authorized it — no scope, no scan.

## Disclaimer

MetSec is provided **as is**, for authorized security testing and educational use only.
You are solely responsible for how you use it. By using this tool you confirm you have
explicit permission to test every target you point it at, and you accept full
responsibility for complying with all applicable laws and the terms of any service,
model, or API it relies on.

Running it against systems you do not own or are not authorized to test may be illegal.
**The author accepts no liability for any misuse, damage, or legal consequence arising
from use of this tool** — the responsibility is entirely the user's. No warranty of any
kind is given. If you do not agree, do not use MetSec.

## Kill chain

| | Stage | Status |
|---|---|---|
| 0 | Scope guard · `static`/`dev`/`prod` modes · Meta API client | ✅ |
| 1 | CVE RAG + active web vuln research | ✅ |
| 2 | Recon: Wappalyzer fingerprint + active (crawl/content/port) + auth + **vision** | ✅ |
| 3 | Agent loop (plan → probe → **verify** → record), self-terminating | ✅ |
| 4 | Reporting: `findings.json` + Markdown + **HTML** + CVSS + attack narrative | ✅ |
| 5 | UX: recon caching, live dashboard, one-command `scan`, audit log | ✅ |
| 6 | Foothold: cmd-injection · multi-engine SSTI · webshell · upload · deserialization | ✅ |
| 7 | Linux post-ex: enumerate → GTFOBins/reasoning privesc → root → loot | ✅ |
| 8 | Windows / lateral movement / Active Directory | ⬜ |

## Models & knowledge

- **Reasoning + vision + fast** → Muse **Spark 1.3 Contributor** (`config.BRAIN`/`FAST`).
- **Segmentation** → **SAM 3.1** — locates UI elements for vision-guided interaction.
- **Knowledge base:** CVEs (CISA KEV / NVD / OSV) · **ExploitDB** exploit availability ·
  **GTFOBins** (Linux privesc) · **LOLBAS** (Windows) · **MITRE ATT&CK** · **Wappalyzer**
  (7.6k signatures) · live web research (DuckDuckGo / Tavily / Brave) — and the agent
  reasons **beyond** the docs (it cracks custom, non-CVE flaws).

## Setup

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
echo "META_API_KEY=your-key" > .env     # Meta Model API key
cp scope.example.yaml scope.yaml        # then edit: mode + targets + (optional) auth
metsec rag build --techniques           # CVE index + GTFOBins/LOLBAS + ExploitDB map
# optional: playwright install chromium   (vision browser)   ·   TAVILY_API_KEY/BRAVE_API_KEY
```

## Usage

```bash
metsec smoke                                   # verify API key + model routing
metsec scope scope.yaml                        # validate a scope file
metsec rag build --techniques [--attack]       # build the knowledge index (+ MITRE ATT&CK)
metsec rag search "sudo find privesc" -k 3     # query the index
metsec research lodash 4.17.4 --ecosystem npm  # live vuln research for a tech+version
metsec recon <url> --scope scope.yaml --active --research   # recon + find vulns
metsec browse <url> --scope scope.yaml         # vision browser recon (screenshot + analysis)
metsec assess <url> --scope scope.yaml [--active] [--exploit] [--out dir] [--fresh]
metsec scan --web <url> --scope scope.yaml --exploit        # one-shot + live dashboard
metsec web                                                  # full web app (login + chat)
```

## Web app

`metsec web` serves a dark-themed control panel at **http://127.0.0.1:8787** (login
`admin` / `METSEC_WEB_PASS`, default `metsec`):

- **Chat** — tell the agent what to do in natural language (*"pentest http://127.0.0.1:5002
  in dev mode with exploit"*); it parses the instruction, launches the scan, and **streams
  its path live** in the conversation. Non-scan messages are answered from the latest run.
- **Dashboard** — live kill-chain tracker (Recon → Exploit → Foothold → Privesc → ROOT).
- **Reports** — every past assessment with CVSS + findings; open the full styled report.
- **Knowledge** — search the CVE / technique index from the browser.

## The agent

`assess`/`scan` run recon, then hand the inventory to the model, which drives a
**self-terminating** loop over a defensive toolset — it decides when it's done and calls
`finish` (`--budget N` is just a safety cap). It records only evidence-backed findings,
each `verified` (confirmed by a probe) or `potential`, with **Where / How exploited / Fix**.

**Tools:** `search_vulns` · `http_probe` · `browse` · `browser_action` (vision+SAM) ·
`establish_foothold` · `upload_shell` · `make_payload` · `run_command` · `privesc_scan` ·
`loot` · `hypothesize` (links findings into attack chains) · `record_finding` · `finish`.

**Modes gate aggressiveness:** `static` = code only (no traffic); `dev` = exploit freely
(localhost/lab); `prod` = detection-first, rate-limited. `--exploit` lifts the prod gate
for authorized aggressive testing (injection, IDOR, forged sessions, foothold, privesc).
A catastrophic-command denylist blocks box-destroyers even then.

## Live dashboard

`metsec scan --web <url> --scope <file>` serves **http://127.0.0.1:8787** — a kill-chain
tracker (Recon → Exploit → Foothold → Privesc → **ROOT**), a live activity feed, a
host-command terminal, hypotheses, and findings as they land (SSE).

## External tools via Exegol

External tools (nmap, nuclei, ffuf, semgrep, nxc, bloodhound, impacket…) run inside a
running **Exegol** container if they're not on the host — nothing to install locally. Set
`EXEGOL_CONTAINER` to pin one. Multi-language SAST uses **Semgrep** this way; pure-Python
fallbacks run when neither host nor Exegol has a tool.

## Reports

`--out <dir>` writes `findings.json` (+ per-finding CVSS), `report.md`, and a styled
`report.html` — ranked critical→info, with an overall CVSS score, an LLM-written **attack
narrative**, the **hypotheses/attack-chain**, and Where/How/Fix per finding. Every tool
call is also recorded in a JSONL **audit log** (`.metsec_cache/audit/`).

## Practice boxes (`testbed/`)

Intentionally vulnerable, **localhost only** — run `./testbed/<box>/run.sh`:

- **linux-lab** — web command-injection → `sudo find` → root (easy).
- **citadel** — SQLi auth-bypass → admin SSTI RCE → `sudo tar` → root (multi-stage).
- **obscura** — *insane, no CVE*: LFI → source review → custom auth bypass → cmd-injection
  → **unsafe-YAML deserialization** privesc → root. The agent must discover its own chain.

## Stack

| Piece | Choice |
|---|---|
| Reasoning / vision / fast | Muse **Spark 1.3 Contributor** |
| Segmentation | **SAM 3.1** (vision-guided interaction) |
| API | `openai` SDK → `https://api.meta.ai/v1` (OpenAI-compatible) |
| Embeddings | local **fastembed** (`bge-small`) — Meta has no embedding model |
| Vector store | **LanceDB** (embedded) |
| Browser | **Playwright** headless Chromium (optional) |
| External tools | **Exegol** container (docker exec) + pure-Python fallbacks |
| SAST | **Semgrep** (multi-language) + Python AST |
