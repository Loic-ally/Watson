<h1 align="center">Watson</h1>

<p align="center">
  <b>An autonomous AI penetration tester for web apps you own.</b><br>
  It fingerprints a target, correlates what it finds against a live CVE knowledge base,<br>
  and — when authorized — exploits to <i>confirm</i> rather than guess: web access into a host foothold,<br>
  privilege escalation, looting, and lateral movement. Every run is scoped, audited, and ranked.
</p>

<p align="center">
  <img alt="Meta Muse" src="https://img.shields.io/badge/Meta-Muse%20Spark-0866FF">
  <img alt="SAM 3.1" src="https://img.shields.io/badge/Meta-SAM%203.1-0866FF">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11+-3776AB">
  <img alt="Backend" src="https://img.shields.io/badge/backend-Rust%20(Axum)-DEA584">
  <img alt="Frontend" src="https://img.shields.io/badge/UI-React%20%2B%20Vite-61DAFB">
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-lightgrey">
</p>

<p align="center">
  <a href="#why">Why</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#capabilities">Capabilities</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#web-console">Web console</a> ·
  <a href="#safety-by-design">Safety</a>
</p>

> **Authorization required.** Watson only runs against targets named in a `scope.yaml` that
> records who authorized the engagement. No scope, no scan. Deep exploitation is gated behind
> an explicit `--exploit` flag.

## Why

A real assessment is slow because a human reads output, looks up each technology against the
CVE landscape, and probes by hand to tell a true finding from a guess. Watson does that loop:
it recons the target, matches every detected technology and version against an indexed
vulnerability base plus live research, and — only when authorized — fires the exact probe that
confirms or refutes each hypothesis. It records a finding only when a concrete observation
backs it, and ends in a ranked report a human can act on.

## How it works

`assess` and `scan` run reconnaissance, then hand the inventory to the model, which drives a
self-terminating loop over a defensive toolset until it decides the assessment is complete (a
`--budget` cap is only a safety limit).

| | |
|---|---|
| **1. Recon** | Technology fingerprinting (Wappalyzer, 7.6k signatures), active crawling, content and port discovery, authenticated sessions, and optional vision-based recon that loads pages in a real browser to catch JS-rendered surface. |
| **2. Correlate** | Detected technologies and versions are matched against an indexed CVE base plus live research, with exploit availability and likelihood signals attached. |
| **3. Probe & verify** | Findings are evidence-backed and marked `verified` (confirmed by a probe), `potential`, or `refuted` — each with where it is, how it is exploited, how to fix it, and the exact proving request for re-validation. |
| **4. Go deep** | A confirmed web RCE becomes command execution (injection, multi-engine SSTI, uploaded shells, deserialization), then Linux post-exploitation, privilege escalation, looting, and a SOCKS pivot to in-scope internal hosts — Windows / AD included. |
| **5. Report** | `findings.json`, Markdown, styled HTML and a rendered PDF — ranked critical → info, with an overall CVSS score, an attack narrative, and the full tool-call audit log. |

**Tools:** `search_vulns` · `http_probe` · `browse` · `browser_action` · `establish_foothold` ·
`upload_shell` · `make_payload` · `run_command` · `privesc_scan` · `pivot_scan` · `open_tunnel` ·
`open_reverse_tunnel` · `ad_recon` · `ad_exec` · `win_privesc_scan` · `loot` · `hypothesize` ·
`record_finding` · `finish`.

**Modes gate aggressiveness.** `static` inspects code only (no traffic); `dev` exploits freely
against localhost or a lab; `prod` is detection-first and rate-limited. `--exploit` lifts the
prod gate for authorized aggressive testing. A catastrophic-command denylist blocks
host-destroying commands even then.

## Capabilities

- **Reconnaissance** — fingerprinting, active crawling, content and port discovery,
  authenticated sessions, optional vision-based recon in a real browser.
- **Vulnerability correlation** — detected tech/versions matched against a CVE base plus live
  research, with exploit availability and likelihood signals.
- **Probe-and-verify exploitation** — evidence-backed findings, each with where / how / fix and
  the exact proving request for re-validation.
- **Host foothold** — web RCE into command execution via command injection, multi-engine SSTI
  (Jinja2 / Twig / Freemarker / ERB / Smarty), uploaded web shells, or deserialization.
- **Linux post-exploitation** — host enumeration, GTFOBins-matched privilege escalation to root,
  and credential/secret looting.
- **Lateral movement** — internal-network recon and a SOCKS tunnel through the foothold
  (forward, or a reverse connect-back tunnel for footholds behind NAT) so probes reach
  in-scope internal hosts.
- **Windows & Active Directory** — SMB/LDAP enumeration, Kerberoasting and AS-REP roasting,
  BloodHound collection, remote command execution, and secret dumping (local SAM and DCSync).
- **Windows local privilege escalation** — token privileges (`SeImpersonate`, `SeBackup`,
  `SeDebug`, …) and group memberships mapped to concrete local-to-SYSTEM techniques — the
  Windows counterpart of GTFOBins-matched Linux privesc.
- **Reporting** — `findings.json`, Markdown, styled HTML and PDF, consistent CVSS, a written
  attack narrative, and the hypotheses / attack chain.
- **Operations** — per-target memory across runs, parallel assessment of all scope targets, recon
  caching, and a full per-run audit log.

## Knowledge base

CVEs (CISA KEV / NVD / OSV, with aliases, CVSS vector, affected/fixed ranges), FIRST EPSS
likelihood, ExploitDB availability, vendor advisories and VEX (CSAF 2.0), GTFOBins (Linux) and
LOLBAS (Windows), MITRE ATT&CK and CWE, OWASP ASVS / WSTG catalogs and cheat sheets, Wappalyzer
signatures, and live web research (DuckDuckGo / Tavily / Brave). The agent also reasons beyond
the indexed material to find custom, non-CVE flaws. Secrets are redacted before any content
reaches a model or the index.

## Models

| Model | Used for |
|---|---|
| **Meta Muse (Spark)** | Reasoning, vision, and fast paths — the investigation loop. |
| **SAM 3.1** | Segmentation: locates UI elements for vision-guided interaction. |
| **Muse Voice** | Speech-to-text for the web console's voice input. |

## Quick start

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
echo "META_API_KEY=your-key" > .env     # model API key
cp scope.example.yaml scope.yaml        # then edit: mode + targets + optional auth
watson rag build --techniques           # build the CVE index + GTFOBins/LOLBAS + ExploitDB map
# optional: playwright install chromium (vision browser) · TAVILY_API_KEY / BRAVE_API_KEY
```

## Usage

```bash
watson smoke                                   # verify API key + model routing
watson scope scope.yaml                        # validate a scope file
watson rag search "sudo find privesc" -k 3     # query the index
watson research lodash 4.17.4 --ecosystem npm  # live vuln research for a tech + version
watson recon <url> --scope scope.yaml --active --research
watson browse <url> --scope scope.yaml         # vision browser recon (screenshot + analysis)
watson assess <url> --scope scope.yaml [--active] [--exploit] [--out dir] [--revalidate] [--pdf]
watson scan --web <url> --scope scope.yaml --exploit        # one-shot + live dashboard
watson scan-all --scope scope.yaml --exploit                # parallel over all scope targets
watson pdf <report-dir>                                     # render the report to PDF
```

`--revalidate` replays the exact proving request of each verified finding to cut false
positives. `--pdf` has the model fill `template.html` and renders it via Chromium. `scan-all`
runs one sub-agent per target in parallel, each with an isolated event feed and audit log.
External tools route through Exegol; the web console accepts voice input and can read replies
aloud.

## Web console

A React/TypeScript SPA (Vite + Tailwind + shadcn/ui) served by a thin Rust (Axum) backend at
`http://127.0.0.1:8787` (login `admin` / `WATSON_WEB_PASS`, default `watson` — change it). The
backend shells out to `python -m watson.bridge`; the agent itself is unchanged. Run it with
`cd backend && cargo run` (which serves `frontend/dist`); see [WEBUI.md](WEBUI.md) for build
details.

- **Chat** — drive the agent in natural language (*"pentest http://127.0.0.1:5002 in dev mode
  with exploit"*); it parses the instruction, launches the scan, and streams its path live.
- **Dashboard** — live kill-chain tracker (Recon → Exploit → Foothold → Privesc → ROOT).
- **Reports** — summary cards and every past assessment with CVSS; open the HTML report or PDF.
- **Knowledge** — CVE and technique search with full detail (CVSS, KEV, products, CWE, refs).

## External tooling via Exegol

External tools (nmap, nuclei, ffuf, semgrep, netexec/nxc, BloodHound, impacket…) run inside a
running Exegol container when they are not present on the host, so nothing has to be installed
locally; set `EXEGOL_CONTAINER` to pin one. Multi-language SAST uses Semgrep this way, and
pure-Python fallbacks run when neither the host nor Exegol has a given tool.

## Reports

`--out <dir>` writes `findings.json` (per-finding CVSS), `report.md`, and a styled `report.html`,
ranked critical → info, with an overall CVSS score, a written attack narrative, the hypotheses
and attack chain, and where/how/fix for each finding. Every tool call is also recorded in a
JSONL audit log under `.watson_cache/audit/`.

## Stack

| Component | Choice |
|---|---|
| Reasoning / vision / fast | Meta Muse (Spark) |
| Segmentation | SAM 3.1 (vision-guided interaction) |
| Model API | `openai` SDK → OpenAI-compatible endpoint |
| Embeddings | local `fastembed` (`bge-small`) |
| Vector store | LanceDB (embedded) |
| Browser | Playwright headless Chromium (optional) |
| External tools | Exegol container (docker exec) + pure-Python fallbacks |
| SAST | Semgrep (multi-language) + Python AST |
| Web backend | Rust (Axum) — thin API over `python -m watson.bridge` |
| Web frontend | TypeScript (React + Vite + Tailwind + shadcn/ui) |

## Practice labs

The vulnerable practice targets (`testbed/`) and the Blackveil CTF environment live in
[Loic-ally/Blackveil](https://github.com/Loic-ally/Blackveil).

A reproducible **Active Directory lab** lives in [`labs/ad/`](labs/ad/README.md): a seeded
domain (Kerberoastable SPN, AS-REP-roastable user, Backup Operators / DnsAdmins members, a
reused credential, and a SYSTEM-granting token-privilege host) that exercises the whole
Windows chain — `ad_recon` → roast → BloodHound → `ad_exec` → `win_privesc_scan` → DCSync.
One `docker compose up` for the Samba path, or `seed-dc.ps1` for a full-fidelity Windows DC.

## Legal & responsible use

Watson is provided **as is**, for authorized security testing and educational use only. By
using it you confirm you have explicit permission to test every target you point it at, and you
accept full responsibility for complying with all applicable laws and with the terms of any
service, model, or API it relies on. Running it against systems you do not own or are not
authorized to test may be illegal. The authors accept no liability for misuse, damage, or legal
consequence arising from use of this tool, and provide no warranty of any kind. If you do not
agree, do not use Watson.

## Safety by design

- **No scope, no scan** — every target must be named in a `scope.yaml` that records the
  authorization; deep exploitation is gated behind `--exploit`.
- **Modes gate aggressiveness** — `static` (no traffic) / `dev` (lab) / `prod` (detection-first,
  rate-limited); a catastrophic-command denylist blocks host-destroying commands even under
  `--exploit`.
- **Evidence or nothing** — a finding is recorded only when a concrete observation backs it, and
  carries the exact request to re-prove it.
- **Redacted** — secrets are stripped before any content reaches a model or the index.
- **Audited** — every tool call is recorded in a per-run JSONL audit log.

## License

[MIT](LICENSE). © 2026 Loic Philippe.
