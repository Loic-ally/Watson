# Watson

Watson is an autonomous AI penetration-testing agent for web applications you own
or are authorized to assess. It performs reconnaissance, correlates findings against
a live vulnerability knowledge base, and — when explicitly authorized — exploits to
*confirm* rather than guess, chaining web access into a host foothold, privilege
escalation, looting, and lateral movement across the internal network. Every run is
scoped, audited, and ends in a ranked report. A live web console lets an operator
drive the agent and watch its path in real time.

> **Authorization required.** Watson only runs against targets named in a `scope.yaml`
> that records who authorized the engagement. No scope, no scan. Deep exploitation is
> gated behind an explicit `--exploit` flag.

## Legal & responsible use

Watson is provided **as is**, for authorized security testing and educational use only.
By using it you confirm you have explicit permission to test every target you point it
at, and you accept full responsibility for complying with all applicable laws and with
the terms of any service, model, or API it relies on. Running it against systems you do
not own or are not authorized to test may be illegal. The authors accept no liability
for misuse, damage, or legal consequence arising from use of this tool, and provide no
warranty of any kind. If you do not agree, do not use Watson.

## Capabilities

- **Reconnaissance** — technology fingerprinting (Wappalyzer, 7.6k signatures), active
  crawling, content and port discovery, authenticated sessions, and optional
  vision-based recon that loads pages in a real browser to catch JS-rendered surface.
- **Vulnerability correlation** — detected technologies and versions are matched against
  an indexed CVE knowledge base plus live research, with exploit availability and
  likelihood signals attached.
- **Probe-and-verify exploitation** — findings are evidence-backed and marked `verified`
  (confirmed by a probe), `potential`, or `refuted`, each with where it is, how it is
  exploited, and how to fix it, plus the exact proving request for re-validation.
- **Host foothold** — turns a confirmed web RCE into command execution via command
  injection, multi-engine server-side template injection (Jinja2 / Twig / Freemarker /
  ERB / Smarty), uploaded web shells, or deserialization payloads.
- **Linux post-exploitation** — host enumeration, GTFOBins-matched (and reasoned)
  privilege escalation to root, and credential/secret looting.
- **Lateral movement** — internal-network recon and a SOCKS tunnel through the foothold
  so probes reach in-scope internal hosts.
- **Windows & Active Directory** — credential- and network-driven: SMB/LDAP enumeration,
  Kerberoasting and AS-REP roasting, BloodHound collection, remote command execution, and
  secret dumping (local SAM and DCSync) via industry-standard tooling.
- **Reporting** — `findings.json`, Markdown and styled HTML, consistent CVSS, a written
  attack narrative, the hypotheses and attack chain, and a rendered PDF.
- **Operations** — per-target memory across runs, parallel assessment of multiple scope
  targets, recon caching, and a full per-run audit log.

## How it works

`assess` and `scan` run reconnaissance, then hand the inventory to the model, which
drives a self-terminating loop over a defensive toolset: it looks up vulnerabilities,
probes in-scope URLs to confirm conditions, links observations into attack chains, and
decides when the assessment is complete (a `--budget` cap is only a safety limit). It
records a finding only when it is backed by a concrete observation the agent collected.

**Tools:** `search_vulns` · `http_probe` · `browse` · `browser_action` ·
`establish_foothold` · `upload_shell` · `make_payload` · `run_command` · `privesc_scan` ·
`pivot_scan` · `open_tunnel` · `ad_recon` · `ad_exec` · `loot` · `hypothesize` ·
`record_finding` · `finish`.

**Modes gate aggressiveness.** `static` inspects code only (no traffic); `dev` exploits
freely against localhost or a lab; `prod` is detection-first and rate-limited. `--exploit`
lifts the prod gate for authorized aggressive testing (injection, IDOR, forged sessions,
foothold, privilege escalation, lateral movement). A catastrophic-command denylist blocks
host-destroying commands even then.

## Models

- **Reasoning, vision, and fast paths** — Meta Muse (Spark).
- **Segmentation** — SAM 3.1, which locates UI elements for vision-guided interaction.
- **Speech-to-text** — Muse Voice (for the web console's voice input).

Secrets are redacted before any content reaches a model or the index.

## Knowledge base

CVEs (CISA KEV / NVD / OSV, with aliases, CVSS vector, and affected/fixed ranges),
FIRST EPSS exploitation likelihood, ExploitDB availability, vendor advisories and VEX
(CSAF 2.0), GTFOBins (Linux) and LOLBAS (Windows), MITRE ATT&CK and CWE, OWASP ASVS /
WSTG control catalogs and cheat sheets for remediation, Wappalyzer signatures, and live
web research (DuckDuckGo / Tavily / Brave). The agent also reasons beyond the indexed
material to find custom, non-CVE flaws. _(CIS Benchmarks: import interface and sample
only — the full content is license-restricted.)_

## Installation

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
watson rag build --techniques [--attack]       # build the knowledge index (+ MITRE ATT&CK)
watson rag search "sudo find privesc" -k 3     # query the index
watson research lodash 4.17.4 --ecosystem npm  # live vuln research for a tech + version
watson recon <url> --scope scope.yaml --active --research   # recon + find vulns
watson browse <url> --scope scope.yaml         # vision browser recon (screenshot + analysis)
watson assess <url> --scope scope.yaml [--active] [--exploit] [--out dir] [--revalidate] [--pdf]
watson scan --web <url> --scope scope.yaml --exploit        # one-shot + live dashboard
watson scan-all --scope scope.yaml --exploit                # parallel over all scope targets
watson pdf <report-dir>                                     # render the report to PDF
watson web                                                  # full web app (login + voice chat)
```

`--revalidate` replays the exact proving request of each verified finding to cut false
positives. `--pdf` has the model fill `template.html` and renders it to PDF via Chromium.
The agent keeps per-target memory across runs, performs internal recon from a foothold
(`pivot_scan`), and opens a SOCKS tunnel through the foothold (`open_tunnel`) so probes
reach in-scope internal hosts. `scan-all` runs one sub-agent per target in parallel, each
with an isolated event feed and audit log. External tools route through Exegol; the web
console accepts voice input and can read replies aloud.

## Web console

A React/TypeScript single-page app (Vite + Tailwind + shadcn/ui) served by a thin Rust
(Axum) backend at `http://127.0.0.1:8787` (login `admin` / `WATSON_WEB_PASS`, default
`watson` — change it). The backend shells out to `python -m watson.bridge`; the agent
itself is unchanged. Run it with `cd backend && cargo run` (which serves `frontend/dist`);
see [WEBUI.md](WEBUI.md) for development and build details.

- **Chat** — drive the agent in natural language (e.g. *"pentest http://127.0.0.1:5002 in
  dev mode with exploit"*); it parses the instruction, launches the scan, and streams its
  path live. Conversations persist in the browser so a past chat can be reopened.
- **Dashboard** — live kill-chain tracker (Recon → Exploit → Foothold → Privesc → ROOT).
- **Reports** — summary cards and every past assessment with CVSS; open the HTML report or PDF.
- **Knowledge** — CVE and technique search with full detail (CVSS, KEV, products, CWE, refs).

A standalone Flask control panel (`watson web`) also exists and shares the same report files.

## External tooling via Exegol

External tools (nmap, nuclei, ffuf, semgrep, netexec/nxc, BloodHound, impacket, …) run
inside a running Exegol container when they are not present on the host, so nothing has to
be installed locally; set `EXEGOL_CONTAINER` to pin one. Multi-language SAST uses Semgrep
this way, and pure-Python fallbacks run when neither the host nor Exegol has a given tool.

## Reports

`--out <dir>` writes `findings.json` (with per-finding CVSS), `report.md`, and a styled
`report.html`, ranked critical → info, with an overall CVSS score, a written attack
narrative, the hypotheses and attack chain, and where/how/fix for each finding. Every tool
call is also recorded in a JSONL audit log under `.watson_cache/audit/`.

## Practice labs

The vulnerable practice targets (`testbed/`) and the Blackveil CTF environment live in
[Loic-ally/Blackveil](https://github.com/Loic-ally/Blackveil).

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
