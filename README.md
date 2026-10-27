# MetSec

Autonomous AI agent that runs an **authorized** pentest against your *own* website,
correlates findings against known CVEs, and reports with evidence + remediation.
Reasoning runs on Meta Muse models; a CVE RAG gives the agent current security knowledge.

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

## Status

- [x] **Phase 0** — API client + scope guard + smoke test
- [x] **Phase 1** — CVE RAG (CISA KEV + NVD-by-keyword → local embeddings → LanceDB)
- [x] **Phase 2** — recon: Wappalyzer fingerprinting + active (crawl, content/port scan, auth)
- [ ] **Phase 3** — agent loop (plan → act → verify)
- [ ] **Phase 4** — reporting
- [ ] **Phase 5** — hardening & CLI UX

## Setup

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
echo "META_API_KEY=your-key" > .env     # Meta Model API key
cp scope.example.yaml scope.yaml        # then edit to your targets
```

## Usage

```bash
metsec smoke                       # verify API key + model routing
metsec scope scope.yaml            # validate a scope file
metsec rag build                   # build the CVE index from CISA KEV
metsec rag build --nvd-keyword log4j   # + enrich with NVD hits for a product
metsec rag search "apache log4j rce" -k 3   # query the index (--kev, --min-cvss X)
metsec research lodash 4.17.4 --ecosystem npm   # live vuln research for a tech+version
metsec research node 18.12.0 --save             # web-researched vulns, learned into the index
metsec fingerprints update                      # download the 7.6k-signature tech DB
metsec recon http://localhost:3000 --scope scope.yaml --research   # fingerprint + find vulns
```

## How it finds vulnerabilities

1. **Static index** — CISA KEV (+ NVD by keyword) embedded in LanceDB.
2. **Active research** (`research.py`) — for any detected tech+version:
   - **OSV.dev** — free, no-key, exact-version lookup for open-source deps (npm, PyPI, …).
   - **Web search** — DuckDuckGo → fetch the top advisory/release pages → Muse extracts
     structured vulns for runtimes and the long tail (e.g. `node vX.XX`) static DBs miss.
   - `--save` folds findings back into the index, so researched knowledge persists.

   Deferred: Muse native *search grounding* (API param undocumented); a keyed search
   backend (Tavily/Brave) if DuckDuckGo rate-limiting becomes a problem.

## Recon

`metsec recon <url> --scope <file>` runs passive fingerprinting (7.6k-signature
Wappalyzer DB + heuristics) and robots/sitemap discovery. Add `--active` for
mode-gated active recon:

- **crawl** — same-origin BFS, forms/inputs, JS endpoint mining (authenticated if
  `scope.auth` is set)
- **content discovery** — `ffuf` + wordlist when installed, else a curated path list
- **port scan** — `nmap -sV` when installed, else a socket scan (`--ports`; on by
  default in dev, opt-in in prod)
- **nuclei** — template vuln scan when installed (`--nuclei`)

External tools (`nmap`/`nuclei`/`ffuf`) are used when present; pure-Python fallbacks
run everywhere else. Mode gates aggressiveness: `static` blocks active recon, `prod`
throttles and is detection-first, `dev` is unthrottled.

## Stack

| Piece        | Choice |
|--------------|--------|
| Agent brain  | Muse Wonder (`muse-wonder-1.0`) — planning, report synthesis |
| Fast tasks   | Muse Spark 1.3 (`muse-spark-1.3`) — triage, classification |
| API          | `openai` SDK → `https://api.meta.ai/v1` (OpenAI-compatible) |
| Embeddings   | local sentence-transformers (Meta has no embedding model) |
| Vector store | LanceDB (embedded) |
| Scanners     | `httpx`, `nuclei`, `nmap`, `whatweb` (wrapped, not reinvented) |
