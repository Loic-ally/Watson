# Watson — next steps

Upgrade ideas, grounded in what the agent already produces. Short version: the agent
already emits all the pieces of a graph (observations `OBS-N`, findings with `affected`,
hypotheses that *link* things, foothold/pivot/loot, per-asset memory) — it just never
assembles them into one model or *reasons over* it. That assembly is the biggest lever,
and the memory-as-a-graph idea is the front door to it.

## 1. The attack graph — make the agent *reason* over it, not just display it

Two layers from the same data.

**Data model** (built from existing outputs — mostly wiring, not new collection):

- **Nodes:** assets (host:port, endpoint, param), services/tech, findings, credentials
  (from `loot`), footholds, internal hosts (from `pivot_scan` / `ad_recon`), domain
  principals (users/groups from BloodHound).
- **Edges:** `runs` (host→tech), `exposes` (endpoint→finding), `authenticates-to`
  (cred→service), `pivots-to` (foothold→internal host), `reused-on` (cred→another host),
  `escalates-to` (finding→root/DA). Hypotheses already *are* edges — promote them to
  first-class graph edges.

**The expert leap:** feed the graph *back into the loop*. The loop is roughly linear
today. An expert maintains a mental model and always picks the highest-value next move
toward an objective. Add a `graph` tool (query reachability) and a planning step: "given
the graph, what's the shortest unexplored path to root / Domain Admin?" This is exactly
BloodHound's shortest-path-to-DA — and AD support is already in, so it fits. Auto-detecting
a **credential-reuse edge** (a looted password that works on another in-scope host) is
textbook expert behavior the agent doesn't do today.

**Viz:** a `Graph` page in the React UI, streamed over the existing SSE bus (emit
`graph_node` / `graph_edge` events alongside the current ones), highlighting the live path
to the objective. Node color by severity, compromise path lit up.

> Note: the `graphify` skill is useful for *offline* exploration of a finished run, but for
> the live UI build the in-app graph, since it has to update during the scan.

## 2. Think like an expert: triage instead of brute-force

- **Lead prioritization.** EPSS + KEV + ExploitDB are already indexed. Rank the agent's
  next actions by `exploitability × reachability × impact` so it chases the CVE with a
  public exploit before the theoretical one. The loop currently explores fairly flatly.
- **Explicit plan + reflection.** A short planning turn up front ("3 hypotheses, ranked")
  and a reflection turn after each phase ("what did I learn, what's now reachable"). Cheap,
  and it makes the reasoning legible.
- **OPSEC awareness in `prod`.** Jitter / rate-limit, prefer passive checks, flag loud
  probes. Surface a per-run noise score.

## 3. Memory upgrades (beyond the graph)

- **Graph-structured memory**, so `recall()` returns a queryable model, not a flat findings
  list — "what creds do I know for this project," "what did I reach from this foothold."
- **Cross-engagement learning:** remember which *techniques* worked against which *tech
  stacks*, so a new target on the same stack starts with a prior. Memory is per-asset only
  today.

## 4. Capability breadth (smaller, additive)

- Recon depth: subdomain enum, JS-endpoint/secret extraction, GraphQL introspection, API fuzzing.
- `nuclei` breadth pass through the existing Exegol path for fast known-vuln coverage.
- **Scan diffing / posture trends:** compare two runs of the same asset ("3 new highs since
  last week") — per-asset memory already sets this up.

## 5. Reporting / UX

- Executive summary + prioritized remediation (impact-ranked, not just severity-sorted).
- A live **reasoning trace** panel (the plan / hypotheses / reflection from #2) next to the graph.

## Recommended order

Build **#1 as the spine** (attack graph: data model → `graph` query tool fed back to the
agent → live viz), and fold in **#2**'s prioritization since the graph gives reachability
for free. That combination turns it from "a scanner with an LLM" into something that
behaves like an operator. Scope it lazy — reuse the observation / finding / hypothesis data
that already exists rather than adding new collection.
