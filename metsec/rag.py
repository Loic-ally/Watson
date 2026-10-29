"""CVE RAG: download + normalize vuln data, embed locally, store/search in LanceDB.

Common record schema (one row per vuln/technique), SCHEMA_VERSION'd so a stale index is
rebuilt rather than silently half-populated:
    id, aliases(list), source, rtype, summary, products, cvss(float), cvss_vector, severity,
    cwe(str, legacy), cwe_ids(list), attack_technique_ids(list), kev(bool),
    affected_ranges(list), fixed_versions(list), applicability(JSON str),
    published, modified, candidate(bool), schema_version(int),
    references(list[str]), provenance, text(embedded)

CVSS *vector* is kept distinct from the qualitative *severity* label, and CWE ids
(weakness taxonomy) distinct from ATT&CK technique ids (adversary-behaviour taxonomy).

Sources:
    - CISA KEV: small, known-exploited-in-the-wild. Default corpus.
    - NVD 2.0 API: by keyword/CPE for enrichment (adds CVSS vector + applicability ranges).
"""
from __future__ import annotations

import json as _json
from pathlib import Path
from typing import Iterable, Iterator

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

EMBED_MODEL = "BAAI/bge-small-en-v1.5"  # 384-dim, retrieval-tuned, ONNX via fastembed (no torch)
DB_PATH = ".metsec_cache/lancedb"
TABLE = "cve"
SCHEMA_VERSION = 2

# The columns every row must carry (LanceDB is columnar — a stale table missing any of
# these can't take new rows, so we detect it and ask for an explicit rebuild).
_COLUMNS = ("id", "aliases", "source", "rtype", "summary", "products", "cvss", "cvss_vector",
            "severity", "cwe", "cwe_ids", "attack_technique_ids", "kev", "affected_ranges",
            "fixed_versions", "applicability", "published", "modified", "candidate",
            "schema_version", "references", "provenance", "text")


# ----------------------------- normalize ------------------------------------

def _record(id, source, summary, products="", cvss=0.0, severity="",
            cwe="", kev=False, references=None, *, aliases=None, cvss_vector="",
            affected_ranges=None, fixed_versions=None, cwe_ids=None,
            attack_technique_ids=None, published="", modified="", applicability="",
            candidate=False, rtype="cve", provenance=""):
    from .redact import redact
    references = references or [f"https://nvd.nist.gov/vuln/detail/{id}"]
    aliases = list(aliases or [])
    cwe_ids = list(cwe_ids or ([c.strip() for c in cwe.split(",") if c.strip()] if cwe else []))
    # researched/web summaries can carry secrets → scrub before it is embedded or stored
    summary = redact(summary or "")
    # embed id + aliases + products + summary so an exact alias query still retrieves it
    text = " ".join(filter(None, [id, " ".join(aliases), products, summary]))
    if isinstance(applicability, (dict, list)):
        applicability = _json.dumps(applicability, default=str)
    return dict(id=id, aliases=aliases, source=source, rtype=rtype, summary=summary,
                products=products, cvss=float(cvss or 0.0), cvss_vector=cvss_vector or "",
                severity=severity, cwe=cwe, cwe_ids=cwe_ids,
                attack_technique_ids=list(attack_technique_ids or []), kev=bool(kev),
                affected_ranges=list(affected_ranges or []),
                fixed_versions=list(fixed_versions or []),
                applicability=applicability or "", published=published or "",
                modified=modified or "", candidate=bool(candidate),
                schema_version=SCHEMA_VERSION, references=references,
                provenance=provenance or source, text=text)


def fetch_kev() -> Iterator[dict]:
    data = requests.get(KEV_URL, timeout=60).json()
    for v in data.get("vulnerabilities", []):
        name = v.get("vulnerabilityName", "")
        desc = v.get("shortDescription", "")
        yield _record(
            id=v["cveID"], source="kev",
            summary=f"{name}. {desc}".strip(". "),
            products=f'{v.get("vendorProject", "")} {v.get("product", "")}'.strip(),
            cwe=",".join(v.get("cwes") or []),
            severity="KEV", kev=True,
        )


def _cvss(metrics: dict) -> tuple[float, str, str]:
    """(base_score, qualitative severity, vector) — the vector kept DISTINCT from severity."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            d = metrics[key][0]["cvssData"]
            return (float(d.get("baseScore", 0.0)), d.get("baseSeverity", ""),
                    d.get("vectorString", ""))
    return 0.0, "", ""


def _products(configs: list) -> str:
    out = set()
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")  # cpe:2.3:a:vendor:product:...
                if len(parts) > 4:
                    out.add(f"{parts[3]} {parts[4]}".replace("_", " "))
    return ", ".join(sorted(out))


def _applicability(configs: list) -> tuple[list[str], str]:
    """Preserve NVD applicability — the CPE ranges and their operators — not just a flat
    product list. Returns (human-readable range strings, JSON of the raw cpeMatch rows)."""
    ranges, raw = [], []
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable", True):
                    continue
                crit = m.get("criteria", "")
                lo = m.get("versionStartIncluding") or m.get("versionStartExcluding")
                lo_op = ">=" if m.get("versionStartIncluding") else (">" if m.get("versionStartExcluding") else "")
                hi = m.get("versionEndIncluding") or m.get("versionEndExcluding")
                hi_op = "<=" if m.get("versionEndIncluding") else ("<" if m.get("versionEndExcluding") else "")
                bits = [b for b in (f"{lo_op}{lo}" if lo else "", f"{hi_op}{hi}" if hi else "") if b]
                ranges.append(f"{crit} {' '.join(bits)}".strip())
                raw.append({k: m.get(k) for k in (
                    "criteria", "versionStartIncluding", "versionStartExcluding",
                    "versionEndIncluding", "versionEndExcluding") if m.get(k)})
    return ranges, _json.dumps(raw, default=str) if raw else ""


def fetch_nvd(keyword: str | None = None, cpe: str | None = None,
              results: int = 200, api_key: str | None = None) -> Iterator[dict]:
    params = {"resultsPerPage": min(results, 2000)}
    if keyword:
        params["keywordSearch"] = keyword
    if cpe:
        params["cpeName"] = cpe
    headers = {"apiKey": api_key} if api_key else {}
    data = requests.get(NVD_API, params=params, headers=headers, timeout=60).json()
    for item in data.get("vulnerabilities", []):
        c = item["cve"]
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
        score, sev, vector = _cvss(c.get("metrics", {}))
        cwe_ids = [w["description"][0]["value"]
                   for w in c.get("weaknesses", []) if w.get("description")]
        ranges, raw = _applicability(c.get("configurations", []))
        yield _record(
            id=c["id"], source="nvd", summary=desc, cvss=score, severity=sev,
            cvss_vector=vector, cwe_ids=cwe_ids, cwe=",".join(cwe_ids),
            products=_products(c.get("configurations", [])),
            affected_ranges=ranges, applicability=raw,
            published=c.get("published", ""), modified=c.get("lastModified", ""),
            references=[r["url"] for r in c.get("references", [])][:5] or None,
        )
    # ponytail: full NVD backfill (all ~250k CVEs, paginated + rate-limited) deferred;
    # add a --backfill loop over startIndex when stack-wide coverage is needed.


# ------------------------------- index --------------------------------------

class CveIndex:
    def __init__(self, path: str = DB_PATH):
        import lancedb
        from fastembed import TextEmbedding

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = lancedb.connect(path)
        self._embed = TextEmbedding(model_name=EMBED_MODEL)

    def _vec(self, texts: list[str]) -> list[list[float]]:
        # ponytail: one embed path for passages and queries; bge query-prefix skipped,
        # symmetric ranking is good enough. Add query_embed() if recall measurably lags.
        return [v.tolist() for v in self._embed.embed(texts)]

    def _schema(self, dim: int):
        import pyarrow as pa
        s = lambda: pa.list_(pa.string())  # noqa: E731 — typed string list (avoids List(Null))
        return pa.schema([
            ("id", pa.string()), ("aliases", s()), ("source", pa.string()),
            ("rtype", pa.string()), ("summary", pa.string()), ("products", pa.string()),
            ("cvss", pa.float64()), ("cvss_vector", pa.string()), ("severity", pa.string()),
            ("cwe", pa.string()), ("cwe_ids", s()), ("attack_technique_ids", s()),
            ("kev", pa.bool_()), ("affected_ranges", s()), ("fixed_versions", s()),
            ("applicability", pa.string()), ("published", pa.string()),
            ("modified", pa.string()), ("candidate", pa.bool_()),
            ("schema_version", pa.int64()), ("references", s()), ("provenance", pa.string()),
            ("text", pa.string()), ("vector", pa.list_(pa.float32(), dim))])

    def _rows(self, records: list[dict]) -> list[dict]:
        vecs = self._vec([r["text"] for r in records])
        return [{**r, "vector": v} for r, v in zip(records, vecs)]

    def _check_schema(self, tbl) -> None:
        """Refuse to write to a table built under an older schema — rebuild explicitly."""
        cols = set(tbl.schema.names)
        missing = [c for c in _COLUMNS if c not in cols]
        if missing:
            raise RuntimeError(
                f"index schema is outdated (missing {missing[:3]}…) — run `metsec rag build` "
                "to rebuild it. Incremental sync needs the current schema.")

    def build(self, records: Iterable[dict]) -> int:
        """Rebuild the index from scratch (explicit full reconstruction)."""
        records = list(records)
        if not records:
            raise ValueError("no records to index")
        rows = self._rows(records)
        self.db.create_table(TABLE, data=rows, mode="overwrite",
                             schema=self._schema(len(rows[0]["vector"])))
        return len(records)

    def sync(self, records: Iterable[dict]) -> int:
        """Idempotent incremental ingest keyed by (id, source): re-ingesting the SAME id from
        the SAME source REPLACES that row (no duplicate pile-up), but a different source's row
        for the same id is PRESERVED — so distinct source contributions and their
        contradictions are kept. Distinct from build(), which reconstructs the whole index."""
        records = list(records)
        if not records:
            return 0
        tbl = self.db.open_table(TABLE)
        self._check_schema(tbl)
        esc = lambda s: str(s).replace("'", "''")  # noqa: E731
        pairs = {(r["id"], r.get("source", "")) for r in records if r.get("id")}
        if pairs:
            clause = " OR ".join(f"(id = '{esc(i)}' AND source = '{esc(s)}')" for i, s in pairs)
            tbl.delete(clause)                # idempotent per (id, source), cross-source kept
        tbl.add(self._rows(records))
        return len(records)

    # back-compat alias; now idempotent (was a blind append)
    add = sync

    _SELECT = ["id", "aliases", "source", "rtype", "summary", "cvss", "cvss_vector",
               "severity", "cwe", "cwe_ids", "attack_technique_ids", "products", "kev",
               "affected_ranges", "fixed_versions", "applicability", "published",
               "modified", "candidate", "references", "provenance"]

    def get(self, id: str) -> dict | None:
        """Exact lookup by canonical id OR alias — no fuzzy ranking."""
        tbl = self.db.open_table(TABLE)
        esc = id.replace("'", "''")
        rows = (tbl.search(self._vec([id])[0])
                .where(f"id = '{esc}' OR array_has(aliases, '{esc}')", prefilter=True)
                .select(self._SELECT).limit(1).to_list())
        return rows[0] if rows else None

    def search(self, query: str, k: int = 5, min_cvss: float | None = None,
               kev_only: bool = False, rtype: str | None = None,
               source: str | None = None) -> list[dict]:
        tbl = self.db.open_table(TABLE)
        q = tbl.search(self._vec([query])[0]).limit(k)
        conds = []
        if kev_only:
            conds.append("kev = true")
        if min_cvss is not None:
            conds.append(f"cvss >= {min_cvss}")
        if rtype:
            conds.append(f"rtype = '{rtype}'")
        if source:
            conds.append(f"source = '{source}'")
        if conds:
            q = q.where(" AND ".join(conds), prefilter=True)
        return q.select(self._SELECT + ["_distance"]).to_list()


if __name__ == "__main__":  # self-check: python -m metsec.rag  (downloads embed model once)
    import tempfile

    tiny = [
        _record("CVE-0001", "test", "Remote code execution in Apache Log4j via JNDI lookup",
                products="apache log4j", cvss=10.0, kev=True),
        _record("CVE-0002", "test", "SQL injection in a WordPress plugin login form",
                products="wordpress", cvss=7.5),
        _record("CVE-0003", "test", "Stored XSS in nginx admin dashboard",
                products="nginx", cvss=5.4),
    ]
    with tempfile.TemporaryDirectory() as d:
        idx = CveIndex(f"{d}/db")
        assert idx.build(tiny) == 3
        hits = idx.search("log4j JNDI remote code execution", k=3)
        assert hits[0]["id"] == "CVE-0001", f"wrong top hit: {hits[0]['id']}"
        kev = idx.search("vulnerability", k=5, kev_only=True)
        assert all(h["kev"] for h in kev) and len(kev) == 1
        hi = idx.search("vulnerability", k=5, min_cvss=7.0)
        assert all(h["cvss"] >= 7.0 for h in hi)
        # exact id + alias lookup (no fuzzy ranking)
        assert idx.get("CVE-0002")["id"] == "CVE-0002"
        assert idx.get("nope") is None
        # idempotent sync: an alias row + re-ingesting CVE-0001 must NOT duplicate it
        aliased = _record("GHSA-xxxx", "osv", "aliased RCE", aliases=["CVE-0001"], cvss=9.0)
        assert idx.sync([aliased, tiny[0]]) == 2          # one new (GHSA) + re-ingest CVE-0001
        assert len(idx.search("vulnerability", k=20)) == 4, "GHSA added; CVE-0001 replaced not dup"
        idx.sync([tiny[0], tiny[1]])                       # re-sync existing ids again
        assert len(idx.search("vulnerability", k=20)) == 4, "idempotent: still 4, no duplicates"
        assert idx.get("GHSA-0") is None                   # miss
        assert idx.get("CVE-0001")["id"] in ("CVE-0001", "GHSA-xxxx")  # exact or via-alias hit
        # type/source filters keep taxonomies separate
        assert all(h["source"] == "osv" for h in idx.search("RCE", k=10, source="osv"))
    print("rag self-check ok")
