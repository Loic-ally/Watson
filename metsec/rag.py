"""CVE RAG: download + normalize vuln data, embed locally, store/search in LanceDB.

Common record schema (one per CVE):
    id, source, summary, cvss(float), severity, products, cwe, kev(bool),
    references(list[str]), text(embedded)

Sources:
    - CISA KEV: small, known-exploited-in-the-wild. Default corpus.
    - NVD 2.0 API: by keyword/CPE for enrichment (adds CVSS + wider coverage).
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

EMBED_MODEL = "BAAI/bge-small-en-v1.5"  # 384-dim, retrieval-tuned, ONNX via fastembed (no torch)
DB_PATH = ".metsec_cache/lancedb"
TABLE = "cve"


# ----------------------------- normalize ------------------------------------

def _record(id, source, summary, products="", cvss=0.0, severity="",
            cwe="", kev=False, references=None):
    references = references or [f"https://nvd.nist.gov/vuln/detail/{id}"]
    text = " ".join(filter(None, [id, products, summary]))
    return dict(id=id, source=source, summary=summary, products=products,
                cvss=float(cvss or 0.0), severity=severity, cwe=cwe,
                kev=bool(kev), references=references, text=text)


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


def _cvss(metrics: dict) -> tuple[float, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            d = metrics[key][0]["cvssData"]
            return float(d.get("baseScore", 0.0)), d.get("baseSeverity", "")
    return 0.0, ""


def _products(configs: list) -> str:
    out = set()
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")  # cpe:2.3:a:vendor:product:...
                if len(parts) > 4:
                    out.add(f"{parts[3]} {parts[4]}".replace("_", " "))
    return ", ".join(sorted(out))


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
        score, sev = _cvss(c.get("metrics", {}))
        cwe = next((w["description"][0]["value"]
                    for w in c.get("weaknesses", []) if w.get("description")), "")
        yield _record(
            id=c["id"], source="nvd", summary=desc, cvss=score, severity=sev,
            cwe=cwe, products=_products(c.get("configurations", [])),
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

    def build(self, records: Iterable[dict]) -> int:
        records = list(records)
        if not records:
            raise ValueError("no records to index")
        vecs = self._vec([r["text"] for r in records])
        rows = [{**r, "vector": v} for r, v in zip(records, vecs)]
        self.db.create_table(TABLE, data=rows, mode="overwrite")
        return len(rows)

    def add(self, records: Iterable[dict]) -> int:
        """Append records to an existing index (how researched vulns are 'learned')."""
        records = list(records)
        if not records:
            return 0
        vecs = self._vec([r["text"] for r in records])
        rows = [{**r, "vector": v} for r, v in zip(records, vecs)]
        self.db.open_table(TABLE).add(rows)
        return len(rows)

    def search(self, query: str, k: int = 5, min_cvss: float | None = None,
               kev_only: bool = False) -> list[dict]:
        tbl = self.db.open_table(TABLE)
        q = tbl.search(self._vec([query])[0]).limit(k)
        conds = []
        if kev_only:
            conds.append("kev = true")
        if min_cvss is not None:
            conds.append(f"cvss >= {min_cvss}")
        if conds:
            q = q.where(" AND ".join(conds), prefilter=True)
        cols = ["id", "source", "summary", "cvss", "severity", "cwe", "products",
                "kev", "references", "_distance"]
        return q.select(cols).to_list()


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
    print("rag self-check ok")
