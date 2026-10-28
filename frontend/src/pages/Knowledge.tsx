import { useState } from "react";
import { ExternalLink } from "lucide-react";
import { PageHeader } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { api } from "@/api";

type Hit = {
  id: string;
  source: string;
  summary: string;
  severity?: string;
  cvss?: number;
  cwe?: string;
  products?: string;
  kev?: boolean;
  references?: string[];
};

export default function Knowledge() {
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<Hit[] | null>(null);
  const [msg, setMsg] = useState("Search CVEs and techniques by keyword, product, or symptom.");
  const [busy, setBusy] = useState(false);

  const go = async () => {
    const query = q.trim();
    if (!query) return;
    setBusy(true);
    setHits(null);
    setMsg("Searching…");
    try {
      const j = await (await api(`/api/knowledge?q=${encodeURIComponent(query)}`)).json();
      if (!j.hits?.length) setMsg(j.error || "No results.");
      else setHits(j.hits);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader title="Knowledge base" sub="Search the CVE / technique index." />
      <div className="flex max-w-xl gap-2">
        <Input
          autoFocus
          placeholder="CVE, product, or symptom… e.g. log4j JNDI RCE"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") go(); }}
        />
        <Button onClick={go} disabled={busy}>Search</Button>
      </div>

      <div className="mt-6 space-y-3">
        {hits
          ? hits.map((h, i) => <HitCard key={i} hit={h} />)
          : <p className="text-sm text-muted-foreground">{msg}</p>}
      </div>
    </>
  );
}

function HitCard({ hit }: { hit: Hit }) {
  const sev = (hit.severity || "").toLowerCase();
  // only show a severity pill for a real CVSS level — "KEV" is already covered by the KEV pill
  const realSev = ["critical", "high", "medium", "low"].includes(sev);
  const cvss = hit.cvss ?? 0;

  return (
    <Card className="p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-sm font-semibold">{hit.id}</span>
          <Badge variant="secondary" className="uppercase">{hit.source}</Badge>
          {hit.kev && <span className="pill sev-critical">KEV</span>}
          {realSev && <span className={`pill sev-${sev}`}>{hit.severity!.toUpperCase()}</span>}
        </div>
        {cvss > 0 && (
          <div className="shrink-0 text-right">
            <div className="text-[10px] uppercase tracking-wide text-muted-foreground">CVSS</div>
            <div className={`text-lg font-semibold tabular-nums ${cvss >= 7 ? "text-destructive" : ""}`}>
              {cvss.toFixed(1)}
            </div>
          </div>
        )}
      </div>

      <p className="mt-2 text-sm leading-relaxed text-foreground/90">{hit.summary}</p>

      {(hit.products || hit.cwe) && (
        <div className="mt-3 space-y-1 text-xs text-muted-foreground">
          {hit.products && <div><span className="text-foreground/70">Affected:</span> {hit.products}</div>}
          {hit.cwe && <div><span className="text-foreground/70">Weakness:</span> {hit.cwe}</div>}
        </div>
      )}

      {hit.references && hit.references.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1">
          {hit.references.map((r, i) => (
            <a
              key={i}
              href={r}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground hover:underline"
            >
              <ExternalLink className="size-3" /> {hostOf(r)}
            </a>
          ))}
        </div>
      )}
    </Card>
  );
}

function hostOf(url: string): string {
  try {
    const u = new URL(url);
    const label = u.hostname.replace(/^www\./, "") + u.pathname.replace(/\/$/, "");
    return label.length > 52 ? label.slice(0, 52) + "…" : label;
  } catch {
    return url.length > 52 ? url.slice(0, 52) + "…" : url;
  }
}
