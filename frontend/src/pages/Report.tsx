import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Download } from "lucide-react";
import { PageHeader } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/api";

type Cvss = { version?: string; base_score?: number; vector?: string; provenance?: string };
type Finding = { severity?: string; cvss?: Cvss | number | null; confidence?: string; status?: string; title?: string; affected?: string };

// authentic CVSS only: an object with a base_score + provenance. A legacy float is NOT authentic.
function cvssLabel(c: Finding["cvss"]): string {
  if (c && typeof c === "object" && c.base_score != null && c.provenance) return `${c.base_score} (${c.provenance})`;
  return "n/a";
}

export default function Report() {
  const { name = "" } = useParams();
  const enc = encodeURIComponent(name);
  const [mode, setMode] = useState<"loading" | "html" | "table" | "missing">("loading");
  const [findings, setFindings] = useState<Finding[]>([]);

  useEffect(() => {
    (async () => {
      const r = await api(`/api/report/${enc}`);
      if (!r.ok) { setMode("missing"); return; }
      const data = await r.json();
      const html = await api(`/api/report/${enc}/html`);
      if (html.ok) { setMode("html"); return; }
      setFindings(data.findings ?? []);
      setMode("table");
    })();
  }, [enc]);

  return (
    <>
      <PageHeader title="Report" sub={name} />
      <div className="mb-4 flex items-center gap-4">
        <Link to="/reports" className="text-sm text-accent hover:underline">← all reports</Link>
        <Button asChild size="sm">
          <a href={`/api/report/${enc}/pdf`}><Download className="size-4" /> PDF</a>
        </Button>
      </div>
      {mode === "loading" && <Card className="p-5 text-muted-foreground">Loading…</Card>}
      {mode === "missing" && <Card className="p-5">Report not found.</Card>}
      {mode === "html" && (
        <iframe
          title="report"
          src={`/api/report/${enc}/html`}
          className="w-full rounded-lg border border-border bg-[#0b0e14]"
          style={{ height: "calc(100vh - 200px)" }}
        />
      )}
      {mode === "table" && (
        <Card className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Sev</TableHead>
                <TableHead>CVSS</TableHead>
                <TableHead>Confidence</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Finding</TableHead>
                <TableHead>Where</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {findings.length === 0 && (
                <TableRow><TableCell colSpan={6}>No findings.</TableCell></TableRow>
              )}
              {findings.map((f, i) => (
                <TableRow key={i}>
                  <TableCell>
                    <span className={`pill sev-${f.severity || "info"}`}>{(f.severity || "").toUpperCase()}</span>
                  </TableCell>
                  <TableCell className="tabular-nums">{cvssLabel(f.cvss)}</TableCell>
                  <TableCell className="text-muted-foreground">{f.confidence ?? "—"}</TableCell>
                  <TableCell>{f.status}</TableCell>
                  <TableCell>{f.title}</TableCell>
                  <TableCell className="text-muted-foreground">{f.affected}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      )}
    </>
  );
}
