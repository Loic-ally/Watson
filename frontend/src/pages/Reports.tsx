import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { PageHeader } from "@/components/Layout";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/api";
import { cn } from "@/lib/utils";

// severity is the qualitative risk; cvss is an AUTHENTIC base score or null (never fabricated)
type Report = { name: string; target: string; date: string; severity: string; cvss: number | null; count: number };

const SEV_RANK = ["critical", "high", "medium", "low", "info"];

export default function Reports() {
  const [reports, setReports] = useState<Report[] | null>(null);

  useEffect(() => {
    api("/api/reports").then((r) => r.json()).then((d) => setReports(d.reports ?? []));
  }, []);

  const topSeverity =
    reports?.map((r) => r.severity).filter(Boolean).sort((a, b) => SEV_RANK.indexOf(a) - SEV_RANK.indexOf(b))[0] ?? "—";
  const stats = reports && {
    assessments: reports.length,
    findings: reports.reduce((n, r) => n + (r.count || 0), 0),
    topSeverity,
  };

  return (
    <>
      <PageHeader title="Reports" sub="Past assessments." />
      {stats && reports!.length > 0 && (
        <div className="mb-6 grid grid-cols-3 gap-3">
          <Stat label="Assessments" value={stats.assessments} />
          <Stat label="Total findings" value={stats.findings} />
          <Stat label="Highest severity" value={stats.topSeverity} danger={["critical", "high"].includes(stats.topSeverity)} />
        </div>
      )}
      <Card className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Target</TableHead>
              <TableHead>Date</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>CVSS</TableHead>
              <TableHead>Findings</TableHead>
              <TableHead>Report</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {reports?.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="text-muted-foreground">
                  No reports yet — run a scan from Chat.
                </TableCell>
              </TableRow>
            )}
            {reports?.map((r) => (
              <TableRow key={r.name}>
                <TableCell>
                  <Link to={`/report/${encodeURIComponent(r.name)}`} className="text-accent hover:underline">
                    {r.target}
                  </Link>
                </TableCell>
                <TableCell>{r.date}</TableCell>
                <TableCell>
                  <span className={`pill sev-${r.severity || "info"}`}>{(r.severity || "—").toUpperCase()}</span>
                </TableCell>
                <TableCell className="font-bold tabular-nums">{r.cvss ?? "n/a"}</TableCell>
                <TableCell>{r.count}</TableCell>
                <TableCell className="text-muted-foreground">{r.name}</TableCell>
              </TableRow>
            ))}
            {reports === null && (
              <TableRow>
                <TableCell colSpan={6} className="text-muted-foreground">Loading…</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </Card>
    </>
  );
}

function Stat({ label, value, danger }: { label: string; value: number | string; danger?: boolean }) {
  return (
    <Card className="p-4">
      <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className={cn("mt-1 text-2xl font-semibold tabular-nums", danger && "text-destructive")}>{value}</div>
    </Card>
  );
}
