import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { PageHeader } from "@/components/Layout";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/api";
import { cn } from "@/lib/utils";

type Report = { name: string; target: string; date: string; cvss: number; count: number };

export default function Reports() {
  const [reports, setReports] = useState<Report[] | null>(null);

  useEffect(() => {
    api("/api/reports").then((r) => r.json()).then((d) => setReports(d.reports ?? []));
  }, []);

  const stats = reports && {
    assessments: reports.length,
    findings: reports.reduce((n, r) => n + (r.count || 0), 0),
    maxCvss: reports.reduce((m, r) => Math.max(m, r.cvss || 0), 0),
  };

  return (
    <>
      <PageHeader title="Reports" sub="Past assessments." />
      {stats && reports!.length > 0 && (
        <div className="mb-6 grid grid-cols-3 gap-3">
          <Stat label="Assessments" value={stats.assessments} />
          <Stat label="Total findings" value={stats.findings} />
          <Stat label="Highest CVSS" value={stats.maxCvss.toFixed(1)} danger={stats.maxCvss >= 7} />
        </div>
      )}
      <Card className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Target</TableHead>
              <TableHead>Date</TableHead>
              <TableHead>CVSS</TableHead>
              <TableHead>Findings</TableHead>
              <TableHead>Report</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {reports?.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="text-muted-foreground">
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
                <TableCell className="font-bold">{r.cvss}</TableCell>
                <TableCell>{r.count}</TableCell>
                <TableCell className="text-muted-foreground">{r.name}</TableCell>
              </TableRow>
            ))}
            {reports === null && (
              <TableRow>
                <TableCell colSpan={5} className="text-muted-foreground">Loading…</TableCell>
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
