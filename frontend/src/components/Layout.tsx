import { useEffect, useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { MessageSquare, Activity, FolderOpen, Brain, LogOut, Hexagon } from "lucide-react";
import { api } from "@/api";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/", label: "Chat", icon: MessageSquare, end: true },
  { to: "/dashboard", label: "Dashboard", icon: Activity, end: false },
  { to: "/reports", label: "Reports", icon: FolderOpen, end: false },
  { to: "/knowledge", label: "Knowledge", icon: Brain, end: false },
];

export function Layout({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate();
  const logout = async () => {
    await api("/api/logout", { method: "POST" });
    navigate("/login", { replace: true });
  };
  return (
    <div className="flex min-h-screen">
      <aside className="flex w-56 flex-col border-r border-border bg-card/30 py-5">
        <div className="flex items-center gap-2 px-5 pb-6 text-base font-semibold tracking-tight">
          <Hexagon className="size-5" strokeWidth={2.2} /> MetSec
        </div>
        <nav className="flex flex-col gap-0.5 px-3">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  isActive ? "bg-secondary text-foreground" : "text-muted-foreground hover:bg-secondary/50 hover:text-foreground"
                )
              }
            >
              <Icon className="size-4" strokeWidth={2} /> {label}
            </NavLink>
          ))}
        </nav>
        <div className="flex-1" />
        <ScanStatus />
        <button
          onClick={logout}
          className="mx-3 mt-2 flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-secondary/50 hover:text-foreground"
        >
          <LogOut className="size-4" strokeWidth={2} /> Logout
        </button>
      </aside>
      <main className="flex-1 overflow-auto px-10 py-8" style={{ maxHeight: "100vh" }}>
        <div className="mx-auto max-w-5xl">{children}</div>
      </main>
    </div>
  );
}

/** Polls /api/status so a running scan is visible from any page. */
function ScanStatus() {
  const [run, setRun] = useState<{ active: boolean; target?: string } | null>(null);
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const d = await (await api("/api/status")).json();
        if (alive) setRun({ active: d.active, target: d.run?.target });
      } catch { /* ignore */ }
    };
    tick();
    const t = setInterval(tick, 3000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  if (!run?.active) return null;
  return (
    <NavLink
      to="/dashboard"
      className="mx-3 flex items-center gap-2 rounded-md border border-border bg-secondary/40 px-3 py-2 text-xs text-foreground hover:bg-secondary/70"
    >
      <span className="relative flex size-2">
        <span className="absolute inline-flex size-2 animate-ping rounded-full bg-foreground opacity-60" />
        <span className="relative inline-flex size-2 rounded-full bg-foreground" />
      </span>
      <span className="truncate">Scanning {run.target ?? ""}</span>
    </NavLink>
  );
}

export function PageHeader({ title, sub }: { title: string; sub?: React.ReactNode }) {
  return (
    <div className="mb-7">
      <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
      {sub && <p className="mt-1.5 text-sm text-muted-foreground">{sub}</p>}
    </div>
  );
}
