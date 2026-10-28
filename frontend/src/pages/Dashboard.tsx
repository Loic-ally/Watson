import { useEffect, useRef, useState } from "react";
import { PageHeader } from "@/components/Layout";
import { cn } from "@/lib/utils";
import { evHtml, stageOf, type Ev } from "@/feed";

const STEPS = ["Recon", "Exploit", "Foothold", "Privesc", "ROOT"];

export default function Dashboard() {
  const [stage, setStage] = useState(-1);
  const [events, setEvents] = useState<string[]>([]);
  const feed = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const src = new EventSource("/stream");
    src.onmessage = (ev) => {
      const e: Ev = JSON.parse(ev.data);
      const h = evHtml(e);
      if (h) setEvents((prev) => [...prev, h]);
      const s = stageOf(e);
      if (s >= 0) setStage((cur) => Math.max(cur, s));
    };
    return () => src.close();
  }, []);

  useEffect(() => {
    feed.current?.scrollTo(0, feed.current.scrollHeight);
  }, [events]);

  return (
    <>
      <PageHeader title="Live dashboard" sub="Kill-chain progress and agent activity in real time." />
      <div className="mb-4 flex flex-wrap gap-2">
        {STEPS.map((label, i) => {
          const on = i <= stage;
          const root = i === 4;
          return (
            <span
              key={label}
              className={cn(
                "rounded-md border px-3.5 py-1.5 text-xs font-semibold transition-colors",
                !on && "border-border bg-secondary/30 text-muted-foreground",
                on && !root && "border-foreground/40 bg-secondary text-foreground",
                on && root && "border-primary bg-primary text-primary-foreground"
              )}
            >
              {label}
            </span>
          );
        })}
      </div>
      <div
        ref={feed}
        className="feed overflow-auto rounded-lg border border-border bg-card p-4"
        style={{ height: "calc(100vh - 230px)" }}
      >
        {events.length === 0 && (
          <div className="text-muted-foreground">Waiting for agent activity… start a scan from Chat.</div>
        )}
        {events.map((h, i) => (
          <div key={i} dangerouslySetInnerHTML={{ __html: h }} />
        ))}
      </div>
    </>
  );
}
