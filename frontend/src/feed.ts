// Render agent events (ported from the old inline _FEED_JS).

export type Ev = Record<string, any> & { type: string };

const ICON: Record<string, string> = {
  http_probe: "🌐", search_vulns: "🔎", record_finding: "📌", establish_foothold: "🎯",
  run_command: "⌨️", privesc_scan: "⬆️", loot: "💰", browse: "📸", browser_action: "🖱️",
  hypothesize: "💡", make_payload: "🧬", upload_shell: "📤", finish: "🏁",
};

export const esc = (s: unknown): string =>
  String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]!));

export function evHtml(e: Ev): string {
  switch (e.type) {
    case "tool":
      return `<div class="ev"><b>${ICON[e.name] || "•"} ${e.name}</b> <span class="d">${esc(e.detail)}</span></div>`;
    case "screenshot":
      return `<div class="ev ev-accent">📸 <span class="d">${esc(e.caption || e.url)}</span><br><a href="/shot/${esc(e.id)}" target="_blank"><img src="/shot/${esc(e.id)}" loading="lazy" style="max-width:100%;margin-top:6px;border:1px solid hsl(var(--border));border-radius:6px"></a></div>`;
    case "command":
      return `<div class="ev ev-accent"><span class="d">⌨️ ${esc(e.cmd)}</span><pre>${esc(e.output) || "(no output)"}</pre></div>`;
    case "foothold":
      return `<div class="ev ev-win">🎯 <b>FOOTHOLD</b> via ${esc(e.kind)} <span class="d">${esc(e.whoami)}</span></div>`;
    case "root":
      return `<div class="ev ev-win">👑 <b>ROOT — uid=0</b></div>`;
    case "finding":
      return `<div class="ev"><span class="pill sev-${e.severity}">${esc((e.severity || "").toUpperCase())}</span> ${esc(e.title)} <span class="d">(${esc(e.status)})</span></div>`;
    case "hypothesis":
      return `<div class="ev ev-accent">💡 <span class="d">${esc(e.statement)}</span></div>`;
    case "finish":
      return `<div class="ev">🏁 <b>agent finished</b> <span class="d">${esc(e.summary)}</span></div>`;
    case "error":
      return `<div class="ev ev-err">⚠️ <span class="d">${esc(e.msg)}</span></div>`;
    case "start":
      return `<div class="ev">▶️ <b>scan started</b> <span class="d">${esc(e.target)} [${esc(e.mode)}]</span></div>`;
    case "done":
      return `<div class="ev ev-win">✅ <b>assessment complete</b></div>`;
    default:
      return "";
  }
}

// Kill-chain stage for the dashboard, from an event. -1 = no change.
const STAGE: Record<string, number> = {
  http_probe: 1, search_vulns: 1, record_finding: 1, establish_foothold: 2,
  run_command: 3, privesc_scan: 3, loot: 3,
};

export function stageOf(e: Ev): number {
  if (e.type === "tool" && STAGE[e.name] != null) return STAGE[e.name];
  if (e.type === "finding") return /privileg|escalat|\broot\b/i.test(e.title || "") ? 3 : 1;
  if (e.type === "foothold") return 2;
  if (e.type === "command") return 3;
  if (e.type === "root") return 4;
  return -1;
}
