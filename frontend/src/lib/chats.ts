// Chat history, persisted per-browser in localStorage (this is a loopback tool).
// Every read/write is guarded so private-mode / blocked-storage degrades to in-memory.

export type Msg = { role: "user" | "bot" | "sys" | "feed"; html: string };
export type Conversation = { id: string; title: string; updated: number; messages: Msg[] };

const KEY = "metsec.chats";
const ACTIVE = "metsec.activeChat";
const MAX = 50; // cap stored conversations

export const GREETING: Msg = {
  role: "bot",
  html:
    "I'm your pentest agent. Give me a target to assess (you must be authorized), " +
    "ask about the last run, or search for a vuln. Try: " +
    "<span class='kbd'>scan http://127.0.0.1:5002 in dev mode with exploit</span>",
};

function read<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v ? (JSON.parse(v) as T) : fallback;
  } catch {
    return fallback;
  }
}

export function loadChats(): Conversation[] {
  return read<Conversation[]>(KEY, []).sort((a, b) => b.updated - a.updated);
}

export function saveChats(chats: Conversation[]): void {
  try {
    const trimmed = [...chats].sort((a, b) => b.updated - a.updated).slice(0, MAX);
    localStorage.setItem(KEY, JSON.stringify(trimmed));
  } catch {
    /* ignore */
  }
}

export function getActiveId(): string | null {
  try {
    return localStorage.getItem(ACTIVE);
  } catch {
    return null;
  }
}

export function setActiveId(id: string): void {
  try {
    localStorage.setItem(ACTIVE, id);
  } catch {
    /* ignore */
  }
}

export function newChat(): Conversation {
  return {
    id: Math.random().toString(36).slice(2, 10),
    title: "New chat",
    updated: Date.now(),
    messages: [GREETING],
  };
}

export function titleFrom(messages: Msg[]): string {
  const firstUser = messages.find((m) => m.role === "user");
  if (!firstUser) return "New chat";
  const t = firstUser.html.replace(/<[^>]+>/g, "").trim();
  return t.length > 42 ? t.slice(0, 42) + "…" : t || "New chat";
}

export function relTime(ts: number): string {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}
