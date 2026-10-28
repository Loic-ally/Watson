import { useEffect, useMemo, useRef, useState } from "react";
import { Mic, Send, Square, Plus, Trash2 } from "lucide-react";
import { PageHeader } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { api, postJson } from "@/api";
import { evHtml, esc, type Ev } from "@/feed";
import { recording, startRec, stopRec } from "@/voice";
import {
  type Conversation, type Msg,
  loadChats, saveChats, getActiveId, setActiveId, newChat, titleFrom, relTime,
} from "@/lib/chats";

type MicState = "idle" | "listening" | "transcribing";

export default function Chat() {
  const [chats, setChats] = useState<Conversation[]>([]);
  const [curId, setCurId] = useState("");
  const [live, setLive] = useState<string[] | null>(null);
  const [input, setInput] = useState("");
  const [mic, setMic] = useState<MicState>("idle");
  const [secs, setSecs] = useState(0);
  const scroller = useRef<HTMLDivElement>(null);
  const srcRef = useRef<EventSource | null>(null);
  const reconnected = useRef(false);

  const cur = useMemo(() => chats.find((c) => c.id === curId), [chats, curId]);
  const messages = cur?.messages ?? [];

  // load history on mount; reconnect to a scan already in progress
  useEffect(() => {
    let cs = loadChats();
    if (cs.length === 0) cs = [newChat()];
    const saved = getActiveId();
    const id = saved && cs.some((c) => c.id === saved) ? saved : cs[0].id;
    setChats(cs);
    setCurId(id);
    setActiveId(id);
    saveChats(cs);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // once a conversation is active, reconnect to a scan still running on the backend
  useEffect(() => {
    if (!curId || reconnected.current) return;
    reconnected.current = true;
    api("/api/status").then((r) => r.json()).then((d) => { if (d.active) startFeed(); }).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [curId]);

  useEffect(() => () => srcRef.current?.close(), []);
  useEffect(() => { scroller.current?.scrollTo(0, scroller.current.scrollHeight); }, [messages, live]);

  // recording timer
  useEffect(() => {
    if (mic !== "listening") return;
    setSecs(0);
    const t = setInterval(() => setSecs((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, [mic]);

  // ---- conversation mutation (persists) ----
  const updateMessages = (updater: (prev: Msg[]) => Msg[]) =>
    setChats((prev) => {
      const next = prev.map((c) => {
        if (c.id !== curId) return c;
        const msgs = updater(c.messages);
        const title = c.title === "New chat" ? titleFrom(msgs) : c.title;
        return { ...c, messages: msgs, title, updated: Date.now() };
      });
      saveChats(next);
      return next;
    });
  const add = (m: Msg) => updateMessages((prev) => [...prev, m]);

  const closeFeed = () => { srcRef.current?.close(); srcRef.current = null; setLive(null); };

  const selectChat = (id: string) => { closeFeed(); setCurId(id); setActiveId(id); };
  const createChat = () => {
    closeFeed();
    const c = newChat();
    setChats((prev) => { const next = [c, ...prev]; saveChats(next); return next; });
    setCurId(c.id);
    setActiveId(c.id);
  };
  const removeChat = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setChats((prev) => {
      let next = prev.filter((c) => c.id !== id);
      if (next.length === 0) next = [newChat()];
      saveChats(next);
      if (id === curId) { setCurId(next[0].id); setActiveId(next[0].id); closeFeed(); }
      return next;
    });
  };

  // ---- scan feed ----
  const startFeed = () => {
    if (srcRef.current) return;
    setLive([]);
    const collected: string[] = [];
    const src = new EventSource("/stream");
    srcRef.current = src;
    src.onmessage = (ev) => {
      const e: Ev = JSON.parse(ev.data);
      const h = evHtml(e);
      if (h) { collected.push(h); setLive((prev) => [...(prev ?? []), h]); }
      if (e.type === "done") {
        src.close();
        srcRef.current = null;
        setLive(null);
        // fold the finished feed into saved history so this chat replays it later
        if (collected.length) add({ role: "feed", html: collected.join("") });
        add({ role: "sys", html: "scan finished — see Reports" });
      }
    };
  };

  const send = async (text?: string) => {
    const t = (text ?? input).trim();
    if (!t) return;
    setInput("");
    add({ role: "user", html: esc(t) });
    const j = await (await postJson("/api/chat", { message: t })).json();
    if (j.type === "reply") add({ role: "bot", html: esc(j.text) });
    else if (j.type === "error") add({ role: "sys", html: "⚠️ " + esc(j.text) });
    else if (j.type === "scan") { add({ role: "bot", html: esc(j.text) }); startFeed(); }
  };

  const toggleMic = async () => {
    if (recording()) {
      setMic("transcribing");
      const { text, error } = await stopRec();
      setMic("idle");
      if (error) add({ role: "sys", html: "⚠️ transcription failed: " + esc(error) });
      else if (!text.trim()) add({ role: "sys", html: "🎤 no speech detected — try again" });
      else send(text);
      return;
    }
    try { await startRec(); setMic("listening"); }
    catch { add({ role: "sys", html: "🎤 microphone blocked — allow access in your browser" }); }
  };

  return (
    <>
      <PageHeader
        title="Chat"
        sub={
          <>
            Tell the agent what to do — e.g.{" "}
            <span className="kbd">pentest http://127.0.0.1:5001 in dev mode with exploit</span>
          </>
        }
      />
      <div className="flex gap-5" style={{ height: "calc(100vh - 150px)" }}>
        {/* history rail */}
        <aside className="hidden w-56 shrink-0 flex-col md:flex">
          <Button variant="secondary" className="mb-3 justify-start gap-2" onClick={createChat}>
            <Plus className="size-4" /> New chat
          </Button>
          <div className="flex-1 space-y-1 overflow-auto pr-1">
            {chats.map((c) => (
              <div
                key={c.id}
                onClick={() => selectChat(c.id)}
                className={cn(
                  "group flex cursor-pointer items-center justify-between gap-2 rounded-md px-3 py-2 text-sm transition-colors",
                  c.id === curId ? "bg-secondary text-foreground" : "text-muted-foreground hover:bg-secondary/50 hover:text-foreground"
                )}
              >
                <div className="min-w-0">
                  <div className="truncate">{c.title}</div>
                  <div className="text-[11px] text-muted-foreground">{relTime(c.updated)}</div>
                </div>
                <button
                  onClick={(e) => removeChat(c.id, e)}
                  className="shrink-0 opacity-0 transition-opacity hover:text-destructive group-hover:opacity-100"
                  title="Delete chat"
                >
                  <Trash2 className="size-3.5" />
                </button>
              </div>
            ))}
          </div>
        </aside>

        {/* conversation */}
        <div className="flex min-w-0 flex-1 flex-col">
          <div ref={scroller} className="flex flex-1 flex-col gap-3 overflow-auto p-1">
            {messages.map((m, i) =>
              m.role === "feed" ? (
                <div key={i} className="feed max-w-[85%] self-start rounded-xl border border-border bg-card p-3"
                     dangerouslySetInnerHTML={{ __html: m.html }} />
              ) : (
                <Bubble key={i} role={m.role} html={m.html} />
              )
            )}
            {live && (
              <div className="feed max-w-[85%] self-start rounded-xl border border-border bg-card p-3">
                {live.map((h, i) => <div key={i} dangerouslySetInnerHTML={{ __html: h }} />)}
              </div>
            )}
          </div>

          {mic !== "idle" && (
            <div className="mt-3 flex items-center gap-2 text-sm text-muted-foreground">
              {mic === "listening" ? (
                <>
                  <span className="inline-block size-2 animate-pulse rounded-full bg-destructive" />
                  Listening… {secs}s — tap the mic to stop
                </>
              ) : "Transcribing…"}
            </div>
          )}

          <div className="mt-3 flex gap-2">
            <Input
              autoFocus
              placeholder="Message the agent…"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") send(); }}
            />
            <Button
              variant={mic === "listening" ? "destructive" : "secondary"}
              size="icon"
              onClick={toggleMic}
              disabled={mic === "transcribing"}
              title="Voice input — speak your instruction"
            >
              {mic === "listening" ? <Square className="size-4" /> : <Mic className="size-4" />}
            </Button>
            <Button onClick={() => send()}><Send className="size-4" /> Send</Button>
          </div>
        </div>
      </div>
    </>
  );
}

function Bubble({ role, html }: Msg) {
  return (
    <div
      className={cn(
        "max-w-[85%] whitespace-pre-wrap break-words rounded-xl px-4 py-2.5 text-sm leading-relaxed",
        role === "user" && "self-end bg-primary text-primary-foreground",
        role === "bot" && "self-start border border-border bg-card",
        role === "sys" && "self-center bg-transparent text-xs text-muted-foreground"
      )}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
