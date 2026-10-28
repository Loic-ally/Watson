// Mic capture -> 16 kHz WAV -> POST /api/transcribe (Muse ASR). Ported as-is.

type F32 = Float32Array<ArrayBufferLike>;

let rec: { on: boolean; ctx?: AudioContext; node?: ScriptProcessorNode;
  src?: MediaStreamAudioSourceNode; stream?: MediaStream; buf: F32[]; sr: number } = { on: false, buf: [], sr: 16000 };

export function recording(): boolean {
  return rec.on;
}

export async function startRec(): Promise<void> {
  const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  let ctx: AudioContext;
  try {
    ctx = new (window.AudioContext || (window as any).webkitAudioContext)({ sampleRate: 16000 });
  } catch {
    ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
  }
  const src = ctx.createMediaStreamSource(stream);
  const node = ctx.createScriptProcessor(4096, 1, 1);
  const buf: Float32Array[] = [];
  node.onaudioprocess = (e) => buf.push(new Float32Array(e.inputBuffer.getChannelData(0)));
  src.connect(node);
  node.connect(ctx.destination);
  rec = { on: true, ctx, src, node, stream, buf, sr: ctx.sampleRate };
}

export type Transcript = { text: string; error?: string };

/** Stop recording, transcribe, and return {text, error}. */
export async function stopRec(): Promise<Transcript> {
  const r = rec;
  rec = { on: false, buf: [], sr: 16000 };
  if (!r.on) return { text: "" };
  r.node!.disconnect();
  r.src!.disconnect();
  r.stream!.getTracks().forEach((t) => t.stop());
  let len = r.buf.reduce((a, c) => a + c.length, 0);
  let pcm: F32 = new Float32Array(len);
  let o = 0;
  for (const c of r.buf) { pcm.set(c, o); o += c.length; }
  if (r.sr !== 16000) pcm = resample(pcm, r.sr, 16000);
  const wav = encodeWav(pcm, 16000);
  r.ctx!.close();
  try {
    const resp = await fetch("/api/transcribe", { method: "POST", body: wav });
    const j = await resp.json();
    return { text: j.text || "", error: j.error };
  } catch (e) {
    return { text: "", error: String(e) };
  }
}

function resample(pcm: F32, from: number, to: number): F32 {
  if (from === to) return pcm;
  const ratio = from / to, n = Math.round(pcm.length / ratio), out = new Float32Array(n);
  for (let i = 0; i < n; i++) {
    const idx = i * ratio, i0 = Math.floor(idx), i1 = Math.min(i0 + 1, pcm.length - 1), f = idx - i0;
    out[i] = pcm[i0] * (1 - f) + pcm[i1] * f;
  }
  return out;
}

function encodeWav(pcm: F32, sr: number): Blob {
  const len = pcm.length, b = new ArrayBuffer(44 + len * 2), v = new DataView(b);
  const ws = (off: number, s: string) => { for (let i = 0; i < s.length; i++) v.setUint8(off + i, s.charCodeAt(i)); };
  ws(0, "RIFF"); v.setUint32(4, 36 + len * 2, true); ws(8, "WAVE"); ws(12, "fmt ");
  v.setUint32(16, 16, true); v.setUint16(20, 1, true); v.setUint16(22, 1, true);
  v.setUint32(24, sr, true); v.setUint32(28, sr * 2, true); v.setUint16(32, 2, true); v.setUint16(34, 16, true);
  ws(36, "data"); v.setUint32(40, len * 2, true);
  let off = 44;
  for (let i = 0; i < len; i++) { const s = Math.max(-1, Math.min(1, pcm[i])); v.setInt16(off, s < 0 ? s * 0x8000 : s * 0x7fff, true); off += 2; }
  return new Blob([b], { type: "audio/wav" });
}
