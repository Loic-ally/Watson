"""MetSec web app — dark control panel for the agent.

Pages: Login · Chat (drive the agent in natural language) · Dashboard (live
kill-chain) · Reports (past runs) · Knowledge (CVE/technique search).

Run it with `metsec web`. Auth: METSEC_WEB_USER / METSEC_WEB_PASS (defaults
admin / metsec — change them). Local tool; bind to loopback.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from functools import wraps
from pathlib import Path

from . import events, runs

USER = os.environ.get("METSEC_WEB_USER", "admin")
PASS = os.environ.get("METSEC_WEB_PASS", "metsec")

_CSS = """
*{box-sizing:border-box}
:root{--bg:#0a0d14;--panel:#111722;--panel2:#0d131d;--line:#1d2635;--txt:#c9d4e3;
--mut:#6b7689;--grn:#36d399;--blu:#3b82f6;--pur:#a78bfa;--red:#f87272;--org:#fbbd23}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.6 ui-sans-serif,system-ui,-apple-system,sans-serif}
a{color:var(--blu);text-decoration:none}a:hover{text-decoration:underline}
.app{display:flex;min-height:100vh}
.side{width:210px;background:var(--panel2);border-right:1px solid var(--line);padding:18px 0;display:flex;flex-direction:column}
.brand{font-weight:800;font-size:17px;letter-spacing:.5px;padding:0 20px 18px;color:var(--grn)}
.side a{display:block;padding:10px 20px;color:var(--mut);font-weight:600;border-left:3px solid transparent}
.side a:hover{color:var(--txt);text-decoration:none;background:#0f1520}
.side a.on{color:var(--txt);border-left-color:var(--grn);background:#0f1520}
.side .sp{flex:1}
.main{flex:1;padding:26px 34px;overflow:auto;max-height:100vh}
h1{font-size:20px;margin:0 0 4px}.sub{color:var(--mut);margin:0 0 22px;font-size:13px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px}
.btn{background:var(--grn);color:#06130c;border:none;padding:10px 18px;border-radius:7px;font-weight:700;cursor:pointer;font-size:14px}
.btn:hover{filter:brightness(1.08)}
input,textarea,select{background:var(--panel2);border:1px solid var(--line);color:var(--txt);
border-radius:7px;padding:10px 12px;font:14px ui-sans-serif,system-ui,sans-serif;width:100%}
input:focus,textarea:focus{outline:none;border-color:var(--blu)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
tr:hover td{background:#0f1520}
.pill{display:inline-block;padding:2px 9px;border-radius:5px;font-size:11px;font-weight:700}
.sev-critical{background:var(--red);color:#2a0d0d}.sev-high{background:#fb7185;color:#2a0d0d}
.sev-medium{background:var(--org);color:#2a1e03}.sev-low{background:var(--blu);color:#07132a}.sev-info{background:var(--mut);color:#0b0e14}
.chain{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 18px}
.step{padding:6px 14px;border-radius:7px;background:#0f1520;color:var(--mut);border:1px solid var(--line);font-size:12px;font-weight:700;transition:.3s}
.step.on{color:#06130c;background:var(--blu);border-color:var(--blu)}.step.on.root{background:var(--grn);border-color:var(--grn)}
.feed{font-family:ui-monospace,Menlo,monospace;font-size:12.5px}
.ev{padding:6px 10px;margin-bottom:5px;border-left:2px solid var(--line);background:var(--panel);border-radius:0 5px 5px 0}
.ev .d{color:var(--mut);word-break:break-all}.ev pre{margin:5px 0 0;padding:7px;background:#070a0f;border-radius:4px;color:#9fe8c4;white-space:pre-wrap;max-height:150px;overflow:auto}
.chat{display:flex;flex-direction:column;height:calc(100vh - 110px)}
.msgs{flex:1;overflow:auto;padding:4px;display:flex;flex-direction:column;gap:10px}
.m{max-width:80%;padding:10px 14px;border-radius:12px;white-space:pre-wrap;word-break:break-word}
.m.user{align-self:flex-end;background:var(--blu);color:#07132a}
.m.bot{align-self:flex-start;background:var(--panel);border:1px solid var(--line)}
.m.sys{align-self:center;color:var(--mut);font-size:12px;background:none}
.inbar{display:flex;gap:10px;margin-top:12px}
.login{max-width:360px;margin:12vh auto;text-align:center}
.err{color:var(--red);font-size:13px;margin:8px 0}
.kbd{background:#0f1520;border:1px solid var(--line);border-radius:4px;padding:1px 6px;font-family:ui-monospace,monospace;font-size:12px}
"""


def _page(active: str, title: str, sub: str, body: str) -> str:
    def nav(h, label, key):
        return f'<a href="{h}" class="{"on" if key == active else ""}">{label}</a>'
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>MetSec · {title}</title>
<style>{_CSS}</style></head><body><div class="app">
<div class="side"><div class="brand">⬢ MetSec</div>
{nav('/chat', '💬 Chat', 'chat')}{nav('/dashboard', '📊 Dashboard', 'dash')}
{nav('/reports', '📁 Reports', 'reports')}{nav('/knowledge', '🧠 Knowledge', 'know')}
<div class="sp"></div>{nav('/logout', '⎋ Logout', '')}</div>
<div class="main"><h1>{title}</h1><p class="sub">{sub}</p>{body}</div></div></body></html>"""


def create_app():
    from flask import (Flask, Response, redirect, request, session, url_for)

    app = Flask(__name__)
    app.secret_key = os.environ.get("METSEC_WEB_SECRET") or secrets.token_hex(16)

    def login_required(f):
        @wraps(f)
        def wrap(*a, **k):
            if not session.get("user"):
                return redirect(url_for("login"))
            return f(*a, **k)
        return wrap

    @app.route("/login", methods=["GET", "POST"])
    def login():
        err = ""
        if request.method == "POST":
            u, p = request.form.get("user", ""), request.form.get("password", "")
            if secrets.compare_digest(u, USER) and secrets.compare_digest(p, PASS):
                session["user"] = u
                return redirect(url_for("chat"))
            err = "Invalid credentials"
        return f"""<!doctype html><html><head><meta charset="utf-8"><title>MetSec Login</title>
<style>{_CSS}</style></head><body><div class="login"><div class="brand" style="font-size:26px">⬢ MetSec</div>
<p class="sub">Autonomous pentest agent — control panel</p>
<form method="post" class="card" style="text-align:left">
<label>User</label><input name="user" autofocus value="admin">
<label>Password</label><input name="password" type="password">
{'<div class="err">' + err + '</div>' if err else ''}
<button class="btn" style="width:100%;margin-top:14px">Sign in</button></form></div></body></html>"""

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def index():
        return redirect(url_for("chat"))

    @app.route("/chat")
    @login_required
    def chat():
        return _page("chat", "Chat", "Tell the agent what to do — e.g. "
                     "<span class='kbd'>pentest http://127.0.0.1:5001 in dev mode with exploit</span>",
                     _CHAT_BODY)

    @app.route("/api/chat", methods=["POST"])
    @login_required
    def api_chat():
        msg = (request.get_json(force=True) or {}).get("message", "").strip()
        if not msg:
            return {"type": "error", "text": "empty"}
        rid, err = runs.launch(msg, authorized_by=session["user"])
        if err:
            return {"type": "error", "text": err}
        if rid:
            r = runs.latest()
            return {"type": "scan", "rid": rid,
                    "text": f"🚀 Launching {r['mode']} scan on {r['target']}"
                            + (" (exploit ON)" if r["exploit"] else "") + " — watch it below."}
        return {"type": "reply", "text": runs.answer(msg)}

    @app.route("/api/transcribe", methods=["POST"])
    @login_required
    def api_transcribe():
        from . import config
        audio = request.files.get("audio")
        if not audio:
            return {"text": "", "error": "no audio"}
        try:
            return {"text": config.transcribe(
                audio.read(), sample_rate=int(request.form.get("sample_rate", 16000)))}
        except Exception as e:  # noqa: BLE001
            return {"text": "", "error": str(e)[:160]}

    @app.route("/stream")
    @login_required
    def stream():
        def gen():
            idx = 0
            while True:
                evs = events.since(idx)
                if evs:
                    idx += len(evs)
                    for e in evs:
                        yield f"data: {json.dumps(e)}\n\n"
                else:
                    yield ": ka\n\n"
                time.sleep(0.4)
        return Response(gen(), mimetype="text/event-stream")

    @app.route("/api/status")
    @login_required
    def status():
        r = runs.latest()
        return {"active": bool(r and r.get("status") == "running"),
                "run": {k: r[k] for k in ("id", "target", "mode", "status", "report")
                        if r and k in r} if r else None}

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return _page("dash", "Live dashboard", "Kill-chain progress and agent activity in real time.",
                     _DASH_BODY)

    @app.route("/reports")
    @login_required
    def reports():
        rows = "".join(
            f"<tr><td><a href='/report/{r['name']}'>{r['target']}</a></td>"
            f"<td>{r['date']}</td><td><b>{r['cvss']}</b></td><td>{r['count']}</td>"
            f"<td style='color:var(--mut)'>{r['name']}</td></tr>" for r in runs.list_reports())
        body = ("<div class='card'><table><tr><th>Target</th><th>Date</th><th>CVSS</th>"
                "<th>Findings</th><th>Report</th></tr>" + (rows or
                "<tr><td colspan=5 style='color:var(--mut)'>No reports yet — run a scan from Chat.</td></tr>")
                + "</table></div>")
        return _page("reports", "Reports", "Past assessments.", body)

    @app.route("/report/<name>")
    @login_required
    def report(name):
        from pathlib import Path
        data = runs.read_report(name)
        if not data:
            return _page("reports", "Report", "", "<div class='card'>Report not found.</div>")
        bar = (f"<p><a href='/reports'>← all reports</a> &nbsp; "
               f"<a class='btn' style='text-decoration:none;padding:6px 14px' "
               f"href='/report/{name}/pdf'>⬇ PDF</a></p>")
        html_f = Path(name) / "report.html"
        if html_f.exists():
            inner = html_f.read_text().replace('"', "&quot;")
            body = (bar + f"<iframe srcdoc=\"{inner}\" style='width:100%;height:calc(100vh - 180px);"
                    f"border:1px solid var(--line);border-radius:10px;background:#0b0e14'></iframe>")
        else:
            body = bar + "<div class='card'>" + _findings_table(data.get("findings", [])) + "</div>"
        return _page("reports", "Report", name, body)

    @app.route("/report/<name>/pdf")
    @login_required
    def report_pdf(name):
        from flask import abort, send_file
        if not runs.read_report(name):   # validates name (no traversal) + existence
            abort(404)
        pdf = Path(name) / "report.pdf"
        if not pdf.exists():
            from .report import make_pdf   # craft (Spark) + render — may take ~30s
            make_pdf(name)
        if not pdf.exists():
            abort(500)
        return send_file(str(pdf.resolve()), mimetype="application/pdf",
                         download_name=f"{name}.pdf")

    @app.route("/knowledge")
    @login_required
    def knowledge():
        return _page("know", "Knowledge base", "Search the CVE / technique index.", _KNOW_BODY)

    @app.route("/api/knowledge")
    @login_required
    def api_knowledge():
        q = request.args.get("q", "").strip()
        if not q:
            return {"hits": []}
        try:
            from .rag import CveIndex
            hits = CveIndex().search(q, k=12)
            return {"hits": [{"id": h["id"], "source": h["source"],
                              "summary": h["summary"][:220], "severity": h.get("severity", "")}
                             for h in hits]}
        except Exception as e:  # noqa: BLE001
            return {"hits": [], "error": str(e)[:120]}

    return app


def _findings_table(findings: list) -> str:
    rows = "".join(
        f"<tr><td><span class='pill sev-{f.get('severity', 'info')}'>{f.get('severity', '').upper()}"
        f"</span></td><td>{f.get('cvss', '')}</td><td>{f.get('status', '')}</td>"
        f"<td>{_esc(f.get('title', ''))}</td><td style='color:var(--mut)'>{_esc(f.get('affected', ''))}</td></tr>"
        for f in findings)
    return ("<table><tr><th>Sev</th><th>CVSS</th><th>Status</th><th>Finding</th><th>Where</th></tr>"
            + (rows or "<tr><td colspan=5>No findings.</td></tr>") + "</table>")


def _esc(s: str) -> str:
    import html
    return html.escape(str(s or ""))


def serve(port: int = 8787) -> None:
    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    if PASS == "metsec":
        print("⚠️  default web password 'metsec' — set METSEC_WEB_PASS to change it")
    print(f"  🌐  MetSec web: http://127.0.0.1:{port}   (login: {USER})")
    create_app().run(host="127.0.0.1", port=port, threaded=True)


_FEED_JS = r"""
const ICON={http_probe:'🌐',search_vulns:'🔎',record_finding:'📌',establish_foothold:'🎯',
run_command:'⌨️',privesc_scan:'⬆️',loot:'💰',browse:'📸',browser_action:'🖱️',hypothesize:'💡',
make_payload:'🧬',upload_shell:'📤',finish:'🏁'};
const esc=s=>(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function evHtml(e){
 if(e.type==='tool')return `<div class="ev"><b>${ICON[e.name]||'•'} ${e.name}</b> <span class="d">${esc(e.detail)}</span></div>`;
 if(e.type==='command')return `<div class="ev" style="border-left-color:var(--pur)"><span class="d">⌨️ ${esc(e.cmd)}</span><pre>${esc(e.output)||'(no output)'}</pre></div>`;
 if(e.type==='foothold')return `<div class="ev" style="border-left-color:var(--org)">🎯 <b>FOOTHOLD</b> via ${esc(e.kind)} <span class="d">${esc(e.whoami)}</span></div>`;
 if(e.type==='root')return `<div class="ev" style="border-left-color:var(--grn)">👑 <b style="color:var(--grn)">ROOT — uid=0</b></div>`;
 if(e.type==='finding')return `<div class="ev"><span class="pill sev-${e.severity}">${(e.severity||'').toUpperCase()}</span> ${esc(e.title)} <span class="d">(${esc(e.status)})</span></div>`;
 if(e.type==='hypothesis')return `<div class="ev" style="border-left-color:var(--pur)">💡 <span class="d">${esc(e.statement)}</span></div>`;
 if(e.type==='finish')return `<div class="ev">🏁 <b>agent finished</b> <span class="d">${esc(e.summary)}</span></div>`;
 if(e.type==='error')return `<div class="ev" style="border-left-color:var(--red)">⚠️ <span class="d">${esc(e.msg)}</span></div>`;
 if(e.type==='start')return `<div class="ev">▶️ <b>scan started</b> <span class="d">${esc(e.target)} [${esc(e.mode)}]</span></div>`;
 if(e.type==='done')return `<div class="ev">✅ <b>assessment complete</b></div>`;
 return '';}
"""

_CHAT_BODY = r"""
<div class="chat">
<div class="msgs" id="msgs">
<div class="m bot">Hi — I'm your pentest agent. Tell me a target to assess (you must be authorized),
ask about the last run, or search for a vuln. Try: <span class="kbd">scan http://127.0.0.1:5002 in dev mode with exploit</span></div>
</div>
<div class="inbar"><input id="in" placeholder="Message the agent… (or tap 🎤)" autofocus>
<button class="btn" id="mic" onclick="mic()" title="Voice input" style="background:#1d2635;color:var(--txt)">🎤</button>
<button class="btn" id="ttsb" onclick="toggleTts()" title="Read replies aloud" style="background:#1d2635;color:var(--mut)">🔇</button>
<button class="btn" onclick="send()">Send</button></div></div>
<script>""" + _FEED_JS + r"""
const msgs=document.getElementById('msgs'),inp=document.getElementById('in');
function add(cls,html){const d=document.createElement('div');d.className='m '+cls;d.innerHTML=html;msgs.appendChild(d);msgs.scrollTop=msgs.scrollHeight;return d;}
let streaming=false,idx0=null;
async function send(){const t=inp.value.trim();if(!t)return;inp.value='';add('user',esc(t));
 const r=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:t})});
 const j=await r.json();
 if(j.type==='reply'){add('bot',esc(j.text));speak(j.text);}
 else if(j.type==='error'){add('sys','⚠️ '+esc(j.text));}
 else if(j.type==='scan'){add('bot',esc(j.text));speak(j.text);startFeed();}}
inp.addEventListener('keydown',e=>{if(e.key==='Enter')send();});
function startFeed(){if(streaming)return;streaming=true;
 const feed=add('bot','<div class="feed" id="live"></div>');const live=feed.querySelector('#live');
 const src=new EventSource('/stream');
 src.onmessage=ev=>{const e=JSON.parse(ev.data);const h=evHtml(e);if(h){live.insertAdjacentHTML('beforeend',h);msgs.scrollTop=msgs.scrollHeight;}
  if(e.type==='done'){src.close();streaming=false;add('sys','scan finished — see Reports');}};}
// --- voice: STT in (Muse Voice Transcribe), TTS out (browser speechSynthesis) ---
let tts=false;
function toggleTts(){tts=!tts;const b=document.getElementById('ttsb');b.textContent=tts?'🔊':'🔇';b.style.color=tts?'var(--grn)':'var(--mut)';if(!tts)speechSynthesis.cancel();}
function speak(t){if(!tts||!window.speechSynthesis)return;const u=new SpeechSynthesisUtterance((t||'').replace(/<[^>]+>/g,' ').slice(0,500));u.rate=1.05;speechSynthesis.cancel();speechSynthesis.speak(u);}
let rec={on:false};
async function mic(){
 if(rec.on){stopRec();return;}
 let stream;try{stream=await navigator.mediaDevices.getUserMedia({audio:true});}catch(e){add('sys','🎤 microphone blocked');return;}
 const ctx=new (window.AudioContext||window.webkitAudioContext)();
 const src=ctx.createMediaStreamSource(stream),node=ctx.createScriptProcessor(4096,1,1),buf=[];
 node.onaudioprocess=e=>buf.push(new Float32Array(e.inputBuffer.getChannelData(0)));
 src.connect(node);node.connect(ctx.destination);
 rec={on:true,ctx,src,node,stream,buf,sr:ctx.sampleRate};
 const m=document.getElementById('mic');m.textContent='⏺';m.style.color='var(--red)';}
function stopRec(){const r=rec;rec={on:false};
 r.node.disconnect();r.src.disconnect();r.stream.getTracks().forEach(t=>t.stop());
 const m=document.getElementById('mic');m.textContent='🎤';m.style.color='var(--txt)';
 const wav=encodeWav(r.buf,r.sr);r.ctx.close();
 const fd=new FormData();fd.append('audio',wav,'rec.wav');fd.append('sample_rate',r.sr);
 add('sys','… transcribing');
 fetch('/api/transcribe',{method:'POST',body:fd}).then(x=>x.json()).then(j=>{
  if(j.text){inp.value=j.text;send();}else add('sys','⚠️ '+(j.error||'no transcript'));});}
function encodeWav(chunks,sr){
 let len=chunks.reduce((a,c)=>a+c.length,0);const pcm=new Float32Array(len);let o=0;
 for(const c of chunks){pcm.set(c,o);o+=c.length;}
 const b=new ArrayBuffer(44+len*2),v=new DataView(b);
 const ws=(off,s)=>{for(let i=0;i<s.length;i++)v.setUint8(off+i,s.charCodeAt(i));};
 ws(0,'RIFF');v.setUint32(4,36+len*2,true);ws(8,'WAVE');ws(12,'fmt ');
 v.setUint32(16,16,true);v.setUint16(20,1,true);v.setUint16(22,1,true);
 v.setUint32(24,sr,true);v.setUint32(28,sr*2,true);v.setUint16(32,2,true);v.setUint16(34,16,true);
 ws(36,'data');v.setUint32(40,len*2,true);let off=44;
 for(let i=0;i<len;i++){let s=Math.max(-1,Math.min(1,pcm[i]));v.setInt16(off,s<0?s*0x8000:s*0x7FFF,true);off+=2;}
 return new Blob([b],{type:'audio/wav'});}
</script>"""

_DASH_BODY = r"""
<div class="chain" id="chain">
<span class="step" data-s="0">Recon</span><span class="step" data-s="1">Exploit</span>
<span class="step" data-s="2">Foothold</span><span class="step" data-s="3">Privesc</span>
<span class="step root" data-s="4">ROOT</span></div>
<div class="card feed" id="feed" style="height:calc(100vh - 210px);overflow:auto"></div>
<script>""" + _FEED_JS + r"""
const feed=document.getElementById('feed');let mx=-1;
const SS={http_probe:1,search_vulns:1,record_finding:1,establish_foothold:2,run_command:3,privesc_scan:3,loot:3};
function stage(n){if(n<=mx)return;mx=n;document.querySelectorAll('.step').forEach(p=>{if(+p.dataset.s<=n)p.classList.add('on')});}
const src=new EventSource('/stream');
src.onmessage=ev=>{const e=JSON.parse(ev.data);const h=evHtml(e);if(h){feed.insertAdjacentHTML('beforeend',h);feed.scrollTop=feed.scrollHeight;}
 if(e.type==='tool'&&SS[e.name]!=null)stage(SS[e.name]);
 if(e.type==='finding')stage(/privileg|escalat|\broot\b/i.test(e.title)?3:1);
 if(e.type==='foothold')stage(2);if(e.type==='command')stage(3);if(e.type==='root')stage(4);};
</script>"""

_KNOW_BODY = r"""
<div class="inbar" style="max-width:600px"><input id="q" placeholder="CVE, tech, technique… e.g. sudo tar privesc" autofocus>
<button class="btn" onclick="go()">Search</button></div>
<div class="card" id="res" style="margin-top:16px;color:var(--mut)">Type a query.</div>
<script>
const esc=s=>(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
async function go(){const q=document.getElementById('q').value.trim();if(!q)return;
 const res=document.getElementById('res');res.innerHTML='Searching…';
 const j=await (await fetch('/api/knowledge?q='+encodeURIComponent(q))).json();
 if(!j.hits.length){res.innerHTML=esc(j.error||'No results.');return;}
 res.innerHTML='<table><tr><th>ID</th><th>Source</th><th>Summary</th></tr>'+
  j.hits.map(h=>`<tr><td>${esc(h.id)}</td><td><span class="pill sev-info">${esc(h.source)}</span></td><td>${esc(h.summary)}</td></tr>`).join('')+'</table>';}
document.getElementById('q').addEventListener('keydown',e=>{if(e.key==='Enter')go();});
</script>"""
