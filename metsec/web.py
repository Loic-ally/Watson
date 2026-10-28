"""Live assessment dashboard — streams the agent's path over Server-Sent Events.

serve() runs a small Flask app: `/` is the dashboard, `/stream` is the SSE feed
that tails the event bus the agent emits to.
"""
from __future__ import annotations

import json
import time

from . import events


def serve(port: int = 8787) -> None:
    try:
        from flask import Flask, Response
    except ImportError:
        print("dashboard needs Flask: pip install flask")
        return

    app = Flask(__name__)

    @app.route("/")
    def index():
        return DASH

    @app.route("/stream")
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
                    yield ": keepalive\n\n"
                time.sleep(0.4)

        return Response(gen(), mimetype="text/event-stream")

    import logging
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app.run(host="127.0.0.1", port=port, threaded=True)


DASH = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MetSec Live</title><style>
:root{--bg:#0b0e14;--panel:#121722;--line:#1f2633;--txt:#c9d4e3;--mut:#6b7689;
--grn:#36d399;--red:#f87272;--org:#fbbd23;--blu:#3b82f6;--pur:#a78bfa}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);
font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
header{display:flex;align-items:center;gap:16px;padding:14px 20px;border-bottom:1px solid var(--line);
background:var(--panel);flex-wrap:wrap}
header h1{font-size:16px;margin:0;letter-spacing:.5px}
header h1 b{color:var(--grn)}
.target{color:var(--mut);font-size:13px}
#status{margin-left:auto;padding:4px 12px;border-radius:20px;font-weight:700;font-size:12px;
background:#1c2534;color:var(--blu);border:1px solid var(--line)}
#status.root{background:#10281f;color:var(--grn);border-color:var(--grn);animation:glow 1s infinite alternate}
#status.done{background:#1c2534;color:var(--mut)}
@keyframes glow{to{box-shadow:0 0 14px #36d39977}}
.chain{display:flex;gap:8px;padding:12px 20px;border-bottom:1px solid var(--line);flex-wrap:wrap}
.pill{padding:5px 14px;border-radius:6px;background:#141a26;color:var(--mut);border:1px solid var(--line);
font-size:12px;font-weight:600;transition:.3s}
.pill.on{color:var(--bg);background:var(--blu);border-color:var(--blu)}
.pill.on.p4{background:var(--grn);border-color:var(--grn);box-shadow:0 0 12px #36d39955}
main{display:grid;grid-template-columns:1.4fr 1fr;gap:1px;background:var(--line);min-height:calc(100vh - 115px)}
section{background:var(--bg);padding:14px 18px;overflow:auto;max-height:calc(100vh - 115px)}
h2{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--mut);margin:0 0 12px}
.row{padding:7px 10px;margin-bottom:6px;border-left:2px solid var(--line);background:var(--panel);border-radius:0 4px 4px 0}
.row .ic{margin-right:8px}
.row .d{color:var(--mut);font-size:12px;word-break:break-all}
.cmd{border-left-color:var(--pur)}
.cmd pre{margin:6px 0 0;padding:8px;background:#0a0d13;border-radius:4px;color:#9fe8c4;
font-size:12px;white-space:pre-wrap;word-break:break-all;max-height:160px;overflow:auto}
.foot{border-left-color:var(--org)}.rootrow{border-left-color:var(--grn)}
.f{padding:9px 11px;margin-bottom:7px;border-radius:5px;background:var(--panel);border-left:3px solid var(--mut)}
.f .sev{font-size:10px;font-weight:700;letter-spacing:.5px;padding:1px 7px;border-radius:3px;margin-right:8px}
.f.critical{border-left-color:var(--red)}.f.critical .sev{background:var(--red);color:#2a0d0d}
.f.high{border-left-color:#fb7185}.f.high .sev{background:#fb7185;color:#2a0d0d}
.f.medium{border-left-color:var(--org)}.f.medium .sev{background:var(--org);color:#2a1e03}
.f.low{border-left-color:var(--blu)}.f.low .sev{background:var(--blu);color:#07132a}
.f.info{border-left-color:var(--mut)}.f.info .sev{background:var(--mut);color:#0b0e14}
.f .st{float:right;font-size:10px;color:var(--mut)}
#banner{position:fixed;inset:0;display:none;align-items:center;justify-content:center;
background:#06120caa;backdrop-filter:blur(3px);z-index:9}
#banner div{font-size:42px;font-weight:800;color:var(--grn);text-shadow:0 0 30px #36d399;letter-spacing:4px}
.count{color:var(--mut);font-weight:400}
@media(max-width:800px){main{grid-template-columns:1fr}}
</style></head><body>
<header><h1>⬢ <b>MetSec</b> — Live Assessment</h1>
<span class="target" id="target">connecting…</span>
<span id="status">RUNNING</span></header>
<div class="chain" id="chain">
<span class="pill" data-s="0">Recon</span><span class="pill" data-s="1">Exploit</span>
<span class="pill" data-s="2">Foothold</span><span class="pill" data-s="3">Privesc</span>
<span class="pill p4" data-s="4">ROOT</span></div>
<main>
<section><h2>Agent activity</h2><div id="feed"></div></section>
<section><h2>Findings <span class="count" id="fc">(0)</span></h2><div id="finds"></div></section>
</main>
<div id="banner"><div id="btext">ROOT</div></div>
<script>
const feed=document.getElementById('feed'),finds=document.getElementById('finds');
const ICON={http_probe:'🌐',search_vulns:'🔎',record_finding:'📌',establish_foothold:'🎯',
run_command:'⌨️',privesc_scan:'⬆️',loot:'💰',browse:'📸',hypothesize:'💡'};
let maxStage=-1;
function stage(n){if(n<=maxStage)return;maxStage=n;
  document.querySelectorAll('.pill').forEach(p=>{if(+p.dataset.s<=n)p.classList.add('on')});}
function setStatus(t,c){const s=document.getElementById('status');s.textContent=t;s.className=c||'';}
function flash(txt){const b=document.getElementById('banner');document.getElementById('btext').textContent=txt;
  b.style.display='flex';setTimeout(()=>b.style.display='none',1600);}
function add(el){feed.appendChild(el);feed.scrollTop=feed.scrollHeight;}
const esc=s=>(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
let nf=0;
const SS={http_probe:1,search_vulns:1,record_finding:1,establish_foothold:2,
  run_command:3,privesc_scan:3,loot:3};
const src=new EventSource('/stream');
src.onmessage=ev=>{const e=JSON.parse(ev.data);
 if(e.type==='start'){document.getElementById('target').textContent=e.target+'  ['+e.mode+']';stage(0);return;}
 if(e.type==='tool'){const r=document.createElement('div');r.className='row';
   r.innerHTML=`<span class="ic">${ICON[e.name]||'•'}</span><b>${e.name}</b> <span class="d">${esc(e.detail)}</span>`;
   add(r);if(SS[e.name]!=null)stage(SS[e.name]);return;}
 if(e.type==='command'){const r=document.createElement('div');r.className='row cmd';
   r.innerHTML=`<span class="ic">⌨️</span><span class="d">${esc(e.cmd)}</span><pre>${esc(e.output)||'(no output)'}</pre>`;
   add(r);stage(3);return;}
 if(e.type==='hypothesis'){const r=document.createElement('div');r.className='row';
   r.style.borderLeftColor='var(--pur)';
   r.innerHTML=`<span class="ic">💡</span><b>hypothesis</b> <span class="d">${esc(e.statement)}</span>`;
   add(r);return;}
 if(e.type==='foothold'){const r=document.createElement('div');r.className='row foot';
   r.innerHTML=`<span class="ic">🎯</span><b>FOOTHOLD</b> via ${esc(e.kind)} <span class="d">${esc(e.whoami)}</span>`;
   add(r);stage(2);flash('FOOTHOLD');return;}
 if(e.type==='root'){const r=document.createElement('div');r.className='row rootrow';
   r.innerHTML=`<span class="ic">👑</span><b style="color:var(--grn)">ROOT — uid=0</b>`;add(r);
   stage(4);setStatus('ROOT','root');flash('👑 ROOT');return;}
 if(e.type==='finding'){nf++;document.getElementById('fc').textContent='('+nf+')';
   const d=document.createElement('div');d.className='f '+(e.severity||'info');
   d.innerHTML=`<span class="sev">${(e.severity||'').toUpperCase()}</span>${esc(e.title)}<span class="st">${esc(e.status)}</span>`;
   finds.insertBefore(d,finds.firstChild);
   stage(/privileg|escalat|\broot\b/i.test(e.title)?3:1);return;}
 if(e.type==='done'){if(maxStage<4)setStatus('DONE','done');
   const r=document.createElement('div');r.className='row';r.innerHTML='<span class="ic">✅</span><b>assessment complete</b>';add(r);return;}
 if(e.type==='error'){const r=document.createElement('div');r.className='row';
   r.style.borderLeftColor='var(--red)';r.innerHTML=`<span class="ic">⚠️</span><span class="d">${esc(e.msg)}</span>`;add(r);}
};
src.onerror=()=>setStatus('·· reconnecting','');
</script></body></html>"""
