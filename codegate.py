"""CodeGate: an HTTPS front door for per-member workspaces (see spaces.py).

What it does, and why it's built this way:
  - HTTPS only (TLS 1.2+), with a leaf certificate from a local CA whose name
    constraints only allow private/loopback addresses, so even a stolen CA key
    can't impersonate real websites on devices that trust it.
  - Nobody reaches a workspace without joining: a name plus the room's PIN
    (new members) or their resume code (returning ones). Failed attempts are
    throttled per device.
  - A joined member is routed ONLY to their own container. Workspaces listen
    on 127.0.0.1 ports that only this process knows; members can't choose or
    even see another member's port.
  - Gate-generated pages refuse framing; unexpected Host headers are rejected
    (DNS rebinding); state-changing requests check Origin.
"""
import html
import http.client
import ipaddress
import os
import secrets
import select
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
from pathlib import Path

from spaces import SpacesError

GATE_PORT = 8901
COOKIE = "codegate_session"
SESSION_LIFETIME = 12 * 3600
PREFIX = "/__cg/"
CA_NAME_CONSTRAINTS = (
    "critical,"
    "permitted;IP:10.0.0.0/255.0.0.0,permitted;IP:172.16.0.0/255.240.0.0,"
    "permitted;IP:192.168.0.0/255.255.0.0,permitted;IP:127.0.0.0/255.0.0.0,"
    "permitted;IP:169.254.0.0/255.255.0.0,permitted;DNS:localhost"
)

CSS = """
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0d10;color:#e8ecef;
font:14px/1.5 "JetBrains Mono",ui-monospace,Menlo,monospace}
.box{width:min(420px,92vw);background:#14171c;border:1px solid #24282f;border-radius:14px;padding:24px;margin:24px 0}
h1{font-size:16px;margin:0 0 4px} h2{font-size:12px;color:#9aa3ad;margin:18px 0 8px;text-transform:uppercase;letter-spacing:.5px}
.sub{color:#9aa3ad;font-size:12px;margin:0 0 16px}
label{display:block;font-size:12px;color:#9aa3ad;margin:12px 0 4px}
input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #24282f;background:#0d1013;color:#e8ecef;font:inherit}
button,.btn{display:inline-block;padding:9px 14px;border:0;border-radius:8px;background:#e8ecef;color:#111;font:inherit;font-weight:700;cursor:pointer;text-decoration:none;font-size:13px}
.full{width:100%;margin-top:14px;text-align:center}
.ghost{background:transparent;color:#e8ecef;border:1px solid #24282f}
.err{color:#ff5c5c;font-size:12px;margin:12px 0 0}.ok{color:#8be9b0}
.row{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px 0;border-top:1px solid #1d2026}
.row:first-of-type{border-top:0}.acts{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.code{font-size:20px;letter-spacing:2px;text-align:center;background:#0d1013;border:1px dashed #3a4049;border-radius:10px;padding:14px;margin:14px 0;user-select:all}
a{color:#9aa3ad}.foot{font-size:11px;color:#5c646d;margin-top:16px}.dim{color:#9aa3ad;font-size:12px}
form{margin:0}.inline{display:inline}
"""


class Gate:
    def __init__(self, base_dir, lan_ip, spaces, log):
        # The certificate folder keeps its old name so devices that already
        # trust this Mac's CA keep working.
        self.dir = Path(base_dir) / "code"
        self.dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.lan_ip = lan_ip
        self.spaces = spaces
        self.log = log
        self.lock = threading.RLock()
        self.listener = None
        self.sessions = {}      # token -> (member id, created)
        self.connections = {}   # member id -> set of (client, upstream) sockets
        threading.Thread(target=self._reaper, daemon=True).start()

    # ------------------------------------------------------ certificates

    def ca_pem(self):
        self._ensure_ca()
        return (self.dir / "ca.pem").read_bytes()

    def _openssl(self, *args):
        subprocess.run(["openssl", *args], check=True, capture_output=True, timeout=30)

    def _ensure_ca(self):
        ca, key = self.dir / "ca.pem", self.dir / "ca-key.pem"
        if ca.exists() and key.exists():
            return
        host = socket.gethostname().split(".")[0]
        self._openssl(
            "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "3650",
            "-keyout", str(key), "-out", str(ca),
            "-subj", f"/CN=CodeGate local CA ({host})",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", f"nameConstraints={CA_NAME_CONSTRAINTS}",
        )
        os.chmod(key, 0o600)

    def _ensure_leaf(self, ip):
        """A server certificate for the current LAN IP, reissued when it changes."""
        self._ensure_ca()
        cert, key = self.dir / "gate-cert.pem", self.dir / "gate-key.pem"
        stamp = self.dir / "gate-cert.ip"
        if cert.exists() and key.exists() and stamp.exists() and stamp.read_text() == ip:
            return cert, key
        ext = self.dir / "leaf.ext"
        sans = ["IP:127.0.0.1", "DNS:localhost"]
        try:
            if ipaddress.ip_address(ip).is_private and ip != "127.0.0.1":
                sans.insert(0, f"IP:{ip}")
        except ValueError:
            pass
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            f"subjectAltName={','.join(sans)}\n"
        )
        csr = self.dir / "leaf.csr"
        self._openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={ip}")
        self._openssl(
            "x509", "-req", "-sha256", "-days", "397", "-in", str(csr),
            "-CA", str(self.dir / "ca.pem"), "-CAkey", str(self.dir / "ca-key.pem"),
            "-set_serial", str(secrets.randbits(63)), "-out", str(cert), "-extfile", str(ext),
        )
        os.chmod(key, 0o600)
        csr.unlink(missing_ok=True)
        ext.unlink(missing_ok=True)
        stamp.write_text(ip)
        return cert, key

    # ------------------------------------------------------ start / stop

    def running(self):
        return self.listener is not None

    def url(self):
        return f"https://{self.lan_ip()}:{GATE_PORT}/" if self.running() else None

    def start(self):
        with self.lock:
            if self.listener:
                return
            cert, key = self._ensure_leaf(self.lan_ip())
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(str(cert), str(key))
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", GATE_PORT))
            listener.listen(128)
            self.listener = listener
            threading.Thread(target=self._accept_loop, args=(listener, ctx), daemon=True).start()
            self.log("gate started")

    def stop(self):
        with self.lock:
            if not self.listener:
                return
            try:
                self.listener.close()
            except OSError:
                pass
            self.listener = None
            for pairs in list(self.connections.values()):
                for pair in list(pairs):
                    for sock in pair:
                        try:
                            sock.close()
                        except OSError:
                            pass
            self.connections.clear()
            self.sessions.clear()
            self.log("gate stopped")

    def drop_member(self, sid):
        """Signs a member out everywhere and cuts their open connections."""
        with self.lock:
            for tok in [t for t, (s, _) in self.sessions.items() if s == sid]:
                del self.sessions[tok]
            for pair in list(self.connections.get(sid, ())):
                for sock in pair:
                    try:
                        sock.close()
                    except OSError:
                        pass

    def _reaper(self):
        while True:
            time.sleep(300)
            cutoff = time.time() - SESSION_LIFETIME
            with self.lock:
                for tok in [t for t, (_, made) in self.sessions.items() if made < cutoff]:
                    del self.sessions[tok]

    # --------------------------------------------------------------- serving

    def _accept_loop(self, listener, ctx):
        while True:
            try:
                raw, addr = listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw, addr[0], ctx), daemon=True).start()

    def _allowed_host(self, host):
        return host in (f"{self.lan_ip()}:{GATE_PORT}", f"127.0.0.1:{GATE_PORT}", f"localhost:{GATE_PORT}")

    def _session(self, headers):
        tok = self._cookie(headers.get("cookie", ""))
        with self.lock:
            entry = self.sessions.get(tok) if tok else None
        if not entry or entry[1] < time.time() - SESSION_LIFETIME:
            return None, None
        member = self.spaces.member(entry[0])
        return (tok, member) if member else (None, None)

    def _handle(self, raw, ip, ctx):
        raw.settimeout(15)
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            return
        upstream = None
        sid = None
        try:
            head, rest = self._read_head(conn)
            if head is None:
                return
            lines = head.decode("latin-1").split("\r\n")
            method, target = (lines[0].split(" ") + ["", ""])[:2]
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            if not self._allowed_host(headers.get("host", "")):
                return self._reply(conn, 421, "text/plain", b"Misdirected request")

            parts = urllib.parse.urlsplit(target)
            token, member = self._session(headers)

            if parts.path.startswith(PREFIX):
                return self._internal(conn, method, parts, headers, rest, ip, token, member)

            if not member:
                if method == "GET" and "upgrade" not in headers:
                    return self._reply(conn, 303, "text/plain", b"", {"Location": PREFIX + "join"})
                return self._reply(conn, 401, "text/plain", b"Join first.")

            sid = member["id"]
            port = self.spaces.upstream_port(sid)
            if not port:
                if method == "GET" and "upgrade" not in headers:
                    return self._reply(conn, 303, "text/plain", b"", {"Location": PREFIX + "home"})
                return self._reply(conn, 503, "text/plain", b"Workspace isn't running.")

            upstream = socket.create_connection(("127.0.0.1", port), timeout=10)
            upstream.sendall(head + rest)
            conn.settimeout(None)
            upstream.settimeout(None)
            with self.lock:
                self.connections.setdefault(sid, set()).add((conn, upstream))
            self.spaces.touch(sid, +1)
            try:
                self._pipe(conn, upstream)
            finally:
                self.spaces.touch(sid, -1)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            if sid:
                with self.lock:
                    self.connections.get(sid, set()).discard((conn, upstream))
            for s in (conn, upstream):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    @staticmethod
    def _read_head(conn):
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                return None, None
            buf += chunk
            if len(buf) > 64 * 1024:
                return None, None
        head, rest = buf.split(b"\r\n\r\n", 1)
        return head + b"\r\n\r\n", rest

    @staticmethod
    def _pipe(a, b):
        while True:
            ready = [a] if isinstance(a, ssl.SSLSocket) and a.pending() else select.select([a, b], [], [], 60)[0]
            for src in ready:
                data = src.recv(65536)
                if not data:
                    return
                (b if src is a else a).sendall(data)

    @staticmethod
    def _cookie(header):
        for part in header.split(";"):
            k, _, v = part.strip().partition("=")
            if k == COOKIE and v:
                return v
        return None

    @staticmethod
    def _reply(conn, status, ctype, body, extra=None):
        reason = http.client.responses.get(status, "")
        hdrs = {
            "Content-Type": ctype,
            "Content-Length": str(len(body)),
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Strict-Transport-Security": "max-age=31536000",
            "Connection": "close",
        }
        hdrs.update(extra or {})
        out = f"HTTP/1.1 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        conn.sendall(out.encode("latin-1") + body)

    # ---------------------------------------------------------------- pages

    def _page(self, conn, status, title, body, extra=None):
        doc = (f'<!doctype html><html><head><meta charset="utf-8">'
               f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title>'
               f'<style>{CSS}</style></head><body><div class="box">{body}</div></body></html>')
        return self._reply(conn, status, "text/html; charset=utf-8", doc.encode("utf-8"), extra)

    def _join_page(self, conn, error="", name="", status=200):
        err = f'<p class="err">{html.escape(error)}</p>' if error else ""
        body = f"""<h1>CodeGate</h1><p class="sub">Join a room with the PIN you were given.</p>
<form method="post" action="{PREFIX}join">
<label>Your name</label><input name="name" value="{html.escape(name)}" autocomplete="off" autocapitalize="none" spellcheck="false" required>
<label>Room PIN</label><input name="pin" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="ABCD-2345">
<label>Resume code <span class="dim">(only if you've joined before)</span></label>
<input name="resume" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="XXXX-XXXX-XXXX">
<button class="full" type="submit">Join</button>{err}</form>
<p class="foot">Certificate warning, or previews not loading? Trust this server's certificate once on this device: <a href="http://{html.escape(self.lan_ip())}:8900/code">how</a>.</p>"""
        return self._page(conn, status, "CodeGate", body)

    def _home_page(self, conn, member, notice=""):
        name = html.escape(member["name"])
        starters = self.spaces.starters()
        label = "desktop" if member["kind"] == "desktop" else "workspace"
        rows = ""
        for s in starters:
            slug = html.escape(s["slug"])
            rows += f"""<div class="row"><div>{html.escape(s['title'])}<div class="dim">{slug}</div></div><div class="acts">
<a class="btn" href="{PREFIX}open?starter={slug}">Open</a>
<a class="btn ghost" href="{PREFIX}download?starter={slug}">Download</a>
<form method="post" action="{PREFIX}reset" onsubmit="return confirm('Reset {slug} to its original files? Your changes to it are lost.')">
<input type="hidden" name="starter" value="{slug}"><button class="ghost" type="submit">Reset</button></form></div></div>"""
        if not rows:
            rows = '<p class="dim">Nothing has been set up for this room yet.</p>'
        note = f'<p class="ok">{html.escape(notice)}</p>' if notice else ""
        body = f"""<h1>Hi, {name}</h1><p class="sub">Your own private {label}. Changes here stay in your copy.</p>{note}
<div class="acts" style="justify-content:flex-start"><a class="btn" href="{PREFIX}open">Open my {label}</a>
<a class="btn ghost" href="{PREFIX}download">Download everything</a></div>
<h2>Starter files</h2>{rows}
<form method="post" action="{PREFIX}logout" style="margin-top:18px"><button class="ghost" type="submit">Sign out</button></form>"""
        return self._page(conn, 200, "CodeGate", body)

    # ------------------------------------------------------------ endpoints

    def _same_origin(self, headers):
        origin = headers.get("origin")
        return origin is None or origin == f"https://{headers.get('host', '')}"

    def _read_form(self, conn, headers, rest):
        length = int(headers.get("content-length", "0") or 0)
        if length > 8192:
            raise ValueError("too large")
        body = rest
        while len(body) < length:
            chunk = conn.recv(length - len(body))
            if not chunk:
                break
            body += chunk
        return {k: v[0] for k, v in urllib.parse.parse_qs(body.decode("utf-8", "replace")).items()}

    def _internal(self, conn, method, parts, headers, rest, ip, token, member):
        action = parts.path[len(PREFIX):]
        query = {k: v[0] for k, v in urllib.parse.parse_qs(parts.query).items()}

        if action == "join":
            if method == "GET":
                return self._join_page(conn)
            if method != "POST" or not self._same_origin(headers):
                return self._reply(conn, 403, "text/plain", b"")
            form = self._read_form(conn, headers, rest)
            try:
                sid, code = self.spaces.join(form.get("name"), form.get("pin"), form.get("resume"), ip)
            except SpacesError as e:
                time.sleep(0.5)
                return self._join_page(conn, str(e), form.get("name", ""), 401)
            tok = secrets.token_urlsafe(32)
            with self.lock:
                self.sessions[tok] = (sid, time.time())
            cookie = f"{COOKIE}={tok}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={SESSION_LIFETIME}"
            if code:
                body = f"""<h1>You're in</h1><p class="sub">Save this resume code. It's the only way to get this same
workspace back from another browser or device. It won't be shown again.</p>
<div class="code">{html.escape(code)}</div>
<a class="btn full" href="{PREFIX}home">Continue</a>"""
                return self._page(conn, 200, "CodeGate", body, {"Set-Cookie": cookie})
            return self._reply(conn, 303, "text/plain", b"", {"Location": PREFIX + "home", "Set-Cookie": cookie})

        if not member:
            return self._reply(conn, 303, "text/plain", b"", {"Location": PREFIX + "join"})

        if action == "home":
            return self._home_page(conn, member, query.get("notice", ""))

        if action == "logout" and method == "POST" and self._same_origin(headers):
            with self.lock:
                self.sessions.pop(token, None)
            return self._reply(conn, 303, "text/plain", b"", {
                "Location": PREFIX + "join", "Set-Cookie": f"{COOKIE}=; Path=/; Secure; HttpOnly; Max-Age=0"})

        if action == "open":
            slug = query.get("starter")
            try:
                self.spaces.ensure_running(member["id"], slug)
            except SpacesError as e:
                return self._page(conn, 503, "CodeGate",
                                  f'<h1>Not ready yet</h1><p class="sub">{html.escape(str(e))}</p>'
                                  f'<a class="btn" href="{html.escape(parts.path)}?{html.escape(parts.query)}">Try again</a> '
                                  f'<a class="btn ghost" href="{PREFIX}home">Back</a>')
            if member["kind"] == "desktop":
                dest = "/vnc.html?autoconnect=true&resize=remote&reconnect=true"
            else:
                folder = f"/home/{member['name']}/work" + (f"/{slug}" if slug else "")
                dest = "/?folder=" + urllib.parse.quote(folder)
            return self._reply(conn, 303, "text/plain", b"", {"Location": dest})

        if action == "download":
            return self._download(conn, member, query.get("starter"))

        if action == "reset" and method == "POST" and self._same_origin(headers):
            form = self._read_form(conn, headers, rest)
            try:
                self.spaces.reset_starter(member["id"], form.get("starter", ""))
            except SpacesError as e:
                return self._page(conn, 503, "CodeGate", f'<h1>Couldn\'t reset</h1><p class="sub">{html.escape(str(e))}</p>'
                                                         f'<a class="btn" href="{PREFIX}home">Back</a>')
            return self._reply(conn, 303, "text/plain", b"", {
                "Location": PREFIX + "home?notice=" + urllib.parse.quote(f"{form.get('starter')} was reset.")})

        return self._reply(conn, 404, "text/plain", b"Not found")

    def _download(self, conn, member, slug):
        try:
            chunks = self.spaces.zip_stream(member["id"], slug)
            first = next(chunks, b"")
        except SpacesError as e:
            return self._page(conn, 503, "CodeGate", f'<h1>Couldn\'t download</h1><p class="sub">{html.escape(str(e))}</p>'
                                                     f'<a class="btn" href="{PREFIX}home">Back</a>')
        if not first:
            return self._page(conn, 404, "CodeGate", '<h1>Nothing to download yet</h1><p class="sub">Open your '
                              f'workspace once first.</p><a class="btn" href="{PREFIX}home">Back</a>')
        fname = f"{member['name']}-{slug or 'all'}.zip"
        conn.sendall((
            "HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\n"
            f'Content-Disposition: attachment; filename="{fname}"\r\n'
            "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n").encode())
        conn.sendall(first)
        for chunk in chunks:
            conn.sendall(chunk)
        self.log(f"{member['name']} downloaded {slug or 'everything'}")
