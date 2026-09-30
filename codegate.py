"""CodeGate: VS Code in the browser (code-server), opened on one folder, behind an HTTPS
gate that requires this Mac's account password.

Security model -- this hands out a terminal, so every layer matters:
  - code-server and everything it starts (terminals, kernels, Node...) run
    inside a macOS sandbox (sandbox.py) confined to the chosen folder, with
    the usual ways of escaping via other processes blocked.
  - code-server listens ONLY on a Unix socket (mode 600, in a 700 dir): no
    TCP port at all, so nothing -- not even another local user -- can reach
    it without going through the gate.
  - The gate is HTTPS only (TLS 1.2+), with a leaf certificate issued by a
    local CA whose name constraints only allow private/loopback IPs, so even
    a stolen CA key can't impersonate real websites on devices that trust it.
  - Unlocking needs Touch ID on the Mac itself (the prompt names the
    requesting device's IP; one prompt at a time) or, if Touch ID isn't
    available or is declined, the Mac account password, checked through PAM
    and never stored. Wrong passwords are slowed down, and 5 failures lock everyone
    out for 5 minutes (a global counter, so spreading guesses across
    devices doesn't help). Every unlock, failure and lockout is logged and
    raises a macOS notification.
  - Sessions are random, HttpOnly + Secure cookies, bound to the device's IP,
    and all die when the gate stops.
  - Only a request from this Mac (via FileDrop's loopback-only API, which
    Dromac calls) can start it. It stops 30 minutes after the last browser
    tab disconnects, after 8 hours regardless, and when FileDrop exits.
  - The gate rejects unexpected Host headers (DNS rebinding). code-server's
    port proxy (/proxy/<port>/) is left on, since it's only reachable
    through the gate and grants nothing a terminal doesn't.
"""
import html
import http.client
import ipaddress
import os
import secrets
import select
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

import macauth
import sandbox

GATE_PORT = 8901
IDLE_AFTER_LAST_TAB = 30 * 60
MAX_LIFETIME = 8 * 3600
MAX_FAILS = 5
LOCKOUT_SECONDS = 5 * 60
COOKIE = "codegate_session"
LOGIN_PATH = "/__codegate/login"
CA_NAME_CONSTRAINTS = (
    "critical,"
    "permitted;IP:10.0.0.0/255.0.0.0,permitted;IP:172.16.0.0/255.240.0.0,"
    "permitted;IP:192.168.0.0/255.255.0.0,permitted;IP:127.0.0.0/255.0.0.0,"
    "permitted;IP:169.254.0.0/255.255.0.0,permitted;DNS:localhost"
)


def _code_server_bin():
    for candidate in ("/opt/homebrew/bin/code-server", "/usr/local/bin/code-server"):
        if os.access(candidate, os.X_OK):
            return candidate
    return None


def _notify(title, message):
    # osascript string literals: escape backslashes and quotes.
    esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
    try:
        subprocess.Popen(
            ["osascript", "-e", f'display notification "{esc(message)}" with title "{esc(title)}" sound name "Funk"'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


class CodeGate:
    def __init__(self, base_dir, lan_ip):
        self.dir = Path(base_dir) / "code"
        self.dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.dir, 0o700)
        self.lan_ip = lan_ip  # callable -> current LAN IP
        self.user = os.environ.get("USER") or os.getlogin()
        self.lock = threading.RLock()
        self.proc = None
        self.folder = None
        self.started_at = 0.0
        self.listener = None
        self.sessions = {}  # token -> client ip
        self.connections = set()
        self.idle_since = None
        self.fail_times = []
        self.locked_until = 0.0
        self.touchid_bin = Path(base_dir) / "touchid"  # compiled by install.sh
        self.touchid_busy = threading.Lock()
        self.touchid_next_allowed = 0.0
        # The socket lives in a fresh private temp dir rather than next to
        # FileDrop: macOS caps Unix socket paths at 104 bytes, which a clone
        # at a long path would exceed. mkdtemp makes it owner-only (700).
        self.socket_path = None
        self.pid_file = self.dir / "code-server.pid"
        self.sockdir_file = self.dir / "code-server.sockdir"
        self._kill_stale()
        threading.Thread(target=self._watchdog, daemon=True).start()

    # ------------------------------------------------------------ logging

    def _log(self, event, ip=""):
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {ip or '-':15}  {event}\n"
        with open(self.dir / "access.log", "a") as f:
            f.write(line)
        print(f"[code] {event} {ip}", file=sys.stderr)

    # ------------------------------------------------------------- status

    def status(self):
        with self.lock:
            running = self.proc is not None and self.proc.poll() is None
            ip = self.lan_ip()
            out = {
                "installed": _code_server_bin() is not None,
                "running": running,
                "folder": self.folder if running else None,
                "url": f"https://{ip}:{GATE_PORT}/" if running else None,
                "caUrl": "/code/ca.pem",
            }
            if running:
                out["stopsAt"] = self.started_at + MAX_LIFETIME
                if not self.connections and self.idle_since:
                    out["idleStopsAt"] = self.idle_since + IDLE_AFTER_LAST_TAB
            return out

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

    def start(self, folder):
        folder = os.path.realpath(os.path.expanduser(folder or ""))
        if not os.path.isdir(folder):
            raise ValueError("That folder doesn't exist.")
        binary = _code_server_bin()
        if not binary:
            raise ValueError("code-server isn't installed (brew install code-server).")
        with self.lock:
            if self.proc is not None and self.proc.poll() is None:
                if self.folder == folder:
                    return self.status()
                self.stop("restarted on another folder")
            ip = self.lan_ip()
            cert, key = self._ensure_leaf(ip)

            sock_dir = tempfile.mkdtemp(prefix="filedrop-code-")
            self.sockdir_file.write_text(sock_dir)
            self.socket_path = Path(sock_dir) / "cs.sock"
            data = self.dir / "user-data"
            data.mkdir(mode=0o700, exist_ok=True)
            extensions = self.dir / "extensions"
            extensions.mkdir(mode=0o700, exist_ok=True)
            # code-server's default config (~/.config/code-server) is outside
            # the sandbox; give it its own, empty one.
            config = data / "config.yaml"
            if not config.exists() or config.read_text().strip().startswith("#"):
                # Must be a YAML mapping (a comment-only file parses as null and
                # code-server refuses it); the real settings are passed as flags.
                config.write_text("disable-telemetry: true\n")
            profile = self.dir / "sandbox.sb"
            profile.write_text(sandbox.build_profile(
                folder, str(Path.home()), tempfile.gettempdir(), [str(data), str(extensions), sock_dir]))
            os.chmod(profile, 0o600)
            env = {k: v for k, v in os.environ.items() if k not in ("PASSWORD", "HASHED_PASSWORD")}
            env["HISTFILE"] = str(data / "zsh_history")  # ~/.zsh_history is outside the sandbox
            self.proc = subprocess.Popen(
                ["/usr/bin/sandbox-exec", "-f", str(profile),
                 binary, "--config", str(config),
                 "--socket", str(self.socket_path), "--socket-mode", "600",
                 "--auth", "none",  # the gate does auth; the socket itself is owner-only
                 # Port proxy stays ON: /proxy/<port>/ lets you view a dev server
                 # (e.g. Express on localhost:3000) from the other device through
                 # this gate, instead of binding it to 0.0.0.0 unauthenticated.
                 # It grants nothing new -- anyone past the gate has a terminal.
                 "--disable-telemetry", "--disable-update-check",
                 "--disable-getting-started-override",
                 "--user-data-dir", str(data),
                 "--extensions-dir", str(extensions),
                 "--ignore-last-opened",
                 folder],
                stdout=open(self.dir / "code-server.log", "ab"), stderr=subprocess.STDOUT,
                # Must start *inside* the sandbox's allowed area: FileDrop's own
                # folder (the inherited cwd) is off-limits, and Node dies if it
                # can't read its working directory.
                cwd=folder, env=env, start_new_session=True,
            )
            self.pid_file.write_text(str(self.proc.pid))
            for _ in range(150):
                if self.socket_path.exists() or self.proc.poll() is not None:
                    break
                time.sleep(0.1)
            if not self.socket_path.exists():
                self._kill_proc()
                raise RuntimeError("code-server didn't start -- see code/code-server.log.")

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(str(cert), str(key))
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", GATE_PORT))
            listener.listen(64)
            self.listener = listener
            self.folder = folder
            self.started_at = time.time()
            self.idle_since = time.time()
            self.sessions.clear()
            threading.Thread(target=self._accept_loop, args=(listener, ctx), daemon=True).start()
            self._log(f"started on {folder}")
            return self.status()

    def stop(self, reason="stopped"):
        with self.lock:
            was_running = self.proc is not None
            if self.listener:
                try:
                    self.listener.close()
                except OSError:
                    pass
                self.listener = None
            for pair in list(self.connections):
                for s in pair:
                    try:
                        s.close()
                    except OSError:
                        pass
            self.connections.clear()
            self.sessions.clear()
            self._kill_proc()
            self.folder = None
            if was_running:
                self._log(reason)

    def _kill_proc(self):
        if self.proc is not None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except Exception:
                    pass
            self.proc = None
        self.pid_file.unlink(missing_ok=True)
        self._remove_socket_dir()

    def _remove_socket_dir(self):
        try:
            sock_dir = Path(self.sockdir_file.read_text())
            if sock_dir.name.startswith("filedrop-code-"):
                (sock_dir / "cs.sock").unlink(missing_ok=True)
                sock_dir.rmdir()
        except Exception:
            pass
        self.sockdir_file.unlink(missing_ok=True)
        self.socket_path = None

    def _kill_stale(self):
        """A code-server left over from a FileDrop that died without cleaning up."""
        try:
            pid = int(self.pid_file.read_text())
            cmd = subprocess.run(["ps", "-o", "command=", "-p", str(pid)], capture_output=True, text=True).stdout
            if "code-server" in cmd:
                os.killpg(pid, signal.SIGTERM)
        except Exception:
            pass
        self.pid_file.unlink(missing_ok=True)
        self._remove_socket_dir()

    def _watchdog(self):
        while True:
            time.sleep(20)
            with self.lock:
                if self.proc is None:
                    continue
                now = time.time()
                if self.proc.poll() is not None:
                    self.stop("code-server exited")
                elif now - self.started_at > MAX_LIFETIME:
                    self.stop("stopped: 8-hour limit")
                elif not self.connections and self.idle_since and now - self.idle_since > IDLE_AFTER_LAST_TAB:
                    self.stop("stopped: 30 min with no open tabs")

    # --------------------------------------------------------------- gate

    def _accept_loop(self, listener, ctx):
        while True:
            try:
                raw, addr = listener.accept()
            except OSError:
                return  # listener closed by stop()
            threading.Thread(target=self._handle, args=(raw, addr[0], ctx), daemon=True).start()

    def _inside(self, path):
        root = self.folder or ""
        real = os.path.realpath(path)
        return bool(root) and (real == root or real.startswith(root + os.sep))

    def _allowed_host(self, host):
        return host in (f"{self.lan_ip()}:{GATE_PORT}", f"127.0.0.1:{GATE_PORT}", f"localhost:{GATE_PORT}")

    def _handle(self, raw, ip, ctx):
        raw.settimeout(15)
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            raw.close()
            return
        upstream = None
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

            path = urllib.parse.urlsplit(target).path
            if path == LOGIN_PATH:
                return self._login(conn, method, target, headers, rest, ip)

            token = self._cookie(headers.get("cookie", ""))
            with self.lock:
                authed = token is not None and self.sessions.get(token) == ip
            if not authed:
                if method == "GET" and "upgrade" not in headers:
                    nxt = urllib.parse.quote(target if target.startswith("/") and not target.startswith("//") else "/")
                    return self._reply(conn, 303, "text/plain", b"", {"Location": f"{LOGIN_PATH}?next={nxt}"})
                return self._reply(conn, 401, "text/plain", b"Unlock CodeGate first.")

            # Keep the window on the chosen folder: "Open Folder..." reloads
            # with ?folder=/?workspace=, so bounce anything outside it back.
            # (The sandbox is what actually enforces this; this just gives a
            # clean result instead of permission errors.)
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(target).query)
            wanted = (query.get("folder") or [None])[0]
            if method == "GET" and ("workspace" in query or (wanted is not None and not self._inside(wanted))):
                return self._reply(conn, 303, "text/plain", b"", {
                    "Location": "/?folder=" + urllib.parse.quote(self.folder or "/")})

            upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            upstream.connect(str(self.socket_path))
            upstream.sendall(head + rest)
            conn.settimeout(None)
            upstream.settimeout(None)
            with self.lock:
                self.connections.add((conn, upstream))
                self.idle_since = None
            self._pipe(conn, upstream)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            with self.lock:
                self.connections.discard((conn, upstream))
                if not self.connections:
                    self.idle_since = time.time()
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

    # -------------------------------------------------------------- login

    def _touchid_available(self):
        if not os.access(self.touchid_bin, os.X_OK):
            return False
        try:
            return subprocess.run([str(self.touchid_bin), "check"], timeout=5).returncode == 0
        except Exception:
            return False

    def _locked_out(self):
        with self.lock:
            left = self.locked_until - time.time()
        return int(left) + 1 if left > 0 else 0

    def _record_failure(self, ip, what):
        now = time.time()
        with self.lock:
            self.fail_times = [t for t in self.fail_times if now - t < LOCKOUT_SECONDS] + [now]
            locked = len(self.fail_times) >= MAX_FAILS
            if locked:
                self.locked_until = now + LOCKOUT_SECONDS
                self.fail_times = []
        self._log(f"unlock FAILED ({what})", ip)
        if locked:
            self._log("LOCKED OUT for 5 min", ip)
            _notify("CodeGate", f"Locked out after {MAX_FAILS} failed unlocks (last from {ip}).")

    def _grant(self, conn, nxt, ip, how):
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions[token] = ip
            self.fail_times = []
        self._log(f"unlocked ({how})", ip)
        _notify("CodeGate", f"Unlocked from {ip} ({how}).")
        return self._reply(conn, 303, "text/plain", b"", {
            "Location": nxt,
            "Set-Cookie": f"{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Lax",
        })

    def _login(self, conn, method, target, headers, rest, ip):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(target).query)
        nxt = (query.get("next") or ["/"])[0]
        if not nxt.startswith("/") or nxt.startswith("//"):
            nxt = "/"
        page = lambda status, msg="", show_password=False: self._reply(
            conn, status, "text/html; charset=utf-8", self._login_page(nxt, msg, show_password))

        if method == "GET":
            wants_password = (query.get("pw") or [""])[0] == "1"
            return page(200, show_password=wants_password or not self._touchid_available())
        if method != "POST":
            return self._reply(conn, 405, "text/plain", b"")

        length = int(headers.get("content-length", "0") or 0)
        if length > 4096:
            return self._reply(conn, 413, "text/plain", b"")
        body = rest
        while len(body) < length:
            chunk = conn.recv(length - len(body))
            if not chunk:
                break
            body += chunk
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))

        wait = self._locked_out()
        if wait:
            return page(429, f"Too many failed unlocks. Try again in {wait}s.", show_password=True)

        if (form.get("mode") or [""])[0] == "touchid":
            return self._login_touchid(page, conn, nxt, ip)

        password = (form.get("password") or [""])[0]
        if macauth.check_password(self.user, password):
            return self._grant(conn, nxt, ip, "password")
        time.sleep(1.5)
        self._record_failure(ip, "password")
        return page(401, "Wrong password.", show_password=True)

    def _login_touchid(self, page, conn, nxt, ip):
        now = time.time()
        with self.lock:
            cooling = self.touchid_next_allowed - now
        if cooling > 0:
            return page(429, f"Wait {int(cooling) + 1}s before asking again, or use the password.", show_password=True)
        # One prompt at a time: stops anyone on the network from stacking
        # prompts on the Mac hoping one gets tapped absent-mindedly.
        if not self.touchid_busy.acquire(blocking=False):
            return page(409, "A Touch ID request is already waiting on the Mac.", show_password=True)
        try:
            self._log("Touch ID requested", ip)
            try:
                rc = subprocess.run(
                    [str(self.touchid_bin), "prompt", f"allow {ip} to open VS Code (CodeGate)"],
                    timeout=60,
                ).returncode
            except subprocess.TimeoutExpired:
                rc = 3
        finally:
            self.touchid_busy.release()
        if rc == 0:
            return self._grant(conn, nxt, ip, "Touch ID")
        if rc == 2:
            return page(503, "Touch ID isn't available on the Mac right now -- use the password.", show_password=True)
        with self.lock:
            self.touchid_next_allowed = time.time() + 10
        self._record_failure(ip, "Touch ID declined" if rc == 1 else "Touch ID timed out")
        return page(401, "Touch ID was declined or timed out. Try again, or use the password.", show_password=True)

    def _login_page(self, nxt, error, show_password):
        folder = html.escape(os.path.basename(self.folder or "") or "?")
        err = f'<p class="err">{html.escape(error)}</p>' if error else ""
        ca_url = f"http://{html.escape(self.lan_ip())}:8900/code"
        action = f"{LOGIN_PATH}?next={urllib.parse.quote(nxt)}"
        touch = "" if show_password else f"""
<form method="post" action="{action}" onsubmit="this.querySelector('button').disabled=true;this.querySelector('button').textContent='Touch the sensor on the Mac…'">
<input type="hidden" name="mode" value="touchid">
<button type="submit">Unlock with Touch ID on the Mac</button>
</form>
<p class="alt"><a href="{action}&amp;pw=1" onclick="document.getElementById('pw').hidden=false;this.parentNode.hidden=true;return false;">Use the Mac password instead</a></p>"""
        pw_form = f"""
<form id="pw" method="post" action="{action}"{'' if show_password else ' hidden'}>
<input type="password" name="password" placeholder="Mac password" autocomplete="current-password" {'autofocus' if show_password else ''} required>
<button type="submit">Unlock with password</button>
</form>"""
        return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Unlock CodeGate</title>
<style>
body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0d10;color:#e8ecef;
font:14px/1.5 "JetBrains Mono",ui-monospace,Menlo,monospace}}
.box{{width:min(360px,90vw);background:#14171c;border:1px solid #24282f;border-radius:14px;padding:24px}}
h1{{font-size:16px;margin:0 0 4px}} .sub{{color:#9aa3ad;font-size:12px;margin:0 0 16px}}
.warn{{background:#2a1414;border:1px solid #5c2626;color:#ffb3b3;border-radius:10px;padding:10px 12px;font-size:12px;margin-bottom:16px}}
input{{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #24282f;background:#0d1013;color:#e8ecef;font:inherit}}
button{{width:100%;margin-top:12px;padding:10px;border:0;border-radius:8px;background:#e8ecef;color:#111;font:inherit;font-weight:700;cursor:pointer}}
button:disabled{{opacity:.6;cursor:wait}}
.err{{color:#ff5c5c;font-size:12px;margin:10px 0 0}} a{{color:#9aa3ad}} .alt{{font-size:12px;text-align:center;margin:12px 0 0}}
.foot{{font-size:11px;color:#5c646d;margin-top:14px}}
</style></head><body><div class="box">
<h1>Unlock CodeGate</h1><p class="sub">VS Code on: {folder}</p>
<div class="warn">This opens VS Code with a terminal that can run code and change anything in this folder (sandboxed to it). Only unlock it from a device you trust.</div>
{touch}{pw_form}{err}
<p class="foot">Seeing a certificate warning, or notebooks not loading? Trust CodeGate's certificate once on this device: <a href="{ca_url}">how</a>.</p>
</div></body></html>""".encode("utf-8")
