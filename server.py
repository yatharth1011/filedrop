#!/usr/bin/env python3
"""FileDrop -- a tiny LAN file-sharing server.

Upload any file (streamed straight to disk, no size cap beyond free disk
space) and get back a shareable download link that works from any PC on the
same network. Files auto-expire and get cleaned up in the background.
"""
import hashlib
import http.server
import json
import mimetypes
import os
import re
import secrets
import shutil
import socket
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
FILES_DIR = BASE_DIR / "files"
STATIC_DIR = BASE_DIR / "static"
META_PATH = BASE_DIR / "meta.json"
CONFIG_PATH = BASE_DIR / "config.json"
PASSWORD_TXT = BASE_DIR / "PASSWORD.txt"

PORT = 8900
EXPIRY_SECONDS = 7 * 24 * 3600
CHUNK = 1024 * 1024
MAX_TEXT_BYTES = 5 * 1024 * 1024  # text drops are read into memory, unlike streamed uploads
SESSION_COOKIE = "filedrop_session"
SESSION_MAX_AGE = 30 * 24 * 3600

FILES_DIR.mkdir(exist_ok=True)

_meta_lock = threading.Lock()
_sessions_lock = threading.Lock()
_sessions = set()


def _load_meta():
    if META_PATH.exists():
        try:
            return json.loads(META_PATH.read_text())
        except Exception:
            return {}
    return {}


def _save_meta(meta):
    META_PATH.write_text(json.dumps(meta))


def _ensure_config():
    if CONFIG_PATH.exists():
        return json.loads(CONFIG_PATH.read_text())
    password = secrets.token_urlsafe(9)
    salt = secrets.token_hex(16)
    pw_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    config = {"salt": salt, "password_hash": pw_hash}
    CONFIG_PATH.write_text(json.dumps(config))
    PASSWORD_TXT.write_text(password + "\n")
    os.chmod(PASSWORD_TXT, 0o600)
    print(f"[filedrop] generated a password, saved to {PASSWORD_TXT}", file=sys.stderr)
    return config


CONFIG = _ensure_config()

# CodeGate: per-member workspaces (spaces.py) behind an HTTPS gate (codegate.py);
# created in main() so importing this module has no side effects.
SPACES = None
GATE = None


def _check_password(password):
    pw_hash = hashlib.sha256((CONFIG["salt"] + (password or "")).encode()).hexdigest()
    return secrets.compare_digest(pw_hash, CONFIG["password_hash"])


def _set_password(new_password):
    salt = secrets.token_hex(16)
    pw_hash = hashlib.sha256((salt + new_password).encode()).hexdigest()
    CONFIG["salt"] = salt
    CONFIG["password_hash"] = pw_hash
    CONFIG_PATH.write_text(json.dumps(CONFIG))
    PASSWORD_TXT.write_text(new_password + "\n")
    os.chmod(PASSWORD_TXT, 0o600)
    # Changing the password invalidates every existing session (including
    # this browser's own) -- otherwise a session cookie handed out under the
    # old password would just keep working forever.
    with _sessions_lock:
        _sessions.clear()


# Anyone who already has the shared password can upload/download, but only
# the Mac this server actually runs on should be able to CHANGE that
# password -- otherwise anyone on the network with the current password
# could lock the owner out. "Local" here means the request's source address
# is either loopback or one of this machine's own network addresses (so it
# still counts as local even when reached via its own LAN IP rather than
# literally "localhost").
def _local_addresses():
    addrs = {"127.0.0.1", "::1"}
    try:
        addrs.add(socket.gethostbyname(socket.gethostname()))
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            addrs.add(info[4][0])
    except Exception:
        pass
    addrs.add(_detect_lan_ip())
    return addrs


# The Mac's LAN IP can change (DHCP re-lease, switching wifi/ethernet, moving
# between networks) so it's never hardcoded -- this asks the OS which local
# address would be used to route outbound traffic, which is always the
# current real LAN-facing IP. The UDP "connect" never actually sends a
# packet, it just resolves routing.
def _detect_lan_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def _cleanup_loop():
    while True:
        now = time.time()
        with _meta_lock:
            meta = _load_meta()
            changed = False
            for token in list(meta.keys()):
                entry = meta[token]
                if entry["expires_at"] < now:
                    path = FILES_DIR / f"{token}_{entry['name']}"
                    try:
                        path.unlink(missing_ok=True)
                    except Exception:
                        pass
                    del meta[token]
                    changed = True
            if changed:
                _save_meta(meta)
        time.sleep(60)


def _sanitize_name(name):
    name = os.path.basename(name or "upload.bin")
    name = re.sub(r"[\x00-\x1f]", "", name).strip()
    return name or "upload.bin"


def _human_size(n):
    size = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


# HTML and SVG are technically "viewable" too, but serving user-uploaded
# content of those types inline would let it run script on FileDrop's own
# origin (same origin as the logged-in session) -- a malicious upload opened
# by the owner could act on their behalf. Everything else a browser can only
# passively display (render, play, or show as text) is safe to open inline
# instead of forcing a download, matching how Chrome behaves for a normal
# link.
_INLINE_UNSAFE_TYPES = {"text/html", "application/xhtml+xml", "image/svg+xml"}


def _is_inline_safe(ctype):
    if not ctype or ctype in _INLINE_UNSAFE_TYPES:
        return False
    return ctype == "application/pdf" or ctype.startswith(("image/", "audio/", "video/", "text/"))


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "FileDrop/1.0"

    def log_message(self, fmt, *args):
        print("[filedrop] " + (fmt % args), file=sys.stderr)

    def _cookie_token(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith(SESSION_COOKIE + "="):
                return part[len(SESSION_COOKIE) + 1:]
        return None

    def _authed(self):
        token = self._cookie_token()
        if not token:
            return False
        with _sessions_lock:
            return token in _sessions

    def _is_local(self):
        return self.client_address[0] in _local_addresses()

    def _admin_ok(self):
        # Running other people's code on this Mac is owner-only: loopback
        # client and Host (blocks DNS rebinding), plus a custom header a
        # cross-site web page can't send without a CORS preflight.
        host = (self.headers.get("Host") or "").lower()
        return (SPACES is not None
                and self.client_address[0] in ("127.0.0.1", "::1")
                and host in (f"127.0.0.1:{PORT}", f"localhost:{PORT}")
                and self.headers.get("X-FileDrop-Local") == "1")

    def _spaces_status(self):
        return {"gate": {"running": GATE.running(), "url": GATE.url()}, **SPACES.status()}

    def _spaces_action(self, action, data):
        from spaces import SpacesError
        try:
            if action == "open":
                SPACES.open_room(data.get("kind"))
                GATE.start()
                if not SPACES.runtime_up():
                    SPACES.start_runtime()
            elif action == "close":
                SPACES.close_room(data.get("kind"))
            elif action == "stop_all":
                SPACES.stop_all("stopped from Dromac")
                for kind in list(SPACES.state["rooms"]):
                    SPACES.close_room(kind)
                GATE.stop()
            elif action == "add_starter":
                SPACES.add_starter(data.get("slug"), data.get("title"), data.get("folder"))
            elif action == "delete_starter":
                SPACES.delete_starter(data.get("slug"))
            elif action == "stop_member":
                SPACES.stop_member(data.get("id"))
                GATE.drop_member(data.get("id"))
            elif action == "remove_member":
                GATE.drop_member(data.get("id"))
                SPACES.remove_member(data.get("id"))
            elif action == "set_internet":
                SPACES.set_internet(bool(data.get("on")))
            elif action == "set_limit":
                SPACES.set_limit(data.get("kind"), data.get("n"))
            elif action == "start_runtime":
                SPACES.start_runtime()
            elif action == "build_image":
                SPACES.build_image(data.get("kind"))
            elif action == "export":
                # Saves zips of members' work into ~/Documents/CodeGate Collected on this Mac.
                dest = Path.home() / "Documents" / "CodeGate Collected"
                ids = ([m["id"] for m in SPACES.status()["members"]] if data.get("id") == "*" else [data.get("id")])
                saved = [SPACES.export_member(i, data.get("starter") or None, dest) for i in ids
                         if SPACES.member(i)]
                if not saved:
                    raise SpacesError("Nothing to export.")
                subprocess.Popen(["open", "-R", saved[0]])
                return {**self._spaces_status(), "exported": len(saved), "folder": str(dest)}
            else:
                return {"error": "unknown action"}
        except SpacesError as e:
            return {"error": str(e)}
        return self._spaces_status()

    def _send_code_page(self):
        esc = lambda v: (str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))
        if GATE is not None and GATE.running():
            state = (f'<p>A room is open.</p><a class="btn" href="{esc(GATE.url())}">Join a room</a>'
                     f'<p class="dim">You\'ll need the PIN you were given.</p>')
        else:
            state = "<p>No room is open right now.</p>"
        body = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>CodeGate</title>
<link rel="stylesheet" href="/styles.css"></head><body>
<header class="topbar"><div class="brand"><a href="/" style="color:inherit;text-decoration:none">FileDrop</a></div></header>
<main class="view"><div class="panel code-page">
<h2 class="section-title">CodeGate</h2>{state}
<h2 class="section-title">First time on this device?</h2>
<p>CodeGate runs over HTTPS with its own certificate. Trust it once per device, or the browser
warns every time and notebooks and previews won't load.</p>
<a class="btn btn-small" href="/code/ca.pem">Download certificate</a>
<ul class="dim">
<li><b>macOS:</b> open the file → Keychain Access adds it → double-click it → Trust → "Always Trust".</li>
<li><b>Windows:</b> rename to .crt, open it → Install Certificate → Current User →
"Trusted Root Certification Authorities".</li>
<li><b>Linux (Chrome):</b> Settings → Privacy and security → Security → Manage certificates →
Authorities → Import.</li>
</ul>
<p class="dim">It can only vouch for private network addresses (10.x, 172.16–31.x, 192.168.x, localhost),
so trusting it can't be used to impersonate real websites.</p>
</div></main></body></html>""".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, path, content_type):
        if not path.exists():
            return self.send_error(404)
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            return self._send_static(STATIC_DIR / "index.html", "text/html; charset=utf-8")
        if path == "/app.js":
            return self._send_static(STATIC_DIR / "app.js", "application/javascript; charset=utf-8")
        if path == "/styles.css":
            return self._send_static(STATIC_DIR / "styles.css", "text/css; charset=utf-8")

        if path == "/code":
            return self._send_code_page()

        if path == "/code/ca.pem":
            if GATE is None:
                return self.send_error(404)
            data = GATE.ca_pem()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Disposition", 'attachment; filename="CodeGate-CA.pem"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/spaces/status":
            if not self._admin_ok():
                return self._send_json({"error": "only available on this Mac"}, 403)
            return self._send_json(self._spaces_status())

        if path == "/api/whoami":
            return self._send_json({"authed": self._authed(), "local": self._is_local()})

        if path == "/api/server-info":
            ip = _detect_lan_ip()
            return self._send_json({"ip": ip, "port": PORT, "url": f"http://{ip}:{PORT}"})

        if path == "/api/files":
            if not self._authed():
                return self._send_json({"error": "unauthorized"}, 401)
            with _meta_lock:
                meta = _load_meta()
            now = time.time()
            items = [
                {
                    "token": token,
                    "name": entry["name"],
                    "size": entry["size"],
                    "size_human": _human_size(entry["size"]),
                    "uploaded_at": entry["uploaded_at"],
                    "expires_at": entry["expires_at"],
                    "seconds_left": max(0, entry["expires_at"] - now),
                    "url": f"/d/{token}/{urllib.parse.quote(entry['name'])}",
                    "inline": _is_inline_safe(mimetypes.guess_type(entry["name"])[0] or ""),
                    "kind": entry.get("kind", "file"),
                    "preview": entry.get("preview"),
                }
                for token, entry in meta.items()
                if entry["expires_at"] >= now
            ]
            items.sort(key=lambda x: -x["uploaded_at"])
            return self._send_json({"files": items})

        if path.startswith("/d/"):
            rest = path[len("/d/"):]
            token = rest.split("/", 1)[0]
            with _meta_lock:
                meta = _load_meta()
            entry = meta.get(token)
            if not entry or entry["expires_at"] < time.time():
                return self.send_error(404, "Not found or expired")
            file_path = FILES_DIR / f"{token}_{entry['name']}"
            if not file_path.exists():
                return self.send_error(404, "Not found")
            ctype, _ = mimetypes.guess_type(entry["name"])
            ctype = ctype or "application/octet-stream"
            self.send_response(200)
            # Declare UTF-8 on text, or browsers may guess a legacy encoding and
            # garble anything non-ASCII (e.g. Hindi) in a text drop.
            self.send_header("Content-Type", f"{ctype}; charset=utf-8" if ctype.startswith("text/") else ctype)
            self.send_header("X-Content-Type-Options", "nosniff")
            quoted = urllib.parse.quote(entry["name"])
            disposition = "inline" if _is_inline_safe(ctype) else "attachment"
            self.send_header("Content-Disposition", f"{disposition}; filename*=UTF-8''{quoted}")
            self.send_header("Content-Length", str(file_path.stat().st_size))
            self.end_headers()
            with open(file_path, "rb") as f:
                shutil.copyfileobj(f, self.wfile, length=CHUNK)
            return

        return self.send_error(404)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/api/login":
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b""
            try:
                data = json.loads(body or b"{}")
            except Exception:
                data = {}
            if _check_password(data.get("password", "")):
                token = secrets.token_urlsafe(24)
                with _sessions_lock:
                    _sessions.add(token)
                out = json.dumps({"ok": True}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header(
                    "Set-Cookie",
                    f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_MAX_AGE}",
                )
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)
            else:
                time.sleep(1)  # slow down password guessing
                self._send_json({"ok": False}, 401)
            return

        if parsed.path.startswith("/api/spaces/"):
            if not self._admin_ok():
                return self._send_json({"error": "only available on this Mac"}, 403)
            length = int(self.headers.get("Content-Length", 0) or 0)
            try:
                data = json.loads(self.rfile.read(length) or b"{}") if length else {}
            except Exception:
                data = {}
            result = self._spaces_action(parsed.path[len("/api/spaces/"):], data)
            return self._send_json(result, 400 if "error" in result else 200)

        if parsed.path == "/api/logout":
            token = self._cookie_token()
            if token:
                with _sessions_lock:
                    _sessions.discard(token)
            return self._send_json({"ok": True})

        if parsed.path == "/api/text":
            if not self._authed():
                return self._send_json({"error": "unauthorized"}, 401)
            try:
                length = int(self.headers.get("Content-Length", 0) or 0)
            except ValueError:
                length = 0
            if length > MAX_TEXT_BYTES * 2:  # JSON escaping can roughly double the size
                return self._send_json({"error": "text too large (max 5 MB) -- upload it as a file instead"}, 413)
            try:
                text = json.loads(self.rfile.read(length) or b"{}").get("text", "")
            except Exception:
                return self._send_json({"error": "bad request"}, 400)
            if not isinstance(text, str) or not text.strip():
                return self._send_json({"error": "empty text"}, 400)
            data = text.encode("utf-8")
            if len(data) > MAX_TEXT_BYTES:
                return self._send_json({"error": "text too large (max 5 MB) -- upload it as a file instead"}, 413)

            token = secrets.token_urlsafe(12)
            now = time.time()
            name = time.strftime("text-%Y-%m-%d-%H%M%S.txt", time.localtime(now))
            (FILES_DIR / f"{token}_{name}").write_bytes(data)
            with _meta_lock:
                meta = _load_meta()
                meta[token] = {
                    "name": name,
                    "size": len(data),
                    "uploaded_at": now,
                    "expires_at": now + EXPIRY_SECONDS,
                    "kind": "text",
                    "preview": " ".join(text.split())[:140],
                }
                _save_meta(meta)
            return self._send_json({"token": token, "url": f"/d/{token}/{urllib.parse.quote(name)}", "name": name})

        if parsed.path == "/api/set-password":
            if not self._is_local():
                return self._send_json({"error": "only the Mac running FileDrop can change its password"}, 403)
            if not self._authed():
                return self._send_json({"error": "unauthorized"}, 401)
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if length else b""
            try:
                data = json.loads(body or b"{}")
            except Exception:
                data = {}
            current = data.get("current_password", "")
            new = data.get("new_password", "")
            if not _check_password(current):
                time.sleep(1)
                return self._send_json({"error": "current password is wrong"}, 401)
            if not new or len(new) < 4:
                return self._send_json({"error": "new password must be at least 4 characters"}, 400)
            _set_password(new)
            return self._send_json({"ok": True})

        return self.send_error(404)

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/upload":
            return self.send_error(404)
        if not self._authed():
            return self._send_json({"error": "unauthorized"}, 401)

        qs = urllib.parse.parse_qs(parsed.query)
        name = _sanitize_name((qs.get("name") or ["upload.bin"])[0])

        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return self._send_json({"error": "missing Content-Length"}, 400)

        token = secrets.token_urlsafe(12)
        dest_path = FILES_DIR / f"{token}_{name}"

        written = 0
        try:
            with open(dest_path, "wb") as f:
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(CHUNK, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    written += len(chunk)
                    remaining -= len(chunk)
        except Exception as e:
            dest_path.unlink(missing_ok=True)
            return self._send_json({"error": str(e)}, 500)

        if written != length:
            dest_path.unlink(missing_ok=True)
            return self._send_json({"error": "incomplete upload"}, 400)

        now = time.time()
        with _meta_lock:
            meta = _load_meta()
            meta[token] = {
                "name": name,
                "size": written,
                "uploaded_at": now,
                "expires_at": now + EXPIRY_SECONDS,
            }
            _save_meta(meta)

        self._send_json({
            "token": token,
            "url": f"/d/{token}/{urllib.parse.quote(name)}",
            "name": name,
            "size": written,
        })

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        if not parsed.path.startswith("/api/files/"):
            return self.send_error(404)
        if not self._authed():
            return self._send_json({"error": "unauthorized"}, 401)
        token = parsed.path[len("/api/files/"):]
        with _meta_lock:
            meta = _load_meta()
            entry = meta.pop(token, None)
            if entry is not None:
                _save_meta(meta)
        if entry:
            (FILES_DIR / f"{token}_{entry['name']}").unlink(missing_ok=True)
            return self._send_json({"ok": True})
        return self._send_json({"error": "not found"}, 404)


def main():
    global SPACES, GATE
    import codegate
    import spaces

    def log(msg, ip=""):
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {ip or '-':15}  {msg}\n"
        (BASE_DIR / "code").mkdir(mode=0o700, exist_ok=True)
        with open(BASE_DIR / "code" / "access.log", "a") as f:
            f.write(line)
        print(f"[codegate] {msg} {ip}", file=sys.stderr)

    SPACES = spaces.Spaces(BASE_DIR, log)
    GATE = codegate.Gate(BASE_DIR, _detect_lan_ip, SPACES, log)
    SPACES.on_idle = GATE.stop
    if SPACES.runtime_up():
        SPACES.stop_all("cleared at startup")  # leftovers from a previous run; workspaces persist
    if SPACES.any_room_open():
        GATE.start()  # a room was open when FileDrop last stopped; its PIN is still valid

    def shutdown(*_):
        # Never leave workspaces running with nothing in front of them.
        GATE.stop()
        SPACES.stop_all("stopped: FileDrop exiting")
        os._exit(0)
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    threading.Thread(target=_cleanup_loop, daemon=True).start()
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    ip = _detect_lan_ip()
    print(f"FileDrop listening on http://{ip}:{PORT}  (and http://0.0.0.0:{PORT})", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
