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

# CodeGate, the VS Code gate (codegate.py); created in main() so importing this module has no side effects.
CODE = None


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

    def _code_admin_ok(self):
        # Starting a terminal-granting server: only from this Mac (loopback
        # Host too, which blocks DNS rebinding), and only with a custom header
        # a cross-site web page can't send without a CORS preflight.
        host = (self.headers.get("Host") or "").lower()
        return (CODE is not None
                and self.client_address[0] in ("127.0.0.1", "::1")
                and host in (f"127.0.0.1:{PORT}", f"localhost:{PORT}")
                and self.headers.get("X-FileDrop-Local") == "1")

    def _send_code_page(self):
        st = CODE.status() if CODE else {"running": False, "installed": False}
        esc = lambda v: (str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))
        if st["running"]:
            state = (f'<p>CodeGate is running on <b>{esc(os.path.basename(st["folder"]))}</b>.</p>'
                     f'<a class="btn" href="{esc(st["url"])}">Open CodeGate</a>'
                     f'<p class="dim">You\'ll be asked for the Mac\'s account password.</p>')
        else:
            state = ("<p>CodeGate isn't running. For safety it can only be started on the Mac itself, "
                     "from Dromac's FileDrop card.</p>")
        body = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>CodeGate</title>
<link rel="stylesheet" href="/styles.css"></head><body>
<header class="topbar"><div class="brand"><a href="/" style="color:inherit;text-decoration:none">FileDrop</a></div></header>
<main class="view"><div class="panel code-page">
<h2 class="section-title">CodeGate · VS Code in the browser</h2>{state}
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
            if CODE is None:
                return self.send_error(404)
            data = CODE.ca_pem()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Disposition", 'attachment; filename="CodeGate-CA.pem"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if path == "/api/code/status":
            if not self._code_admin_ok():
                return self._send_json({"error": "only available on this Mac"}, 403)
            return self._send_json(CODE.status())

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

        if parsed.path in ("/api/code/start", "/api/code/stop"):
            if not self._code_admin_ok():
                return self._send_json({"error": "only available on this Mac"}, 403)
            length = int(self.headers.get("Content-Length", 0) or 0)
            try:
                data = json.loads(self.rfile.read(length) or b"{}") if length else {}
            except Exception:
                data = {}
            if parsed.path == "/api/code/stop":
                CODE.stop("stopped from Dromac")
                return self._send_json(CODE.status())
            try:
                return self._send_json(CODE.start(data.get("folder", "")))
            except (ValueError, RuntimeError, OSError) as e:
                return self._send_json({"error": str(e)}, 400)

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
    global CODE
    import codegate
    CODE = codegate.CodeGate(BASE_DIR, _detect_lan_ip)

    def shutdown(*_):
        # Never leave a code-server running with nothing gating it.
        CODE.stop("stopped: FileDrop exiting")
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
