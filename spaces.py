"""CodeGate spaces: per-member Docker workspaces.

The owner opens a "room" (VS Code, or a full Ubuntu desktop) from Dromac and
gets a PIN for it. A member joins with a name and that PIN and gets their own
container with their own persistent volume, pre-seeded with the starter
files as hosted. Nothing a member does touches anyone else's files or the
Mac: containers run as an unprivileged user with no capabilities, hard
CPU/memory/process/disk limits, no access to the Mac's files (the VM has no
mounts) and a firewall that blocks the Mac, the LAN and other members.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

NETWORK = "cg-members"
SUBNET = "172.29.77.0/24"
PRIVATE_RANGES = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # the Mac, the campus LAN, the VM's own bridges
    "169.254.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "224.0.0.0/4",
]
NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{2,23}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
PIN_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I
RESERVED = {
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news", "uucp", "proxy",
    "www-data", "backup", "list", "irc", "gnats", "nobody", "coder", "admin", "owner", "node",
    "ubuntu", "user", "member", "test", "guest", "systemd", "messagebus", "sshd", "codegate",
}
PIN_LIFETIME = 12 * 3600
IDLE_STOP = 30 * 60
MAX_TEMPLATE_BYTES = 100 * 1024 * 1024
MAX_TEMPLATE_FILES = 5000

KINDS = {
    "code": {
        "label": "VS Code", "image": "codegate-workspace:1", "port": 8080,
        "cpus": "1", "memory": "1g", "pids": "256", "shm": "128m",
    },
    "desktop": {
        "label": "Ubuntu desktop", "image": "codegate-desktop:1", "port": 6080,
        "cpus": "2", "memory": "2g", "pids": "512", "shm": "512m",
    },
}


class SpacesError(Exception):
    """A problem worth showing to the user as-is."""


def _docker_bin():
    for c in (shutil.which("docker"), "/opt/homebrew/bin/docker", "/usr/local/bin/docker"):
        if c and os.access(c, os.X_OK):
            return c
    return None


def _colima_bin():
    for c in (shutil.which("colima"), "/opt/homebrew/bin/colima", "/usr/local/bin/colima"):
        if c and os.access(c, os.X_OK):
            return c
    return None


class Spaces:
    def __init__(self, base_dir, log):
        self.base = Path(base_dir)
        self.dir = self.base / "spaces"
        self.dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.dir, 0o700)
        (self.dir / "starters").mkdir(mode=0o700, exist_ok=True)
        self.state_path = self.dir / "state.json"
        self.log = log
        self.lock = threading.RLock()
        self.fails = {}            # ip -> [timestamps]
        self.joins = []            # timestamps of recent new-member creations
        self.activity = {}         # sid -> (open_connections, last_activity)
        self.ports = {}            # sid -> host port of its running container
        self.starting = set()
        self.building = set()
        self.runtime_starting = False
        self.on_idle = None        # called when no room is open and no workspace is running
        self.state = self._load()
        self.docker = _docker_bin()
        threading.Thread(target=self._watchdog, daemon=True).start()

    # ---------------------------------------------------------------- state

    def _load(self):
        state = {"rooms": {}, "members": {}, "starters": {}, "settings": {"internet": True}}
        try:
            state.update(json.loads(self.state_path.read_text()))
        except Exception:
            pass
        for kind in KINDS:
            state["rooms"].setdefault(kind, {"open": False, "pin": None, "pin_expires": 0, "max_running": 4 if kind == "code" else 2})
        return state

    def _save(self):
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=1))
        os.chmod(tmp, 0o600)
        tmp.replace(self.state_path)

    # --------------------------------------------------------------- docker

    def _run(self, *args, timeout=60, check=True, input_=None):
        if not self.docker:
            raise SpacesError("Docker isn't installed (brew install colima docker).")
        try:
            r = subprocess.run([self.docker, *args], capture_output=True, timeout=timeout, input=input_)
        except subprocess.TimeoutExpired:
            raise SpacesError("Docker took too long to respond.")
        if check and r.returncode != 0:
            raise SpacesError(r.stderr.decode("utf-8", "replace").strip()[-300:] or "docker failed")
        return r

    def runtime_up(self):
        if not self.docker:
            return False
        try:
            return subprocess.run([self.docker, "info"], capture_output=True, timeout=8).returncode == 0
        except Exception:
            return False

    def start_runtime(self):
        """Boots the Colima VM (30-60 s) in the background."""
        colima = _colima_bin()
        if not colima:
            raise SpacesError("Colima isn't installed (brew install colima docker).")
        with self.lock:
            if self.runtime_starting:
                return
            self.runtime_starting = True

        def go():
            try:
                subprocess.run([colima, "start"], capture_output=True, timeout=300)
            finally:
                self.runtime_starting = False
        threading.Thread(target=go, daemon=True).start()

    def build_image(self, kind):
        """Builds a room type's image (minutes the first time) in the background."""
        self._check_kind(kind)
        ctx = self.base / "docker" / kind
        if not ctx.is_dir():
            raise SpacesError(f"No build files for the {KINDS[kind]['label']} image.")
        if not self.runtime_up():
            raise SpacesError("Start the container runtime first.")
        with self.lock:
            if kind in self.building:
                return
            self.building.add(kind)

        def go():
            try:
                r = subprocess.run([self.docker, "build", "-t", KINDS[kind]["image"], str(ctx)],
                                   capture_output=True, timeout=3600)
                self.log(f"image {kind} build " + ("done" if r.returncode == 0 else "FAILED: " + r.stderr.decode()[-200:]))
            finally:
                with self.lock:
                    self.building.discard(kind)
        threading.Thread(target=go, daemon=True).start()

    def image_ready(self, kind):
        return self._run("image", "inspect", KINDS[kind]["image"], check=False).returncode == 0

    def _vm(self, script):
        colima = _colima_bin()
        return subprocess.run([colima, "ssh", "--", "sudo", "sh", "-c", script], capture_output=True, timeout=30)

    def apply_firewall(self):
        """Member containers can reach the internet (if allowed) but not the
        Mac, the campus LAN, the VM, or each other. Idempotent; re-applied
        whenever a container is started because a VM reboot drops the rules."""
        internet = bool(self.state["settings"].get("internet", True))
        rules = [
            "iptables -N CODEGATE 2>/dev/null || true",
            "iptables -F CODEGATE",
            "iptables -A CODEGATE -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
        ]
        rules += [f"iptables -A CODEGATE -d {r} -j DROP" for r in PRIVATE_RANGES]
        rules.append("iptables -A CODEGATE -j " + ("RETURN" if internet else "DROP"))
        rules.append(f"iptables -C DOCKER-USER -s {SUBNET} -j CODEGATE 2>/dev/null || iptables -I DOCKER-USER 1 -s {SUBNET} -j CODEGATE")
        r = self._vm(" && ".join(rules))
        if r.returncode != 0:
            raise SpacesError("Couldn't set up the member firewall: " + r.stderr.decode()[-200:])

    def _ensure_network(self):
        if self._run("network", "inspect", NETWORK, check=False).returncode != 0:
            self._run("network", "create", "--driver", "bridge", "--subnet", SUBNET,
                      "-o", "com.docker.network.bridge.enable_icc=false", NETWORK)

    # ------------------------------------------------------------- members

    @staticmethod
    def _sid(kind, name):
        return f"{kind}:{name}"

    @staticmethod
    def _hash(secret, salt):
        return hashlib.sha256((salt + secret).encode()).hexdigest()

    def _throttled(self, ip):
        now = time.time()
        self.fails[ip] = [t for t in self.fails.get(ip, []) if now - t < 300]
        return len(self.fails[ip]) >= 5

    def _fail(self, ip):
        self.fails.setdefault(ip, []).append(time.time())

    def open_room(self, kind):
        self._check_kind(kind)
        with self.lock:
            room = self.state["rooms"][kind]
            room.update(open=True, pin="".join(secrets.choice(PIN_ALPHABET) for _ in range(8)),
                        pin_expires=time.time() + PIN_LIFETIME)
            self._save()
        self.log(f"room {kind} opened")
        return self.status()

    def close_room(self, kind):
        self._check_kind(kind)
        with self.lock:
            self.state["rooms"][kind].update(open=False, pin=None, pin_expires=0)
            self._save()
        self.log(f"room {kind} closed to new joins")
        return self.status()

    def _pin_ok(self, pin):
        """Which open room (if any) this PIN belongs to."""
        pin = (pin or "").strip().upper().replace("-", "").replace(" ", "")
        now = time.time()
        match = None
        for kind, room in self.state["rooms"].items():
            ok = bool(room["open"] and room["pin"] and room["pin_expires"] > now
                      and hmac.compare_digest(room["pin"], pin))
            if ok:
                match = kind
        return match

    def join(self, name, pin, resume, ip):
        """Returns (member_id, new_resume_code_or_None). Raises SpacesError."""
        name = (name or "").strip().lower()
        if not NAME_RE.match(name) or name in RESERVED:
            raise SpacesError("Pick a name of 3-24 letters, digits, - or _, starting with a letter.")
        with self.lock:
            if self._throttled(ip):
                raise SpacesError("Too many wrong attempts from your device. Wait a few minutes.")
            resume = (resume or "").strip().upper().replace(" ", "").replace("-", "")
            # Returning member: the resume code is the only thing that gets an existing name back.
            existing = [s for s in self.state["members"].values() if s["name"] == name]
            if existing:
                if not resume:
                    self._fail(ip)
                    raise SpacesError("That name is taken. If it's yours, enter your resume code too.")
                for s in existing:
                    if not s.get("disabled") and hmac.compare_digest(self._hash(resume, s["salt"]), s["resume_hash"]):
                        s["last_seen"], s["ip"] = time.time(), ip
                        self._save()
                        return s["id"], None
                self._fail(ip)
                raise SpacesError("Wrong resume code for that name.")
            kind = self._pin_ok(pin)
            if kind is None:
                self._fail(ip)
                raise SpacesError("That PIN isn't right, or the room isn't open.")
            now = time.time()
            self.joins = [t for t in self.joins if now - t < 3600]
            if len(self.joins) >= 60:
                raise SpacesError("Too many people joined in the last hour. Ask the owner.")
            self.joins.append(now)
            code = "-".join("".join(secrets.choice(PIN_ALPHABET) for _ in range(4)) for _ in range(3))
            salt = secrets.token_hex(8)
            sid = self._sid(kind, name)
            self.state["members"][sid] = {
                "id": sid, "kind": kind, "name": name, "salt": salt,
                "resume_hash": self._hash(code.replace("-", ""), salt),
                "created": now, "last_seen": now, "ip": ip, "quota_mb": 2048, "seeded": [], "disabled": False,
            }
            self._save()
        self.log(f"{name} joined {kind}", ip)
        return sid, code

    def member(self, sid):
        with self.lock:
            s = self.state["members"].get(sid)
            return dict(s) if s and not s.get("disabled") else None

    # ---------------------------------------------------------- starters

    def add_starter(self, slug, title, folder):
        slug = (slug or "").strip().lower()
        if not SLUG_RE.match(slug):
            raise SpacesError("Starter id: letters, digits, - or _ (max 40).")
        src = Path(os.path.realpath(os.path.expanduser(folder or "")))
        if not src.is_dir():
            raise SpacesError("That folder doesn't exist.")
        dest = self.dir / "starters" / slug
        tmp = self.dir / "starters" / f".{slug}.tmp"
        shutil.rmtree(tmp, ignore_errors=True)
        total = count = 0
        tmp.mkdir(mode=0o700)
        for root, dirs, files in os.walk(src, followlinks=False):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules", ".venv") and not os.path.islink(os.path.join(root, d))]
            rel = Path(root).relative_to(src)
            (tmp / rel).mkdir(parents=True, exist_ok=True)
            for f in files:
                p = Path(root) / f
                if p.is_symlink() or not p.is_file():
                    continue  # never follow links out of the folder the owner picked
                total += p.stat().st_size
                count += 1
                if total > MAX_TEMPLATE_BYTES or count > MAX_TEMPLATE_FILES:
                    shutil.rmtree(tmp, ignore_errors=True)
                    raise SpacesError("That folder is too big for an starter (100 MB / 5000 files max).")
                shutil.copy2(p, tmp / rel / f)
        shutil.rmtree(dest, ignore_errors=True)
        tmp.replace(dest)
        with self.lock:
            self.state["starters"][slug] = {"title": (title or slug).strip()[:80], "created": time.time(), "files": count}
            self._save()
        self.log(f"starter {slug} added ({count} files)")
        return self.status()

    def delete_starter(self, slug):
        with self.lock:
            self.state["starters"].pop(slug, None)
            self._save()
        shutil.rmtree(self.dir / "starters" / slug, ignore_errors=True)
        return self.status()

    # ----------------------------------------------------------- containers

    def _cname(self, s):
        return f"cg-{s['kind']}-{s['name']}"

    def _vname(self, s):
        return f"cg-vol-{s['kind']}-{s['name']}"

    def running_count(self, kind):
        r = self._run("ps", "--filter", "label=codegate=1", "--filter", f"label=codegate.kind={kind}", "--format", "{{.Names}}", check=False)
        return len([x for x in r.stdout.decode().split() if x])

    def ensure_running(self, sid, starter=None):
        """Starts the member's container if needed, seeds starters, returns the host port."""
        s = self.member(sid)
        if not s:
            raise SpacesError("Unknown member.")
        kind = KINDS[s["kind"]]
        if starter and (not SLUG_RE.match(starter) or starter not in self.state["starters"]):
            raise SpacesError("Unknown starter.")
        with self.lock:
            if sid in self.starting:
                raise SpacesError("Your workspace is starting... try again in a few seconds.")
            self.starting.add(sid)
        try:
            if not self.runtime_up():
                self.start_runtime()
                raise SpacesError("The server is starting up (about a minute). Try again shortly.")
            if not self.image_ready(s["kind"]):
                raise SpacesError(f"The {kind['label']} image isn't built yet.")
            cname = self._cname(s)
            state = self._run("inspect", "-f", "{{.State.Running}}", cname, check=False)
            if state.stdout.decode().strip() != "true":
                if self.running_count(s["kind"]) >= self.state["rooms"][s["kind"]]["max_running"]:
                    raise SpacesError("This room is full right now. Try again in a minute.")
                self._ensure_network()
                self.apply_firewall()
                self._run("rm", "-f", cname, check=False)
                self._run(*self._run_args(s, starter), timeout=120)
            port = self._wait_port(cname, kind["port"])
            self._seed(s, cname)
            with self.lock:
                self.ports[sid] = port
                self.activity.setdefault(sid, (0, time.time()))
            return port
        finally:
            with self.lock:
                self.starting.discard(sid)

    def _run_args(self, s, starter):
        kind = KINDS[s["kind"]]
        name = s["name"]
        folder = f"/home/{name}/work" + (f"/{starter}" if starter else "")
        return [
            "run", "-d", "--name", self._cname(s), "--hostname", "codegate",
            "--init",  # PID 1 that reaps finished children; otherwise zombies fill the process quota
            "--workdir", "/",  # the image's default (the removed coder user's home) no longer exists
            "--network", NETWORK,
            "--cpus", kind["cpus"], "--memory", kind["memory"], "--memory-swap", kind["memory"],
            "--pids-limit", kind["pids"], "--shm-size", kind["shm"],
            "--ulimit", "nofile=4096:4096", "--ulimit", "core=0",
            "--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID",
            "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
            "--cap-add", "SETPCAP",  # only so the entrypoint can drop every capability before member code runs
            "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,size=256m",
            "-v", f"{self._vname(s)}:/home/{name}",
            "-p", f"127.0.0.1::{kind['port']}",
            "-e", f"CG_USER={name}", "-e", "CG_UID=1000", "-e", f"CG_FOLDER={folder}",
            "--label", "codegate=1", "--label", f"codegate.kind={s['kind']}", "--label", f"codegate.member={s['id']}",
            "--restart", "no", kind["image"],
        ]

    def _wait_port(self, cname, container_port):
        deadline = time.time() + 45
        while time.time() < deadline:
            alive = self._run("inspect", "-f", "{{.State.Running}}", cname, check=False).stdout.decode().strip()
            if alive != "true":
                tail = self._run("logs", "--tail", "3", cname, check=False)
                msg = (tail.stdout + tail.stderr).decode("utf-8", "replace").strip()[-200:]
                self._run("rm", "-f", cname, check=False)
                raise SpacesError("Your workspace stopped while starting: " + (msg or "no output"))
            r = self._run("port", cname, f"{container_port}/tcp", check=False)
            out = r.stdout.decode().strip().splitlines()
            if out:
                port = int(out[0].rsplit(":", 1)[1])
                try:
                    # The published port accepts connections before the app inside
                    # is ready, so insist on a real HTTP answer.
                    with socket.create_connection(("127.0.0.1", port), timeout=2) as c:
                        c.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                        if c.recv(16).startswith(b"HTTP/"):
                            return port
                except OSError:
                    pass
            time.sleep(0.5)
        raise SpacesError("Your workspace didn't start in time. Try again.")

    def _seed(self, s, cname):
        """Copies each starter the member hasn't received yet into their workspace."""
        for slug in list(self.state["starters"]):
            if slug in s["seeded"]:
                continue
            self._copy_template(s, cname, slug)
            with self.lock:
                self.state["members"][s["id"]]["seeded"].append(slug)
                self._save()

    def _copy_template(self, s, cname, slug):
        name = s["name"]
        src = self.dir / "starters" / slug
        if not src.is_dir():
            return
        dest = f"/home/{name}/work/{slug}"
        self._run("exec", "-u", "0", cname, "mkdir", "-p", dest)
        self._run("cp", f"{src}/.", f"{cname}:{dest}", timeout=120)
        self._run("exec", "-u", "0", cname, "chown", "-R", "1000:1000", dest)

    def reset_starter(self, sid, slug):
        s = self.member(sid)
        if not s or slug not in self.state["starters"]:
            raise SpacesError("Unknown starter.")
        self.ensure_running(sid)
        cname = self._cname(s)
        self._run("exec", "-u", "0", cname, "rm", "-rf", f"/home/{s['name']}/work/{slug}")
        self._copy_template(s, cname, slug)
        self.log(f"{s['name']} reset {slug}")

    def zip_stream(self, sid, slug=None):
        """Yields a zip of the member's workspace (or one starter), read from
        their volume without needing their container to be running."""
        s = self.member(sid)
        if not s:
            raise SpacesError("Unknown member.")
        if slug and not SLUG_RE.match(slug):
            raise SpacesError("Bad starter.")
        sub = f"/w/work/{slug}" if slug else "/w"
        excludes = ["-x", "*/node_modules/*", "*/.cache/*", "*/.local/share/code-server/*", "*/__pycache__/*"]
        cmd = [self.docker, "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--read-only",
               "-v", f"{self._vname(s)}:/w:ro", "--entrypoint", "sh", KINDS[s["kind"]]["image"],
               "-c", f"cd '{sub}' && zip -qr - . " + " ".join(f"'{e}'" for e in excludes)]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            while True:
                chunk = proc.stdout.read(65536)
                if not chunk:
                    break
                yield chunk
        finally:
            proc.kill()
            proc.wait()

    def starters(self):
        with self.lock:
            return [{"slug": k, "title": v.get("title", k)} for k, v in self.state["starters"].items()]

    def export_member(self, sid, slug, dest_dir):
        """Saves a member's workspace (or one starter) as a zip on this Mac."""
        m = self.member(sid)
        if not m:
            raise SpacesError("Unknown member.")
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        out = dest / f"{m['name']}-{slug or 'all'}.zip"
        size = 0
        with open(out, "wb") as f:
            for chunk in self.zip_stream(sid, slug):
                f.write(chunk)
                size += len(chunk)
        if not size:
            out.unlink(missing_ok=True)
            raise SpacesError(f"{m['name']} has nothing to export yet.")
        return str(out)

    # ----------------------------------------------------------- lifecycle

    def touch(self, sid, delta):
        """The gate reports proxied connections opening (+1) and closing (-1)."""
        with self.lock:
            n, _ = self.activity.get(sid, (0, time.time()))
            self.activity[sid] = (max(0, n + delta), time.time())

    def upstream_port(self, sid):
        with self.lock:
            return self.ports.get(sid)

    def stop_member(self, sid, reason="stopped"):
        s = self.state["members"].get(sid)
        if not s:
            return
        self._run("rm", "-f", self._cname(s), check=False, timeout=30)
        with self.lock:
            self.ports.pop(sid, None)
            self.activity.pop(sid, None)
        self.log(f"{s['name']} {reason}")

    def stop_all(self, reason="stopped"):
        if not self.docker:
            return
        r = self._run("ps", "-aq", "--filter", "label=codegate=1", check=False)
        ids = r.stdout.decode().split()
        if ids:
            self._run("rm", "-f", *ids, check=False, timeout=60)
        with self.lock:
            self.ports.clear()
            self.activity.clear()
        self.log(f"all workspaces {reason}")

    def remove_member(self, sid):
        s = self.state["members"].get(sid)
        if not s:
            return self.status()
        self.stop_member(sid, "removed")
        self._run("volume", "rm", "-f", self._vname(s), check=False)
        with self.lock:
            self.state["members"].pop(sid, None)
            self._save()
        return self.status()

    def set_internet(self, on):
        with self.lock:
            self.state["settings"]["internet"] = bool(on)
            self._save()
        if self.runtime_up():
            self.apply_firewall()
        return self.status()

    def set_limit(self, kind, n):
        self._check_kind(kind)
        with self.lock:
            self.state["rooms"][kind]["max_running"] = max(1, min(int(n), 30))
            self._save()
        return self.status()

    def _watchdog(self):
        while True:
            time.sleep(60)
            try:
                self._sweep()
            except Exception as e:
                self.log(f"watchdog error: {e}")

    def _sweep(self):
        if not self.runtime_up():
            return
        now = time.time()
        for sid, (conns, last) in list(self.activity.items()):
            if conns == 0 and now - last > IDLE_STOP:
                self.stop_member(sid, "stopped (idle)")
        self._enforce_quota()
        if self.on_idle and not self.ports and not self.starting and not any(
                r["open"] and r["pin_expires"] > now for r in self.state["rooms"].values()):
            self.on_idle()

    def _enforce_quota(self):
        for sid in list(self.ports):
            s = self.state["members"].get(sid)
            if not s:
                continue
            r = self._run("exec", "-u", "0", self._cname(s), "du", "-sk", f"/home/{s['name']}", check=False, timeout=30)
            try:
                used_mb = int(r.stdout.split()[0]) // 1024
            except (ValueError, IndexError):
                continue
            if used_mb > s["quota_mb"]:
                self.stop_member(sid, f"stopped: over its {s['quota_mb']} MB disk quota ({used_mb} MB used)")

    # --------------------------------------------------------------- status

    def any_room_open(self):
        now = time.time()
        with self.lock:
            return any(r["open"] and r["pin_expires"] > now for r in self.state["rooms"].values())

    def _check_kind(self, kind):
        if kind not in KINDS:
            raise SpacesError("Unknown room type.")

    def status(self):
        now = time.time()
        with self.lock:
            rooms = {}
            for kind, room in self.state["rooms"].items():
                live = bool(room["open"] and room["pin_expires"] > now)
                rooms[kind] = {
                    "label": KINDS[kind]["label"], "open": live, "pin": room["pin"] if live else None,
                    "pinExpires": room["pin_expires"] if live else 0, "maxRunning": room["max_running"],
                    "members": sum(1 for s in self.state["members"].values() if s["kind"] == kind),
                }
            members = [{
                "id": s["id"], "name": s["name"], "kind": s["kind"], "ip": s.get("ip"),
                "lastSeen": s.get("last_seen"), "running": s["id"] in self.ports,
                "quotaMb": s["quota_mb"],
            } for s in self.state["members"].values()]
            starters = [{"slug": k, **v} for k, v in self.state["starters"].items()]
        up = self.runtime_up()
        return {
            "building": sorted(self.building),
            "runtime": {"installed": bool(self.docker and _colima_bin()), "up": up, "starting": self.runtime_starting},
            "images": {k: (self.image_ready(k) if up else None) for k in KINDS},
            "internet": bool(self.state["settings"].get("internet", True)),
            "rooms": rooms, "members": sorted(members, key=lambda x: x["name"]), "starters": starters,
        }
