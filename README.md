# FileDrop

A tiny password-protected file drop for your local network. Run it on your
Mac, open its URL from any other computer on the same network, and drag,
pick or paste (⌘V) a file of any size, or share a snippet of text. You get
back a link anyone on the network can open.

- **Any size, any type.** Uploads stream straight to disk in 1 MB chunks,
  so the only limit is free disk space. There's a live progress bar.
- **Shareable links.** Each upload gets an unguessable link
  (`/d/<token>/<filename>`) that works without logging in, so you can
  hand it to someone. PDFs, images, audio, video and plain text open in the
  browser; everything else downloads.
- **Text, too.** Type or paste text into the box and hit ⌘↵ to share it
  the same way. Its link opens as readable text (UTF-8, so any language
  works), and the list shows a preview with a one-click copy button.
  Pasting text on the page fills the box rather than sending it straight
  away, so clipboard contents never get shared by accident.
- **Auto-expiry.** Files delete themselves 7 days after upload.
- **"Get URL" button.** Shows the Mac's current LAN address, detected live
  since DHCP can change it.
- **Password only settable from the Mac itself.** "Change password" only
  appears, and only works, for requests coming from the machine FileDrop
  runs on, and it needs the current password too.
- **CodeGate** (optional): PIN-protected rooms where people get their own
  private VS Code or Ubuntu desktop in the browser, in isolated containers.
  See [CodeGate](#codegate) below.
- Plain Python 3 standard library: no dependencies (CodeGate needs
  Colima + Docker).

## Run it

```bash
python3 server.py
```

It listens on port 8900 on all interfaces, so open
`http://<your-mac's-LAN-IP>:8900` from another machine (the page's
**Get URL** button shows the exact address). On first run it generates a
random password and writes it to `PASSWORD.txt` next to `server.py`
(readable only by your user). Log in with that, then change it from the
Mac if you like.

Everything it stores lives next to `server.py`: `config.json` (salted
password hash), `meta.json` (upload index), `files/` (uploads and text drops) and
`PASSWORD.txt`. None of these are committed.

### With Dromac

[Dromac](https://github.com/yatharth1011/dromac)'s dashboard has a FileDrop
card with start, copy-URL and open-as-window buttons. It expects FileDrop
in `~/Library/Application Support/FileDrop`, which is what this installs:

```bash
./install.sh
```

Re-run it to update. Your password and uploads are left alone.

## CodeGate

CodeGate lets people on your network get their **own private workspace** on
your Mac, either **VS Code in the browser** (editor, terminal, Python,
Jupyter, Node) or a **full Ubuntu desktop**, with nothing to install on their
side. Each person gets their own container, their own copy of the files you
prepared, and their own login name in the terminal. Their changes stay in
their copy, and they can download all of it as a zip.

You run it from [Dromac](https://github.com/yatharth1011/dromac)'s FileDrop
card ("manage" under `$ codegate`); there is deliberately no way to start it
from a web page or from another machine.

```bash
brew install colima docker     # the container runtime
./install.sh                   # installs FileDrop + the image build files
```

Then, in Dromac: **manage → build image** (once per room type; the first build
downloads a few GB), **+ add from folder…** to add starter files, and
**open room** to get a PIN.

### How people use it

1. You open a room and share its PIN. Each room type (VS Code, Ubuntu desktop)
   has its own PIN.
2. They go to `https://<your-mac-ip>:8901/`, enter a name and the PIN, and are
   shown a **resume code**, the only way to get the same workspace back from
   another browser or device.
3. They open their workspace (or a specific starter), edit and run things, and
   press **Download** for a zip of their work. **Reset** restores a starter's
   original files.
4. You can see who's active, stop or remove anyone, and save any member's (or
   everyone's) work as zips into `~/Documents/CodeGate Collected`.

### What it protects

Running other people's code on your Mac is the risky part, so it's built to
contain them:

- **Off by default and owner-only.** Rooms are opened only from your Mac
  (loopback client and Host, plus a custom header web pages can't send). Dromac
  warns you before opening one.
- **Joining needs a PIN** (8 characters, expires after 12 hours, one per room
  type) and a name; returning members need their resume code. Wrong attempts
  are throttled per device, and there's a cap on new joins per hour.
- **One container per member**, running as an unprivileged user with **no
  Linux capabilities and `no-new-privileges`**, hard **CPU, memory,
  process and disk limits** (1 CPU / 1 GB / 256 processes / 2 GB for VS Code,
  more for the desktop), an init process so runaway processes can't wedge it,
  and no Docker socket. Idle workspaces are removed after 30 minutes; their
  files persist.
- **They can't reach your Mac.** The container VM has no access to your files
  (Colima's default home-folder mount is removed), and a firewall in the VM
  drops all traffic from member containers to private and local networks: your
  Mac and its services, your LAN, the VM itself, and other members. They can
  still reach the internet (you can switch that off), because installing
  packages needs it.
- **HTTPS only** (TLS 1.2+) with a certificate from a local CA whose name
  constraints only allow private addresses. Sessions are random `Secure` /
  `HttpOnly` cookies; each session is routed only to its own member's container.
  Gate pages refuse framing and check `Host` and `Origin`.

**Trust the certificate once per device:** open `http://<your-mac-ip>:8900/code`
and follow the steps. Without it the browser warns every time, and VS Code's
notebooks and previews won't load (they need a trusted HTTPS origin).

### Limits to know about

- Members can use your internet connection. Turn internet off in
  Dromac's manager if that's a problem, or only open rooms for people you know.
- The container VM is capped at 4 CPUs / 8 GB by default (`colima start --cpu
  --memory` to change); the per-room "at once" limit keeps you inside it.
- Isolation is container-grade, not a hardware boundary. A kernel-level
  container escape would land in the small Linux VM, not on macOS, but treat
  rooms as "people I'd let use a shared lab machine".

## Security

This is a convenience tool for a network you trust, not a hardened file
server. (CodeGate has its own, much stricter model; see above.)

- **No HTTPS.** Your password, session cookie and files travel unencrypted
  over the local network, so anyone who can sniff that network can see
  them.
- **Download links aren't password-protected**, by design, so they can be
  shared. They're random and unguessable, but anyone who has a link can
  use it until the file expires or you delete it.
- Uploaded HTML/SVG is always served as a download, never rendered, so
  an uploaded page can't run script as your logged-in session.
- Passwords are stored as a salted SHA-256 hash, and wrong guesses are
  slowed by a one-second delay. Sessions live in memory and end when the
  server restarts.

## License

MIT. See [LICENSE](LICENSE).
