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
- **CodeGate, VS Code in the browser** (optional): a full VS Code window (editor,
  terminal, Python, Jupyter) on a folder you pick, unlocked with Touch ID on
  the Mac (or the Mac's password). See [CodeGate](#codegate) below.
- Plain Python 3 standard library: no dependencies (VS Code needs
  `code-server`).

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

CodeGate (`/code`) gives you a full VS Code window in the browser (via
[code-server](https://github.com/coder/code-server)), opened on a folder of
your choice: editor, integrated terminal, Python and Jupyter notebooks on the
Mac's own Python.

```bash
brew install code-server   # Touch ID also needs a Swift compiler (Xcode Command Line Tools)
code-server --extensions-dir "$HOME/Library/Application Support/FileDrop/code/extensions" \
  --install-extension ms-python.python --install-extension ms-toolsai.jupyter
```

**It gives a terminal on the Mac, so it's locked down hard:**

- **Off by default. Only the Mac itself can start it**, via
  [Dromac](https://github.com/yatharth1011/dromac)'s FileDrop card, which
  warns you first. The start/stop API only answers loopback requests with a
  loopback `Host` and a custom header, so web pages can't trigger it.
- **Unlocked with Touch ID on the Mac itself.** Pressing "Unlock with Touch
  ID" raises the system Touch ID prompt on the Mac, naming the requesting
  device's IP, and a finger on the Mac's sensor lets that device in. Only one
  prompt can be pending at a time, with a 10 s cooldown after a decline, so
  nobody can flood you with prompts.
- **Falls back to the Mac account password** when Touch ID isn't available
  (no sensor, lid closed) or is declined or times out, e.g. when you're away
  from the Mac. The password is checked through macOS PAM (`checkpw`)
  in-process and never stored. After 5 failed unlocks of either kind
  (counted across all devices), it locks for 5 minutes.
- **You get a macOS notification on every unlock and lockout**, and
  everything is logged to `code/access.log` with the device's IP.
- **HTTPS only** (TLS 1.2+) on port 8901, using a certificate from a local CA
  generated on first use. That CA's name constraints only allow private and
  loopback addresses, so even a stolen CA key can't impersonate real websites
  on devices that trust it.
- **code-server has no network port at all.** It listens on an owner-only
  Unix socket in a private temp directory, reachable only through the gate.
- **Sessions** are random `Secure`/`HttpOnly` cookies bound to the device's
  IP. The gate rejects unexpected `Host` headers (DNS rebinding) and the
  login page can't be framed.
- **It stops by itself** 30 minutes after the last VS Code tab closes, after 8
  hours regardless, and whenever FileDrop exits.

**Node, Express and other dev servers** work as usual in the terminal (it's
your normal login shell). To view one running on, say, `localhost:3000` from
the other device, open `https://<mac-ip>:8901/proxy/3000/`. VS Code also
offers this when it detects the port. That goes through the same password and
HTTPS gate, so there's no need to bind your app to `0.0.0.0` and expose it to
the whole network. (For apps that need to be served from `/`, use
`/absproxy/3000/`.)

The folder limit applies to the editor only. **The terminal, Python and
Jupyter run as your Mac user and can reach everything your account can.**
Only unlock it on devices you trust.

**Trusting the certificate:** open `/code` on each device you'll use and
follow the steps to download and trust CodeGate's certificate once. Without
that, the browser warns every time, and notebooks and previews won't load
(VS Code's webviews need a trusted HTTPS origin).

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
