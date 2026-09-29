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
- Plain Python 3 standard library: no dependencies.

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

## Security

This is a convenience tool for a network you trust, not a hardened file
server.

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
