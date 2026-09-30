#!/bin/bash
# Installs FileDrop into ~/Library/Application Support/FileDrop -- the
# location Dromac's dashboard looks for it in. Safe to re-run to update:
# your password, uploaded files and their metadata live in that same
# folder and are left untouched.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
dest="$HOME/Library/Application Support/FileDrop"

mkdir -p "$dest"
cp "$here/server.py" "$here/codegate.py" "$here/macauth.py" "$dest/"
rsync -a --delete "$here/static/" "$dest/static/"

# CodeGate's Touch ID prompt. Without a Swift compiler (Xcode Command Line
# Tools), CodeGate just falls back to the Mac password.
if command -v swiftc >/dev/null 2>&1; then
  swiftc -O "$here/touchid.swift" -o "$dest/touchid"
else
  rm -f "$dest/touchid"
  echo "swiftc not found: CodeGate will use the Mac password instead of Touch ID."
fi

# A running server keeps serving the old code until restarted.
if pids="$(lsof -tiTCP:8900 -sTCP:LISTEN 2>/dev/null)" && [ -n "$pids" ]; then
  kill $pids
  echo "Stopped the running FileDrop server; start it again to use the new version."
fi

echo "Installed to $dest"
echo "Start it with:  python3 \"$dest/server.py\"   (or the start button in Dromac)"
