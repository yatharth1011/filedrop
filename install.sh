#!/bin/bash
# Installs FileDrop into ~/Library/Application Support/FileDrop -- the
# location Dromac's dashboard looks for it in. Safe to re-run to update:
# your password, uploaded files and their metadata live in that same
# folder and are left untouched.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
dest="$HOME/Library/Application Support/FileDrop"

mkdir -p "$dest"
cp "$here/server.py" "$here/codegate.py" "$here/spaces.py" "$dest/"
rsync -a --delete "$here/static/" "$dest/static/"
rsync -a --delete "$here/docker/" "$dest/docker/"

# CodeGate runs each member in a Docker container. That's optional; if Docker
# and Colima aren't installed, FileDrop works as before without it.
if ! command -v docker >/dev/null 2>&1 || ! command -v colima >/dev/null 2>&1; then
  echo "Optional: for CodeGate rooms, run:  brew install colima docker"
fi

# A running server keeps serving the old code until restarted.
if pids="$(lsof -tiTCP:8900 -sTCP:LISTEN 2>/dev/null)" && [ -n "$pids" ]; then
  kill $pids
  echo "Stopped the running FileDrop server; start it again to use the new version."
fi

echo "Installed to $dest"
echo "Start it with:  python3 \"$dest/server.py\"   (or the start button in Dromac)"
