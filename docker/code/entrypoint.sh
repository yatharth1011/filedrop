#!/bin/bash
# Env: CG_USER (unix user to create), CG_UID, CG_FOLDER (folder VS Code opens).
set -e
: "${CG_USER:?}" "${CG_UID:=1000}" "${CG_FOLDER:=/home/$CG_USER/work}"
case "$CG_USER" in *[!a-z0-9_-]*|"") echo "bad user" >&2; exit 64;; esac

HOME_DIR="/home/$CG_USER"
mkdir -p "$HOME_DIR"
# The coder user baked into the base image would collide on uid 1000.
userdel -r coder 2>/dev/null || true
id "$CG_USER" >/dev/null 2>&1 || useradd -M -d "$HOME_DIR" -s /bin/bash -u "$CG_UID" "$CG_USER"
mkdir -p "$CG_FOLDER"
chown "$CG_UID:$CG_UID" "$HOME_DIR" "$CG_FOLDER"

# Terminal identity: their own user name in the prompt.
PROMPT='\[\e[1;32m\]\u@codegate\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
grep -q CODEGATE_PS1 "$HOME_DIR/.bashrc" 2>/dev/null || cat >> "$HOME_DIR/.bashrc" <<RC
# CODEGATE_PS1
PS1='$PROMPT'
cd "$CG_FOLDER" 2>/dev/null
RC
chown "$CG_UID:$CG_UID" "$HOME_DIR/.bashrc"

# The base image's working directory was the removed coder user's home.
cd "$HOME_DIR"
exec setpriv --reuid="$CG_UID" --regid="$CG_UID" --init-groups \
  --inh-caps=-all --bounding-set=-all --no-new-privs \
  env HOME="$HOME_DIR" USER="$CG_USER" LOGNAME="$CG_USER" SHELL=/bin/bash \
      XDG_DATA_HOME="$HOME_DIR/.local/share" XDG_CONFIG_HOME="$HOME_DIR/.config" \
  code-server --bind-addr 0.0.0.0:8080 --auth none \
    --disable-telemetry --disable-update-check --disable-getting-started-override \
    --extensions-dir /opt/codegate/extensions \
    --user-data-dir "$HOME_DIR/.local/share/code-server" \
    "$CG_FOLDER"
