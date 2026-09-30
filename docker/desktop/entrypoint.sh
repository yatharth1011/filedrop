#!/bin/bash
# Env: CG_USER (unix user to create), CG_UID, CG_FOLDER (folder Files opens on).
set -e
: "${CG_USER:?}" "${CG_UID:=1000}" "${CG_FOLDER:=/home/$CG_USER/work}"
case "$CG_USER" in *[!a-z0-9_-]*|"") echo "bad user" >&2; exit 64;; esac

HOME_DIR="/home/$CG_USER"
mkdir -p "$HOME_DIR"
# Ubuntu 24.04 ships a default 'ubuntu' user on uid 1000.
userdel -r ubuntu 2>/dev/null || true
id "$CG_USER" >/dev/null 2>&1 || useradd -M -d "$HOME_DIR" -s /bin/bash -u "$CG_UID" "$CG_USER"
mkdir -p "$CG_FOLDER"
chown "$CG_UID:$CG_UID" "$HOME_DIR" "$CG_FOLDER"

PROMPT='\[\e[1;32m\]\u@codegate\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '
grep -q CODEGATE_PS1 "$HOME_DIR/.bashrc" 2>/dev/null || cat >> "$HOME_DIR/.bashrc" <<RC
# CODEGATE_PS1
PS1='$PROMPT'
RC
chown "$CG_UID:$CG_UID" "$HOME_DIR/.bashrc"

cd "$HOME_DIR"
exec setpriv --reuid="$CG_UID" --regid="$CG_UID" --init-groups \
  --inh-caps=-all --bounding-set=-all --no-new-privs \
  env HOME="$HOME_DIR" USER="$CG_USER" LOGNAME="$CG_USER" SHELL=/bin/bash CG_FOLDER="$CG_FOLDER" \
      XDG_RUNTIME_DIR="/tmp/runtime-$CG_USER" \
  /opt/codegate/xstartup.sh
