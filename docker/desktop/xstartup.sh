#!/bin/bash
# Runs as the member: virtual display + XFCE + the noVNC web server on 6080.
mkdir -p "$XDG_RUNTIME_DIR" && chmod 700 "$XDG_RUNTIME_DIR"
mkdir -p "$HOME/.vnc"

# The X server listens on localhost only and the container publishes just 6080;
# CodeGate's gate is the only way in, so VNC itself needs no password.
Xtigervnc :1 -geometry 1600x900 -depth 24 -localhost yes -SecurityTypes None -AlwaysShared \
  -rfbport 5901 >"$HOME/.vnc/xserver.log" 2>&1 &
for i in $(seq 1 50); do [ -e /tmp/.X11-unix/X1 ] && break; sleep 0.2; done
export DISPLAY=:1

( dbus-launch --exit-with-session startxfce4 >"$HOME/.vnc/xfce.log" 2>&1 & )
# Open the file manager on their work folder once the desktop is up.
( sleep 6; thunar "$CG_FOLDER" >/dev/null 2>&1 & ) &

exec websockify --web /usr/share/novnc 6080 localhost:5901
