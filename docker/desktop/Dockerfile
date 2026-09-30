# CodeGate desktop workspace: Ubuntu 24.04 + XFCE, served to the browser with
# noVNC. Like the VS Code image, the entrypoint runs as root only long enough
# to create the member's Unix user, then drops to that user with no
# capabilities and no-new-privileges.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8

RUN echo 'Acquire::Retries "8";' > /etc/apt/apt.conf.d/80-retries \
    && apt-get update && apt-get install -y --no-install-recommends \
      xfce4 xfce4-terminal thunar mousepad dbus-x11 x11-xserver-utils xdg-utils \
      tigervnc-standalone-server tigervnc-common novnc websockify \
      fonts-dejavu fonts-noto-core fonts-jetbrains-mono adwaita-icon-theme yaru-theme-icon yaru-theme-gtk \
      python3 python3-pip python3-venv python3-dev python3-numpy python3-pandas python3-matplotlib \
      python3-scipy python3-ipykernel python3-tk git curl wget unzip zip nano vim less procps \
      build-essential nodejs npm ca-certificates gnupg software-properties-common \
    && rm -rf /var/lib/apt/lists/* && ln -sf /usr/bin/python3 /usr/local/bin/python

# Firefox from Mozilla's PPA (Ubuntu's own package is a snap, which can't run in a container).
RUN add-apt-repository -y ppa:mozillateam/ppa \
    && printf 'Package: *\nPin: release o=LP-PPA-mozillateam\nPin-Priority: 1001\n' > /etc/apt/preferences.d/mozilla-firefox \
    && apt-get update && apt-get install -y --no-install-recommends firefox \
    && rm -rf /var/lib/apt/lists/*

# Firefox's own content sandbox needs kernel features the locked-down container (no capabilities)
# deliberately lacks; the container itself is the sandbox.
ENV MOZ_DISABLE_CONTENT_SANDBOX=1 MOZ_DISABLE_GMP_SANDBOX=1

COPY entrypoint.sh /opt/codegate/entrypoint.sh
COPY xstartup.sh /opt/codegate/xstartup.sh
RUN chmod 755 /opt/codegate/entrypoint.sh /opt/codegate/xstartup.sh

WORKDIR /
ENTRYPOINT ["/opt/codegate/entrypoint.sh"]
