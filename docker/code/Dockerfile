# CodeGate member workspace: code-server + Python/Jupyter/Node, no sudo.
# The entrypoint starts as root only long enough to create the member's Unix
# user, then drops to that user with no capabilities and no-new-privileges.
FROM codercom/code-server:4.112.0

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv python3-dev python3-numpy python3-pandas python3-matplotlib \
      python3-scipy python3-ipykernel git curl wget unzip zip nano vim less procps \
      build-essential nodejs npm ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/local/bin/python

# Extensions are installed system-wide and read-only: members can use them
# but not add their own.
ENV VSCODE_EXT_DIR=/opt/codegate/extensions
RUN mkdir -p $VSCODE_EXT_DIR \
    && code-server --extensions-dir $VSCODE_EXT_DIR \
         --install-extension ms-python.python --install-extension ms-toolsai.jupyter \
    && chmod -R a+rX /opt/codegate

COPY entrypoint.sh /opt/codegate/entrypoint.sh
RUN chmod 755 /opt/codegate/entrypoint.sh

ENTRYPOINT ["/opt/codegate/entrypoint.sh"]
