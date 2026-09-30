"""macOS sandbox profile that confines CodeGate's code-server -- and every
process it starts (terminals, Python/Jupyter kernels, Node, ...), since the
sandbox is inherited -- to one folder.

What stays usable: the chosen folder (read/write), the system and anything
installed outside your home folder (Homebrew, python.org Python, Node:
read-only), caches and temp dirs (read/write), the network, and the few
dotfiles shells and dev tools read.

What's blocked: everything else under /Users (your other files, SSH keys,
FileDrop's own password + CA key) and /Volumes; writing anywhere else; and
the ways a process could get *another*, unsandboxed program to act for it:
Apple Events (osascript), launching apps (`open`), creating launchd jobs,
the keychain and the clipboard.
"""
import os


def _q(path):
    # SBPL string literal.
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_profile(folder, home, tmp_dir, code_dirs):
    folder, home, tmp_dir = (os.path.realpath(p) for p in (folder, home, tmp_dir))
    code_dirs = [os.path.realpath(p) for p in code_dirs]
    h = lambda rel: os.path.join(home, rel)

    # Read-only bits of your home that shells and dev tools look at.
    read_only = [
        h(".zshrc"), h(".zprofile"), h(".zshenv"), h(".zlogin"), h(".profile"),
        h(".bash_profile"), h(".bashrc"), h(".inputrc"), h(".gitconfig"), h(".gitignore_global"),
        h(".npmrc"), h(".condarc"), h(".config/git"), h(".oh-my-zsh"), h(".nvm"), h(".pyenv"),
        h(".cargo"), h(".rustup"), h(".bun"), h(".deno"), h(".local/bin"), h(".local/lib"),
        h(".jupyter"), h("Library/Python"),
    ]
    # Read/write scratch space tools expect (caches, notebook runtime files).
    scratch = [
        tmp_dir, "/private/tmp", "/private/var/tmp",
        h("Library/Caches"), h(".cache"), h(".npm"), h(".matplotlib"),
        h("Library/Jupyter"), h(".ipython"),
    ]

    def paths(op, items):
        return f"(allow {op}\n" + "\n".join(f"  (subpath {_q(p)})" for p in items) + ")\n"

    return (
        "(version 1)\n"
        "(allow default)\n"
        # --- reads: nothing of yours outside the allowlist
        '(deny file-read* (subpath "/Users") (subpath "/Volumes"))\n'
        # Stat and path resolution only (names, never contents), so tools that
        # canonicalise paths through your home folder don't fall over.
        '(allow file-read-metadata (subpath "/Users"))\n'
        + paths("file-read*", [folder] + code_dirs + read_only + scratch)
        # --- writes: only the folder, code-server's own data, scratch, devices
        + '(deny file-write* (subpath "/"))\n'
        + paths("file-write*", [folder] + code_dirs + scratch + ["/dev"])
        # --- ways out of the sandbox via other processes
        + "(deny appleevent-send)\n"
        "(deny job-creation)\n"
        "(deny mach-lookup\n"
        '  (global-name "com.apple.coreservices.launchservicesd")\n'
        '  (global-name "com.apple.coreservices.quarantine-resolver")\n'
        '  (global-name "com.apple.SecurityServer")\n'
        '  (global-name "com.apple.securityd.xpc")\n'
        '  (global-name "com.apple.pasteboard.1"))\n'
        "(deny process-exec\n"
        '  (literal "/usr/bin/open") (literal "/usr/bin/osascript") (literal "/bin/launchctl")\n'
        '  (literal "/usr/bin/security") (literal "/usr/sbin/screencapture")\n'
        '  (literal "/usr/bin/pbcopy") (literal "/usr/bin/pbpaste"))\n'
    )
