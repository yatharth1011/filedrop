const $ = (id) => document.getElementById(id);

const loginView = $("loginView");
const appView = $("appView");
const passwordInput = $("passwordInput");
const btnLogin = $("btnLogin");
const loginError = $("loginError");
const btnLogout = $("btnLogout");
const btnGetUrl = $("btnGetUrl");
const urlBox = $("urlBox");
const urlBoxText = $("urlBoxText");
const urlBoxCopy = $("urlBoxCopy");
const btnChangePassword = $("btnChangePassword");
const passwordBox = $("passwordBox");
const currentPasswordInput = $("currentPasswordInput");
const newPasswordInput = $("newPasswordInput");
const btnSavePassword = $("btnSavePassword");
const passwordBoxMsg = $("passwordBoxMsg");
const dropZone = $("dropZone");
const fileInput = $("fileInput");
const uploadProgress = $("uploadProgress");
const uploadName = $("uploadName");
const progressFill = $("progressFill");
const uploadPct = $("uploadPct");
const uploadResult = $("uploadResult");
const uploadResultLink = $("uploadResultLink");
const uploadResultCopy = $("uploadResultCopy");
const textInput = $("textInput");
const btnSendText = $("btnSendText");
const fileList = $("fileList");
const fileListEmpty = $("fileListEmpty");

async function api(url, opts) {
  const res = await fetch(url, opts);
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) {}
  if (!res.ok) throw { status: res.status, data };
  return data;
}

async function checkAuth() {
  const data = await api("/api/whoami");
  if (data && data.authed) {
    loginView.classList.add("hidden");
    appView.classList.remove("hidden");
    btnLogout.classList.remove("hidden");
    btnChangePassword.classList.toggle("hidden", !data.local);
    refreshFileList();
  } else {
    loginView.classList.remove("hidden");
    appView.classList.add("hidden");
    btnLogout.classList.add("hidden");
    btnChangePassword.classList.add("hidden");
    passwordBox.classList.add("hidden");
  }
}

btnLogin.addEventListener("click", doLogin);
passwordInput.addEventListener("keydown", (e) => { if (e.key === "Enter") doLogin(); });

async function doLogin() {
  loginError.classList.add("hidden");
  try {
    const data = await api("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: passwordInput.value }),
    });
    if (data && data.ok) {
      passwordInput.value = "";
      checkAuth();
    } else {
      loginError.classList.remove("hidden");
    }
  } catch (e) {
    // Remember the default text so a lockout message doesn't stick around.
    loginError.dataset.defaultText ??= loginError.textContent;
    loginError.textContent = (e && e.data && e.data.error) || loginError.dataset.defaultText;
    loginError.classList.remove("hidden");
  }
}

btnLogout.addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); } catch (e) {}
  checkAuth();
});

btnGetUrl.addEventListener("click", async () => {
  try {
    const info = await api("/api/server-info");
    urlBoxText.textContent = info.url;
    urlBox.classList.remove("hidden");
  } catch (e) {
    urlBoxText.textContent = "Could not detect address.";
    urlBox.classList.remove("hidden");
  }
});

btnChangePassword.addEventListener("click", () => {
  passwordBoxMsg.textContent = "";
  currentPasswordInput.value = "";
  newPasswordInput.value = "";
  passwordBox.classList.toggle("hidden");
});

btnSavePassword.addEventListener("click", async () => {
  passwordBoxMsg.textContent = "Saving…";
  try {
    await api("/api/set-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        current_password: currentPasswordInput.value,
        new_password: newPasswordInput.value,
      }),
    });
    passwordBoxMsg.textContent = "";
    passwordBox.classList.add("hidden");
    checkAuth(); // the server clears every session on a password change, this one included
  } catch (e) {
    passwordBoxMsg.textContent = (e.data && e.data.error) || "Could not change password.";
  }
});

urlBoxCopy.addEventListener("click", () => copyText(urlBoxText.textContent, urlBoxCopy, "Copy"));

// Briefly swaps a button's own label/icon to a "copied" state so clicking
// copy actually confirms something happened, instead of looking like a
// no-op.
function flashCopied(btn, restoreText) {
  if (!btn) return;
  if (btn._copiedTimer) clearTimeout(btn._copiedTimer);
  const isIcon = btn.classList.contains("icon-btn");
  btn.textContent = isIcon ? "✓" : "Copied!";
  btn.classList.add("icon-btn--copied");
  btn._copiedTimer = setTimeout(() => {
    btn.textContent = restoreText;
    btn.classList.remove("icon-btn--copied");
  }, 1200);
}

function copyText(text, btn, restoreText) {
  // navigator.clipboard needs a secure context (HTTPS or localhost) -- this
  // page is plain HTTP on a LAN IP, so that API is simply absent here and
  // silently does nothing. Fall back to the old select+execCommand trick,
  // which still works over plain HTTP.
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => fallbackCopyText(text));
  } else {
    fallbackCopyText(text);
  }
  flashCopied(btn, restoreText);
}

function fallbackCopyText(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  try {
    document.execCommand("copy");
  } catch (e) {}
  document.body.removeChild(ta);
}

// --- Upload ---

dropZone.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => {
  if (fileInput.files && fileInput.files[0]) uploadFile(fileInput.files[0]);
  fileInput.value = "";
});

["dragenter", "dragover"].forEach((evt) =>
  dropZone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  })
);
["dragleave", "drop"].forEach((evt) =>
  dropZone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
  })
);
dropZone.addEventListener("drop", (e) => {
  const file = e.dataTransfer.files && e.dataTransfer.files[0];
  if (file) uploadFile(file);
});

document.addEventListener("paste", (e) => {
  if (appView.classList.contains("hidden")) return; // don't hijack pasting a password on the login screen
  const files = e.clipboardData && e.clipboardData.files;
  if (files && files.length > 0) {
    e.preventDefault();
    uploadFile(files[0]);
    return;
  }
  // Pasted text goes into the text box rather than being shared right away:
  // the clipboard often holds things (passwords, OTPs) you'd never want to
  // publish by accident. Pastes into a field behave normally.
  const text = e.clipboardData && e.clipboardData.getData("text/plain");
  if (text && !e.target.closest?.("input, textarea")) {
    e.preventDefault();
    textInput.value = textInput.value ? `${textInput.value}\n${text}` : text;
    textInput.focus();
    textInput.setSelectionRange(textInput.value.length, textInput.value.length);
  }
});

async function sendText() {
  const text = textInput.value;
  if (!text.trim()) return;
  btnSendText.disabled = true;
  try {
    const data = await api("/api/text", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    textInput.value = "";
    uploadResultLink.value = window.location.origin + data.url;
    uploadResult.classList.remove("hidden");
    refreshFileList();
  } catch (e) {
    if (e.status === 401) checkAuth();
    else alert("Sending text failed" + (e.data && e.data.error ? ` -- ${e.data.error}` : ` (${e.status || "connection error"})`));
  } finally {
    btnSendText.disabled = false;
  }
}

btnSendText.addEventListener("click", sendText);
textInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
    e.preventDefault();
    sendText();
  }
});

function uploadFile(file) {
  uploadResult.classList.add("hidden");
  uploadProgress.classList.remove("hidden");
  uploadName.textContent = file.name;
  progressFill.style.width = "0%";
  uploadPct.textContent = "0%";

  const xhr = new XMLHttpRequest();
  xhr.open("PUT", "/api/upload?name=" + encodeURIComponent(file.name));
  xhr.upload.addEventListener("progress", (e) => {
    if (!e.lengthComputable) return;
    const pct = Math.round((e.loaded / e.total) * 100);
    progressFill.style.width = pct + "%";
    uploadPct.textContent = pct + "%";
  });
  xhr.addEventListener("load", () => {
    uploadProgress.classList.add("hidden");
    if (xhr.status >= 200 && xhr.status < 300) {
      const data = JSON.parse(xhr.responseText);
      const fullUrl = window.location.origin + data.url;
      uploadResultLink.value = fullUrl;
      uploadResult.classList.remove("hidden");
      refreshFileList();
    } else if (xhr.status === 401) {
      checkAuth();
    } else {
      alert("Upload failed (" + xhr.status + ")");
    }
  });
  xhr.addEventListener("error", () => {
    uploadProgress.classList.add("hidden");
    alert("Upload failed -- connection error.");
  });
  xhr.send(file);
}

uploadResultCopy.addEventListener("click", () => copyText(uploadResultLink.value, uploadResultCopy, "Copy"));

// --- File list ---

function formatTimeLeft(seconds) {
  if (seconds <= 0) return "expired";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${days}d ${hours}h left`;
  const minutes = Math.floor((seconds % 3600) / 60);
  if (hours > 0) return `${hours}h ${minutes}m left`;
  return `${minutes}m left`;
}

async function refreshFileList() {
  let data;
  try {
    data = await api("/api/files");
  } catch (e) {
    return;
  }
  const files = (data && data.files) || [];
  fileList.innerHTML = "";
  fileListEmpty.classList.toggle("hidden", files.length > 0);
  for (const f of files) {
    const row = document.createElement("div");
    row.className = "file-row";

    const info = document.createElement("div");
    info.className = "file-row-info";
    const name = document.createElement("div");
    name.className = "file-row-name";
    const isText = f.kind === "text";
    name.textContent = isText ? (f.preview || f.name) : f.name;
    const meta = document.createElement("div");
    meta.className = "file-row-meta";
    meta.textContent = `${isText ? "text · " : ""}${f.size_human} · ${formatTimeLeft(f.seconds_left)}`;
    info.appendChild(name);
    info.appendChild(meta);

    const actions = document.createElement("div");
    actions.className = "file-row-actions";

    if (isText) {
      const copyTextBtn = document.createElement("button");
      copyTextBtn.className = "icon-btn";
      copyTextBtn.title = "Copy text";
      copyTextBtn.textContent = "\u00B6"; // ¶
      copyTextBtn.addEventListener("click", async () => {
        try {
          const res = await fetch(f.url, { cache: "no-store" });
          if (!res.ok) throw new Error(res.status);
          copyText(await res.text(), copyTextBtn, "\u00B6");
        } catch (e) {
          alert("Couldn't fetch that text -- it may have expired.");
        }
      });
      actions.appendChild(copyTextBtn);
    }

    const copyBtn = document.createElement("button");
    copyBtn.className = "icon-btn";
    copyBtn.title = "Copy link";
    copyBtn.textContent = "⧉"; // ⧉
    copyBtn.addEventListener("click", () => copyText(window.location.origin + f.url, copyBtn, "⧉"));
    actions.appendChild(copyBtn);

    if (f.inline) {
      const openBtn = document.createElement("a");
      openBtn.className = "icon-btn";
      openBtn.title = "Open";
      openBtn.textContent = "↗"; // ↗
      openBtn.href = f.url;
      openBtn.target = "_blank";
      actions.appendChild(openBtn);
    }

    const downloadBtn = document.createElement("a");
    downloadBtn.className = "icon-btn";
    downloadBtn.title = "Download";
    downloadBtn.textContent = "⬇"; // ⬇
    downloadBtn.href = f.url;
    downloadBtn.download = f.name; // forces save-as even for inline-viewable types
    actions.appendChild(downloadBtn);

    const deleteBtn = document.createElement("button");
    deleteBtn.className = "icon-btn icon-btn--danger";
    deleteBtn.title = "Delete";
    deleteBtn.textContent = "✕"; // ✕
    deleteBtn.addEventListener("click", async () => {
      try {
        await api("/api/files/" + f.token, { method: "DELETE" });
        refreshFileList();
      } catch (e) {}
    });
    actions.appendChild(deleteBtn);

    row.appendChild(info);
    row.appendChild(actions);
    fileList.appendChild(row);
  }
}

setInterval(() => {
  if (!appView.classList.contains("hidden")) refreshFileList();
}, 30000);

checkAuth();
