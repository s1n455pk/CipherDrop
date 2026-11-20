const $ = (id) => document.getElementById(id);

function showBox(id, message) {
  const el = $(id);
  if (!el) return;
  el.textContent = message;
  el.classList.remove("hidden");
}
function hideBox(id) {
  const el = $(id);
  if (el) el.classList.add("hidden");
}
function setProgress(prefix, visible, message) {
  const box = $(prefix + "-progress");
  if (!box) return;
  box.classList.toggle("hidden", !visible);
  const status = $(prefix + "-status");
  if (status && message) status.textContent = message;
}
function bytesToB64(bytes) {
  let binary = "";
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function b64ToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
function randomSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return bytesToB64(bytes);
}
async function sha256Hex(data) {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}
async function deriveAesKey(passphrase, salt) {
  const material = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {name: "PBKDF2", salt, iterations: 310000, hash: "SHA-256"},
    material,
    {name: "AES-GCM", length: 256},
    false,
    ["encrypt", "decrypt"]
  );
}
async function encryptInBrowser(file, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(passphrase, salt);
  const plain = await file.arrayBuffer();
  const encrypted = await crypto.subtle.encrypt({name: "AES-GCM", iv}, key, plain);
  return {
    encrypted: new Blob([encrypted], {type: "application/octet-stream"}),
    originalHash: await sha256Hex(plain),
    salt: bytesToB64(salt),
    iv: bytesToB64(iv)
  };
}
async function decryptInBrowser(encryptedBuffer, passphrase, saltText, ivText) {
  const key = await deriveAesKey(passphrase, b64ToBytes(saltText));
  return crypto.subtle.decrypt(
    {name: "AES-GCM", iv: b64ToBytes(ivText)},
    key,
    encryptedBuffer
  );
}
async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const old = button.textContent;
    button.textContent = "Copied!";
    setTimeout(() => button.textContent = old, 1200);
  } catch {
    button.textContent = "Select & copy";
  }
}

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const target = $(button.dataset.copy);
  if (target) copyText(target.textContent || target.value, button);
});

const sendForm = $("send-form");
if (sendForm) {
  const fileInput = $("file-input");
  const dropzone = $("dropzone");
  const MAX_SIZE = 25 * 1024 * 1024;

  fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    $("file-picked").textContent = file ? `${file.name} · ${(file.size / 1024 / 1024).toFixed(2)} MB` : "";
    $("file-title").textContent = file ? "File ready to encrypt" : "Drop your file here";
  });
  ["dragenter", "dragover"].forEach(name => dropzone.addEventListener(name, e => {
    e.preventDefault(); dropzone.classList.add("dragging");
  }));
  ["dragleave", "drop"].forEach(name => dropzone.addEventListener(name, e => {
    e.preventDefault(); dropzone.classList.remove("dragging");
  }));
  dropzone.addEventListener("drop", e => {
    if (e.dataTransfer.files.length) {
      fileInput.files = e.dataTransfer.files;
      fileInput.dispatchEvent(new Event("change"));
    }
  });

  sendForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    hideBox("send-error");
    $("send-result").classList.add("hidden");
    const file = fileInput.files[0];
    if (!file) return showBox("send-error", "Please choose a file first.");
    if (file.size > MAX_SIZE) return showBox("send-error", "Maximum file size is 25 MB.");
    if (file.size === 0) return showBox("send-error", "Empty files are not supported.");

    const button = $("send-button");
    button.disabled = true;
    setProgress("send", true, "Generating a strong secret passphrase…");
    try {
      const passphrase = randomSecret();
      setProgress("send", true, "Encrypting file in your browser with AES-256-GCM…");
      const result = await encryptInBrowser(file, passphrase);
      setProgress("send", true, "Uploading encrypted bytes and recording transfer…");

      const metadata = {
        filename: file.name,
        original_hash: result.originalHash,
        salt: result.salt,
        iv: result.iv,
        expiry_hours: Number($("expiry").value),
        max_downloads: Number($("downloads").value)
      };
      const form = new FormData();
      form.append("encrypted_file", result.encrypted, "encrypted.bin");
      form.append("metadata", JSON.stringify(metadata));

      const response = await fetch("/api/transfers", {method: "POST", body: form});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Transfer could not be created.");

      $("result-id").textContent = data.transfer_id;
      $("result-secret").textContent = passphrase;
      $("send-result").classList.remove("hidden");
      $("send-result").scrollIntoView({behavior: "smooth", block: "center"});
      setProgress("send", false);
      $("send-button").classList.add("hidden");
    } catch (error) {
      showBox("send-error", error.message || "Something went wrong.");
      setProgress("send", false);
    } finally {
      button.disabled = false;
    }
  });

  $("new-transfer").addEventListener("click", () => window.location.reload());
}

const receiveForm = $("receive-form");
if (receiveForm) {
  receiveForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    hideBox("receive-error");
    hideBox("download-result");
    const id = $("transfer-id").value.trim();
    const passphrase = $("passphrase").value.trim();
    if (!id || !passphrase) return showBox("receive-error", "Enter both the Transfer ID and secret passphrase.");

    const button = $("receive-button");
    button.disabled = true;
    setProgress("receive", true, "Looking up transfer…");
    try {
      const infoResponse = await fetch(`/api/transfers/${encodeURIComponent(id)}`);
      const info = await infoResponse.json();
      if (!infoResponse.ok) throw new Error(info.error || "Transfer could not be found.");

      setProgress("receive", true, "Retrieving encrypted file…");
      const downloadResponse = await fetch(`/api/transfers/${encodeURIComponent(id)}/download`);
      if (!downloadResponse.ok) {
        const err = await downloadResponse.json();
        throw new Error(err.error || "Download failed.");
      }
      const encryptedBuffer = await downloadResponse.arrayBuffer();

      setProgress("receive", true, "Decrypting in your browser…");
      const plainBuffer = await decryptInBrowser(
        encryptedBuffer, passphrase, info.salt, info.iv
      );

      setProgress("receive", true, "Verifying SHA-256 file fingerprint…");
      const actualHash = await sha256Hex(plainBuffer);
      if (actualHash !== info.original_hash) {
        throw new Error("Integrity verification failed. The file fingerprint does not match.");
      }

      const blob = new Blob([plainBuffer], {type: "application/octet-stream"});
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = info.filename || "cipherdrop-download";
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 30000);

      const result = $("download-result");
      result.textContent = `✓ ${info.filename} decrypted and verified. Your download should begin automatically.`;
      result.classList.remove("hidden");
      setProgress("receive", false);
    } catch (error) {
      showBox("receive-error", error.message || "Decryption failed. Check the passphrase.");
      setProgress("receive", false);
    } finally {
      button.disabled = false;
    }
  });
}
