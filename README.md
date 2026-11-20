# CipherDrop — Secure File Transfer System

A beginner-friendly educational project built with Python Flask and browser Web Crypto.

## Features

- No user registration or login.
- Browser-side AES-256-GCM file encryption.
- PBKDF2-SHA-256 passphrase-based key derivation (310,000 iterations).
- Random 256-bit transfer passphrase generated in the browser.
- SHA-256 original-file integrity check.
- Encrypted file storage on the Flask server.
- Transfer expiry and configurable download limits.
- Hash-linked JSON blockchain-style audit ledger.
- Blockchain explorer UI.

## Important security and project-scope notes

- The passphrase is generated and used in the browser. It is not submitted to Flask.
- The original file is encrypted in the browser before upload. Flask stores ciphertext only.
- The server stores transfer metadata, including filename and SHA-256 fingerprint. These may reveal information about a known file; this is a lab demonstration, not a privacy-maximal production service.
- A download slot is consumed when the encrypted payload is retrieved, before browser-side decryption. If the passphrase is mistyped, the browser closes, or decryption fails after retrieval, that slot is still consumed. For testing, choose 3 or more downloads until the passphrase is confirmed.
- The blockchain is a single-server, hash-linked educational ledger. It is not decentralized, consensus-based, or immutable against a privileged server operator who can rewrite the entire chain.
- This prototype has no malware scanning, distributed storage, abuse controls, or production-grade operational hardening. Do not use it for highly sensitive real-world files.
- Use HTTPS when deploying publicly. Do not expose Flask's development server to the internet.

## Run on Windows

```powershell
cd CipherDrop
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open: http://127.0.0.1:5000

## Test

1. Open **Send file**.
2. Select a small PDF or image.
3. Choose expiry and download limit.
4. Click **Encrypt & create transfer**.
5. Copy the Transfer ID and secret passphrase.
6. Open **Receive** in another browser tab.
7. Enter both values and download.
8. Open the downloaded file and check it.
9. Visit **Explorer** to inspect ledger entries.

For a one-time transfer, a successful retrieval consumes the only download slot. The secret passphrase is not recoverable by the server.
