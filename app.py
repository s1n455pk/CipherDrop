import hashlib
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from blockchain import Blockchain

from contextlib import contextmanager

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
DB_PATH = BASE_DIR / "instance" / "cipherdrop.db"
MAX_FILE_BYTES = 25 * 1024 * 1024
ALLOWED_EXPIRY_HOURS = {1, 6, 24, 72, 168}
ALLOWED_DOWNLOADS = {1, 3, 5, 10}

STORAGE_DIR.mkdir(exist_ok=True)
DB_PATH.parent.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_BYTES + 256 * 1024
blockchain = Blockchain(str(BASE_DIR / "blockchain_data" / "chain.json"))


def utc_now():
    return datetime.now(timezone.utc)


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def db_connection():
    conn = get_db()
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS transfers (
                transfer_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                encrypted_filename TEXT NOT NULL,
                original_hash TEXT NOT NULL,
                encrypted_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                iv TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                max_downloads INTEGER NOT NULL,
                downloads INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'available'
            )
        """)
        conn.commit()


def valid_transfer_id(value):
    return bool(value and re.fullmatch(r"[A-Za-z0-9_-]{12,40}", value))


def transfer_public(row):
    return {
        "transfer_id": row["transfer_id"],
        "filename": row["filename"],
        "original_hash": row["original_hash"],
        "encrypted_hash": row["encrypted_hash"],
        "salt": row["salt"],
        "iv": row["iv"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "max_downloads": row["max_downloads"],
        "downloads": row["downloads"],
        "status": row["status"],
    }


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "File is too large. Maximum size is 25 MB."}), 413


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/send")
def send_page():
    return render_template("send.html")


@app.route("/receive")
def receive_page():
    return render_template("receive.html")


@app.route("/blockchain")
def blockchain_page():
    return render_template("blockchain.html")


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "app": "CipherDrop"})


@app.post("/api/transfers")
def create_transfer():
    uploaded = request.files.get("encrypted_file")
    raw_metadata = request.form.get("metadata", "")

    if not uploaded or not uploaded.filename:
        return jsonify({"error": "Encrypted file is missing."}), 400

    try:
        metadata = json.loads(raw_metadata)
    except (TypeError, json.JSONDecodeError):
        return jsonify({"error": "Invalid transfer metadata."}), 400

    required = ["filename", "original_hash", "salt", "iv", "expiry_hours", "max_downloads"]
    if any(key not in metadata for key in required):
        return jsonify({"error": "Some transfer details are missing."}), 400

    original_filename = secure_filename(str(metadata["filename"]))[:180]
    if not original_filename:
        original_filename = "downloaded-file"

    original_hash = str(metadata["original_hash"]).lower()
    salt = str(metadata["salt"])
    iv = str(metadata["iv"])

    if not re.fullmatch(r"[a-f0-9]{64}", original_hash):
        return jsonify({"error": "Invalid file fingerprint."}), 400
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", salt):
        return jsonify({"error": "Invalid encryption salt."}), 400
    if not re.fullmatch(r"[A-Za-z0-9_-]{12,40}", iv):
        return jsonify({"error": "Invalid encryption nonce."}), 400

    try:
        expiry_hours = int(metadata["expiry_hours"])
        max_downloads = int(metadata["max_downloads"])
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid expiry or download limit."}), 400

    if expiry_hours not in ALLOWED_EXPIRY_HOURS or max_downloads not in ALLOWED_DOWNLOADS:
        return jsonify({"error": "Choose a supported expiry and download limit."}), 400

    encrypted_bytes = uploaded.read()
    if not encrypted_bytes:
        return jsonify({"error": "Encrypted file is empty."}), 400
    if len(encrypted_bytes) > MAX_FILE_BYTES + 64:
        return jsonify({"error": "Encrypted file exceeds the 25 MB limit."}), 413

    encrypted_hash = hashlib.sha256(encrypted_bytes).hexdigest()
    transfer_id = secrets.token_urlsafe(12)
    encrypted_filename = transfer_id + ".cipher"
    destination = STORAGE_DIR / encrypted_filename

    created = utc_now()
    expires = created + timedelta(hours=expiry_hours)

    # Save encrypted bytes only. The passphrase is never sent to this server.
    temp_path = STORAGE_DIR / (encrypted_filename + ".tmp")
    temp_path.write_bytes(encrypted_bytes)
    os.replace(temp_path, destination)

    try:
        with db_connection() as conn:
            conn.execute("""
                INSERT INTO transfers (
                    transfer_id, filename, encrypted_filename,
                    original_hash, encrypted_hash, salt, iv,
                    created_at, expires_at, max_downloads, downloads, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'available')
            """, (
                transfer_id, original_filename, encrypted_filename,
                original_hash, encrypted_hash, salt, iv,
                created.isoformat(), expires.isoformat(),
                max_downloads
            ))
            conn.commit()
    except Exception:
        destination.unlink(missing_ok=True)
        app.logger.exception("Could not save transfer metadata")
        return jsonify({"error": "Could not create the transfer. Please retry."}), 500

    try:
        blockchain.add_block({
            "event": "FILE_UPLOADED",
            "transfer_id": transfer_id,
            "filename": original_filename,
            "original_hash": original_hash,
            "encrypted_hash": encrypted_hash,
            "created_at": created.isoformat(),
            "expires_at": expires.isoformat(),
        })
    except Exception:
        app.logger.exception("Blockchain write failed")

    return jsonify({
        "message": "Secure transfer created.",
        "transfer_id": transfer_id,
        "filename": original_filename,
        "expires_at": expires.isoformat(),
        "max_downloads": max_downloads,
        "encrypted_hash": encrypted_hash,
    }), 201


@app.get("/api/transfers/<transfer_id>")
def get_transfer(transfer_id):
    if not valid_transfer_id(transfer_id):
        return jsonify({"error": "Invalid transfer ID."}), 400

    with db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM transfers WHERE transfer_id = ?",
            (transfer_id,)
        ).fetchone()

    if row is None:
        return jsonify({"error": "Transfer not found."}), 404

    if utc_now() >= datetime.fromisoformat(row["expires_at"]):
        return jsonify({"error": "This transfer has expired."}), 410

    if row["downloads"] >= row["max_downloads"] or row["status"] != "available":
        return jsonify({"error": "Download limit has been reached."}), 410

    return jsonify(transfer_public(row))


@app.get("/api/transfers/<transfer_id>/download")
def download_transfer(transfer_id):
    if not valid_transfer_id(transfer_id):
        return jsonify({"error": "Invalid transfer ID."}), 400

    # Atomic consume: concurrent requests cannot exceed the configured limit.
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM transfers WHERE transfer_id = ?",
            (transfer_id,)
        ).fetchone()

        if row is None:
            conn.rollback()
            return jsonify({"error": "Transfer not found."}), 404

        if utc_now() >= datetime.fromisoformat(row["expires_at"]):
            conn.rollback()
            return jsonify({"error": "This transfer has expired."}), 410

        if row["status"] != "available" or row["downloads"] >= row["max_downloads"]:
            conn.rollback()
            return jsonify({"error": "Download limit has been reached."}), 410

        file_path = STORAGE_DIR / row["encrypted_filename"]
        if not file_path.is_file():
            conn.rollback()
            return jsonify({"error": "Encrypted file is unavailable."}), 404

        new_downloads = row["downloads"] + 1
        new_status = "consumed" if new_downloads >= row["max_downloads"] else "available"

        conn.execute("""
            UPDATE transfers SET downloads = ?, status = ?
            WHERE transfer_id = ?
        """, (new_downloads, new_status, transfer_id))
        conn.commit()

        filename = row["filename"]
        encrypted_hash = row["encrypted_hash"]
    finally:
        conn.close()

    try:
        blockchain.add_block({
            "event": "FILE_DOWNLOADED",
            "transfer_id": transfer_id,
            "encrypted_hash": encrypted_hash,
            "download_number": new_downloads,
            "downloaded_at": utc_now().isoformat(),
        })
    except Exception:
        app.logger.exception("Could not record download event")

    return send_file(
        file_path,
        as_attachment=True,
        download_name=transfer_id + ".cipher",
        mimetype="application/octet-stream",
        conditional=True
    )


@app.get("/api/blockchain")
def get_blockchain():
    return jsonify({
        "chain": blockchain.chain,
        "valid": blockchain.verify_chain(),
        "total_blocks": len(blockchain.chain),
    })


@app.get("/api/stats")
def stats():
    with db_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM transfers").fetchone()[0]
        active = conn.execute("""
            SELECT COUNT(*) FROM transfers
            WHERE status = 'available' AND expires_at > ?
        """, (utc_now().isoformat(),)).fetchone()[0]
        downloads = conn.execute(
            "SELECT COALESCE(SUM(downloads), 0) FROM transfers"
        ).fetchone()[0]

    return jsonify({
        "total_transfers": total,
        "active_transfers": active,
        "downloads": downloads,
        "blocks": len(blockchain.chain),
        "blockchain_valid": blockchain.verify_chain(),
    })


@app.errorhandler(500)
def internal_error(_error):
    return jsonify({"error": "An unexpected server error occurred."}), 500


init_db()

if __name__ == "__main__":
    # Local development only. Use a production WSGI server for deployment.
    app.run(host="127.0.0.1", port=5000, debug=True)
