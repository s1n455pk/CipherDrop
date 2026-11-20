import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


class Blockchain:
    """Educational, single-server hash-linked ledger (not a decentralized chain)."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            try:
                self.chain = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self.chain = []
        else:
            self.chain = []

        if not self.chain:
            self._create_genesis()

    @staticmethod
    def calculate_hash(block_without_hash):
        payload = json.dumps(
            block_without_hash,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _save(self):
        temp = self.path.with_suffix(".tmp")
        temp.write_text(
            json.dumps(self.chain, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        os.replace(temp, self.path)

    def _create_genesis(self):
        block = {
            "index": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"event": "CIPHERDROP_GENESIS"},
            "previous_hash": "0" * 64
        }
        block["hash"] = self.calculate_hash(block)
        self.chain.append(block)
        self._save()

    def add_block(self, data):
        previous = self.chain[-1]
        block = {
            "index": len(self.chain),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
            "previous_hash": previous["hash"]
        }
        block["hash"] = self.calculate_hash(block)
        self.chain.append(block)
        self._save()
        return block

    def verify_chain(self):
        if not self.chain:
            return False

        for index, block in enumerate(self.chain):
            if "hash" not in block:
                return False

            content = {key: value for key, value in block.items() if key != "hash"}
            if self.calculate_hash(content) != block["hash"]:
                return False

            if block.get("index") != index:
                return False

            if index == 0:
                if block.get("previous_hash") != "0" * 64:
                    return False
            elif block.get("previous_hash") != self.chain[index - 1].get("hash"):
                return False

        return True
