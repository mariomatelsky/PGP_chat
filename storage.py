"""
Encrypted chat log. One file per contact at ~/.pgpchat/logs/<fp_no_colons>.enc

Each line is a base64 blob (AES-256-GCM) that decrypts to:
  {"ts": float, "dir": "sent"|"recv", "nick": str, "msg": str}

Key derived from your private key via HKDF — no separate key file needed.
"""

import json
import time
from pathlib import Path
from typing import List, Dict

from crypto import derive_log_key, encrypt_log_entry, decrypt_log_entry


class ChatLog:
    """Append-only encrypted log for one contact."""

    def __init__(self, logs_dir: Path, contact_fingerprint: str, private_key):
        # Strip colons for a valid filename
        safe_fp = contact_fingerprint.replace(":", "")
        self.log_path = logs_dir / f"{safe_fp}.enc"
        self._key = derive_log_key(private_key, contact_fingerprint)

    # ── Write ─────────────────────────────────────────────────────────────────

    def append(self, direction: str, nickname: str, message: str) -> None:
        record = {
            "ts":   time.time(),
            "dir":  direction,
            "nick": nickname,
            "msg":  message,
        }
        blob = encrypt_log_entry(json.dumps(record, ensure_ascii=False), self._key)
        with self.log_path.open("a", encoding="ascii") as fh:
            fh.write(blob + "\n")

    # ── Read ──────────────────────────────────────────────────────────────────

    def read_all(self) -> List[Dict]:
        if not self.log_path.exists():
            return []

        entries: List[Dict] = []
        with self.log_path.open("r", encoding="ascii") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    plaintext = decrypt_log_entry(line, self._key)
                    entries.append(json.loads(plaintext))
                except Exception:
                    pass  # corrupt / truncated entry — skip it

        return entries
