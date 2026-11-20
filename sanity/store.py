"""State and the audit trail. Every AI suggestion, human decision and action is appended, redacted, never edited."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

from .guardrails import redact


class Store:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # ---- audit log: hash-chained so tampering is detectable ----
    @property
    def audit_path(self) -> Path:
        return self.root / "audit.jsonl"

    def _last_hash(self) -> str:
        if not self.audit_path.exists():
            return "0" * 64
        lines = self.audit_path.read_text().splitlines()
        return json.loads(lines[-1])["hash"] if lines else "0" * 64

    def audit(self, actor: str, event: str, **details) -> dict:
        safe = json.loads(redact(json.dumps(details, default=str))[0])
        record = {"ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "actor": actor,
                  "event": event, "details": safe, "prev": self._last_hash()}
        record["hash"] = hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()
        with self.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        return record

    def audit_records(self) -> list[dict]:
        if not self.audit_path.exists():
            return []
        return [json.loads(line) for line in self.audit_path.read_text().splitlines() if line.strip()]

    def verify_audit_chain(self) -> bool:
        prev = "0" * 64
        for rec in self.audit_records():
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec["prev"] != prev or hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != rec["hash"]:
                return False
            prev = rec["hash"]
        return True

    # ---- simple JSON documents ----
    def save(self, name: str, data) -> Path:
        p = self.root / name
        p.write_text(json.dumps(data, indent=2, default=str))
        return p

    def load(self, name: str, default=None):
        p = self.root / name
        return json.loads(p.read_text()) if p.exists() else default
