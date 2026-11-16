"""
Stage 11 Defensive Lab — Personal Agent Security, Append-Only Hash-Chained Memory & Entropy Secret Hygiene
===========================================================================================================
1. AppendOnlyHashChainedArchive:
   - Enforces Rule 7 (append-only decision & memory archive) via SHA-256 hash chaining.
   - Enforces provenance tagging (`OWNER_VERIFIED` vs `EXTERNAL_UNTRUSTED`) and blocks memory-poisoning payloads.
   - Automatically redacts accidental secrets before persistence (Rule 3).
2. ShannonEntropySecretScanner:
   - Combines Python AST variable inspection with Shannon Entropy H(X) to detect high-entropy secrets
     without leaking raw values.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


POISON_PATTERNS = re.compile(
    r"(?i)(?:ignore\s+(?:all\s+)?previous\s+instructions|override\s+charter|disable\s+ci|force[\-\s]?push|exfiltrate\s+secret)"
)
BIDI_CHARS = {"\u202a", "\u202b", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}
INLINE_TOKEN_RE = re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9_\-]{32,}|AKIA[0-9A-Z]{16})\b")


@dataclass
class MemoryRecord:
    seq: int
    timestamp: str
    trust_tier: str
    category: str
    content: str
    prev_hash: str
    entry_hash: str


class AppendOnlyHashChainedArchive:
    GENESIS_HASH = hashlib.sha256(b"GENESIS_NOUR_COMPANY_ARENA96").hexdigest()

    def __init__(self, ledger_path: Path):
        self.ledger_path = Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.ledger_path.exists():
            self.ledger_path.write_text("", encoding="utf-8")

    @staticmethod
    def sanitize_for_memory(text: str, trust_tier: str) -> str:
        if any(ch in text for ch in BIDI_CHARS):
            raise ValueError("MEMORY_POISON_BIDI_BLOCKED: محارف توجيه ثنائية مخفية محظورة")
        if trust_tier != "OWNER_VERIFIED" and POISON_PATTERNS.search(text):
            raise ValueError("MEMORY_POISON_INJECTION_BLOCKED: محاولة تسميم ذاكرة من مصدر خارجي غير موثوق")

        def _redact(match: re.Match) -> str:
            fp = hashlib.sha256(match.group(0).encode("utf-8")).hexdigest()[:10]
            return f"<REDACTED:sha256:{fp}>"

        return INLINE_TOKEN_RE.sub(_redact, text)

    @staticmethod
    def _compute_hash(seq: int, timestamp: str, trust_tier: str, category: str, content: str, prev_hash: str) -> str:
        canonical = json.dumps(
            {
                "seq": seq,
                "timestamp": timestamp,
                "trust_tier": trust_tier,
                "category": category,
                "content": content,
                "prev_hash": prev_hash,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def append_entry(self, content: str, category: str = "decision", trust_tier: str = "OWNER_VERIFIED") -> MemoryRecord:
        if trust_tier not in {"OWNER_VERIFIED", "EXTERNAL_UNTRUSTED"}:
            raise ValueError("Invalid trust_tier")
        clean_content = self.sanitize_for_memory(content, trust_tier)
        existing = self.read_all()
        seq = len(existing) + 1
        prev_hash = existing[-1].entry_hash if existing else self.GENESIS_HASH
        ts = datetime.now(timezone.utc).isoformat()
        entry_hash = self._compute_hash(seq, ts, trust_tier, category, clean_content, prev_hash)
        rec = MemoryRecord(
            seq=seq,
            timestamp=ts,
            trust_tier=trust_tier,
            category=category,
            content=clean_content,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        with self.ledger_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec.__dict__, ensure_ascii=False) + "\n")
        return rec

    def read_all(self) -> List[MemoryRecord]:
        records: List[MemoryRecord] = []
        if not self.ledger_path.exists():
            return records
        for raw_line in self.ledger_path.read_text(encoding="utf-8").splitlines():
            if raw_line.strip():
                records.append(MemoryRecord(**json.loads(raw_line)))
        return records

    def verify_integrity(self) -> Dict[str, object]:
        records = self.read_all()
        expected_prev = self.GENESIS_HASH
        for idx, rec in enumerate(records, start=1):
            if rec.seq != idx or rec.prev_hash != expected_prev:
                return {"valid": False, "tampered_seq": idx, "reason": "broken_prev_hash_or_deleted_row"}
            recomputed = self._compute_hash(
                rec.seq, rec.timestamp, rec.trust_tier, rec.category, rec.content, rec.prev_hash
            )
            if recomputed != rec.entry_hash:
                return {"valid": False, "tampered_seq": idx, "reason": "modified_entry_payload"}
            expected_prev = rec.entry_hash
        return {"valid": True, "entries_count": len(records), "head_hash": expected_prev}


class ShannonEntropySecretScanner:
    SENSITIVE_NAMES = {"secret", "token", "api_key", "apikey", "private_key", "passphrase", "password"}
    SAFE_PLACEHOLDERS = {"changeme", "placeholder", "example", "dummy", "none", "redacted"}

    @staticmethod
    def shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = Counter(value)
        length = len(value)
        return -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())

    @classmethod
    def scan_python_source(cls, source_code: str, file_label: str = "<memory>") -> List[Dict[str, object]]:
        hits: List[Dict[str, object]] = []
        tree = ast.parse(source_code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                val = node.value.value
                if len(val) < 20 or any(p in val.lower() for p in cls.SAFE_PLACEHOLDERS):
                    continue
                target_names = [
                    t.id.lower() for t in node.targets if isinstance(t, ast.Name)
                ]
                if any(any(sn in tname for sn in cls.SENSITIVE_NAMES) for tname in target_names):
                    ent = cls.shannon_entropy(val)
                    if ent >= 3.7:
                        fp = hashlib.sha256(val.encode("utf-8")).hexdigest()[:10]
                        hits.append(
                            {
                                "file": file_label,
                                "line": node.lineno,
                                "entropy_bits": round(ent, 3),
                                "fingerprint": f"<REDACTED:sha256:{fp}>",
                            }
                        )
        return hits
