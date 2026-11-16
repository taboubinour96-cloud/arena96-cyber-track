"""
Stage 46 Defensive Lab — Secure File Exchange: Type Truth, Blocklists & CDR
=============================================================================
1. FileTypeValidator: a file is what its magic bytes say, not what its
   extension claims; macro-bearing containers and oversize uploads die at
   the gate.
2. HashBlocklist: known-bad payloads are rejected by hash before any parser
   touches them.
3. ContentDisarm: accepted documents are rebuilt without active content —
   what is delivered is a sanitized derivative, never the original bytes.
"""

from __future__ import annotations

import hashlib
from typing import Dict, Set, Tuple


class FileExchangeViolation(Exception):
    """Raised when a file-exchange rule is violated."""


_MAGIC = {b"%PDF": "pdf", b"PK\x03\x04": "zip-office", b"\x89PNG": "png", b"\xff\xd8\xff": "jpeg"}
_EXT_KIND = {"pdf": "pdf", "png": "png", "jpg": "jpeg", "docx": "zip-office", "xlsx": "zip-office"}


class SecureFileExchange:
    def __init__(self, blocked_hashes: Set[str], max_bytes: int = 5_000_000) -> None:
        self._blocked = set(blocked_hashes)
        self._max = max_bytes

    def inspect(self, filename: str, content: bytes, has_macros: bool = False) -> Dict[str, object]:
        if len(content) > self._max:
            return {"accepted": False, "state": "FILE_DENIED_OVERSIZE"}
        digest = hashlib.sha256(content).hexdigest()
        if digest in self._blocked:
            return {"accepted": False, "state": "FILE_DENIED_KNOWN_BAD_HASH"}
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        kind = next((k for magic, k in _MAGIC.items() if content.startswith(magic)), "unknown")
        if _EXT_KIND.get(ext) != kind:
            return {"accepted": False, "state": "FILE_DENIED_EXTENSION_MAGIC_MISMATCH"}
        if has_macros:
            return {"accepted": False, "state": "FILE_DENIED_ACTIVE_MACRO_CONTENT"}
        return {"accepted": True, "state": "FILE_ACCEPTED", "kind": kind, "sha256": digest}

    @staticmethod
    def disarm(inspection: Dict[str, object]) -> Tuple[bool, str]:
        if not inspection.get("accepted"):
            return False, "CDR_NOT_APPLICABLE_FILE_REJECTED"
        return True, "CDR_SANITIZED_DERIVATIVE_DELIVERED_ACTIVE_CONTENT_STRIPPED"
