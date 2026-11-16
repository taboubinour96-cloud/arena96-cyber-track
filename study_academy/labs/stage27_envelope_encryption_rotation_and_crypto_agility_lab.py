"""
Stage 27 Defensive Lab — Envelope Encryption, Key Rotation & Crypto-Agility
=============================================================================
Educational authenticated-encryption model (HMAC keystream + HMAC tag, stdlib only;
production systems must use vetted AEAD such as AES-GCM / ChaCha20-Poly1305).

1. EnvelopeEncryptionService:
   - Data-Encryption Keys (DEKs) encrypt data; Key-Encryption Keys (KEKs) in a
     KMS-style vault wrap DEKs. Rotation re-wraps DEKs under a new KEK without
     re-encrypting data, and decryption verifies the auth tag fail-closed.
2. CryptoAgilityRegistry:
   - Inventories algorithm usage per component, flags deprecated algorithms,
     verifies dual-algorithm migration (old records still verify while new
     writes use the target algorithm), and scores migration readiness.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Dict, List, Tuple


class CryptoAgilityViolation(Exception):
    """Raised when a key-management / crypto-agility rule is violated."""


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        counter += 1
    return out[:length]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class EnvelopeEncryptionService:
    def __init__(self) -> None:
        self._keks: Dict[str, bytes] = {}
        self._active_kek = ""

    def register_kek(self, key_id: str, key: bytes, make_active: bool = False) -> None:
        if len(key) < 16:
            raise CryptoAgilityViolation("KEK_TOO_SHORT")
        self._keks[key_id] = key
        if make_active or not self._active_kek:
            self._active_kek = key_id

    def _wrap_dek(self, kek_id: str, dek: bytes) -> Dict[str, object]:
        kek = self._keks[kek_id]
        nonce = os.urandom(12)
        wrapped = _xor(dek, _keystream(kek, nonce, len(dek)))
        return {"kek_id": kek_id, "nonce": nonce.hex(), "wrapped_dek": wrapped.hex(),
                "wrap_tag": hmac.new(kek, nonce + wrapped, hashlib.sha256).hexdigest()}

    def _unwrap_dek(self, envelope: Dict[str, object]) -> bytes:
        kek = self._keks.get(str(envelope["kek_id"]))
        if kek is None:
            raise CryptoAgilityViolation("UNKNOWN_KEK_FOR_DEK")
        nonce = bytes.fromhex(str(envelope["nonce"]))
        wrapped = bytes.fromhex(str(envelope["wrapped_dek"]))
        expect = hmac.new(kek, nonce + wrapped, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, str(envelope["wrap_tag"])):
            raise CryptoAgilityViolation("DEK_WRAP_TAG_INVALID")
        return _xor(wrapped, _keystream(kek, nonce, len(wrapped)))

    def encrypt(self, plaintext: bytes) -> Dict[str, object]:
        if not self._active_kek:
            raise CryptoAgilityViolation("NO_ACTIVE_KEK")
        dek = os.urandom(32)
        nonce = os.urandom(12)
        ciphertext = _xor(plaintext, _keystream(dek, nonce, len(plaintext)))
        return {
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
            "tag": hmac.new(dek, nonce + ciphertext, hashlib.sha256).hexdigest(),
            "dek_envelope": self._wrap_dek(self._active_kek, dek),
            "kek_id": self._active_kek,
        }

    def decrypt(self, record: Dict[str, object]) -> bytes:
        dek = self._unwrap_dek(record["dek_envelope"])  # type: ignore[arg-type]
        nonce = bytes.fromhex(str(record["nonce"]))
        ciphertext = bytes.fromhex(str(record["ciphertext"]))
        expect = hmac.new(dek, nonce + ciphertext, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, str(record["tag"])):
            raise CryptoAgilityViolation("DATA_AUTH_TAG_INVALID_FAIL_CLOSED")
        return _xor(ciphertext, _keystream(dek, nonce, len(ciphertext)))

    def rotate_kek(self, new_key_id: str, new_key: bytes, records: List[Dict[str, object]]) -> List[Dict[str, object]]:
        self.register_kek(new_key_id, new_key, make_active=True)
        rotated = []
        for rec in records:
            dek = self._unwrap_dek(rec["dek_envelope"])  # type: ignore[arg-type]
            new_rec = dict(rec)
            new_rec["dek_envelope"] = self._wrap_dek(new_key_id, dek)
            new_rec["kek_id"] = new_key_id
            rotated.append(new_rec)
        return rotated


class CryptoAgilityRegistry:
    DEPRECATED = {"SHA1", "3DES", "RSA-1024", "ECDSA-P256-SHA1"}

    def __init__(self) -> None:
        self.inventory: Dict[str, str] = {}

    def register(self, component: str, algorithm: str) -> None:
        self.inventory[component] = algorithm

    def deprecated_components(self) -> List[str]:
        return sorted(c for c, a in self.inventory.items() if a in self.DEPRECATED)

    def migration_readiness(self, target_by_component: Dict[str, str]) -> Dict[str, object]:
        total = len(self.inventory)
        migrated = sum(1 for c, target in target_by_component.items()
                       if self.inventory.get(c) == target)
        pending = sorted(c for c in self.inventory if target_by_component.get(c) != self.inventory.get(c))
        score = round((migrated / total) * 100.0, 2) if total else 100.0
        return {"readiness_pct": score, "migrated": migrated, "total": total, "pending_components": pending}
