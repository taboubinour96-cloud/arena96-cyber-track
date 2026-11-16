"""
المختبر العملي للمرحلة 6 (Stage 6 Expert Lab: Sigma Detection Engine, Binary Entropy & KMS Envelope Encryption) — أرينا 96
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List


# ============================================================================
# 1. Portable Sigma-Style Behavioral Detection Engine (Detection-as-Code)
# ============================================================================

def _match_selector(event: Dict[str, Any], selector: Dict[str, List[str]]) -> bool:
    for field_expr, expected_values in selector.items():
        if "|" in field_expr:
            field_name, modifier = field_expr.split("|", 1)
        else:
            field_name, modifier = field_expr, "equals"

        actual = str(event.get(field_name, "")).lower()
        targets = [v.lower() for v in expected_values]

        if modifier == "endswith":
            if not any(actual.endswith(t) for t in targets):
                return False
        elif modifier == "contains":
            if not any(t in actual for t in targets):
                return False
        else:
            if actual not in targets:
                return False
    return True


def evaluate_sigma_rule(
    event: Dict[str, Any],
    selection: Dict[str, List[str]],
    filter_allowlist: Dict[str, List[str]] | None = None,
) -> bool:
    """Evaluates `condition: selection and not filter_allowlist` for high-precision alerting."""
    if not _match_selector(event, selection):
        return False
    if filter_allowlist and _match_selector(event, filter_allowlist):
        return False
    return True


# ============================================================================
# 2. Defensive Binary Header (PE / ELF) & Shannon Entropy Triage Inspector
# ============================================================================

@dataclass
class ArtifactTriageSummary:
    binary_format: str  # "PE", "ELF", or "UNKNOWN"
    size_bytes: int
    shannon_entropy: float
    likely_packed_or_encrypted: bool


def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    entropy = -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())
    return round(entropy, 4)


def inspect_artifact_metadata(raw_bytes: bytes) -> ArtifactTriageSummary:
    if raw_bytes.startswith(b"\x7fELF"):
        fmt = "ELF"
    elif raw_bytes.startswith(b"MZ"):
        fmt = "PE"
    else:
        fmt = "UNKNOWN"

    ent = calculate_shannon_entropy(raw_bytes)
    return ArtifactTriageSummary(
        binary_format=fmt,
        size_bytes=len(raw_bytes),
        shannon_entropy=ent,
        likely_packed_or_encrypted=(ent >= 7.2),
    )


# ============================================================================
# 3. Cloud KMS Envelope Encryption & O(1) Master Key (KEK) Rotation Simulator
# ============================================================================

def _xor_keystream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """Deterministic CTR-like stream generator using SHA-256 blocks for zero-dependency lab simulation."""
    out = bytearray(len(data))
    block_idx = 0
    pos = 0
    while pos < len(data):
        digest = hashlib.sha256(key + nonce + block_idx.to_bytes(4, "big")).digest()
        chunk = digest[: min(32, len(data) - pos)]
        for i, b in enumerate(chunk):
            out[pos + i] = data[pos + i] ^ b
        pos += len(chunk)
        block_idx += 1
    return bytes(out)


def _aead_seal(plaintext: bytes, key: bytes) -> Dict[str, str]:
    nonce = secrets.token_bytes(16)
    ciphertext = _xor_keystream(plaintext, key, nonce)
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    return {"nonce": nonce.hex(), "ciphertext": ciphertext.hex(), "tag": tag.hex()}


def _aead_open(bundle: Dict[str, str], key: bytes) -> bytes:
    nonce = bytes.fromhex(bundle["nonce"])
    ciphertext = bytes.fromhex(bundle["ciphertext"])
    tag = bytes.fromhex(bundle["tag"])
    expected_tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("AEAD authentication tag verification failed!")
    return _xor_keystream(ciphertext, key, nonce)


class EnvelopeEncryptionVault:
    """Demonstrates encrypting large payloads with a DEK wrapped by an HSM/KMS KEK."""

    def __init__(self, initial_kek: bytes) -> None:
        self._kek = initial_kek

    def encrypt_record(self, plaintext: bytes) -> Dict[str, Any]:
        dek = secrets.token_bytes(32)
        encrypted_payload = _aead_seal(plaintext, dek)
        wrapped_dek = _aead_seal(dek, self._kek)
        return {"wrapped_dek": wrapped_dek, "payload": encrypted_payload}

    def decrypt_record(self, envelope: Dict[str, Any]) -> bytes:
        dek = _aead_open(envelope["wrapped_dek"], self._kek)
        return _aead_open(envelope["payload"], dek)

    def rotate_kek_on_envelope(self, envelope: Dict[str, Any], new_kek: bytes) -> Dict[str, Any]:
        """Re-wraps ONLY the 32-byte DEK under `new_kek` without touching `envelope['payload']`!"""
        dek = _aead_open(envelope["wrapped_dek"], self._kek)
        new_wrapped = _aead_seal(dek, new_kek)
        return {"wrapped_dek": new_wrapped, "payload": envelope["payload"]}
