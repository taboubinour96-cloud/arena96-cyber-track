"""
Stage 57 Defensive Lab — Post-Quantum Migration & Crypto Agility
===============================================================
1. CryptoInventory: every use carries algorithm, key size, secrecy lifetime
   and owner. Priority blends "how long must this stay secret" with "how
   weak is the algorithm" — harvest-now-decrypt-later is an archive risk.
2. HybridProfileVerifier: a handshake is accepted only if BOTH the classic
   and the post-quantum component verify; a downgrade to one is a break.
3. EnvelopeRotation: rotate by re-wrapping data keys only, and report every
   key left on the legacy algorithm by name.
"""

from __future__ import annotations

from typing import Dict, Iterable, List


class CryptoViolation(Exception):
    """Raised when a cryptography record is unusable."""


QUANTUM_VULNERABLE = {"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDH-P256", "DH-2048", "AES-128"}
PQ_SAFE = {"ML-KEM-768", "ML-DSA-65", "HYBRID-X25519-MLKEM768", "AES-256"}


class CryptoInventory:
    def __init__(self, uses: Iterable[Dict[str, object]]):
        self.uses = list(uses)
        if not self.uses:
            raise CryptoViolation("EMPTY_CRYPTO_INVENTORY")
        for u in self.uses:
            algo = str(u.get("algorithm", ""))
            if algo not in QUANTUM_VULNERABLE and algo not in PQ_SAFE:
                raise CryptoViolation(f"UNKNOWN_ALGORITHM_{algo}")

    def classify(self) -> Dict[str, object]:
        rows: List[Dict[str, object]] = []
        for u in self.uses:
            algo = str(u["algorithm"])
            lifetime = int(u.get("secrecy_years", 0))
            if algo not in QUANTUM_VULNERABLE and algo not in PQ_SAFE:
                raise CryptoViolation(f"UNKNOWN_ALGORITHM_{algo}")
            vulnerable = algo in QUANTUM_VULNERABLE
            # Harvest-now-decrypt-later: long secrecy + vulnerable algorithm.
            score = (lifetime * 2) + (60 if vulnerable else 0)
            rows.append({
                "id": u["id"], "algorithm": algo, "secrecy_years": lifetime,
                "ownder": u.get("owner", "unassigned"),
                "quantum_vulnerable": vulnerable,
                "priority_score": score,
                "priority": "IMMEDIATE" if vulnerable and lifetime >= 10
                else ("PLANNED" if vulnerable else "ACCEPTABLE"),
            })
        rows.sort(key=lambda r: (-r["priority_score"], r["id"]))
        immediate = [r["id"] for r in rows if r["priority"] == "IMMEDIATE"]
        return {"rows": rows, "immediate": immediate,
                "state": "INVENTORY_CLASSIFIED"}


class HybridProfileVerifier:
    def __init__(self, required: Iterable[str] = ("classic", "post_quantum")):
        self.required = set(required)

    def verify(self, parts: Dict[str, Dict[str, object]]) -> Dict[str, object]:
        missing = sorted(self.required - set(parts))
        if missing:
            return {"accepted": False, "missing": missing,
                    "state": "REJECTED_HYBRID_DOWNGRADE"}
        invalid = sorted(k for k, v in parts.items() if k in self.required and not v.get("valid"))
        if invalid:
            return {"accepted": False, "invalid": invalid,
                    "state": "REJECTED_PART_SIGNATURE_INVALID"}
        return {"accepted": True, "state": "HYBRID_ACCEPTED_BOTH_PARTS_VALID"}


class EnvelopeRotation:
    """Rotate the KEK and re-wrap DEKs; the payload is never rewritten."""

    def __init__(self, kek_id: str, wrapped: Dict[str, Dict[str, object]]):
        if not wrapped:
            raise CryptoViolation("NO_WRAPPED_KEYS")
        self.kek_id = kek_id
        self.wrapped = wrapped

    def rotate(self, new_kek_id: str) -> Dict[str, object]:
        rewrapped = {}
        legacy: List[str] = []
        for name, rec in self.wrapped.items():
            algo = rec.get("algorithm")
            if algo in QUANTUM_VULNERABLE:
                legacy.append(name)
            rewrapped[name] = {**rec, "kek": new_kek_id, "rewrapped": True}
        if legacy:
            return {"rotated": False, "legacy_keys": sorted(legacy),
                    "state": "ROTATION_BLOCKED_LEGACY_ALGORITHM"}
        self.wrapped = rewrapped
        self.kek_id = new_kek_id
        return {"rotated": True, "kek": new_kek_id,
                "rewrapped_count": len(rewrapped),
                "state": "KEK_ROTATED_BY_REWRAPPING_ONLY"}

    def compliance(self) -> Dict[str, object]:
        legacy = sorted(k for k, r in self.wrapped.items()
                        if r.get("algorithm") in QUANTUM_VULNERABLE)
        return {"legacy_keys": legacy, "kek": self.kek_id,
                "state": "NO_LEGACY_KEYS" if not legacy else "LEGACY_KEYS_REMAIN"}
