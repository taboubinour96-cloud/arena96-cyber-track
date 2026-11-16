"""
Stage 15 Defensive Lab — ECDSA Nonce-Reuse Cryptanalysis vs RFC 6979, TVLA Timing Test & WebAuthn/DPoP
======================================================================================================
1. ECDSANonceSecurityLab:
   - Demonstrates algebraically over NIST P-256 curve order n how reusing ephemeral nonce k across
     two distinct messages immediately leaks private key d, and implements RFC 6979-style HMAC
     deterministic nonce derivation that eliminates k-reuse permanently.
2. TVLATimingLeakDetector:
   - Implements Welch's two-sample t-test (ISO/IEC 17825 TVLA |t| > 4.5 criterion) to detect
     timing side-channel distributions vs constant-time distributions.
3. WebAuthnAndDPoPVerifier:
   - Verifies cryptographic origin binding (blocking reverse-proxy AiTM phishing), monotonic
     signCount clone detection, and DPoP sender-constrained token proof binding.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from typing import Dict, Sequence, Tuple


# NIST P-256 prime subgroup order n (for pure modular signature algebra)
SECP256R1_ORDER_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class ECDSANonceSecurityLab:
    @staticmethod
    def _hash_msg(msg: bytes) -> int:
        return int.from_bytes(hashlib.sha256(msg).digest(), "big") % SECP256R1_ORDER_N

    @staticmethod
    def deterministic_rfc6979_nonce(private_key_d: int, msg: bytes) -> int:
        """Deterministic k derived from HMAC-SHA256(private_key || H(msg)) mod (n-1) + 1."""
        key_bytes = private_key_d.to_bytes(32, "big")
        digest = hashlib.sha256(msg).digest()
        v = b"\x01" * 32
        k_mac = b"\x00" * 32
        k_mac = hmac.new(k_mac, v + b"\x00" + key_bytes + digest, hashlib.sha256).digest()
        v = hmac.new(k_mac, v, hashlib.sha256).digest()
        candidate = int.from_bytes(hmac.new(k_mac, v, hashlib.sha256).digest(), "big")
        return (candidate % (SECP256R1_ORDER_N - 1)) + 1

    @classmethod
    def sign_modular_model(cls, private_key_d: int, msg: bytes, k: int, r_coord: int) -> Tuple[int, int]:
        z = cls._hash_msg(msg)
        k_inv = pow(k, -1, SECP256R1_ORDER_N)
        s = (k_inv * (z + r_coord * private_key_d)) % SECP256R1_ORDER_N
        return r_coord, s

    @classmethod
    def recover_private_key_from_reused_nonce(
        cls,
        msg1: bytes,
        sig1: Tuple[int, int],
        msg2: bytes,
        sig2: Tuple[int, int],
    ) -> int:
        r1, s1 = sig1
        r2, s2 = sig2
        if r1 != r2 or s1 == s2:
            raise ValueError("Signatures do not share a reused nonce on distinct messages")
        z1 = cls._hash_msg(msg1)
        z2 = cls._hash_msg(msg2)
        recovered_k = ((z1 - z2) * pow(s1 - s2, -1, SECP256R1_ORDER_N)) % SECP256R1_ORDER_N
        recovered_d = (pow(r1, -1, SECP256R1_ORDER_N) * (s1 * recovered_k - z1)) % SECP256R1_ORDER_N
        return recovered_d


class TVLATimingLeakDetector:
    THRESHOLD_T = 4.5

    @classmethod
    def welch_t_statistic(cls, sample_a: Sequence[float], sample_b: Sequence[float]) -> Tuple[float, bool]:
        if len(sample_a) < 2 or len(sample_b) < 2:
            raise ValueError("Each TVLA trace group requires at least 2 observations")
        mean_a = sum(sample_a) / len(sample_a)
        mean_b = sum(sample_b) / len(sample_b)
        var_a = sum((x - mean_a) ** 2 for x in sample_a) / (len(sample_a) - 1)
        var_b = sum((x - mean_b) ** 2 for x in sample_b) / (len(sample_b) - 1)
        denom = math.sqrt((var_a / len(sample_a)) + (var_b / len(sample_b)))
        if denom == 0.0:
            t_val = 0.0 if mean_a == mean_b else float("inf")
        else:
            t_val = (mean_a - mean_b) / denom
        leak_detected = abs(t_val) > cls.THRESHOLD_T
        return round(t_val, 4), leak_detected


class WebAuthnAndDPoPVerifier:
    def __init__(self, expected_origin: str, expected_rp_id: str, credential_secret: bytes) -> None:
        self.expected_origin = expected_origin
        self.expected_rp_id = expected_rp_id
        self._cred_secret = bytes(credential_secret)
        self.stored_sign_count: int = 0
        self._seen_dpop_jti: set[str] = set()

    def verify_webauthn_assertion(
        self,
        client_data_json: str,
        rp_id_claimed: str,
        sign_count: int,
        expected_challenge: str,
        signature_hex: str,
    ) -> Tuple[bool, str]:
        data = json.loads(client_data_json)
        if data.get("type") != "webauthn.get":
            return False, "INVALID_WEBAUTHN_TYPE"
        if data.get("origin") != self.expected_origin:
            return False, f"PHISHING_ORIGIN_MISMATCH:{data.get('origin')}"
        if data.get("challenge") != expected_challenge:
            return False, "CHALLENGE_MISMATCH"
        if rp_id_claimed != self.expected_rp_id:
            return False, "RP_ID_MISMATCH"
        if sign_count <= self.stored_sign_count:
            return False, "CLONED_AUTHENTICATOR_SIGNCOUNT_ANOMALY"

        rp_hash = hashlib.sha256(rp_id_claimed.encode("utf-8")).digest()
        client_hash = hashlib.sha256(client_data_json.encode("utf-8")).digest()
        signed_blob = rp_hash + sign_count.to_bytes(4, "big") + client_hash
        expected_sig = hmac.new(self._cred_secret, signed_blob, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, signature_hex):
            return False, "INVALID_ASSERTION_SIGNATURE"

        self.stored_sign_count = sign_count
        return True, "WEBAUTHN_PHISHING_RESISTANT_OK"

    def verify_dpop_proof(self, proof: Dict[str, object], actual_method: str, actual_uri: str) -> Tuple[bool, str]:
        jti = str(proof.get("jti", ""))
        htm = str(proof.get("htm", "")).upper()
        htu = str(proof.get("htu", ""))
        mac = str(proof.get("mac", ""))
        if not jti or jti in self._seen_dpop_jti:
            return False, "DPOP_REPLAY_JTI"
        if htm != actual_method.upper() or htu != actual_uri:
            return False, "DPOP_METHOD_OR_URI_MISMATCH"
        expected = hmac.new(self._cred_secret, f"{jti}:{htm}:{htu}".encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            return False, "DPOP_INVALID_PROOF"
        self._seen_dpop_jti.add(jti)
        return True, "DPOP_BOUND_OK"
