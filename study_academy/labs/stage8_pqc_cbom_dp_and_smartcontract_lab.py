"""
مختبر المرحلة 8: جاهزية التشفير ما بعد الكمومي (CBOM FIPS 203/204/205)، الخصوصية التفاضلية، وفحص العقود الذكية
"""

from __future__ import annotations

import math
import random
import re
from typing import Any, Dict, List

QUANTUM_SAFE_ALGORITHMS = {
    "ML-KEM-768",
    "ML-KEM-1024",
    "X25519MLKEM768",
    "ML-DSA-65",
    "ML-DSA-87",
    "SLH-DSA-SHA2-256f",
    "AES-256-GCM",
    "CHACHA20-POLY1305",
    "SHA-384",
    "SHA-512",
    "SHA3-256",
}

QUANTUM_VULNERABLE_ASYMMETRIC = {"RSA-2048", "RSA-4096", "ECDSA-P256", "ECDH-X25519", "DSA-1024"}


class CBOMQuantumReadinessAuditor:
    """Audits a Cryptographic Bill of Materials (CBOM) against NIST PQC standards (FIPS 203/204/205)."""

    @staticmethod
    def evaluate_cbom(assets: List[Dict[str, str]]) -> Dict[str, Any]:
        safe_count = 0
        migrations_needed: List[Dict[str, str]] = []
        for item in assets:
            alg = item["algorithm"].upper()
            if alg in QUANTUM_SAFE_ALGORITHMS:
                safe_count += 1
            elif alg in QUANTUM_VULNERABLE_ASYMMETRIC:
                replacement = "X25519MLKEM768 (FIPS 203)" if "ECDH" in alg or "RSA" in alg else "ML-DSA-65 (FIPS 204)"
                migrations_needed.append(
                    {"service": item["service"], "current": alg, "recommended_pqc": replacement}
                )
            else:
                migrations_needed.append(
                    {"service": item["service"], "current": alg, "recommended_pqc": "AES-256-GCM / ML-KEM-768"}
                )
        pct = round((safe_count / max(1, len(assets))) * 100.0, 1)
        return {"pqc_readiness_percent": pct, "migrations_needed": migrations_needed}


class DifferentialPrivacyEngine:
    """Implements epsilon-Differential Privacy using the Laplace Mechanism."""

    def __init__(self, epsilon: float, seed: int = 96):
        if epsilon <= 0:
            raise ValueError("epsilon must be strictly positive")
        self.epsilon = epsilon
        self._rng = random.Random(seed)

    def privatize_query(self, true_value: float, sensitivity: float = 1.0) -> float:
        scale = sensitivity / self.epsilon
        u = self._rng.uniform(-0.499999, 0.499999)
        laplace_noise = -scale * (1.0 if u >= 0 else -1.0) * math.log(1.0 - 2.0 * abs(u))
        return round(true_value + laplace_noise, 4)


class SmartContractCEIAuditor:
    """Detects Reentrancy violations where external value transfer occurs BEFORE state balance update (SWC-107)."""

    @staticmethod
    def audit_solidity_function(sol_source: str) -> Dict[str, Any]:
        lines = sol_source.splitlines()
        external_call_line = -1
        state_zero_line = -1
        for idx, ln in enumerate(lines, 1):
            if re.search(r"\.call\s*\{.*value\s*:", ln) or ".transfer(" in ln:
                if external_call_line == -1:
                    external_call_line = idx
            if re.search(r"balances\[.*\]\s*[-=]=\s*", ln) or re.search(r"balances\[.*\]\s*=\s*0", ln):
                state_zero_line = idx

        reentrancy_vuln = external_call_line != -1 and state_zero_line != -1 and external_call_line < state_zero_line
        return {
            "vulnerable_to_reentrancy": reentrancy_vuln,
            "external_call_line": external_call_line,
            "state_update_line": state_zero_line,
            "cwe": "CWE-841 / SWC-107" if reentrancy_vuln else "SAFE_CEI_ORDER",
        }
