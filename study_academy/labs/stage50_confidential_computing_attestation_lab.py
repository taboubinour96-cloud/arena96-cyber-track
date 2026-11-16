"""
Stage 50 Defensive Lab — Confidential Computing: Attestation-Gated Key Release
================================================================================
1. EnclaveAttestationVerifier: secrets are released to an enclave only when
   its attestation quote is authentic, debug is off, the code measurement
   is allow-listed, and the platform TCB is at/above the floor.
2. KeyReleaseBroker: policy is evaluated before key material exists in
   memory — a failed quote receives nothing, not even an error oracle
   beyond the state label.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Dict, Set, Tuple


class EnclaveViolation(Exception):
    """Raised when a confidential-computing rule is violated."""


class ConfidentialKeyBroker:
    def __init__(self, platform_key: bytes, allowed_measurements: Set[str], min_tcb: int) -> None:
        if len(platform_key) < 16:
            raise EnclaveViolation("PLATFORM_KEY_TOO_SHORT")
        self._key = platform_key
        self._allowed = set(allowed_measurements)
        self._min_tcb = min_tcb

    def make_quote(self, measurement: str, debug: bool, tcb: int) -> Dict[str, object]:
        body = {"measurement": measurement, "debug": debug, "tcb": tcb}
        sig = hmac.new(self._key, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        return {**body, "signature": sig}

    def release_key(self, quote: Dict[str, object]) -> Tuple[bool, str]:
        body = {"measurement": quote.get("measurement"), "debug": quote.get("debug"), "tcb": quote.get("tcb")}
        expected = hmac.new(self._key, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(quote.get("signature", "")), expected):
            return False, "KEY_DENIED_QUOTE_SIGNATURE_INVALID"
        if bool(quote.get("debug")):
            return False, "KEY_DENIED_ENCLAVE_DEBUG_ENABLED"
        if str(quote.get("measurement")) not in self._allowed:
            return False, "KEY_DENIED_MEASUREMENT_NOT_ALLOWLISTED"
        if int(quote.get("tcb", 0)) < self._min_tcb:
            return False, "KEY_DENIED_TCB_BELOW_FLOOR"
        return True, "KEY_RELEASED_TO_ATTESTED_ENCLAVE"
