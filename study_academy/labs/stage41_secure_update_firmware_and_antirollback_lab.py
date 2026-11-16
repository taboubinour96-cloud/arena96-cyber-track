"""
Stage 41 Defensive Lab — Secure Updates: Signed Manifests, Anti-Rollback & Rollout Rings
===========================================================================================
1. UpdateManifestSigner: an update is trusted only when its manifest is
   signed, the payload hash matches, and its version is strictly newer than
   the installed one — rollback to a vulnerable build is a downgrade attack.
2. RolloutGate: new builds earn fleet-wide trust in rings; a ring whose
   error rate breaches the ceiling halts promotion automatically.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Dict, Tuple


class UpdateViolation(Exception):
    """Raised when a secure-update rule is violated."""


class SecureUpdateVerifier:
    def __init__(self, vendor_key: bytes) -> None:
        if len(vendor_key) < 16:
            raise UpdateViolation("UPDATE_VENDOR_KEY_TOO_SHORT")
        self._key = vendor_key

    def sign_manifest(self, version: int, payload: bytes, channel: str = "stable") -> Dict[str, object]:
        manifest = {"version": version, "sha256": hashlib.sha256(payload).hexdigest(), "channel": channel}
        sig = hmac.new(self._key, json.dumps(manifest, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        return {**manifest, "signature": sig}

    def verify(self, manifest: Dict[str, object], payload: bytes, installed_version: int) -> Tuple[bool, str]:
        body = {"version": manifest.get("version"), "sha256": manifest.get("sha256"), "channel": manifest.get("channel")}
        expected = hmac.new(self._key, json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(manifest.get("signature", "")), expected):
            return False, "UPDATE_SIGNATURE_INVALID"
        if hashlib.sha256(payload).hexdigest() != manifest.get("sha256"):
            return False, "UPDATE_PAYLOAD_HASH_MISMATCH"
        if int(manifest.get("version", 0)) <= installed_version:
            return False, "UPDATE_REJECTED_ANTI_ROLLBACK"
        return True, "UPDATE_VERIFIED_INSTALL_ALLOWED"


class RolloutGate:
    def evaluate(self, ring: str, error_rate_pct: float, ceiling_pct: float = 2.0) -> Dict[str, object]:
        if error_rate_pct > ceiling_pct:
            return {"promote": False, "state": "ROLLOUT_HALTED_RING_ERROR_RATE_BREACH", "ring": ring}
        return {"promote": True, "state": "ROLLOUT_PROMOTE_NEXT_RING", "ring": ring}
