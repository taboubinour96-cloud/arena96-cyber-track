"""
Stage 31 Defensive Lab — Browser Extension Permission Risk & Mobile Device Attestation
=========================================================================================
1. BrowserExtensionRiskAnalyzer:
   - Scores extension manifests by permission danger (broad host access,
     cookies, scripting, request interception...) and store/publisher signals;
     dangerous extensions are blocked or forced into review, never silently
     allowed.
2. MobileDeviceAttestationVerifier:
   - Verifies an HMAC-signed device attestation (integrity verdict, jailbreak
     flag, OS floor, security-patch freshness) before the device may hold a
     work profile / agent access. Any failed leg denies enrollment.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Dict, List, Tuple


class DeviceTrustViolation(Exception):
    """Raised when a browser/device trust rule is violated."""


class BrowserExtensionRiskAnalyzer:
    _PERMISSION_RISK = {
        "<all_urls>": 35, "cookies": 25, "scripting": 20, "webRequest": 25,
        "webRequestBlocking": 20, "downloads": 15, "clipboardRead": 15,
        "history": 15, "tabs": 5, "storage": 3, "activeTab": 5, "notifications": 3,
    }

    def analyze(self, *, name: str, permissions: List[str], host_permissions: List[str],
                publisher_verified: bool) -> Dict[str, object]:
        requested = list(permissions) + list(host_permissions)
        unknown = [p for p in requested if p not in self._PERMISSION_RISK]
        if unknown:
            raise DeviceTrustViolation(f"UNKNOWN_EXTENSION_PERMISSION_{unknown[0]}")
        score = sum(self._PERMISSION_RISK[p] for p in requested)
        signals: List[str] = []
        if "<all_urls>" in requested:
            signals.append("BROAD_HOST_ACCESS_ALL_URLS")
        if "cookies" in requested and "scripting" in requested:
            score += 15
            signals.append("COOKIE_PLUS_SCRIPTING_SESSION_THEFT_COMBO")
        if not publisher_verified:
            score += 10
            signals.append("UNVERIFIED_PUBLISHER")
        if score >= 60:
            decision = "BLOCK_EXTENSION"
        elif score >= 35:
            decision = "REQUIRE_SECURITY_REVIEW"
        else:
            decision = "ALLOW_EXTENSION"
        return {"extension": name, "risk_score": score, "decision": decision, "signals": signals}


class MobileDeviceAttestationVerifier:
    def __init__(self, attestation_key: bytes, min_os_major: int = 14, max_patch_age_days: int = 90) -> None:
        if len(attestation_key) < 16:
            raise DeviceTrustViolation("ATTESTATION_KEY_TOO_SHORT")
        self._key = attestation_key
        self.min_os = min_os_major
        self.max_patch_age = max_patch_age_days

    def sign_attestation(self, payload: Dict[str, object]) -> Dict[str, object]:
        att = dict(payload)
        att["signature"] = hmac.new(self._key, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        return att

    def verify_enrollment(self, att: Dict[str, object]) -> Tuple[bool, str]:
        payload = {k: v for k, v in att.items() if k != "signature"}
        expect = hmac.new(self._key, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, str(att.get("signature", ""))):
            return False, "ATTESTATION_SIGNATURE_INVALID"
        if att.get("integrity") != "PASS":
            return False, "ATTESTATION_INTEGRITY_NOT_PASS"
        if att.get("jailbroken") is True or att.get("rooted") is True:
            return False, "ATTESTATION_COMPROMISED_OS_JAILBREAK_ROOT"
        if int(att.get("os_major", 0)) < self.min_os:  # type: ignore[arg-type]
            return False, "ATTESTATION_OS_BELOW_FLOOR"
        if int(att.get("patch_age_days", 10_000)) > self.max_patch_age:  # type: ignore[arg-type]
            return False, "ATTESTATION_SECURITY_PATCH_STALE"
        return True, "DEVICE_ATTESTATION_VERIFIED_ENROLL_ALLOWED"
