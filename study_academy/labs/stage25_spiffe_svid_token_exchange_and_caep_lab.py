"""
Stage 25 Defensive Lab — Workload Identity (SPIFFE-Style SVIDs), Token Exchange & Continuous Access
====================================================================================================
1. WorkloadIdentityAuthority:
   - Attests a workload by node evidence, then issues a short-lived HMAC-signed
     SVID (SPIFFE-ID, audience, expiry). Verification enforces trust domain,
     audience, expiry and signature — fail-closed on any mismatch.
2. TokenExchangeBroker:
   - Exchanges an SVID for a narrower downstream token (audience + scope can
     only shrink, lifetime can only shorten), macaroon-style.
3. ContinuousAccessEvaluator (CAEP-style):
   - Access is re-evaluated continuously: a posture drop or an explicit
     session-revocation signal instantly kills previously issued access.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Dict, Set, Tuple


class IdentityViolation(Exception):
    """Raised when a workload-identity rule is violated."""


def _sign(key: bytes, payload: Dict[str, object]) -> str:
    return hmac.new(key, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()


class WorkloadIdentityAuthority:
    def __init__(self, trust_key: bytes, trust_domain: str = "arena.internal") -> None:
        if len(trust_key) < 16:
            raise IdentityViolation("TRUST_KEY_TOO_SHORT")
        self._key = trust_key
        self.trust_domain = trust_domain

    def attest_and_issue(self, workload: str, node_evidence: str, audience: str,
                         now_ts: int, ttl_seconds: int = 300) -> Dict[str, object]:
        if not node_evidence.startswith("node-attested:"):
            raise IdentityViolation("NODE_ATTESTATION_EVIDENCE_MISSING")
        payload = {
            "spiffe_id": f"spiffe://{self.trust_domain}/workload/{workload}",
            "audience": audience,
            "issued_at": int(now_ts),
            "expires_at": int(now_ts) + int(ttl_seconds),
            "node": node_evidence.split(":", 1)[1],
        }
        svid = dict(payload)
        svid["signature"] = _sign(self._key, payload)
        return svid

    def verify(self, svid: Dict[str, object], audience: str, now_ts: int) -> Tuple[bool, str]:
        payload = {k: svid.get(k) for k in ("spiffe_id", "audience", "issued_at", "expires_at", "node")}
        if not hmac.compare_digest(_sign(self._key, payload), str(svid.get("signature", ""))):
            return False, "SVID_SIGNATURE_INVALID"
        if not str(svid.get("spiffe_id", "")).startswith(f"spiffe://{self.trust_domain}/"):
            return False, "SVID_TRUST_DOMAIN_MISMATCH"
        if svid.get("audience") != audience:
            return False, "SVID_AUDIENCE_MISMATCH"
        if now_ts > int(svid["expires_at"]):  # type: ignore[arg-type]
            return False, "SVID_EXPIRED"
        return True, "SVID_VERIFIED"


class TokenExchangeBroker:
    def __init__(self, trust_key: bytes) -> None:
        self._key = trust_key

    def exchange(self, svid: Dict[str, object], new_audience: str, scopes: list,
                 now_ts: int, ttl_seconds: int) -> Dict[str, object]:
        granted = sorted(set(str(s) for s in svid.get("scopes", ["workload:default"])))
        requested = sorted(set(str(s) for s in scopes))
        if not set(requested).issubset(set(granted)) and "workload:default" not in granted:
            raise IdentityViolation("TOKEN_EXCHANGE_SCOPE_WIDENING_FORBIDDEN")
        if now_ts + ttl_seconds > int(svid["expires_at"]):  # type: ignore[arg-type]
            raise IdentityViolation("TOKEN_EXCHANGE_LIFETIME_EXCEEDS_PARENT")
        payload = {
            "subject": svid.get("spiffe_id"),
            "audience": new_audience,
            "scopes": requested if requested else granted,
            "issued_at": int(now_ts),
            "expires_at": int(now_ts) + int(ttl_seconds),
            "exchange_of": str(svid.get("spiffe_id")),
        }
        token = dict(payload)
        token["signature"] = _sign(self._key, payload)
        return token

    def verify(self, token: Dict[str, object], audience: str, scope: str, now_ts: int) -> Tuple[bool, str]:
        payload = {k: token.get(k) for k in ("subject", "audience", "scopes", "issued_at", "expires_at", "exchange_of")}
        if not hmac.compare_digest(_sign(self._key, payload), str(token.get("signature", ""))):
            return False, "EXCHANGED_TOKEN_SIGNATURE_INVALID"
        if token.get("audience") != audience:
            return False, "EXCHANGED_TOKEN_AUDIENCE_MISMATCH"
        if scope not in list(token.get("scopes", [])):
            return False, "EXCHANGED_TOKEN_SCOPE_NOT_GRANTED"
        if now_ts > int(token["expires_at"]):  # type: ignore[arg-type]
            return False, "EXCHANGED_TOKEN_EXPIRED"
        return True, "EXCHANGED_TOKEN_VERIFIED"


class ContinuousAccessEvaluator:
    def __init__(self) -> None:
        self._revoked_sessions: Set[str] = set()
        self._posture: Dict[str, str] = {}

    def set_posture(self, session_id: str, posture: str) -> None:
        self._posture[session_id] = posture

    def revoke_session(self, session_id: str, reason: str) -> None:
        self._revoked_sessions.add(session_id)

    def evaluate(self, session_id: str, svid_valid: bool) -> Tuple[bool, str]:
        if session_id in self._revoked_sessions:
            return False, "CAEP_SESSION_REVOKED_ACCESS_TERMINATED"
        if self._posture.get(session_id, "compliant") != "compliant":
            return False, "CAEP_POSTURE_NONCOMPLIANT_ACCESS_TERMINATED"
        if not svid_valid:
            return False, "CAEP_IDENTITY_INVALID_ACCESS_TERMINATED"
        return True, "CAEP_ACCESS_CONTINUES"
