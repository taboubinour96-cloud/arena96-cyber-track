"""
Stage 33 Defensive Lab — API Gateway: Signed Tokens, BOLA Guard, Schema & Rate Limits
=======================================================================================
1. SignedAPIToken: HMAC-signed bearer tokens bound to subject, audience,
   expiry and scopes. Forged/expired/wrong-audience tokens never pass.
2. APIGateway.authorize: scope check + Broken Object Level Authorization
   (BOLA/IDOR) guard — a caller may only touch resources it owns unless it
   carries an explicit admin scope.
3. Payload schema validation (required fields, no unknown fields, types) and
   a fixed-window per-client rate limiter.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Dict, List, Tuple


class APIViolation(Exception):
    """Raised when an API gateway rule is violated."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SignedAPIToken:
    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) < 16:
            raise APIViolation("API_SIGNING_KEY_TOO_SHORT")
        self._key = signing_key

    def issue(self, subject: str, audience: str, scopes: List[str], expires_at: int) -> str:
        payload = {"sub": subject, "aud": audience, "scopes": sorted(scopes), "exp": expires_at}
        body = _b64(json.dumps(payload, sort_keys=True).encode())
        sig = _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def verify(self, token: str, audience: str, now: int) -> Tuple[bool, str, Dict[str, object]]:
        try:
            body, sig = token.split(".", 1)
        except ValueError:
            return False, "API_TOKEN_MALFORMED", {}
        expected = _b64(hmac.new(self._key, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return False, "API_TOKEN_SIGNATURE_INVALID", {}
        payload = json.loads(_unb64(body))
        if int(payload.get("exp", 0)) <= now:
            return False, "API_TOKEN_EXPIRED", {}
        if payload.get("aud") != audience:
            return False, "API_TOKEN_AUDIENCE_MISMATCH", {}
        return True, "API_TOKEN_VERIFIED", payload


class APIGateway:
    def __init__(self, tokens: SignedAPIToken, rate_limit: int = 5, window_seconds: int = 60) -> None:
        self._tokens = tokens
        self._rate_limit = rate_limit
        self._window = window_seconds
        self._counters: Dict[Tuple[str, int], int] = {}

    def _rate_ok(self, client: str, now: int) -> bool:
        bucket = (client, now // self._window)
        self._counters[bucket] = self._counters.get(bucket, 0) + 1
        return self._counters[bucket] <= self._rate_limit

    @staticmethod
    def validate_payload(payload: Dict[str, object], schema: Dict[str, str]) -> Tuple[bool, str]:
        unknown = set(payload) - set(schema)
        if unknown:
            return False, f"API_SCHEMA_UNKNOWN_FIELDS_{sorted(unknown)}"
        for field, kind in schema.items():
            if field not in payload:
                return False, f"API_SCHEMA_MISSING_FIELD_{field}"
            value = payload[field]
            ok = {"string": isinstance(value, str), "number": isinstance(value, (int, float)) and not isinstance(value, bool),
                  "boolean": isinstance(value, bool)}[kind]
            if not ok:
                return False, f"API_SCHEMA_TYPE_MISMATCH_{field}"
        return True, "API_SCHEMA_VALID"

    def authorize(self, token: str, audience: str, required_scope: str,
                  resource_owner: str, now: int, client: str = "client") -> Dict[str, object]:
        ok, state, claims = self._tokens.verify(token, audience, now)
        if not ok:
            return {"allowed": False, "state": state}
        if not self._rate_ok(client, now):
            return {"allowed": False, "state": "API_RATE_LIMIT_EXCEEDED"}
        scopes = list(claims.get("scopes", []))
        if required_scope not in scopes and "api.admin" not in scopes:
            return {"allowed": False, "state": "API_SCOPE_INSUFFICIENT"}
        subject = str(claims.get("sub", ""))
        if resource_owner != subject and "api.admin" not in scopes:
            return {"allowed": False, "state": "API_BOLA_BLOCKED_NOT_RESOURCE_OWNER"}
        return {"allowed": True, "state": "API_REQUEST_AUTHORIZED", "subject": subject, "scopes": scopes}
