"""
Stage 43 Defensive Lab — Web Sessions: Fixation Resistance, CSRF Tokens & Cookie Flags
=========================================================================================
1. WebSessionManager: session identifiers rotate on privilege change (a
   pre-login ID an attacker planted — fixation — dies at login), and both
   idle and absolute lifetimes are enforced.
2. CSRFDefense: state-changing requests need a token bound to the session;
   a cross-site forgery arrives without it and fails.
3. CookiePolicy: session cookies are Secure + HttpOnly + SameSite — flags
   are cheap, missing them is expensive.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Dict, Tuple


class SessionViolation(Exception):
    """Raised when a web-session rule is violated."""


class WebSessionManager:
    def __init__(self, session_key: bytes) -> None:
        if len(session_key) < 16:
            raise SessionViolation("SESSION_KEY_TOO_SHORT")
        self._key = session_key
        self._counter = 0

    def _new_id(self, user: str) -> str:
        self._counter += 1
        return "sess-" + hmac.new(self._key, f"{user}|{self._counter}".encode(), hashlib.sha256).hexdigest()[:24]

    def create(self, user: str, now: int, idle_seconds: int = 900, absolute_seconds: int = 43200) -> Dict[str, object]:
        return {"session_id": self._new_id(user), "user": user, "created_at": now,
                "last_seen": now, "idle_seconds": idle_seconds, "absolute_seconds": absolute_seconds}

    def rotate_on_privilege_change(self, session: Dict[str, object]) -> Dict[str, object]:
        rotated = dict(session)
        rotated["session_id"] = self._new_id(str(session["user"]))
        return rotated

    def validate(self, session: Dict[str, object], presented_id: str, now: int) -> Tuple[bool, str]:
        if not hmac.compare_digest(presented_id, str(session["session_id"])):
            return False, "SESSION_ID_MISMATCH_POSSIBLE_FIXATION"
        if now - int(session["last_seen"]) > int(session["idle_seconds"]):
            return False, "SESSION_EXPIRED_IDLE_TIMEOUT"
        if now - int(session["created_at"]) > int(session["absolute_seconds"]):
            return False, "SESSION_EXPIRED_ABSOLUTE_LIFETIME"
        return True, "SESSION_VALID"

    def csrf_token(self, session: Dict[str, object]) -> str:
        return hmac.new(self._key, ("csrf|" + str(session["session_id"])).encode(), hashlib.sha256).hexdigest()

    def verify_csrf(self, session: Dict[str, object], presented: str) -> Tuple[bool, str]:
        if hmac.compare_digest(presented, self.csrf_token(session)):
            return True, "CSRF_TOKEN_VALID"
        return False, "CSRF_TOKEN_INVALID_REQUEST_BLOCKED"

    @staticmethod
    def cookie_flags() -> Dict[str, object]:
        return {"Secure": True, "HttpOnly": True, "SameSite": "Strict", "Path": "/"}
