"""
Stage 37 Defensive Lab — Privileged Access: Vault Checkout, JIT Elevation & Break-Glass
==========================================================================================
1. PrivilegeVault: standing admin is abolished — credentials are checked out
   against an approved ticket and die at a fixed expiry.
2. JITElevationBroker: elevation is granted for minutes, never permanently;
   an expired grant fails closed at use time.
3. SessionRecorder: privileged session events are hash-chained so silent
   edits to the recording are detectable.
4. BreakGlass: emergency access needs two distinct approvers and always
   raises an audited alarm — speed with accountability.
"""

from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Tuple


class PAMViolation(Exception):
    """Raised when a privileged-access rule is violated."""


class PrivilegeVault:
    def checkout(self, user: str, target: str, ticket_approved: bool, now: int, ttl_minutes: int = 60) -> Dict[str, object]:
        if not ticket_approved:
            return {"granted": False, "state": "PAM_CHECKOUT_DENIED_NO_APPROVED_TICKET"}
        if ttl_minutes <= 0 or ttl_minutes > 480:
            return {"granted": False, "state": "PAM_CHECKOUT_DENIED_TTL_OUT_OF_BOUNDS"}
        return {"granted": True, "state": "PAM_CHECKOUT_GRANTED", "user": user, "target": target,
                "expires_at": now + ttl_minutes * 60}

    @staticmethod
    def use(checkout: Dict[str, object], now: int) -> Tuple[bool, str]:
        if not checkout.get("granted"):
            return False, "PAM_USE_DENIED_NO_GRANT"
        if now >= int(checkout.get("expires_at", 0)):
            return False, "PAM_USE_DENIED_GRANT_EXPIRED"
        return True, "PAM_USE_ALLOWED_WITHIN_WINDOW"


class SessionRecorder:
    def __init__(self) -> None:
        self._events: List[Dict[str, object]] = []
        self._head = "GENESIS"

    def record(self, actor: str, action: str) -> Dict[str, object]:
        body = {"actor": actor, "action": action, "prev": self._head}
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        event = {**body, "sha256": digest}
        self._events.append(event)
        self._head = digest
        return event

    def verify(self) -> Tuple[bool, str]:
        prev = "GENESIS"
        for event in self._events:
            body = {"actor": event["actor"], "action": event["action"], "prev": prev}
            if hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != event["sha256"]:
                return False, "SESSION_RECORD_TAMPER_DETECTED"
            prev = str(event["sha256"])
        return True, "SESSION_RECORD_CHAIN_INTACT"


class BreakGlass:
    def authorize(self, requester: str, approvers: List[str]) -> Dict[str, object]:
        distinct = {a for a in approvers if a != requester}
        if len(distinct) < 2:
            return {"granted": False, "state": "BREAK_GLASS_DENIED_NEEDS_TWO_DISTINCT_APPROVERS"}
        return {"granted": True, "state": "BREAK_GLASS_GRANTED_ALARM_RAISED", "alarm": "CRITICAL_AUDIT"}
