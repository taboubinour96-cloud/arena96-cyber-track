"""
Stage 42 Defensive Lab — Dynamic Secrets: Leases, Revocation & Rotation Compliance
=====================================================================================
1. DynamicSecretBroker: instead of static database passwords living for
   years, workloads lease credentials that expire in minutes and can be
   revoked instantly — a leaked lease is a soon-dead lease.
2. RotationCompliance: every long-lived secret has a maximum age; the
   register reports overdue rotations as findings, not folklore.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Dict, List, Tuple


class SecretLeaseViolation(Exception):
    """Raised when a secret-lease rule is violated."""


class DynamicSecretBroker:
    def __init__(self, broker_key: bytes) -> None:
        if len(broker_key) < 16:
            raise SecretLeaseViolation("SECRET_BROKER_KEY_TOO_SHORT")
        self._key = broker_key
        self._revoked: set = set()

    def issue(self, workload: str, scope: str, now: int, ttl_seconds: int = 900) -> Dict[str, object]:
        if ttl_seconds <= 0 or ttl_seconds > 3600:
            return {"issued": False, "state": "SECRET_LEASE_DENIED_TTL_OUT_OF_BOUNDS"}
        lease_id = "lease-" + hmac.new(self._key, f"{workload}|{scope}|{now}".encode(), hashlib.sha256).hexdigest()[:20]
        return {"issued": True, "state": "SECRET_LEASE_ISSUED", "lease_id": lease_id,
                "workload": workload, "scope": scope, "expires_at": now + ttl_seconds}

    def revoke(self, lease_id: str) -> None:
        self._revoked.add(lease_id)

    def use(self, lease: Dict[str, object], now: int) -> Tuple[bool, str]:
        if not lease.get("issued"):
            return False, "SECRET_USE_DENIED_NO_LEASE"
        if str(lease.get("lease_id")) in self._revoked:
            return False, "SECRET_USE_DENIED_LEASE_REVOKED"
        if now >= int(lease.get("expires_at", 0)):
            return False, "SECRET_USE_DENIED_LEASE_EXPIRED"
        return True, "SECRET_USE_ALLOWED"


class RotationCompliance:
    def audit(self, secrets: List[Dict[str, object]], max_age_days: int = 90) -> Dict[str, object]:
        overdue = sorted(str(s["name"]) for s in secrets if int(s.get("age_days", 0)) > max_age_days)
        return {"overdue": overdue, "overdue_count": len(overdue),
                "state": "ROTATION_OVERDUE_FINDINGS_PRESENT" if overdue else "ROTATION_COMPLIANT"}
