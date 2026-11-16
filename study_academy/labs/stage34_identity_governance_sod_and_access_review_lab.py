"""
Stage 34 Defensive Lab — Identity Governance: SoD, Access Reviews & Privilege Creep
======================================================================================
1. SegregationOfDuties: toxic role combinations (create+approve payments,
   create vendor + execute payment, grant roles + approve own access) are
   denied at assignment time — fraud needs two people by construction.
2. AccessReviewEngine: periodic certification — privileged entitlements that
   are dormant, unattested, or held by departed users are revoked/suspended
   instead of silently persisting.
3. PrivilegeCreepAnalyzer: compares granted entitlements against the role
   baseline; excess privilege is measured, not guessed.
"""

from __future__ import annotations

from typing import Dict, List, Set, Tuple


class GovernanceViolation(Exception):
    """Raised when an identity-governance rule is violated."""


class SegregationOfDuties:
    _TOXIC: List[Tuple[str, str, str]] = [
        ("payments.create", "payments.approve", "CREATE_AND_APPROVE_SAME_PAYMENT_FLOW"),
        ("vendor.create", "payments.execute", "CREATE_VENDOR_AND_PAY_IT"),
        ("iam.grant_roles", "iam.approve_access", "GRANT_AND_APPROVE_ACCESS"),
    ]

    def check_assignment(self, user: str, existing_roles: Set[str], new_role: str) -> Dict[str, object]:
        combined = set(existing_roles) | {new_role}
        for left, right, label in self._TOXIC:
            if left in combined and right in combined:
                return {"allowed": False, "state": f"SOD_VIOLATION_{label}", "user": user}
        return {"allowed": True, "state": "SOD_CLEAR_ASSIGNMENT_ALLOWED", "user": user}


class AccessReviewEngine:
    def review(self, entitlement: Dict[str, object]) -> Dict[str, object]:
        if not bool(entitlement.get("user_active", True)):
            return {"decision": "REVOKE", "state": "REVIEW_REVOKE_DEPARTED_USER"}
        if not bool(entitlement.get("manager_attested", False)):
            return {"decision": "SUSPEND", "state": "REVIEW_SUSPEND_UNATTESTED_ENTITLEMENT"}
        dormant_days = int(entitlement.get("last_used_days_ago", 0))
        privileged = bool(entitlement.get("privileged", False))
        if privileged and dormant_days > 90:
            return {"decision": "REVOKE", "state": "REVIEW_REVOKE_DORMANT_PRIVILEGE"}
        if dormant_days > 180:
            return {"decision": "REVOKE", "state": "REVIEW_REVOKE_LONG_DORMANT_ACCESS"}
        return {"decision": "CERTIFY", "state": "REVIEW_CERTIFIED_ACTIVE_ATTESTED"}


class PrivilegeCreepAnalyzer:
    def analyze(self, granted: Set[str], role_baseline: Set[str]) -> Dict[str, object]:
        excess = sorted(set(granted) - set(role_baseline))
        missing = sorted(set(role_baseline) - set(granted))
        creep_pct = round((len(excess) / max(1, len(granted))) * 100.0, 2)
        return {
            "excess_entitlements": excess, "missing_baseline": missing,
            "creep_pct": creep_pct,
            "state": "PRIVILEGE_CREEP_EXCESS_PRESENT" if excess else "PRIVILEGE_WITHIN_BASELINE",
        }
