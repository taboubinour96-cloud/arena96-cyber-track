"""
Stage 56 Defensive Lab — SOAR Automation With Blast Radius
==========================================================
1. ResponsePlaybook: a playbook resolves a decision tree, not a script.
   An action whose scope exceeds the cap is held for dual approval instead
   of executing.
2. ReversibleAction: every automated action must carry a rollback token
   before it runs; and success means the target state changed AND nothing
   else did.
3. ActionVerifier: post-action verification compares target state and
   surrounding state; an action that "succeeded" while touching others is
   a failure with a name.
"""

from __future__ import annotations

from typing import Dict, Iterable, List


class SoarViolation(Exception):
    """Raised when a playbook or action is unsafe to run."""


DEFAULT_CAPS = {"max_hosts": 5, "max_users": 10, "max_services": 2}


class ResponsePlaybook:
    def __init__(self, caps: Dict[str, int] | None = None):
        self.caps = dict(DEFAULT_CAPS if caps is None else caps)
        if any(v <= 0 for v in self.caps.values()):
            raise SoarViolation("INVALID_CAP")

    def decide(self, action: str, scope: Dict[str, int], critical_asset: bool,
               reversible: bool, has_evidence: bool) -> Dict[str, object]:
        exceeded = [k for k, v in scope.items() if v > self.caps.get(k, 0)]
        if not reversible and not has_evidence:
            return {"action": action, "execute": False,
                    "state": "DENIED_IRREVERSIBLE_WITHOUT_EVIDENCE"}
        if exceeded or critical_asset:
            return {"action": action, "execute": False, "approvals_required": 2,
                    "exceeded": exceeded, "critical_asset": critical_asset,
                    "state": "HELD_FOR_DUAL_APPROVAL"}
        return {"action": action, "execute": True, "approvals_required": 0,
                "state": "AUTOMATED_EXECUTION_ALLOWED"}


class ReversibleAction:
    def __init__(self, name: str, target: str):
        self.name = name
        self.target = target
        self.rollback_token: str | None = None
        self.snapshot: Dict[str, object] = {}
        self.applied = False

    def prepare(self, snapshot: Dict[str, object], rollback_token: str | None) -> Dict[str, object]:
        if not rollback_token:
            return {"prepared": False, "state": "REFUSED_NO_ROLLBACK_TOKEN"}
        self.snapshot = dict(snapshot)
        self.rollback_token = rollback_token
        return {"prepared": True, "state": "ACTION_ARMED_WITH_ROLLBACK"}

    def apply(self, state: Dict[str, object], changes: Dict[str, object]) -> Dict[str, object]:
        if not self.rollback_token:
            raise SoarViolation("APPLY_WITHOUT_PREPARE")
        new_state = dict(state)
        new_state.update(changes)
        self.applied = True
        return new_state

    def rollback(self, state: Dict[str, object]) -> Dict[str, object]:
        if not self.applied:
            raise SoarViolation("ROLLBACK_WITHOUT_APPLY")
        self.applied = False
        return dict(self.snapshot)


class ActionVerifier:
    def verify(self, before: Dict[str, object], after: Dict[str, object],
               intended: Iterable[str]) -> Dict[str, object]:
        intended = list(intended)
        missing = [k for k in intended if before.get(k) == after.get(k)]
        collateral: List[str] = [
            k for k in set(before) | set(after)
            if k not in intended and before.get(k) != after.get(k)
        ]
        ok = not missing and not collateral
        return {"verified": ok, "unchanged_targets": missing,
                "collateral_changes": sorted(collateral),
                "state": "ACTION_VERIFIED" if ok else "ACTION_EFFECT_UNPROVEN"}


class BlastRadiusReport:
    """Summarises how much of the estate a wave of actions would touch."""

    def evaluate(self, actions: List[Dict[str, int]]) -> Dict[str, object]:
        total = {k: sum(a.get(k, 0) for a in actions) for k in DEFAULT_CAPS}
        exceeded = [k for k, v in total.items() if v > DEFAULT_CAPS[k]]
        return {"totals": total, "caps": dict(DEFAULT_CAPS),
                "exceeded": exceeded,
                "state": "WITHIN_BLAST_RADIUS" if not exceeded else "BLAST_RADIUS_EXCEEDED"}
