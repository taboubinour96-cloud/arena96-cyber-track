"""
Stage 51 Defensive Lab — Security Control Failure Drills: Fail-Closed Proofs
==============================================================================
1. ControlDrillEvaluator: every critical control must declare what happens
   when *it* fails. Drills score controls whose degraded mode fails closed
   and expose those that silently fail open.
2. DrillGate: a control plane with any critical fail-open fallback is not
   production-ready, however strong its happy path looks.
"""

from __future__ import annotations

from typing import Dict, List


class DrillViolation(Exception):
    """Raised when a control-drill rule is violated."""


class ControlDrillEvaluator:
    def evaluate(self, controls: List[Dict[str, object]]) -> Dict[str, object]:
        dangerous = sorted(str(c["name"]) for c in controls
                           if c.get("critical") and c.get("on_failure") == "fail_open")
        untested = sorted(str(c["name"]) for c in controls if not c.get("drilled"))
        passed = not dangerous
        return {"fail_open_critical": dangerous, "untested_controls": untested,
                "drill_gate_passed": passed and not untested,
                "state": "CONTROL_PLANE_FAILS_CLOSED" if passed and not untested else "CONTROL_PLANE_GAPS_PRESENT"}
