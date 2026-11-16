"""
Stage 60 Defensive Lab — Final Capstone: Sovereign Security Operating Model
===========================================================================
1. ControlEvidenceRegistry: a control is only "proven" when a verifiable
   evidence artifact exists. Missing evidence is unproven, never "pending".
2. OperatingModelGate: every control needs an owner AND a deputy; build and
   approve duties may not sit in one person.
3. BoardRiskReport: reports impact and downtime in decision language, states
   the uncovered percentage explicitly, and forces a decision on every item.
4. AcademyCharterGate: the closing gate — no charter passes unless all
   sixty control families clear one measurement gate with no exception.
"""

from __future__ import annotations

from typing import Dict, Iterable, List


class CapstoneViolation(Exception):
    """Raised when the operating model is internally inconsistent."""


class ControlEvidenceRegistry:
    def __init__(self, controls: Iterable[Dict[str, object]]):
        self.controls = {c["id"]: dict(c) for c in controls}
        if not self.controls:
            raise CapstoneViolation("NO_CONTROLS_DECLARED")

    def status(self) -> Dict[str, object]:
        proven, unproven = [], []
        for cid, c in sorted(self.controls.items()):
            has_source = bool(c.get("evidence_source")) and bool(c.get("evidence_digest"))
            if has_source and c.get("verified"):
                proven.append(cid)
            else:
                unproven.append(cid)
        total = len(self.controls)
        pct = round(100.0 * len(proven) / total, 1)
        return {"proven": proven, "unproven": unproven, "coverage_pct": pct,
                "state": "ALL_CONTROLS_PROVEN" if not unproven else "CONTROLS_UNPROVEN"}

    def add_evidence(self, cid: str, source: str, digest: str) -> Dict[str, object]:
        if cid not in self.controls:
            raise CapstoneViolation(f"UNKNOWN_CONTROL_{cid}")
        if not source or not digest:
            return {"accepted": False, "state": "EVIDENCE_REJECTED_INCOMPLETE"}
        self.controls[cid].update({"evidence_source": source,
                                   "evidence_digest": digest, "verified": True})
        return {"accepted": True, "state": "EVIDENCE_ATTACHED_TO_CONTROL"}


class OperatingModelGate:
    def evaluate(self, controls: Iterable[Dict[str, object]],
                 people: Dict[str, Dict[str, object]]) -> Dict[str, object]:
        problems: List[str] = []
        for c in controls:
            owner = c.get("owner")
            deputy = c.get("deputy")
            if not owner:
                problems.append(f"{c['id']}:NO_OWNER")
                continue
            if not deputy:
                problems.append(f"{c['id']}:NO_DEPUTY")
            if owner == deputy:
                problems.append(f"{c['id']}:OWNER_IS_DEPUTY")
            # Separation of duties applies to BOTH accountable people: a
            # deputy who can build and approve can silently replace the owner.
            for role_holder in {str(owner), str(deputy)}:
                roles = set(people.get(role_holder, {}).get("roles", []))
                if {"build", "approve"} <= roles:
                    problems.append(
                        f"{c['id']}:BUILD_AND_APPROVE_SAME_PERSON:{role_holder}"
                    )
        return {"problems": problems, "gate_passed": not problems,
                "state": "OPERATING_MODEL_APPROVED" if not problems
                else "OPERATING_MODEL_REJECTED"}


class BoardRiskReport:
    def __init__(self, measured_controls: int, total_controls: int):
        if total_controls <= 0 or measured_controls < 0:
            raise CapstoneViolation("INVALID_COVERAGE_INPUT")
        if measured_controls > total_controls:
            raise CapstoneViolation("MEASURED_EXCEEDS_TOTAL")
        self.measured = measured_controls
        self.total = total_controls

    def build(self, items: Iterable[Dict[str, object]]) -> Dict[str, object]:
        rows: List[Dict[str, object]] = []
        for it in items:
            if not it.get("decision"):
                raise CapstoneViolation(f"ITEM_WITHOUT_DECISION_{it.get('id')}")
            rows.append({"id": it["id"], "impact": it.get("impact", "unknown"),
                         "downtime_hours": int(it.get("downtime_hours", 0)),
                         "decision": it["decision"]})
        unmeasured_pct = round(100.0 * (self.total - self.measured) / self.total, 1)
        return {"rows": rows, "unmeasured_pct": unmeasured_pct,
                "total_downtime_hours": sum(r["downtime_hours"] for r in rows),
                "state": "BOARD_REPORT_READY_WITH_DISCLOSED_GAPS"}


class AcademyCharterGate:
    def __init__(self, expected_families: int = 60):
        self.expected = expected_families

    def evaluate(self, passed_families: Iterable[str],
                 exceptions: Iterable[str] = ()) -> Dict[str, object]:
        passed = sorted(set(passed_families))
        exc = sorted(set(exceptions))
        complete = len(passed) == self.expected
        ok = complete and not exc
        if exc:
            state = "CHARTER_DENIED_WITH_EXCEPTIONS"
        elif not complete:
            state = "CHARTER_DENIED_INCOMPLETE_EVIDENCE"
        else:
            state = "CHARTER_APPROVED_ALL_FAMILIES_PROVEN"
        return {"families_passed": len(passed), "expected": self.expected,
                "exceptions": exc, "charter_passed": ok, "state": state}
