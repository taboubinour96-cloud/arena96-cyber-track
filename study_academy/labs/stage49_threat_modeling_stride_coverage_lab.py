"""
Stage 49 Defensive Lab — Threat Modelling: STRIDE Coverage & Mitigation Gates
================================================================================
1. ThreatModelRegistry: each component declares its applicable STRIDE
   threats; a design may not ship while an applicable threat lacks a
   mitigation or an explicitly accepted risk with an owner.
2. ResidualRisk: mitigations reduce, never erase — residual scores keep
   the conversation honest after the checklist is green.
"""

from __future__ import annotations

from typing import Dict, List


class ThreatModelViolation(Exception):
    """Raised when a threat-modelling rule is violated."""


STRIDE = ["spoofing", "tampering", "repudiation", "information_disclosure", "denial_of_service", "elevation_of_privilege"]


class ThreatModelRegistry:
    def evaluate(self, component: str, applicable: List[str],
                 mitigations: Dict[str, str], accepted_risks: Dict[str, str]) -> Dict[str, object]:
        unknown = [t for t in applicable if t not in STRIDE]
        if unknown:
            raise ThreatModelViolation(f"UNKNOWN_STRIDE_CATEGORY_{unknown}")
        uncovered = [t for t in applicable if t not in mitigations and t not in accepted_risks]
        coverage = round(((len(applicable) - len(uncovered)) / len(applicable)) * 100.0, 2) if applicable else 100.0
        return {"component": component, "coverage_pct": coverage, "uncovered": uncovered,
                "design_gate_passed": not uncovered,
                "state": "THREAT_MODEL_COMPLETE" if not uncovered else "THREAT_MODEL_GAPS_BLOCK_DESIGN"}
