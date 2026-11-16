"""
Stage 55 Defensive Lab — Data Residency & Jurisdictional Routing
===============================================================
1. DataResidencyGate: a record may only cross into a jurisdiction that is
   approved for its classification — and a sovereign record may not live
   with its key held elsewhere.
2. JurisdictionRouter: picks exactly one eligible region; when none is
   eligible the answer is NO_ELIGIBLE_REGION, never the nearest guess.
3. AdequacyLedger: jurisdictions are approved per data class, with a
   legal basis reference; an expired basis is not a basis.
"""

from __future__ import annotations

from typing import Dict, Iterable, Set


class ResidencyViolation(Exception):
    """Raised when residency inputs are inconsistent."""


class DataResidencyGate:
    def __init__(self, approved_jurisdictions: Dict[str, Set[str]]):
        if not approved_jurisdictions:
            raise ResidencyViolation("NO_APPROVED_JURISDICTIONS")
        self.approved = {k: set(v) for k, v in approved_jurisdictions.items()}

    def evaluate(self, record: str, classification: str, origin: str,
                 destination: str, key_jurisdiction: str) -> Dict[str, object]:
        if classification not in self.approved:
            return {"allowed": False, "record": record,
                    "state": "DENIED_UNKNOWN_CLASSIFICATION"}
        if destination != origin and destination not in self.approved[classification]:
            return {"allowed": False, "record": record, "reason": "JURISDICTION_NOT_APPROVED",
                    "state": "DENIED_CROSS_BORDER_NO_ADEQUACY"}
        if classification == "sovereign" and key_jurisdiction != origin:
            return {"allowed": False, "record": record, "reason": "KEY_OUTSIDE_SOVEREIGN_JURISDICTION",
                    "origin": origin, "key_jurisdiction": key_jurisdiction,
                    "state": "DENIED_KEY_CUSTODY_MISMATCH"}
        return {"allowed": True, "record": record,
                "state": "ALLOWED_WITHIN_APPROVED_JURISDICTION"}


class JurisdictionRouter:
    def __init__(self, region_capacity: Dict[str, Dict[str, object]]):
        if not region_capacity:
            raise ResidencyViolation("NO_REGIONS")
        self.regions = region_capacity

    def route(self, classification: str, healthy: Iterable[str]) -> Dict[str, object]:
        healthy_set = set(healthy)
        candidates = [
            (name, meta) for name, meta in sorted(self.regions.items())
            if name in healthy_set
            and classification in set(meta.get("classes", []))
            and meta.get("status") == "ready"
        ]
        if not candidates:
            return {"selected": None, "state": "NO_ELIGIBLE_REGION",
                    "classification": classification}
        name, meta = candidates[0]
        return {"selected": name, "jurisdiction": meta.get("jurisdiction"),
                "state": "ROUTED_TO_ELIGIBLE_REGION", "classification": classification}


class AdequacyLedger:
    def __init__(self, entries: Iterable[Dict[str, object]]):
        self.entries = list(entries)
        if not self.entries:
            raise ResidencyViolation("EMPTY_ADEQUACY_LEDGER")

    def approved(self, jurisdiction: str, classification: str, now: int) -> Dict[str, object]:
        for e in self.entries:
            if e["jurisdiction"] == jurisdiction and e["classification"] == classification:
                if int(e.get("expires_at", 0)) <= now:
                    return {"approved": False, "basis": e.get("basis"),
                            "state": "ADEQUACY_EXPIRED"}
                if not e.get("basis"):
                    return {"approved": False, "state": "ADEQUACY_WITHOUT_LEGAL_BASIS"}
                return {"approved": True, "basis": e["basis"], "state": "ADEQUACY_VALID"}
        return {"approved": False, "state": "NO_ADEQUACY_RECORDED"}
