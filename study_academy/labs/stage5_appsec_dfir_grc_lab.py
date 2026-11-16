"""
المختبر العملي للمرحلة 5 (Stage 5 Hands-On AppSec SBOM, DFIR Chain-of-Custody & MITRE Coverage Lab) — أرينا 96
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List


# ============================================================================
# 1. CycloneDX-Style SBOM Supply-Chain Advisory Matcher (AppSec / DevSecOps)
# ============================================================================

def match_sbom_components_to_advisories(
    sbom_components: List[Dict[str, str]],
    advisories: Dict[str, List[str]],
) -> List[str]:
    """
    Matches `[{"name": "libwebp", "version": "1.3.1"}]` against known affected
    `{"libwebp@1.3.1": ["CVE-2023-4863"]}` records for rapid incident impact scoping.
    """
    hits: List[str] = []
    for comp in sbom_components:
        key = f"{comp['name']}@{comp['version']}"
        for cve in advisories.get(key, []):
            hits.append(f"{key} -> {cve}")
    return hits


# ============================================================================
# 2. DFIR Forensic Evidence Locker & Chain-of-Custody Integrity Verifier
# ============================================================================

@dataclass
class CustodyTransfer:
    from_custodian: str
    to_custodian: str
    purpose: str
    verified_sha256: str


@dataclass
class EvidenceRecord:
    evidence_id: str
    description: str
    volatility_rank: int  # 1 = RAM (most volatile) .. 5 = Archival backup
    acquisition_sha256: str
    transfers: List[CustodyTransfer] = field(default_factory=list)


class ForensicEvidenceLocker:
    """Maintains cryptographic SHA-256 Chain-of-Custody integrity across transfers."""

    def __init__(self) -> None:
        self._store: Dict[str, EvidenceRecord] = {}

    def acquire_evidence(
        self, evidence_id: str, description: str, volatility_rank: int, raw_bytes: bytes
    ) -> EvidenceRecord:
        digest = hashlib.sha256(raw_bytes).hexdigest()
        rec = EvidenceRecord(
            evidence_id=evidence_id,
            description=description,
            volatility_rank=volatility_rank,
            acquisition_sha256=digest,
        )
        self._store[evidence_id] = rec
        return rec

    def transfer_custody(
        self,
        evidence_id: str,
        from_custodian: str,
        to_custodian: str,
        purpose: str,
        current_bytes: bytes,
    ) -> bool:
        rec = self._store[evidence_id]
        current_hash = hashlib.sha256(current_bytes).hexdigest()
        if current_hash != rec.acquisition_sha256:
            raise ValueError(
                f"TAMPERING DETECTED on {evidence_id}: expected {rec.acquisition_sha256}, got {current_hash}"
            )
        rec.transfers.append(
            CustodyTransfer(from_custodian, to_custodian, purpose, current_hash)
        )
        return True


# ============================================================================
# 3. MITRE ATT&CK Threat-Informed Defense Coverage Calculator
# ============================================================================

def calculate_mitre_detection_coverage(
    technique_controls: Dict[str, Dict[str, bool]]
) -> Dict[str, float]:
    """
    Input example:
    {"T1059.001": {"logged": True, "alerted": True, "prevented": False}, ...}
    Returns telemetry_pct, alert_coverage_pct, and prevention_pct.
    """
    if not technique_controls:
        return {"telemetry_pct": 0.0, "alert_coverage_pct": 0.0, "prevention_pct": 0.0}

    total = len(technique_controls)
    logged = sum(1 for v in technique_controls.values() if v.get("logged"))
    alerted = sum(1 for v in technique_controls.values() if v.get("alerted"))
    prevented = sum(1 for v in technique_controls.values() if v.get("prevented"))

    return {
        "telemetry_pct": round((logged / total) * 100.0, 1),
        "alert_coverage_pct": round((alerted / total) * 100.0, 1),
        "prevention_pct": round((prevented / total) * 100.0, 1),
    }
