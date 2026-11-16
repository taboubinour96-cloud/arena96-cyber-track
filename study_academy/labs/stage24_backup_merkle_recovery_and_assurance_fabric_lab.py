"""
Stage 24 Defensive Lab — Merkle-Verified Backups, Recovery Objectives & Sovereign Assurance Fabric
====================================================================================================
1. MerkleBackupVault:
   - Chunks data, builds a SHA-256 Merkle root over chunks, and verifies a
     restore chunk-by-chunk: a single corrupted/tampered chunk is located
     exactly and the restore fails closed instead of trusting bad data.
2. RecoveryObjectiveSimulator:
   - Simulates failover against declared RTO/RPO objectives: data-loss window
     and restore duration are measured, not asserted; breaches are explicit.
3. SovereignAssuranceFabric:
   - Fuses per-domain measured scores (supply-chain, detection, shield,
     recovery) with mandatory minimum gates into one signed enterprise
     attestation. Any domain below its gate fails the whole attestation.
"""

from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Tuple


class ResilienceViolation(Exception):
    """Raised when a resilience/assurance rule is violated."""


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class MerkleBackupVault:
    def __init__(self, chunk_size: int = 16) -> None:
        self.chunk_size = chunk_size

    @staticmethod
    def _merkle_root(leaves: List[str]) -> str:
        if not leaves:
            return _h(b"EMPTY")
        level = leaves[:]
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                nxt.append(_h((left + right).encode()))
            level = nxt
        return level[0]

    def backup(self, data: bytes) -> Dict[str, object]:
        chunks = [data[i:i + self.chunk_size] for i in range(0, len(data), self.chunk_size)] or [b""]
        leaves = [_h(c) for c in chunks]
        return {"chunks": chunks, "chunk_hashes": leaves, "merkle_root": self._merkle_root(leaves), "size": len(data)}

    def verify_restore(self, snapshot: Dict[str, object], chunks: List[bytes]) -> Tuple[bool, str]:
        if len(chunks) != len(snapshot["chunk_hashes"]):  # type: ignore[arg-type]
            return False, "RESTORE_CHUNK_COUNT_MISMATCH"
        for idx, (chunk, expect) in enumerate(zip(chunks, snapshot["chunk_hashes"])):  # type: ignore[arg-type]
            if _h(chunk) != expect:
                return False, f"RESTORE_CORRUPT_CHUNK_LOCATED_{idx}"
        leaves = [_h(c) for c in chunks]
        if self._merkle_root(leaves) != snapshot["merkle_root"]:
            return False, "RESTORE_MERKLE_ROOT_MISMATCH"
        return True, "RESTORE_VERIFIED_MERKLE_OK"


class RecoveryObjectiveSimulator:
    def simulate_failover(self, *, last_backup_ts: int, incident_ts: int, restore_started_ts: int,
                          service_restored_ts: int, rpo_seconds: int, rto_seconds: int) -> Dict[str, object]:
        data_loss = incident_ts - last_backup_ts
        restore_duration = service_restored_ts - restore_started_ts
        return {
            "data_loss_seconds": data_loss,
            "restore_duration_seconds": restore_duration,
            "rpo_seconds": rpo_seconds,
            "rto_seconds": rto_seconds,
            "rpo_met": data_loss <= rpo_seconds,
            "rto_met": restore_duration <= rto_seconds,
            "objectives_met": data_loss <= rpo_seconds and restore_duration <= rto_seconds,
        }


class SovereignAssuranceFabric:
    GATES = {"supply_chain": 90.0, "detection": 80.0, "shield": 90.0, "recovery": 85.0}

    @staticmethod
    def attest(domain_scores: Dict[str, float]) -> Dict[str, object]:
        missing = [d for d in SovereignAssuranceFabric.GATES if d not in domain_scores]
        if missing:
            raise ResilienceViolation(f"ASSURANCE_MISSING_DOMAIN_{missing[0]}")
        gates = {
            d: {"score": float(domain_scores[d]), "gate": g, "passed": float(domain_scores[d]) >= g}
            for d, g in SovereignAssuranceFabric.GATES.items()
        }
        all_passed = all(v["passed"] for v in gates.values())
        composite = round(sum(float(domain_scores[d]) for d in SovereignAssuranceFabric.GATES) / len(SovereignAssuranceFabric.GATES), 2)
        payload = {
            "domains": gates,
            "composite_score_pct": composite,
            "all_gates_passed": all_passed,
            "verdict": "SOVEREIGN_ASSURANCE_GRANTED" if all_passed else "ASSURANCE_DENIED_DOMAIN_BELOW_GATE",
        }
        payload["attestation_sha256"] = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()
        return payload
