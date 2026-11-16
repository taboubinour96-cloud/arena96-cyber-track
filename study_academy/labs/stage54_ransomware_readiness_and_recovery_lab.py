"""
Stage 54 Defensive Lab — Ransomware Readiness & Recovery Proof
==============================================================
1. ContainmentPlanner: if a host shares a credential with anything, that
   anything is already exposed. Exposure is computed from shared identity,
   not from network distance.
2. BackupGate: a backup the attacker can delete is not a backup. Deletion
   needs a second approver, and only immutable + off-identity backups
   count as safe copies.
3. RestoreDrillEvaluator: RPO/RTO are measured, never declared; and a
   restore that reaches the target too fast usually means the drill never
   actually ran.
"""

from __future__ import annotations

from typing import Dict, Iterable, List


class ReadinessViolation(Exception):
    """Raised when readiness inputs contradict the model."""


class ContainmentPlanner:
    def __init__(self, host_credentials: Dict[str, Iterable[str]]):
        if not host_credentials:
            raise ReadinessViolation("NO_HOSTS_DECLARED")
        self.host_creds = {h: sorted(set(c)) for h, c in host_credentials.items()}

    def isolation_set(self, infected: Iterable[str]) -> Dict[str, object]:
        infected = [h for h in infected if h in self.host_creds]
        if not infected:
            raise ReadinessViolation("UNKNOWN_INFECTED_HOST")
        exposed: List[str] = []
        shared: List[str] = []
        infected_creds = set()
        for host in infected:
            infected_creds.update(self.host_creds[host])
        for host, creds in sorted(self.host_creds.items()):
            if host in infected:
                continue
            overlap = sorted(set(creds) & infected_creds)
            if overlap:
                exposed.append(host)
                shared.extend(overlap)
        order = list(infected) + exposed
        return {"isolation_order": order, "exposed_by_shared_credential": exposed,
                "shared_credentials": sorted(set(shared)),
                "state": "CONTAINMENT_MAP_READY"}


class BackupGate:
    def __init__(self, copies: Iterable[Dict[str, object]]):
        self.copies = list(copies)
        if not self.copies:
            raise ReadinessViolation("NO_BACKUP_COPIES")

    def classify(self) -> Dict[str, object]:
        safe = [c for c in self.copies
                if c.get("immutable") and c.get("separate_identity")]
        unsafe = [c for c in self.copies if c not in safe]
        return {"safe_copies": len(safe), "unsafe_copies": len(unsafe),
                "safe_ids": [c["id"] for c in safe],
                "unsafe_ids": [c["id"] for c in unsafe],
                "state": "SAFE_BACKUPS_PRESENT" if safe else "NO_SAFE_BACKUP"}

    def delete(self, copy_id: str, approvers: Iterable[str]) -> Dict[str, object]:
        target = next((c for c in self.copies if c["id"] == copy_id), None)
        if target is None:
            raise ReadinessViolation(f"UNKNOWN_COPY_{copy_id}")
        if target.get("immutable"):
            return {"deleted": False, "state": "DELETE_DENIED_IMMUTABLE_COPY"}
        names = sorted({a for a in approvers if a})
        if len(names) < 2:
            return {"deleted": False, "state": "DELETE_DENIED_NEEDS_DUAL_APPROVAL"}
        self.copies = [c for c in self.copies if c["id"] != copy_id]
        return {"deleted": True, "approvers": names, "state": "COPY_DELETED_WITH_DUAL_APPROVAL"}


class RestoreDrillEvaluator:
    def __init__(self, max_rpo_minutes: int, max_rto_minutes: int):
        self.max_rpo = max_rpo_minutes
        self.max_rto = max_rto_minutes

    def evaluate(self, systems: Iterable[Dict[str, object]]) -> Dict[str, object]:
        failures: List[str] = []
        measured: Dict[str, Dict[str, int]] = {}
        for s in systems:
            rpo = int(s.get("rpo_minutes", 10 ** 6))
            rto = int(s.get("rto_minutes", 10 ** 6))
            drilled = bool(s.get("drilled"))
            name = s["name"]
            measured[name] = {"rpo_minutes": rpo, "rto_minutes": rto}
            if not drilled:
                failures.append(f"{name}:NOT_DRILLED")
            if rpo > self.max_rpo:
                failures.append(f"{name}:RPO_EXCEEDED")
            if rto > self.max_rto:
                failures.append(f"{name}:RTO_EXCEEDED")
        ready = not failures
        return {"measured": measured, "failures": failures,
                "restore_gate_passed": ready,
                "state": "RESTORE_PROVEN" if ready else "RESTORE_UNPROVEN"}


class RansomwareReadinessMatrix:
    """All four capabilities must hold at once."""

    def evaluate(self, containment: bool, safe_backups: bool,
                 restore_proven: bool, evidence_preserved: bool) -> Dict[str, object]:
        missing = []
        if not containment:
            missing.append("containment")
        if not safe_backups:
            missing.append("safe_backups")
        if not restore_proven:
            missing.append("restore_proven")
        if not evidence_preserved:
            missing.append("evidence_preserved")
        return {"ready": not missing, "missing": missing,
                "state": "READY" if not missing else "NOT_READY"}
