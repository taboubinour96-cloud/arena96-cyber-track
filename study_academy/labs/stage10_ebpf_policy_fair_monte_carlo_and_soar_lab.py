"""
مختبر المرحلة 10: رصد النواة عبر eBPF LSM، محاكاة المخاطر المالية FAIR بمونت كارلو، ومحرك SOAR السيادي
"""

from __future__ import annotations

import random
from typing import Any, Dict, List


class EBPFLSMKernelGuardSimulator:
    """Simulates in-kernel eBPF LSM hook blocking unauthorized container/process syscalls in sub-millisecond time."""

    SENSITIVE_PATHS = ("/etc/shadow", "/var/run/docker.sock", "/run/secrets/kubernetes.io/serviceaccount/token")

    @classmethod
    def evaluate_syscall_event(cls, event: Dict[str, Any]) -> Dict[str, Any]:
        syscall = event.get("syscall", "")
        target_path = event.get("path", "")
        is_container = bool(event.get("in_container", False))
        binary = event.get("binary", "")

        if is_container and syscall in {"open", "openat"} and any(target_path.startswith(p) for p in cls.SENSITIVE_PATHS):
            return {"verdict": "SIGKILL_AND_DENY", "errno": "EPERM", "rule": "EBPF-LSM-001-SENSITIVE-MOUNT"}

        if is_container and syscall == "execve" and binary in {"/bin/nc", "/usr/bin/ncat", "/bin/socat"}:
            return {"verdict": "SIGKILL_AND_DENY", "errno": "EPERM", "rule": "EBPF-LSM-002-REVERSE-SHELL-BIN"}

        return {"verdict": "ALLOW", "errno": None, "rule": None}


class FAIRMonteCarloRiskSimulator:
    """Quantitative CISO Cyber Risk Engine computing Expected Annual Loss & 95th-Percentile VaR."""

    @staticmethod
    def simulate_annual_risk(
        trials: int = 2000,
        tef_min: float = 0.5,
        tef_max: float = 4.0,
        vuln_prob: float = 0.20,
        loss_min_usd: float = 15_000.0,
        loss_max_usd: float = 250_000.0,
        seed: int = 96,
    ) -> Dict[str, float]:
        rng = random.Random(seed)
        annual_losses: List[float] = []
        for _ in range(trials):
            attempts = int(round(rng.uniform(tef_min, tef_max)))
            year_loss = 0.0
            for _ in range(attempts):
                if rng.random() < vuln_prob:
                    year_loss += rng.triangular(loss_min_usd, loss_max_usd, (loss_min_usd + loss_max_usd) * 0.35)
            annual_losses.append(year_loss)

        annual_losses.sort()
        mean_ale = sum(annual_losses) / len(annual_losses)
        var_95 = annual_losses[int(0.95 * len(annual_losses))]
        return {
            "expected_annual_loss_usd": round(mean_ale, 2),
            "var_95_percentile_usd": round(var_95, 2),
        }


class SovereignSOAROrchestrator:
    """Distinguishes immediate local safe containment from high-impact actions gated by Noor's Sovereign Approval."""

    HIGH_IMPACT_ACTIONS = {"shutdown_production_cluster", "notify_external_regulator", "revoke_org_root_ca"}

    @classmethod
    def run_playbook_step(cls, action: str, target: str, owner_approval_signature: str = "") -> Dict[str, Any]:
        if action in cls.HIGH_IMPACT_ACTIONS and not owner_approval_signature.strip():
            return {
                "executed": False,
                "status": "QUEUED_IN_NOOR_SOVEREIGN_GATE",
                "action": action,
                "target": target,
            }
        return {"executed": True, "status": "CONTAINMENT_APPLIED", "action": action, "target": target}
