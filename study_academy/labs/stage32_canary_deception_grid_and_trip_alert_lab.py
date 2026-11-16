"""
Stage 32 Defensive Lab — Canary Tokens, Deception Grid Coverage & Tripwire Alerting
======================================================================================
1. CanaryTokenRegistry:
   - Issues HMAC-bound canary IDs for decoy files, credentials, API keys and
     DNS names. Canaries have NO legitimate use: any verified trigger is by
     definition a high-fidelity breach signal (critical, near-zero noise).
     Forged/unknown canary IDs are rejected instead of alerting.
2. DeceptionGridPlanner:
   - Measures deception coverage: every crown-jewel asset needs at least one
     canary, and coverage below the floor denies the deception gate.
3. HoneyInteractionClassifier:
   - Grades honeypot interaction depth (scan < auth attempt < exploit-shaped
     payload) so response scales with attacker commitment.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Dict, List, Set, Tuple


class DeceptionViolation(Exception):
    """Raised when a deception-defense rule is violated."""


class CanaryTokenRegistry:
    _TYPES = {"file", "credential", "api_key", "dns", "database_row"}

    def __init__(self, registry_key: bytes) -> None:
        if len(registry_key) < 16:
            raise DeceptionViolation("CANARY_REGISTRY_KEY_TOO_SHORT")
        self._key = registry_key
        self._issued: Dict[str, Dict[str, object]] = {}

    def _canary_id(self, canary_type: str, asset: str, nonce: str) -> str:
        msg = json.dumps({"type": canary_type, "asset": asset, "nonce": nonce}, sort_keys=True).encode()
        return "canary-" + hmac.new(self._key, msg, hashlib.sha256).hexdigest()[:20]

    def issue(self, canary_type: str, asset: str, nonce: str) -> Dict[str, object]:
        if canary_type not in self._TYPES:
            raise DeceptionViolation(f"UNKNOWN_CANARY_TYPE_{canary_type}")
        cid = self._canary_id(canary_type, asset, nonce)
        record = {"canary_id": cid, "type": canary_type, "asset": asset}
        self._issued[cid] = record
        return record

    def trigger(self, canary_id: str, source_context: str) -> Tuple[bool, str, Dict[str, object]]:
        record = self._issued.get(canary_id)
        if record is None:
            return False, "CANARY_UNKNOWN_OR_FORGED_NO_ALERT", {}
        alert = {
            "severity": "critical",
            "canary_id": canary_id,
            "type": record["type"],
            "asset": record["asset"],
            "source_context": source_context,
            "signal": "CANARY_TRIPPED_BY_DEFINITION_MALICIOUS_OR_MISPLACED",
        }
        alert["alert_sha256"] = hashlib.sha256(json.dumps(alert, sort_keys=True).encode()).hexdigest()
        return True, "CANARY_ALERT_CRITICAL_HIGH_FIDELITY", alert

    def issued_assets(self) -> Set[str]:
        return {str(r["asset"]) for r in self._issued.values()}


class DeceptionGridPlanner:
    @staticmethod
    def coverage(crown_jewels: List[str], covered_assets: Set[str], floor_pct: float = 100.0) -> Dict[str, object]:
        if not crown_jewels:
            raise DeceptionViolation("NO_CROWN_JEWELS_DECLARED")
        covered = [a for a in crown_jewels if a in covered_assets]
        missing = [a for a in crown_jewels if a not in covered_assets]
        pct = round((len(covered) / len(crown_jewels)) * 100.0, 2)
        return {
            "coverage_pct": pct, "covered": covered, "missing": missing,
            "deception_gate_passed": pct >= floor_pct,
        }


class HoneyInteractionClassifier:
    _EXPLOIT_MARKERS = ["../", "union select", "<script", "$(", "; rm ", "/etc/passwd", "cmd.exe"]

    def classify(self, interaction: Dict[str, object]) -> Dict[str, object]:
        payload = str(interaction.get("payload", "")).lower()
        action = str(interaction.get("action", ""))
        if any(m in payload for m in self._EXPLOIT_MARKERS):
            depth, severity = "exploit_attempt", "critical"
        elif action in {"auth_attempt", "login"}:
            depth, severity = "auth_attempt", "high"
        elif action in {"port_scan", "banner_grab", "connect"}:
            depth, severity = "recon", "medium"
        else:
            depth, severity = "unknown_interaction", "review"
        return {"depth": depth, "severity": severity, "action": action}
