"""
Stage 48 Defensive Lab — Transaction Fraud Risk: Velocity, Anomaly & New-Payee Signals
==========================================================================================
1. FraudRiskEngine: a payment is scored by stacked signals — amount anomaly
   versus the account's own history, hourly velocity, first-seen payee,
   geo mismatch and unknown device.
2. DecisionBands: low risk flows, stacked risk steps up to human review,
   and critical combinations block outright — friction proportional to risk.
"""

from __future__ import annotations

from typing import Dict, List


class FraudViolation(Exception):
    """Raised when a fraud-engine rule is violated."""


class FraudRiskEngine:
    def score(self, txn: Dict[str, object]) -> Dict[str, object]:
        signals: List[str] = []
        score = 0
        amount = float(txn.get("amount", 0))
        average = float(txn.get("account_avg_amount", 1)) or 1.0
        if amount >= average * 10:
            signals.append("AMOUNT_ANOMALY_10X"); score += 30
        elif amount >= average * 4:
            signals.append("AMOUNT_ELEVATED"); score += 12
        if int(txn.get("txns_last_hour", 0)) >= 8:
            signals.append("VELOCITY_BURST"); score += 25
        if bool(txn.get("new_payee")):
            signals.append("FIRST_SEEN_PAYEE"); score += 15
        if bool(txn.get("geo_mismatch")):
            signals.append("GEO_MISMATCH"); score += 15
        if not bool(txn.get("known_device", True)):
            signals.append("UNKNOWN_DEVICE"); score += 15
        decision = "BLOCK" if score >= 60 else ("STEP_UP_REVIEW" if score >= 30 else "ALLOW")
        return {"risk_score": score, "decision": decision, "signals": signals}
