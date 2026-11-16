"""
Stage 40 Defensive Lab — Insider Risk & UEBA: Behaviour Signals to Cases
==========================================================================
1. BehaviourRiskScorer: single actions are weak signals; impossible travel,
   mass downloads, off-hours privilege use and dormant-account revivals
   accumulate into a defensible risk score.
2. InsiderCaseBuilder: only stacked signals open a case — one odd event is
   coaching territory, a pattern is an investigation with evidence attached.
"""

from __future__ import annotations

from typing import Dict, List


class InsiderViolation(Exception):
    """Raised when an insider-risk rule is violated."""


class BehaviourRiskScorer:
    def score(self, event: Dict[str, object]) -> Dict[str, object]:
        signals: List[str] = []
        score = 0
        if event.get("country_changed_within_1h"):
            signals.append("IMPOSSIBLE_TRAVEL"); score += 35
        downloads = int(event.get("downloads_1h", 0))
        if downloads >= 500:
            signals.append("MASS_DOWNLOAD"); score += 30
        elif downloads >= 100:
            signals.append("ELEVATED_DOWNLOAD"); score += 12
        if event.get("off_hours_privileged"):
            signals.append("OFF_HOURS_PRIVILEGE"); score += 20
        if event.get("dormant_days", 0) and int(event.get("dormant_days", 0)) >= 60 and downloads > 0:
            signals.append("DORMANT_ACCOUNT_REVIVAL_ACTIVITY"); score += 15
        band = "critical" if score >= 60 else ("high" if score >= 40 else ("medium" if score >= 20 else "low"))
        return {"risk_score": score, "band": band, "signals": signals}


class InsiderCaseBuilder:
    def build(self, user: str, scored_events: List[Dict[str, object]]) -> Dict[str, object]:
        total = sum(int(e.get("risk_score", 0)) for e in scored_events)
        all_signals = sorted({s for e in scored_events for s in e.get("signals", [])})
        if total >= 60 and len(all_signals) >= 2:
            return {"case_opened": True, "state": "INSIDER_CASE_OPENED_PATTERN_CONFIRMED",
                    "user": user, "total_score": total, "signals": all_signals}
        return {"case_opened": False, "state": "NO_CASE_SINGLE_SIGNAL_COACH_OR_MONITOR",
                "user": user, "total_score": total, "signals": all_signals}
