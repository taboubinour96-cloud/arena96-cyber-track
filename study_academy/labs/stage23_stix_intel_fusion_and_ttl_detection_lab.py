"""
Stage 23 Defensive Lab — Threat-Intel Fusion, Confidence Decay & Intel-to-Detection TTL
==========================================================================================
1. ThreatIntelFusionEngine:
   - Fuses STIX-style indicators from multiple sources: reliability-weighted
     confidence, exponential decay with age, and revocation handling.
     Indicators below the confidence floor or revoked/expired never fire.
2. IntelToDetectionCompiler:
   - Compiles fused indicators into expiring detection rules (intel-to-detection
     pipeline) and matches telemetry against only LIVE rules.
3. ObservationRiskScorer:
   - Scores an observed indicator hit by fused confidence x asset criticality,
     producing a deterministic triage band (critical/high/monitor).
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Dict, List, Tuple


class IntelViolation(Exception):
    """Raised when a threat-intel rule is violated."""


class ThreatIntelFusionEngine:
    def __init__(self, half_life_seconds: int = 86_400, confidence_floor: float = 0.35) -> None:
        self.half_life = half_life_seconds
        self.floor = confidence_floor
        self._reports: Dict[str, List[Dict[str, object]]] = {}
        self._revoked: set = set()

    def ingest_report(self, indicator: str, source: str, reliability: float, confidence: float, observed_ts: int) -> None:
        if not (0.0 <= reliability <= 1.0 and 0.0 <= confidence <= 1.0):
            raise IntelViolation("CONFIDENCE_OR_RELIABILITY_OUT_OF_RANGE")
        self._reports.setdefault(indicator, []).append({
            "source": source, "reliability": float(reliability),
            "confidence": float(confidence), "ts": int(observed_ts),
        })

    def revoke(self, indicator: str) -> None:
        self._revoked.add(indicator)

    def fused_confidence(self, indicator: str, now_ts: int) -> Tuple[float, str]:
        if indicator in self._revoked:
            return 0.0, "INDICATOR_REVOKED"
        reports = self._reports.get(indicator, [])
        if not reports:
            return 0.0, "NO_INTEL"
        # Reliability-weighted, time-decayed evidence accumulation (noisy-OR).
        survival = 1.0
        for r in reports:
            age = max(0, now_ts - int(r["ts"]))  # type: ignore[arg-type]
            decay = math.pow(0.5, age / self.half_life) if self.half_life else 1.0
            evidence = float(r["reliability"]) * float(r["confidence"]) * decay  # type: ignore[arg-type]
            survival *= (1.0 - evidence)
        fused = round(1.0 - survival, 4)
        state = "LIVE" if fused >= self.floor else "BELOW_CONFIDENCE_FLOOR_STALE"
        return fused, state


class IntelToDetectionCompiler:
    def __init__(self, fusion: ThreatIntelFusionEngine) -> None:
        self.fusion = fusion

    def compile_rules(self, indicators: List[str], now_ts: int, ttl_seconds: int = 604_800) -> List[Dict[str, object]]:
        rules = []
        for ind in indicators:
            conf, state = self.fusion.fused_confidence(ind, now_ts)
            if state != "LIVE":
                continue
            payload = {"indicator": ind, "confidence": conf, "expires_at": now_ts + ttl_seconds}
            payload["rule_id"] = "INTEL-" + hashlib.sha256(
                json.dumps(payload, sort_keys=True).encode()
            ).hexdigest()[:10]
            rules.append(payload)
        return sorted(rules, key=lambda r: str(r["indicator"]))

    @staticmethod
    def match(event_value: str, rules: List[Dict[str, object]], now_ts: int) -> Tuple[bool, str]:
        for r in rules:
            if r["indicator"] == event_value:
                if now_ts > int(r["expires_at"]):  # type: ignore[arg-type]
                    return False, "INTEL_RULE_EXPIRED_NO_FIRE"
                return True, f"MATCHED_{r['rule_id']}"
        return False, "NO_INTEL_MATCH"


class ObservationRiskScorer:
    _CRITICALITY = {"crown_jewel": 1.0, "production": 0.7, "workstation": 0.4, "sandbox": 0.1}

    def score(self, fused_confidence: float, asset_class: str) -> Dict[str, object]:
        crit = self._CRITICALITY.get(asset_class)
        if crit is None:
            raise IntelViolation(f"UNKNOWN_ASSET_CLASS_{asset_class}")
        risk = round(float(fused_confidence) * crit * 100.0, 2)
        band = "critical" if risk >= 70 else "high" if risk >= 40 else "monitor" if risk >= 15 else "log_only"
        return {"risk_score": risk, "band": band, "asset_class": asset_class}
