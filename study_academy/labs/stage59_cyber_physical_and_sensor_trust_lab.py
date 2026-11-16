"""
Stage 59 Defensive Lab — Cyber-Physical Systems & Sensor Trust
=============================================================
1. SensorTrustGate: a physical decision needs corroboration from at least
   two independent sensors, each inside its freshness window. A fresh wrong
   reading is survivable; a stale right one is not.
2. SafeActuationPlanner: every actuator declares its safe state and a
   manual takeover path. Safety wins over security when they conflict.
3. CommandIntegrityGuard: OT commands must be signed, in sequence, inside a
   value range and inside a time window. Replays and out-of-range values
   are refused with distinct reasons.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Dict, Iterable, List


class PhysicalViolation(Exception):
    """Raised when a cyber-physical invariant is broken."""


class SensorTrustGate:
    def __init__(self, max_age_seconds: int = 5, min_sources: int = 2):
        if max_age_seconds <= 0 or min_sources < 2:
            raise PhysicalViolation("INVALID_SENSOR_POLICY")
        self.max_age = max_age_seconds
        self.min_sources = min_sources

    def evaluate(self, readings: Iterable[Dict[str, object]], now: int,
                 plausibility: tuple[float, float] | None = None) -> Dict[str, object]:
        fresh: List[str] = []
        stale: List[str] = []
        implausible: List[str] = []
        for r in readings:
            name = str(r["source"])
            age = now - int(r["ts"])
            if age > self.max_age:
                stale.append(name)
                continue
            if plausibility is not None and not (plausibility[0] <= float(r["value"]) <= plausibility[1]):
                implausible.append(name)
                continue
            fresh.append(name)
        decision = len(fresh) >= self.min_sources
        return {"decision_allowed": decision, "fresh": sorted(fresh),
                "stale": sorted(stale), "implausible": sorted(implausible),
                "state": "CORROBORATED_DECISION_ALLOWED" if decision
                else "DECISION_BLOCKED_INSUFFICIENT_FRESH_SOURCES"}


class SafeActuationPlanner:
    SAFE_STATES = {"open", "closed", "stopped", "vented", "isolated"}

    def __init__(self, actuators: Iterable[Dict[str, object]]):
        self.actuators = {a["name"]: dict(a) for a in actuators}
        if not self.actuators:
            raise PhysicalViolation("NO_ACTUATORS")

    def evaluate(self) -> Dict[str, object]:
        problems: List[str] = []
        for name, a in sorted(self.actuators.items()):
            if a.get("safe_state") not in self.SAFE_STATES:
                problems.append(f"{name}:UNDEFINED_SAFE_STATE")
            if not a.get("manual_takeover"):
                problems.append(f"{name}:NO_MANUAL_TAKEOVER")
            if not a.get("physically_tested"):
                problems.append(f"{name}:SAFE_STATE_UNTESTED")
        return {"problems": problems, "actuators": sorted(self.actuators),
                "plan_approved": not problems,
                "state": "SAFE_ACTUATION_PLAN_APPROVED" if not problems
                else "SAFE_ACTUATION_PLAN_REJECTED"}

    def on_failure(self, name: str) -> Dict[str, object]:
        a = self.actuators.get(name)
        if a is None:
            raise PhysicalViolation(f"UNKNOWN_ACTUATOR_{name}")
        return {"actuator": name, "move_to": a["safe_state"],
                "manual_path": a.get("manual_takeover"),
                "state": "FAILED_TO_SAFE_STATE"}


class CommandIntegrityGuard:
    def __init__(self, secret: bytes, allowed_range: tuple[float, float],
                 window_seconds: int = 30):
        self.secret = secret
        self.allowed_range = allowed_range
        self.window = window_seconds
        self.last_seq = 0

    def _sign(self, payload: str) -> str:
        return hmac.new(self.secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def issue(self, device: str, value: float, seq: int, ts: int) -> Dict[str, object]:
        payload = f"{device}|{value}|{seq}|{ts}"
        return {"device": device, "value": value, "seq": seq, "ts": ts,
                "sig": self._sign(payload)}

    def accept(self, command: Dict[str, object], now: int) -> Dict[str, object]:
        expected = self._sign(f"{command['device']}|{command['value']}|{command['seq']}|{command['ts']}")
        if not hmac.compare_digest(expected, str(command.get("sig", ""))):
            return {"accepted": False, "state": "COMMAND_REJECTED_BAD_SIGNATURE"}
        if int(command["seq"]) <= self.last_seq:
            return {"accepted": False, "state": "COMMAND_REJECTED_REPLAY_OR_OUT_OF_ORDER"}
        if now - int(command["ts"]) > self.window:
            return {"accepted": False, "state": "COMMAND_REJECTED_EXPIRED"}
        if not (self.allowed_range[0] <= float(command["value"]) <= self.allowed_range[1]):
            return {"accepted": False, "state": "COMMAND_REJECTED_OUT_OF_RANGE"}
        self.last_seq = int(command["seq"])
        return {"accepted": True, "state": "COMMAND_ACCEPTED"}
