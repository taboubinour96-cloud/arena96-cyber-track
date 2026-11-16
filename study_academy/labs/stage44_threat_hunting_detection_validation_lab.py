"""
Stage 44 Defensive Lab — Threat Hunting & Detection Validation
================================================================
1. HuntEngine: hypothesis-driven hunting over telemetry — e.g. shells
   spawned by office/service parents, beacon-like regular callbacks —
   returns grouped evidence instead of dashboard vibes.
2. DetectionValidator: a detection library is only as good as its proven
   coverage; labelled cases (must-alert / must-not-alert) are executed and
   blind spots are named, so coverage is a measured percentage.
"""

from __future__ import annotations

from typing import Callable, Dict, List


class HuntViolation(Exception):
    """Raised when a hunting rule is violated."""


class HuntEngine:
    _SUSPICIOUS_PARENTS = {"winword.exe", "excel.exe", "outlook.exe", "wps.exe"}

    def hunt_shell_children(self, process_events: List[Dict[str, object]]) -> Dict[str, object]:
        hits = [e for e in process_events
                if str(e.get("parent", "")).lower() in self._SUSPICIOUS_PARENTS
                and str(e.get("process", "")).lower() in {"powershell.exe", "cmd.exe", "bash", "sh"}]
        hosts = sorted({str(e.get("host", "")) for e in hits})
        return {"hypothesis": "OFFICE_OR_MAIL_PARENT_SPAWNS_SHELL", "hit_count": len(hits), "hosts": hosts,
                "state": "HUNT_HITS_REQUIRE_TRIAGE" if hits else "HUNT_NO_HITS"}

    def hunt_beaconing(self, net_events: List[Dict[str, object]], min_callbacks: int = 5) -> Dict[str, object]:
        counts: Dict[str, int] = {}
        for event in net_events:
            key = f"{event.get('host')}->{event.get('dst')}"
            counts[key] = counts.get(key, 0) + 1
        beacons = sorted(k for k, v in counts.items() if v >= min_callbacks)
        return {"hypothesis": "REGULAR_CALLBACK_BEACONING", "beacons": beacons,
                "state": "HUNT_BEACONS_REQUIRE_TRIAGE" if beacons else "HUNT_NO_HITS"}


class DetectionValidator:
    def validate(self, detector: Callable[[Dict[str, object]], bool],
                 cases: List[Dict[str, object]]) -> Dict[str, object]:
        blind_spots: List[str] = []
        false_alarms: List[str] = []
        passed = 0
        for case in cases:
            got = bool(detector(case["event"]))
            if got == bool(case["should_alert"]):
                passed += 1
            elif case["should_alert"]:
                blind_spots.append(str(case["name"]))
            else:
                false_alarms.append(str(case["name"]))
        total = len(cases)
        return {"cases": total, "passed": passed,
                "coverage_pct": round((passed / total) * 100.0, 2) if total else 0.0,
                "blind_spots": blind_spots, "false_alarms": false_alarms,
                "state": "DETECTION_COVERAGE_PROVEN" if passed == total else "DETECTION_GAPS_PRESENT"}
