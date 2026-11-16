"""
Stage 39 Defensive Lab — Cloud Posture (CSPM) Rules & Configuration Drift
===========================================================================
1. CloudPostureScanner: deterministic misconfiguration rules — public
   storage, world-open admin ports, disabled encryption/logging, and
   unprotected root accounts are findings with severities, not opinions.
2. DriftDetector: an approved baseline is compared with observed state;
   every changed field is drift that must be explained or reverted.
"""

from __future__ import annotations

from typing import Dict, List


class PostureViolation(Exception):
    """Raised when a posture rule is violated."""


class CloudPostureScanner:
    def scan(self, resources: List[Dict[str, object]]) -> Dict[str, object]:
        findings: List[Dict[str, object]] = []
        for res in resources:
            rtype, name = str(res.get("type", "")), str(res.get("name", ""))
            if rtype == "storage" and res.get("public") is True:
                findings.append({"resource": name, "rule": "STORAGE_PUBLIC", "severity": "critical"})
            if rtype == "security_group" and res.get("cidr") == "0.0.0.0/0" and int(res.get("port", 0)) in {22, 3389}:
                findings.append({"resource": name, "rule": "ADMIN_PORT_WORLD_OPEN", "severity": "high"})
            if rtype in {"storage", "database", "disk"} and res.get("encrypted") is False:
                findings.append({"resource": name, "rule": "ENCRYPTION_DISABLED", "severity": "high"})
            if rtype == "account" and res.get("root_mfa") is False:
                findings.append({"resource": name, "rule": "ROOT_MFA_DISABLED", "severity": "critical"})
            if rtype == "account" and res.get("audit_logging") is False:
                findings.append({"resource": name, "rule": "AUDIT_LOGGING_DISABLED", "severity": "medium"})
        severities = [f["severity"] for f in findings]
        return {"findings": findings, "finding_count": len(findings),
                "posture": "FAIL" if "critical" in severities else ("WARN" if findings else "PASS")}


class DriftDetector:
    def diff(self, baseline: Dict[str, object], observed: Dict[str, object]) -> Dict[str, object]:
        changed = sorted(k for k in set(baseline) | set(observed) if baseline.get(k) != observed.get(k))
        return {"drift_fields": changed, "drifted": bool(changed),
                "state": "DRIFT_DETECTED_REVIEW_REQUIRED" if changed else "CONFIG_MATCHES_BASELINE"}
