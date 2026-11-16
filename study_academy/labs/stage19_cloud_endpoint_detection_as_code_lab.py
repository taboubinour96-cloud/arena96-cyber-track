"""
Stage 19 Defensive Lab — Detection-as-Code for Cloud & Endpoint Telemetry
===========================================================================
1. TelemetrySanitizerPipeline:
   - Validates required telemetry fields, redacts secrets/PII before SIEM ingest,
     and enforces per-source monotonic timestamps (clock-rollback / replay guard).
2. DetectionAsCodeEngine:
   - Sigma-style deterministic rules over cloud audit + endpoint events with
     MITRE ATT&CK mapping and alert deduplication/correlation counting.
3. DetectionCoverageCalculator:
   - Measures ATT&CK technique coverage of the rule set and lists exact gaps.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, List, Tuple

_SECRET_PATTERNS = [
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "[REDACTED:GITHUB_TOKEN]"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "[REDACTED:GITHUB_TOKEN]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:AWS_KEY]"),
    (re.compile(r"Bearer\s+[A-Za-z0-9._\-]{16,}", re.I), "Bearer [REDACTED]"),
    (re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{30,}\b"), "[REDACTED:TELEGRAM_TOKEN]"),
]
_DROP_FIELDS = {"password", "token", "secret", "api_key", "authorization"}


class TelemetrySanitizerPipeline:
    def __init__(self) -> None:
        self._last_ts: Dict[str, int] = {}

    @staticmethod
    def redact_text(text: str) -> Tuple[str, int]:
        out = text
        count = 0
        for pat, repl in _SECRET_PATTERNS:
            out, n = pat.subn(repl, out)
            count += n
        return out, count

    def ingest(self, event: Dict[str, object]) -> Tuple[bool, str, Dict[str, object]]:
        for field in ("ts", "source", "principal", "action"):
            if field not in event:
                return False, f"TELEMETRY_MISSING_FIELD_{field.upper()}", {}
        source = str(event["source"])
        ts = int(event["ts"])  # type: ignore[arg-type]
        if source in self._last_ts and ts < self._last_ts[source]:
            return False, "TELEMETRY_TIMESTAMP_ROLLBACK_BLOCKED", {}
        clean: Dict[str, object] = {}
        redactions = 0
        for k, v in event.items():
            if k.lower() in _DROP_FIELDS:
                continue
            if isinstance(v, str):
                nv, n = self.redact_text(v)
                clean[k] = nv
                redactions += n
            else:
                clean[k] = v
        clean["_redactions"] = redactions
        clean["_event_sha256"] = hashlib.sha256(
            repr(sorted(clean.items())).encode()
        ).hexdigest()
        self._last_ts[source] = ts
        return True, "TELEMETRY_INGESTED_CLEAN", clean


class DetectionAsCodeEngine:
    RULES: List[Dict[str, object]] = [
        {"id": "CLOUD-001", "title": "Root/access-key used from new ASN", "mitre": "T1078", "severity": "high", "kind": "root_key_new_asn"},
        {"id": "CLOUD-002", "title": "Storage bucket made public", "mitre": "T1567", "severity": "critical", "kind": "bucket_public"},
        {"id": "CLOUD-003", "title": "Impossible travel for principal", "mitre": "T1078.004", "severity": "high", "kind": "impossible_travel"},
        {"id": "ENDP-001", "title": "Office process spawning shell (injection pattern)", "mitre": "T1059", "severity": "high", "kind": "office_spawns_shell"},
        {"id": "ENDP-002", "title": "Secret-like argument on command line", "mitre": "T1552.001", "severity": "medium", "kind": "secret_in_cmdline"},
    ]

    def _matches(self, rule: Dict[str, object], e: Dict[str, object]) -> bool:
        kind = rule["kind"]
        if kind == "root_key_new_asn":
            return e.get("action") == "aws:AssumeRoot" or (
                e.get("principal_type") == "root_key" and e.get("asn_seen_before") is False
            )
        if kind == "bucket_public":
            return e.get("action") == "storage:SetPublic" and e.get("public") is True
        if kind == "impossible_travel":
            return e.get("impossible_travel") is True
        if kind == "office_spawns_shell":
            parent = str(e.get("parent_process", "")).lower()
            child = str(e.get("process", "")).lower()
            return parent in {"winword.exe", "excel.exe", "outlook.exe"} and child in {"powershell.exe", "cmd.exe", "bash"}
        if kind == "secret_in_cmdline":
            cmd = str(e.get("cmdline", ""))
            return ("ghp_" in cmd) or ("AKIA" in cmd) or ("--api-key" in cmd)
        return False

    def evaluate(self, events: List[Dict[str, object]]) -> Dict[str, object]:
        grouped: Dict[Tuple[str, str, str], Dict[str, object]] = {}
        for e in events:
            for rule in self.RULES:
                if not self._matches(rule, e):
                    continue
                key = (str(rule["id"]), str(e.get("principal", "unknown")), str(e.get("resource", "unknown")))
                if key not in grouped:
                    grouped[key] = {
                        "rule_id": rule["id"],
                        "title": rule["title"],
                        "mitre": rule["mitre"],
                        "severity": rule["severity"],
                        "principal": key[1],
                        "resource": key[2],
                        "count": 0,
                        "first_ts": int(e.get("ts", 0)),  # type: ignore[arg-type]
                        "last_ts": int(e.get("ts", 0)),  # type: ignore[arg-type]
                    }
                grouped[key]["count"] = int(grouped[key]["count"]) + 1
                grouped[key]["last_ts"] = max(int(grouped[key]["last_ts"]), int(e.get("ts", 0)))  # type: ignore[arg-type]
        alerts = sorted(grouped.values(), key=lambda a: (str(a["rule_id"]), str(a["principal"])))
        return {
            "alerts": alerts,
            "alert_count": len(alerts),
            "critical_or_high": sum(1 for a in alerts if a["severity"] in {"critical", "high"}),
        }


class DetectionCoverageCalculator:
    @staticmethod
    def coverage(required_techniques: List[str], rules: List[Dict[str, object]]) -> Dict[str, object]:
        covered_set = {str(r["mitre"]) for r in rules}
        covered = [t for t in required_techniques if t in covered_set]
        gaps = [t for t in required_techniques if t not in covered_set]
        pct = round((len(covered) / len(required_techniques)) * 100.0, 2) if required_techniques else 100.0
        return {"covered": covered, "gaps": gaps, "coverage_pct": pct}
