"""
Data models for the White-Box Cybersecurity Code Auditing Agent Branch.
Strictly designed for defensive source-code review, static configuration auditing,
dependency CVE checking, and remediation reporting.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class TriageStatus(str, Enum):
    CONFIRMED_CANDIDATE = "CONFIRMED_CANDIDATE"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"
    LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"


@dataclass
class CodeLocation:
    file_path: str
    line_start: int
    line_end: int
    snippet: str = ""
    function_name: Optional[str] = None


@dataclass
class RouteEndpoint:
    file_path: str
    line_number: int
    framework: str
    http_method: str
    route_path: str
    handler_name: str
    auth_mechanisms: List[str] = field(default_factory=list)
    has_auth_guard: bool = False


@dataclass
class AuditFinding:
    finding_id: str
    rule_id: str
    title: str
    category: str  # SAST, AUTHZ, CONFIG_IAC, DEPENDENCY_CVE, SECRET_HYGIENE
    cwe_id: str
    owasp_category: str
    severity: Severity
    confidence: Confidence
    cvss_vector: str
    cvss_score: float
    location: CodeLocation
    description: str
    impact_summary: str
    remediation: str
    secure_code_example: str = ""
    triage_status: TriageStatus = TriageStatus.NEEDS_HUMAN_REVIEW
    triage_notes: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    mitre_attack_ids: List[str] = field(default_factory=list)
    rbvm_priority: str = "P2"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["confidence"] = self.confidence.value
        data["triage_status"] = self.triage_status.value
        return data


@dataclass
class AuditScope:
    target_directory: str
    program_name: str = "Local Authorized Code Audit"
    include_extensions: List[str] = field(
        default_factory=lambda: [
            ".py",
            ".js",
            ".ts",
            ".tsx",
            ".jsx",
            ".go",
            ".java",
            ".php",
            ".yml",
            ".yaml",
            ".json",
            ".toml",
            ".env",
            "Dockerfile",
            "SKILL.md",
            "AGENTS.md",
        ]
    )
    exclude_dirs: List[str] = field(
        default_factory=lambda: [
            ".git",
            "node_modules",
            ".venv",
            "venv",
            "__pycache__",
            "dist",
            "build",
            ".next",
            "vendor",
        ]
    )
    max_file_size_bytes: int = 1_048_576  # 1 MB per file
    enable_osv_network_lookup: bool = True


@dataclass
class AuditSummaryReport:
    program_name: str
    target_directory: str
    scanned_files_count: int
    discovered_routes: List[RouteEndpoint]
    findings: List[AuditFinding]
    human_verification_required: bool = True
    methodology_notes: List[str] = field(default_factory=list)

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            if f.triage_status != TriageStatus.LIKELY_FALSE_POSITIVE:
                counts[f.severity.value] += 1
        return counts

    def active_findings(self) -> List[AuditFinding]:
        return [
            f
            for f in self.findings
            if f.triage_status != TriageStatus.LIKELY_FALSE_POSITIVE
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "program_name": self.program_name,
            "target_directory": self.target_directory,
            "scanned_files_count": self.scanned_files_count,
            "human_verification_required": self.human_verification_required,
            "severity_counts": self.counts_by_severity(),
            "total_active_findings": len(self.active_findings()),
            "total_suppressed_false_positives": len(self.findings)
            - len(self.active_findings()),
            "discovered_routes": [asdict(r) for r in self.discovered_routes],
            "findings": [f.to_dict() for f in self.findings],
            "methodology_notes": self.methodology_notes,
        }
