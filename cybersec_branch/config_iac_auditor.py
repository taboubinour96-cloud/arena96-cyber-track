"""
Configuration, Infrastructure-as-Code (IaC), CORS & Secret Hygiene Auditor.

Audits local configuration artifacts (Dockerfiles, docker-compose/Kubernetes manifests,
CORS middleware configs, OpenAPI specs, and hardcoded secret patterns) with safe secret
redaction so sensitive credentials are never echoed in plain text.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import List, Tuple

from .cvss_calculator import calculate_cvss_v31
from .models import AuditFinding, CodeLocation, Confidence


def _cfg_finding_id(prefix: str, rel_path: str, line: int, rule_id: str) -> str:
    h = hashlib.sha256(f"{rel_path}:{line}:{rule_id}".encode("utf-8")).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


def _redact_secret(line: str) -> str:
    """Masks high-entropy secret values so reports never leak raw credentials."""
    return re.sub(
        r"(['\"\s:=])([A-Za-z0-9_\-]{6})[A-Za-z0-9_\-/+=]{10,}(['\"]?)",
        r"\1\2***REDACTED***\3",
        line,
    )


_SECRET_PATTERNS: List[Tuple[str, str, re.Pattern]] = [
    (
        "SEC-001",
        "Hardcoded AWS Access Key ID",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    ),
    (
        "SEC-002",
        "Hardcoded Private Cryptographic Key Block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "SEC-003",
        "Hardcoded API Token / Secret Assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|secret[_-]?key|jwt[_-]?secret|access[_-]?token|db[_-]?password)\b"
            r"\s*[:=]\s*['\"](?!changeme|your[_-]|example|placeholder|test|<|\$\{)[A-Za-z0-9_\-@#$%^&*+/=]{14,}['\"]"
        ),
    ),
]


class ConfigIaCAuditor:
    """Audits Dockerfiles, YAML manifests, CORS settings, OpenAPI specs, and secret hygiene."""

    def scan_file(self, file_path: Path, root_dir: Path) -> List[AuditFinding]:
        rel_path = str(file_path.relative_to(root_dir))
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        lines = content.splitlines()
        fname = file_path.name
        ext = file_path.suffix.lower()
        findings: List[AuditFinding] = []

        # 1. Dockerfile Hardening Checks
        if fname == "Dockerfile" or fname.startswith("Dockerfile."):
            findings.extend(self._audit_dockerfile(lines, rel_path))

        # 2. Container / Kubernetes YAML Misconfigurations
        if ext in {".yml", ".yaml"}:
            findings.extend(self._audit_yaml_iac(lines, rel_path))

        # 3. OpenAPI / Swagger Specification Auth Checks
        if ext == ".json" and ("openapi" in content[:400] or "swagger" in content[:400]):
            findings.extend(self._audit_openapi_json(content, rel_path))

        # 4. Permissive CORS + Credentials Misconfiguration in App Configs
        findings.extend(self._audit_cors_settings(content, lines, rel_path))

        # 5. Secret Hygiene Checks (skip test files with obvious mock labels if needed, redact output)
        findings.extend(self._audit_secrets(lines, rel_path))

        # 6. v2.0 Upgrade: Trojan-Source Bidirectional Unicode Control Characters (CVE-2021-42574 / CWE-1007)
        findings.extend(self._audit_trojan_unicode(lines, rel_path))

        # 7. v2.0 Upgrade: Agent Skill (SKILL.md / AGENTS.md) Prompt-Injection & Curl-Pipe-Shell Guard
        if fname in {"SKILL.md", "AGENTS.md", ".cursorrules"}:
            findings.extend(self._audit_agent_skill_markdown(lines, rel_path))

        return findings

    def _audit_dockerfile(self, lines: List[str], rel_path: str) -> List[AuditFinding]:
        results: List[AuditFinding] = []
        has_user_directive = False

        for idx, raw in enumerate(lines, start=1):
            stripped = raw.strip()
            if not stripped or stripped.startswith("#"):
                continue
            upper = stripped.upper()
            if upper.startswith("USER ") and stripped.split(None, 1)[1].strip() not in {"root", "0"}:
                has_user_directive = True

            if upper.startswith("FROM ") and (":latest" in stripped or (":" not in stripped.split()[1] and "@" not in stripped.split()[1])):
                vec = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
                score, sev = calculate_cvss_v31(vec)
                results.append(
                    AuditFinding(
                        finding_id=_cfg_finding_id("IAC", rel_path, idx, "IAC-DOCKER-001"),
                        rule_id="IAC-DOCKER-001",
                        title="Unpinned Container Base Image Tag (`:latest` or Implicit Tag)",
                        category="CONFIG_IAC",
                        cwe_id="CWE-829",
                        owasp_category="A08:2021 - Software and Data Integrity Failures",
                        severity=sev,
                        confidence=Confidence.HIGH,
                        cvss_vector=vec,
                        cvss_score=score,
                        location=CodeLocation(rel_path, idx, idx, f">> {idx:4d} | {raw}"),
                        description="Container base image is not pinned to an immutable version or SHA256 digest.",
                        impact_summary="Supply-chain drift or upstream tag mutation can introduce unreviewed packages into production builds.",
                        remediation="Pin base images to a specific version and SHA256 digest (e.g., `python:3.12.7-slim@sha256:...`).",
                        secure_code_example="FROM python:3.12-slim-bookworm",
                    )
                )

        if lines and not has_user_directive:
            vec = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"
            score, sev = calculate_cvss_v31(vec)
            results.append(
                AuditFinding(
                    finding_id=_cfg_finding_id("IAC", rel_path, len(lines), "IAC-DOCKER-002"),
                    rule_id="IAC-DOCKER-002",
                    title="Container Runs as `root` (Missing Non-Root `USER` Directive)",
                    category="CONFIG_IAC",
                    cwe_id="CWE-250",
                    owasp_category="A05:2021 - Security Misconfiguration",
                    severity=sev,
                    confidence=Confidence.HIGH,
                    cvss_vector=vec,
                    cvss_score=score,
                    location=CodeLocation(rel_path, 1, len(lines), f">>    1 | {lines[0]}"),
                    description="Dockerfile does not switch to an unprivileged non-root `USER` before `CMD`/`ENTRYPOINT`.",
                    impact_summary="Processes compromised inside the container execute with UID 0 privileges, increasing container breakout impact.",
                    remediation="Create a dedicated system user and add `USER appuser` prior to launching the application.",
                    secure_code_example="RUN useradd --system --uid 10001 appuser\nUSER appuser",
                )
            )
        return results

    def _audit_yaml_iac(self, lines: List[str], rel_path: str) -> List[AuditFinding]:
        results: List[AuditFinding] = []
        for idx, line in enumerate(lines, start=1):
            if re.search(r"^\s*privileged\s*:\s*true\b", line):
                vec = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
                score, sev = calculate_cvss_v31(vec)
                results.append(
                    AuditFinding(
                        finding_id=_cfg_finding_id("IAC", rel_path, idx, "IAC-K8S-001"),
                        rule_id="IAC-K8S-001",
                        title="Privileged Container Enabled (`privileged: true`)",
                        category="CONFIG_IAC",
                        cwe_id="CWE-250",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        severity=sev,
                        confidence=Confidence.HIGH,
                        cvss_vector=vec,
                        cvss_score=score,
                        location=CodeLocation(rel_path, idx, idx, f">> {idx:4d} | {line}"),
                        description="Container manifest grants full host kernel capabilities via `privileged: true`.",
                        impact_summary="Trivial host compromise if the container workload is breached.",
                        remediation="Set `privileged: false`, `allowPrivilegeEscalation: false`, and drop `ALL` Linux capabilities.",
                        secure_code_example="securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false",
                    )
                )
            if re.search(r"^\s*pull_request_target\s*:", line):
                vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"
                score, sev = calculate_cvss_v31(vec)
                results.append(
                    AuditFinding(
                        finding_id=_cfg_finding_id("CICD", rel_path, idx, "CICD-001"),
                        rule_id="CICD-001",
                        title="GitHub Actions `pull_request_target` Workflow Trigger Hazard",
                        category="CONFIG_IAC",
                        cwe_id="CWE-829",
                        owasp_category="A08:2021 - Software and Data Integrity Failures",
                        severity=sev,
                        confidence=Confidence.MEDIUM,
                        cvss_vector=vec,
                        cvss_score=score,
                        location=CodeLocation(rel_path, idx, idx, f">> {idx:4d} | {line}"),
                        description="Workflow uses `pull_request_target`, which executes with repository secrets and write permissions on untrusted fork PR events.",
                        impact_summary="Checking out untrusted PR head commits inside `pull_request_target` leads to secret exfiltration and supply-chain compromise.",
                        remediation="Prefer `pull_request` with read-only permissions, pin third-party actions to 40-char commit SHAs, and never checkout PR head code inside `pull_request_target`.",
                        secure_code_example="on:\n  pull_request:\npermissions:\n  contents: read",
                        mitre_attack_ids=["T1195.002"],
                        rbvm_priority="P0",
                    )
                )
        return results

    def _audit_cors_settings(
        self, content: str, lines: List[str], rel_path: str
    ) -> List[AuditFinding]:
        results: List[AuditFinding] = []
        if "allow_origins" in content and "allow_credentials" in content:
            if re.search(r'allow_origins\s*=\s*\[\s*["\']\*["\']\s*\]', content) and re.search(
                r"allow_credentials\s*=\s*True", content
            ):
                line_no = 1
                for idx, ln in enumerate(lines, start=1):
                    if "allow_origins" in ln:
                        line_no = idx
                        break
                vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"
                score, sev = calculate_cvss_v31(vec)
                results.append(
                    AuditFinding(
                        finding_id=_cfg_finding_id("CFG", rel_path, line_no, "CFG-CORS-001"),
                        rule_id="CFG-CORS-001",
                        title="Insecure CORS Wildcard Combined with `allow_credentials=True`",
                        category="CONFIG_IAC",
                        cwe_id="CWE-942",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        severity=sev,
                        confidence=Confidence.HIGH,
                        cvss_vector=vec,
                        cvss_score=score,
                        location=CodeLocation(rel_path, line_no, line_no, f">> {line_no:4d} | {lines[line_no - 1]}"),
                        description="CORS middleware allows arbitrary origins (`*`) alongside credentialed cross-origin requests.",
                        impact_summary="Frameworks that reflect the `Origin` header when `*` is configured with credentials expose authenticated responses to third-party origins.",
                        remediation="Specify an explicit list of trusted HTTPS origins in `allow_origins`.",
                        secure_code_example='allow_origins=["https://app.example.com"], allow_credentials=True',
                    )
                )
        return results

    def _audit_openapi_json(self, content: str, rel_path: str) -> List[AuditFinding]:
        try:
            spec = json.loads(content)
        except json.JSONDecodeError:
            return []
        if not isinstance(spec, dict) or "paths" not in spec:
            return []

        global_sec = spec.get("security")
        unprotected_ops: List[str] = []
        for path_key, ops in spec.get("paths", {}).items():
            if not isinstance(ops, dict):
                continue
            for method, details in ops.items():
                if method.lower() in {"post", "put", "delete", "patch"} and isinstance(details, dict):
                    op_sec = details.get("security", global_sec)
                    if not op_sec:
                        unprotected_ops.append(f"{method.upper()} {path_key}")

        if not unprotected_ops:
            return []

        vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
        score, sev = calculate_cvss_v31(vec)
        preview = ", ".join(unprotected_ops[:5])
        return [
            AuditFinding(
                finding_id=_cfg_finding_id("CFG", rel_path, 1, "CFG-OPENAPI-001"),
                rule_id="CFG-OPENAPI-001",
                title="OpenAPI State-Changing Operations Missing `security` Scheme Definition",
                category="CONFIG_IAC",
                cwe_id="CWE-306",
                owasp_category="A01:2021 - Broken Access Control",
                severity=sev,
                confidence=Confidence.MEDIUM,
                cvss_vector=vec,
                cvss_score=score,
                location=CodeLocation(rel_path, 1, 1, f"Operations without security requirement: {preview}"),
                description=f"Found {len(unprotected_ops)} mutating API operation(s) in `{rel_path}` with no declared security scheme ({preview}).",
                impact_summary="API gateways or code generators relying on the OpenAPI contract may expose endpoints without authentication.",
                remediation="Define `components.securitySchemes` and apply a global or operation-level `security` requirement.",
            )
        ]

    def _audit_secrets(self, lines: List[str], rel_path: str) -> List[AuditFinding]:
        results: List[AuditFinding] = []
        for idx, line in enumerate(lines, start=1):
            for rule_id, title, pattern in _SECRET_PATTERNS:
                if pattern.search(line):
                    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                    score, sev = calculate_cvss_v31(vec)
                    redacted = _redact_secret(line)
                    results.append(
                        AuditFinding(
                            finding_id=_cfg_finding_id("SEC", rel_path, idx, rule_id),
                            rule_id=rule_id,
                            title=title,
                            category="SECRET_HYGIENE",
                            cwe_id="CWE-798",
                            owasp_category="A07:2021 - Identification and Authentication Failures",
                            severity=sev,
                            confidence=Confidence.HIGH,
                            cvss_vector=vec,
                            cvss_score=score,
                            location=CodeLocation(rel_path, idx, idx, f">> {idx:4d} | {redacted}"),
                            description=f"Detected hardcoded credential/key material in `{rel_path}` (value redacted for safety).",
                            impact_summary="Source repository readers or CI artifacts gain direct access to sensitive credentials.",
                            remediation="Revoke/rotate the exposed secret immediately and load credentials at runtime from a secret manager or environment variable.",
                            secure_code_example='api_key = os.environ["SERVICE_API_KEY"]',
                        )
                    )
        return results

    def _audit_trojan_unicode(self, lines: List[str], rel_path: str) -> List[AuditFinding]:
        """v2.0 Upgrade: Detects Trojan-Source Bidirectional Unicode characters (CVE-2021-42574 / CWE-1007)."""
        bidi_chars = {"\u202a", "\u202b", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u202c", "\u2069"}
        results: List[AuditFinding] = []
        for idx, line in enumerate(lines, start=1):
            if any(ch in line for ch in bidi_chars):
                vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
                score, sev = calculate_cvss_v31(vec)
                results.append(
                    AuditFinding(
                        finding_id=_cfg_finding_id("BIDI", rel_path, idx, "AI-SKILL-001"),
                        rule_id="AI-SKILL-001",
                        title="Trojan-Source Bidirectional Unicode Control Character Detected",
                        category="CONFIG_IAC",
                        cwe_id="CWE-1007",
                        owasp_category="A08:2021 - Software and Data Integrity Failures",
                        severity=sev,
                        confidence=Confidence.HIGH,
                        cvss_vector=vec,
                        cvss_score=score,
                        location=CodeLocation(rel_path, idx, idx, f">> {idx:4d} | [Hidden Bidi Control Char Stripped]"),
                        description="File contains Unicode bidirectional override/isolate control characters capable of visually disguising malicious logic or hidden prompt instructions.",
                        impact_summary="Human reviewers see benign code/text while interpreters or LLM agents execute hidden instructions (CVE-2021-42574).",
                        remediation="Strip all Unicode Bidi override characters (`U+202A..U+202E`, `U+2066..U+2069`) before committing or loading skills.",
                        mitre_attack_ids=["T1036"],
                        rbvm_priority="P0",
                    )
                )
        return results

    def _audit_agent_skill_markdown(self, lines: List[str], rel_path: str) -> List[AuditFinding]:
        """v2.0 Upgrade: Audits AI Agent Skill files (`SKILL.md` / `AGENTS.md`) for curl-pipe-shell or prompt-override traps."""
        results: List[AuditFinding] = []
        dangerous_skill_re = re.compile(
            r"(?i)(curl\s+[^\n|]+\|\s*(?:ba)?sh|wget\s+[^\n|]+\|\s*(?:ba)?sh|ignore\s+all\s+previous\s+instructions)"
        )
        for idx, line in enumerate(lines, start=1):
            if dangerous_skill_re.search(line):
                vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"
                score, sev = calculate_cvss_v31(vec)
                results.append(
                    AuditFinding(
                        finding_id=_cfg_finding_id("SKILL", rel_path, idx, "AI-SKILL-002"),
                        rule_id="AI-SKILL-002",
                        title="Suspicious Remote Shell Pipe or Prompt-Override Directive in Agent Skill",
                        category="CONFIG_IAC",
                        cwe_id="CWE-94",
                        owasp_category="OWASP-LLM01 - Prompt Injection & Supply Chain",
                        severity=sev,
                        confidence=Confidence.HIGH,
                        cvss_vector=vec,
                        cvss_score=score,
                        location=CodeLocation(rel_path, idx, idx, f">> {idx:4d} | {line[:160]}"),
                        description="Agent skill markdown instructs executing unverified remote shell scripts (`curl|sh`) or overriding system instructions.",
                        impact_summary="Compromises the AI agent sandbox or exfiltrates workspace secrets upon skill invocation.",
                        remediation="Remove piped remote shell execution and enforce checksum-verified package installation with Owner approval.",
                        mitre_attack_ids=["T1059.004", "T1195.002"],
                        rbvm_priority="P0",
                    )
                )
        return results

