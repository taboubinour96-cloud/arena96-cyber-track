"""
Supply-Chain & Dependency Vulnerability Auditor (`DependencyOSVAuditor`).

Parses local dependency manifests (`requirements.txt`, `package.json`, `go.mod`) and
queries the open-source OSV.dev advisory database (`https://api.osv.dev/v1/querybatch`)
to report known CVEs/GHSAs and exact fixed versions to upgrade to.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .cvss_calculator import calculate_cvss_v31
from .models import AuditFinding, CodeLocation, Confidence, Severity


@dataclass
class _PinnedDependency:
    ecosystem: str  # PyPI, npm, Go
    name: str
    version: str
    rel_path: str
    line_number: int
    raw_line: str


def _dep_finding_id(rel_path: str, pkg: str, vuln_id: str) -> str:
    h = hashlib.sha256(f"{rel_path}:{pkg}:{vuln_id}".encode("utf-8")).hexdigest()[:8]
    return f"SCA-{h.upper()}"


class DependencyOSVAuditor:
    """Extracts pinned dependencies and checks OSV.dev for known security advisories."""

    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
    OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

    def audit_manifests(
        self, files: List[Path], root_dir: Path, enable_network: bool = True
    ) -> List[AuditFinding]:
        deps: List[_PinnedDependency] = []
        for fpath in files:
            fname = fpath.name
            rel = str(fpath.relative_to(root_dir))
            if fname == "requirements.txt":
                deps.extend(self._parse_requirements_txt(fpath, rel))
            elif fname == "package.json":
                deps.extend(self._parse_package_json(fpath, rel))
            elif fname == "go.mod":
                deps.extend(self._parse_go_mod(fpath, rel))

        if not deps or not enable_network:
            return []

        return self._query_osv_batch(deps)

    @staticmethod
    def _parse_requirements_txt(fpath: Path, rel_path: str) -> List[_PinnedDependency]:
        results: List[_PinnedDependency] = []
        req_re = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-+!]+)")
        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        for idx, line in enumerate(lines, start=1):
            stripped = line.split("#", 1)[0].strip()
            m = req_re.match(stripped)
            if m:
                results.append(
                    _PinnedDependency("PyPI", m.group(1), m.group(2), rel_path, idx, line)
                )
        return results

    @staticmethod
    def _parse_package_json(fpath: Path, rel_path: str) -> List[_PinnedDependency]:
        try:
            raw = fpath.read_text(encoding="utf-8", errors="replace")
            data = json.loads(raw)
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(data, dict):
            return []

        lines = raw.splitlines()
        results: List[_PinnedDependency] = []
        for section in ("dependencies", "devDependencies"):
            sec_obj = data.get(section)
            if not isinstance(sec_obj, dict):
                continue
            for name, ver_spec in sec_obj.items():
                if not isinstance(ver_spec, str):
                    continue
                clean_ver = ver_spec.lstrip("^~=").strip()
                if not re.match(r"^\d+\.\d+\.\d+", clean_ver):
                    continue
                line_no = 1
                for i, ln in enumerate(lines, start=1):
                    if f'"{name}"' in ln:
                        line_no = i
                        break
                results.append(
                    _PinnedDependency("npm", name, clean_ver, rel_path, line_no, lines[line_no - 1])
                )
        return results

    @staticmethod
    def _parse_go_mod(fpath: Path, rel_path: str) -> List[_PinnedDependency]:
        results: List[_PinnedDependency] = []
        go_re = re.compile(r"^\s*([a-zA-Z0-9.\-_/]+)\s+v([0-9]+\.[0-9]+\.[0-9]+[^\s/]*)")
        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        for idx, line in enumerate(lines, start=1):
            m = go_re.match(line.split("//", 1)[0])
            if m:
                results.append(
                    _PinnedDependency("Go", m.group(1), m.group(2), rel_path, idx, line)
                )
        return results

    def _query_osv_batch(self, deps: List[_PinnedDependency]) -> List[AuditFinding]:
        queries = [
            {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
            for d in deps
        ]
        payload = json.dumps({"queries": queries}).encode("utf-8")
        req = urllib.request.Request(
            self.OSV_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "CyberSecAuditBranch/1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                batch_data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            return []

        results_list = batch_data.get("results", [])
        findings: List[AuditFinding] = []

        for dep, res in zip(deps, results_list):
            vulns = res.get("vulns") or []
            for v_stub in vulns[:3]:  # Cap per-package advisories to keep signal high
                vuln_id = v_stub.get("id", "OSV-UNKNOWN")
                detail = self._fetch_vuln_detail(vuln_id) or v_stub
                findings.append(self._build_finding(dep, vuln_id, detail))

        return findings

    def _fetch_vuln_detail(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        if not re.fullmatch(r"[A-Za-z0-9.\-_]{3,64}", vuln_id):
            return None
        safe_url = "https://api.osv.dev/v1/vulns/" + urllib.parse.quote(vuln_id, safe="")
        req = urllib.request.Request(
            safe_url,
            headers={"User-Agent": "CyberSecAuditBranch/1.0"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:  # nosec: pinned to api.osv.dev
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            return None

    def _build_finding(
        self, dep: _PinnedDependency, vuln_id: str, detail: Dict[str, Any]
    ) -> AuditFinding:
        aliases = detail.get("aliases") or []
        cve_alias = next((a for a in aliases if str(a).startswith("CVE-")), vuln_id)
        summary = detail.get("summary") or f"Known vulnerability {vuln_id} in {dep.name}=={dep.version}"

        # Extract CVSS v3.1 vector if available
        cvss_vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
        for sev_entry in detail.get("severity") or []:
            if sev_entry.get("type") == "CVSS_V3" and str(sev_entry.get("score", "")).startswith(
                "CVSS:3.1/"
            ):
                cvss_vec = sev_entry["score"]
                break

        try:
            score, severity = calculate_cvss_v31(cvss_vec)
        except ValueError:
            score, severity = 6.5, Severity.MEDIUM

        # Extract fixed version if listed
        fixed_versions: List[str] = []
        for aff in detail.get("affected") or []:
            for rng in aff.get("ranges") or []:
                for ev in rng.get("events") or []:
                    if "fixed" in ev:
                        fixed_versions.append(str(ev["fixed"]))

        fix_hint = (
            f"Upgrade `{dep.name}` to version `{fixed_versions[0]}` or newer."
            if fixed_versions
            else f"Upgrade `{dep.name}` to the latest patched release and review advisory `{vuln_id}`."
        )

        cwe_ids = (detail.get("database_specific") or {}).get("cwe_ids") or []
        cwe_id = cwe_ids[0] if cwe_ids else "CWE-1395"

        return AuditFinding(
            finding_id=_dep_finding_id(dep.rel_path, dep.name, vuln_id),
            rule_id=f"OSV-{vuln_id}",
            title=f"Vulnerable Dependency: `{dep.name}=={dep.version}` ({cve_alias})",
            category="DEPENDENCY_CVE",
            cwe_id=cwe_id,
            owasp_category="A06:2021 - Vulnerable and Outdated Components",
            severity=severity,
            confidence=Confidence.HIGH,
            cvss_vector=cvss_vec,
            cvss_score=score,
            location=CodeLocation(
                file_path=dep.rel_path,
                line_start=dep.line_number,
                line_end=dep.line_number,
                snippet=f">> {dep.line_number:4d} | {dep.raw_line}",
            ),
            description=f"{summary} (Advisory ID: `{vuln_id}`, Ecosystem: `{dep.ecosystem}`).",
            impact_summary=(
                "Applications invoking affected code paths in this outdated library inherit its publicly known weakness."
            ),
            remediation=fix_hint,
            secure_code_example=(
                f"{dep.name}>={fixed_versions[0]}" if fixed_versions and dep.ecosystem == "PyPI" else ""
            ),
            references=[f"https://osv.dev/vulnerability/{vuln_id}"],
        )
