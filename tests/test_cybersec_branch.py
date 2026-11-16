"""
Comprehensive test suite for `cybersec_branch`.
Verifies guardrails, CVSS v3.1 accuracy, static AST analysis, route authz coverage,
configuration auditing, false-positive suppression, and SARIF/Markdown report generation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cybersec_branch import (
    AGENT_TOOLS_SCHEMA,
    AuditScope,
    CyberSecAuditBranch,
    ReportBuilder,
    ScopeGuard,
    ScopeViolationError,
    Severity,
    TriageStatus,
    calculate_cvss_v31,
)


def test_scope_guard_blocks_external_urls_ips_and_offensive_prompts(tmp_path: Path) -> None:
    with pytest.raises(ScopeViolationError):
        ScopeGuard.validate_target_path("https://example.com")

    with pytest.raises(ScopeViolationError):
        ScopeGuard.validate_target_path("192.168.1.10")

    with pytest.raises(ScopeViolationError):
        ScopeGuard.validate_target_path("/etc")

    with pytest.raises(ScopeViolationError):
        ScopeGuard.validate_task_instruction("Please generate exploit payload for target")

    valid = ScopeGuard.validate_target_path(str(tmp_path))
    assert valid == tmp_path.resolve()


def test_cvss_v31_official_vectors() -> None:
    # Classic critical unauthenticated RCE-equivalent vector -> 9.8 CRITICAL
    score1, sev1 = calculate_cvss_v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score1 == 9.8
    assert sev1 == Severity.CRITICAL

    # Medium reflected UI-required vector -> 6.1 MEDIUM
    score2, sev2 = calculate_cvss_v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert score2 == 6.1
    assert sev2 == Severity.MEDIUM

    # Zero impact vector -> 0.0 INFO
    score3, sev3 = calculate_cvss_v31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert score3 == 0.0
    assert sev3 == Severity.INFO


def test_end_to_end_audit_pipeline_and_false_positive_filtering(tmp_path: Path) -> None:
    # Create a synthetic local sample codebase to audit defensively
    app_dir = tmp_path / "sample_service"
    tests_dir = app_dir / "tests"
    app_dir.mkdir()
    tests_dir.mkdir()

    # 1. Sample backend file with:
    #    - Unsafe YAML loader
    #    - Parameterized SQL (safe) vs interpolated SQL (unsafe)
    #    - Protected route vs unprotected admin route
    #    - Wildcard CORS + credentials misconfiguration
    (app_dir / "api.py").write_text(
        '''import yaml
from fastapi import APIRouter, Depends
from fastapi.middleware.cors import CORSMiddleware

router = APIRouter()

def configure_cors(app):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
    )

def load_settings(raw_text: str):
    return yaml.load(raw_text)

def get_user_Unsafe(cursor, account_id: str):
    cursor.execute(f"SELECT id, role FROM accounts WHERE id = '{account_id}'")

def get_user_safe(cursor, account_id: int):
    cursor.execute("SELECT id, role FROM accounts WHERE id = %s", (account_id,))

@router.get("/health")
def health_check():
    return {"ok": True}

@router.delete("/admin/accounts/{account_id}")
def remove_account(account_id: int):
    return {"deleted": account_id}

@router.post("/billing/refund")
def issue_refund(order_id: int, current_user=Depends(verify_jwt_token)):
    return {"refunded": order_id}
''',
        encoding="utf-8",
    )

    # 2. Sample Dockerfile missing non-root USER and using :latest
    (app_dir / "Dockerfile").write_text(
        "FROM python:latest\nWORKDIR /app\nCOPY . /app\nCMD [\"python\", \"api.py\"]\n",
        encoding="utf-8",
    )

    # 3. Sample unit test file containing `eval` — should be suppressed as LIKELY_FALSE_POSITIVE!
    (tests_dir / "test_helpers.py").write_text(
        "def test_parser():\n    assert eval('1 + 1') == 2\n",
        encoding="utf-8",
    )

    branch = CyberSecAuditBranch()
    assert len(AGENT_TOOLS_SCHEMA) == 4

    out_md = tmp_path / "out" / "report.md"
    out_sarif = tmp_path / "out" / "report.sarif.json"

    result = branch.dispatch_tool_call(
        "cybersec_audit_repository",
        {
            "target_directory": str(app_dir),
            "program_name": "Synthetic App Audit",
            "enable_osv_lookup": False,
            "output_markdown_path": str(out_md),
            "output_sarif_path": str(out_sarif),
        },
    )

    assert result["human_verification_required"] is True
    assert result["scanned_files_count"] == 3
    assert result["total_suppressed_false_positives"] >= 1

    rule_ids_active = {
        f["rule_id"]
        for f in result["findings"]
        if f["triage_status"] != TriageStatus.LIKELY_FALSE_POSITIVE.value
    }

    # Verify expected real issues were caught
    assert "PY-SAST-004" in rule_ids_active  # yaml.load without SafeLoader
    assert "PY-SAST-005" in rule_ids_active  # SQL f-string interpolation
    assert "AUTHZ-001" in rule_ids_active    # Unprotected DELETE /admin/accounts/{account_id}
    assert "CFG-CORS-001" in rule_ids_active # Wildcard CORS + credentials
    assert "IAC-DOCKER-001" in rule_ids_active
    assert "IAC-DOCKER-002" in rule_ids_active

    # Verify test file eval() was suppressed as LIKELY_FALSE_POSITIVE
    suppressed_rules = {
        f["rule_id"]
        for f in result["findings"]
        if f["triage_status"] == TriageStatus.LIKELY_FALSE_POSITIVE.value
    }
    assert "PY-SAST-002" in suppressed_rules

    # Verify protected route `/billing/refund` was NOT flagged while `/admin/accounts` WAS flagged
    routes = {r["route_path"]: r for r in result["discovered_routes"]}
    assert routes["/billing/refund"]["has_auth_guard"] is True
    assert routes["/admin/accounts/{account_id}"]["has_auth_guard"] is False

    # Verify Markdown & SARIF files were created properly
    assert out_md.exists()
    assert "Mandatory Human-in-the-Loop Verification Notice" in out_md.read_text(encoding="utf-8")
    assert out_sarif.exists()
    assert '"version": "2.1.0"' in out_sarif.read_text(encoding="utf-8")
