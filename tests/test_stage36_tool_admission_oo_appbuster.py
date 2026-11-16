from __future__ import annotations

import pytest

from study_academy.labs.stage36_tool_admission_oo_appbuster_lab import (
    BaselineRevalidation,
    DebloatEvidenceRecord,
    RemovalImpactPlanner,
    ToolAdmissionGate,
    ToolPolicyViolation,
)

GOOD_TOOL = {
    "source_url": "https://dl5.oo-software.com/files/ooappbuster/OOAppBuster.exe",
    "signature_valid": True,
    "sha256": "9f2c" * 16,
    "run_as": "jit_admin",
    "restore_point_confirmed": True,
    "scope": "current_user",
}


def test_tool_admission_accepts_only_full_control_set() -> None:
    gate = ToolAdmissionGate()
    admitted = gate.evaluate(GOOD_TOOL)
    assert admitted["admitted"] is True
    assert admitted["state"] == "TOOL_ADMITTED_WITH_CONTROLS"

    # A mirror download instead of the vendor domain is refused.
    mirror = dict(GOOD_TOOL, source_url="https://random-mirror.example/OOAppBuster.exe")
    assert gate.evaluate(mirror)["problems"] == ["SOURCE_NOT_OFFICIAL_HTTPS_DOMAIN"]

    # Plain http is refused even on the vendor domain.
    http = dict(GOOD_TOOL, source_url="http://www.oo-software.com/ooappbuster")
    assert "SOURCE_NOT_OFFICIAL_HTTPS_DOMAIN" in gate.evaluate(http)["problems"]

    broken = dict(GOOD_TOOL, signature_valid=False, sha256="", run_as="domain_admin",
                  restore_point_confirmed=False, scope="everything")
    denied = gate.evaluate(broken)
    assert denied["admitted"] is False
    assert denied["problems"] == [
        "BINARY_SIGNATURE_INVALID",
        "DIGEST_NOT_PINNED",
        "PRIVILEGE_NOT_TIME_BOXED",
        "NO_ROLLBACK_POINT",
        "UNKNOWN_SCOPE",
    ]


def test_baseline_must_be_recaptured_after_state_change() -> None:
    baseline = BaselineRevalidation("baseline-2026-11", captured_at=100)
    assert baseline.evaluate(change_at=200, recaptured_at=None)["state"] == "BASELINE_STALE_AFTER_SYSTEM_CHANGE"
    assert baseline.evaluate(change_at=200, recaptured_at=150)["state"] == "BASELINE_RECAPTURE_PREDATES_CHANGE"
    assert baseline.evaluate(change_at=200, recaptured_at=260)["state"] == "BASELINE_REVALIDATED"
    with pytest.raises(ToolPolicyViolation):
        baseline.evaluate(change_at=50, recaptured_at=60)


def test_removal_planner_protects_runtimes_and_dependants() -> None:
    planner = RemovalImpactPlanner({
        "microsoft.webview2": ["teams", "outlook-new"],
        "contoso.news": [],
    })
    result = planner.plan(["contoso.news", "microsoft.webview2", "Microsoft.WindowsStore"])
    assert result["safe_to_remove"] == ["contoso.news"]
    assert "microsoft.webview2" in result["refused_protected"]
    assert "Microsoft.WindowsStore" in result["refused_protected"]
    assert result["plan_approved"] is False
    assert result["state"] == "REMOVAL_PLAN_PARTIALLY_REFUSED"

    clean = planner.plan(["contoso.news", "contoso.weather"])
    assert clean["plan_approved"] is True
    assert clean["state"] == "REMOVAL_PLAN_APPROVED"


def test_debloat_evidence_is_exportable_from_the_estate() -> None:
    record = DebloatEvidenceRecord()
    assert record.audit_trail()["state"] == "NO_EVIDENCE_RECORDED"

    saved = record.record(
        tool="O&O AppBuster", version="3.1.1029", digest="9f2c" * 16,
        removed=["contoso.news"], kept_protected=["microsoft.webview2"],
        restore_point="rp-2026-11-11-01",
    )
    assert saved["recorded"] is True and saved["seq"] == 1
    assert record.audit_trail()["state"] == "EVIDENCE_TRAIL_COMPLETE"

    with pytest.raises(ToolPolicyViolation):
        record.record(tool="O&O AppBuster", version="3.1.1029", digest="", removed=[], kept_protected=[], restore_point="rp")
    with pytest.raises(ToolPolicyViolation):
        record.record(tool="O&O AppBuster", version="3.1.1029", digest="x", removed=[], kept_protected=[], restore_point="")
