from __future__ import annotations

from study_academy.labs.stage37_pam_jit_and_break_glass_lab import (
    BreakGlass,
    PrivilegeVault,
    SessionRecorder,
)
from study_academy.labs.stage38_vulnerability_risk_prioritization_lab import (
    RemediationVerifier,
    VulnerabilityPrioritizer,
)
from study_academy.labs.stage39_cloud_posture_cspm_and_drift_lab import (
    CloudPostureScanner,
    DriftDetector,
)
from study_academy.labs.stage40_insider_risk_ueba_and_case_lab import (
    BehaviourRiskScorer,
    InsiderCaseBuilder,
)


def test_stage37_vault_checkout_expiry_and_ttl_bounds() -> None:
    vault = PrivilegeVault()
    denied = vault.checkout("ops", "db-1", ticket_approved=False, now=1000)
    assert denied["state"] == "PAM_CHECKOUT_DENIED_NO_APPROVED_TICKET"
    grant = vault.checkout("ops", "db-1", ticket_approved=True, now=1000, ttl_minutes=60)
    assert grant["granted"] is True and vault.use(grant, now=2000) == (True, "PAM_USE_ALLOWED_WITHIN_WINDOW")
    assert vault.use(grant, now=1000 + 3600)[1] == "PAM_USE_DENIED_GRANT_EXPIRED"
    assert vault.checkout("ops", "db-1", ticket_approved=True, now=0, ttl_minutes=9999)["granted"] is False


def test_stage37_session_chain_tamper_and_break_glass() -> None:
    rec = SessionRecorder()
    rec.record("ops", "checkout db-1")
    rec.record("ops", "run migration")
    assert rec.verify() == (True, "SESSION_RECORD_CHAIN_INTACT")
    rec._events[0]["action"] = "delete logs"
    assert rec.verify()[1] == "SESSION_RECORD_TAMPER_DETECTED"

    glass = BreakGlass()
    assert glass.authorize("req", ["lead-a"])["granted"] is False
    assert glass.authorize("req", ["req", "lead-a"])["granted"] is False
    ok = glass.authorize("req", ["lead-a", "lead-b"])
    assert ok["granted"] is True and ok["alarm"] == "CRITICAL_AUDIT"


def test_stage38_risk_prioritization_bands() -> None:
    prio = VulnerabilityPrioritizer()
    hot = prio.prioritize(cvss=9.8, exploited_known=True, internet_exposed=True, asset_criticality="crown")
    assert hot["band"] == "PATCH_NOW" and hot["sla_days"] == 3
    cold = prio.prioritize(cvss=3.1, exploited_known=False, internet_exposed=False, asset_criticality="low")
    assert cold["band"] == "PATCH_PLANNED" and cold["sla_days"] == 90
    mid = prio.prioritize(cvss=7.5, exploited_known=False, internet_exposed=True, asset_criticality="standard")
    assert mid["band"] == "PATCH_STANDARD" and mid["sla_days"] == 30


def test_stage38_remediation_requires_rescan_evidence() -> None:
    verifier = RemediationVerifier()
    assert verifier.verify("2.4.57", "2.4.57") == (True, "REMEDIATION_VERIFIED_ON_RESCAN")
    assert verifier.verify("2.4.58", "2.4.57")[0] is True
    assert verifier.verify("2.4.41", "2.4.57") == (False, "REMEDIATION_NOT_PRESENT_FINDING_STAYS_OPEN")


def test_stage39_cspm_rules_and_drift() -> None:
    scan = CloudPostureScanner().scan([
        {"type": "storage", "name": "backups", "public": True, "encrypted": False},
        {"type": "security_group", "name": "ssh", "cidr": "0.0.0.0/0", "port": 22},
        {"type": "account", "name": "root", "root_mfa": False, "audit_logging": True},
        {"type": "storage", "name": "media", "public": False, "encrypted": True},
    ])
    rules = {f["rule"] for f in scan["findings"]}
    assert rules == {"STORAGE_PUBLIC", "ENCRYPTION_DISABLED", "ADMIN_PORT_WORLD_OPEN", "ROOT_MFA_DISABLED"}
    assert scan["posture"] == "FAIL"

    clean = CloudPostureScanner().scan([{"type": "storage", "name": "m", "public": False, "encrypted": True}])
    assert clean["posture"] == "PASS" and clean["finding_count"] == 0

    drift = DriftDetector().diff({"encrypted": True, "public": False}, {"encrypted": True, "public": True})
    assert drift["drifted"] is True and drift["drift_fields"] == ["public"]
    assert DriftDetector().diff({"a": 1}, {"a": 1})["state"] == "CONFIG_MATCHES_BASELINE"


def test_stage40_ueba_scoring_and_case_threshold() -> None:
    scorer = BehaviourRiskScorer()
    quiet = scorer.score({"downloads_1h": 3})
    assert quiet["band"] == "low" and quiet["signals"] == []
    hostile = scorer.score({"country_changed_within_1h": True, "downloads_1h": 900,
                            "off_hours_privileged": True, "dormant_days": 90})
    assert hostile["band"] == "critical" and hostile["risk_score"] >= 60
    assert "IMPOSSIBLE_TRAVEL" in hostile["signals"] and "MASS_DOWNLOAD" in hostile["signals"]

    builder = InsiderCaseBuilder()
    single = builder.build("u1", [scorer.score({"off_hours_privileged": True})])
    assert single["case_opened"] is False
    case = builder.build("u2", [hostile])
    assert case["case_opened"] is True and case["state"] == "INSIDER_CASE_OPENED_PATTERN_CONFIRMED"
