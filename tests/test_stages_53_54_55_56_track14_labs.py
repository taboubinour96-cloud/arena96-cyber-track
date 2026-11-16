from __future__ import annotations

import pytest

from study_academy.labs.stage53_attack_path_privilege_escalation_lab import (
    AttackPathAnalyzer,
    GraphViolation,
)
from study_academy.labs.stage54_ransomware_readiness_and_recovery_lab import (
    BackupGate,
    ContainmentPlanner,
    RansomwareReadinessMatrix,
    RestoreDrillEvaluator,
)
from study_academy.labs.stage55_data_residency_and_jurisdiction_lab import (
    AdequacyLedger,
    DataResidencyGate,
    JurisdictionRouter,
)
from study_academy.labs.stage56_soar_automation_blast_radius_lab import (
    ActionVerifier,
    BlastRadiusReport,
    ResponsePlaybook,
    ReversibleAction,
)

TIER0 = {"domain-controller"}


def test_stage53_attack_path_and_choke_points() -> None:
    analyzer = AttackPathAnalyzer([
        ("intern-laptop", "file-share"),
        ("file-share", "svc-backup"),
        ("svc-backup", "domain-controller"),
        ("intern-laptop", "print-server"),
        ("print-server", "helpdesk-admin"),
        ("helpdesk-admin", "svc-backup"),
    ])

    found = analyzer.analyze("intern-laptop", TIER0)
    assert found["path_found"] is True
    assert found["target"] == "domain-controller"
    assert found["hop_count"] == 3
    assert found["state"] == "ATTACK_PATH_OPEN_TO_TIER0"

    # One node on every route: cutting it closes the path entirely.
    chokes = [c["node"] for c in analyzer.choke_points("intern-laptop", TIER0)]
    assert chokes == ["svc-backup"]
    assert analyzer.analyze("intern-laptop", TIER0, blocked={"svc-backup"})["path_found"] is False

    # Escalation edges are ranked by weight, not by discovery order.
    ranked = analyzer.privilege_escalation_edges({
        "svc-backup->domain-controller": 90,
        "intern-laptop->file-share": 10,
        "print-server->helpdesk-admin": 55,
    })
    assert ranked[0]["edge"] == "svc-backup->domain-controller"

    with pytest.raises(GraphViolation):
        analyzer.analyze("ghost-host", TIER0)


def test_stage54_containment_backups_and_restore_proof() -> None:
    planner = ContainmentPlanner({
        "ws-01": ["svc-local-admin", "user-nour"],
        "ws-02": ["svc-local-admin"],
        "db-01": ["svc-db"],
    })
    plan = planner.isolation_set(["ws-01"])
    assert plan["isolation_order"] == ["ws-01", "ws-02"]
    assert plan["shared_credentials"] == ["svc-local-admin"]

    gate = BackupGate([
        {"id": "b1", "immutable": True, "separate_identity": True},
        {"id": "b2", "immutable": False, "separate_identity": True},
    ])
    assert gate.classify()["safe_ids"] == ["b1"]
    assert gate.delete("b1", ["nour", "master"])["state"] == "DELETE_DENIED_IMMUTABLE_COPY"
    assert gate.delete("b2", ["nour"])["state"] == "DELETE_DENIED_NEEDS_DUAL_APPROVAL"
    assert gate.delete("b2", ["nour", "master"])["deleted"] is True

    drills = RestoreDrillEvaluator(max_rpo_minutes=15, max_rto_minutes=60)
    bad = drills.evaluate([
        {"name": "erp", "rpo_minutes": 12, "rto_minutes": 45, "drilled": True},
        {"name": "mail", "rpo_minutes": 40, "rto_minutes": 30, "drilled": False},
    ])
    assert bad["restore_gate_passed"] is False
    assert "mail:NOT_DRILLED" in bad["failures"] and "mail:RPO_EXCEEDED" in bad["failures"]

    good = drills.evaluate([{"name": "erp", "rpo_minutes": 10, "rto_minutes": 40, "drilled": True}])
    assert good["state"] == "RESTORE_PROVEN"

    matrix = RansomwareReadinessMatrix()
    assert matrix.evaluate(True, True, True, False)["missing"] == ["evidence_preserved"]
    assert matrix.evaluate(True, True, True, True)["state"] == "READY"


def test_stage55_residency_routing_and_key_custody() -> None:
    gate = DataResidencyGate({
        "public": {"TN", "FR"},
        "sovereign": {"TN"},
        "financial": {"TN"},
    })
    assert gate.evaluate("r1", "public", "TN", "FR", "FR")["allowed"] is True
    assert gate.evaluate("r2", "sovereign", "TN", "FR", "TN")["state"] == "DENIED_CROSS_BORDER_NO_ADEQUACY"
    assert gate.evaluate("r3", "sovereign", "TN", "TN", "FR")["state"] == "DENIED_KEY_CUSTODY_MISMATCH"
    assert gate.evaluate("r3", "sovereign", "TN", "TN", "TN")["allowed"] is True
    assert gate.evaluate("r4", "secret", "TN", "TN", "TN")["state"] == "DENIED_UNKNOWN_CLASSIFICATION"

    router = JurisdictionRouter({
        "tn-south": {"jurisdiction": "TN", "classes": ["sovereign", "public"], "status": "ready"},
        "fr-west": {"jurisdiction": "FR", "classes": ["public"], "status": "ready"},
        "tn-dry": {"jurisdiction": "TN", "classes": ["sovereign"], "status": "draining"},
    })
    assert router.route("sovereign", ["tn-south", "fr-west", "tn-dry"])["selected"] == "tn-south"
    assert router.route("sovereign", ["fr-west", "tn-dry"])["state"] == "NO_ELIGIBLE_REGION"

    ledger = AdequacyLedger([
        {"jurisdiction": "FR", "classification": "public", "basis": "decision-2026-14", "expires_at": 500},
        {"jurisdiction": "FR", "classification": "sovereign", "basis": "lapsed-2019", "expires_at": 100},
    ])
    assert ledger.approved("FR", "public", now=100)["state"] == "ADEQUACY_VALID"
    assert ledger.approved("FR", "sovereign", now=200)["state"] == "ADEQUACY_EXPIRED"
    assert ledger.approved("TN", "public", now=100)["state"] == "NO_ADEQUACY_RECORDED"


def test_stage56_playbook_caps_and_verification() -> None:
    playbook = ResponsePlaybook({"max_hosts": 3, "max_users": 2, "max_services": 1})

    auto = playbook.decide("isolate", {"max_hosts": 2, "max_users": 0, "max_services": 0},
                           critical_asset=False, reversible=True, has_evidence=True)
    assert auto["execute"] is True and auto["state"] == "AUTOMATED_EXECUTION_ALLOWED"

    held = playbook.decide("isolate", {"max_hosts": 9, "max_users": 0, "max_services": 0},
                           critical_asset=False, reversible=True, has_evidence=True)
    assert held["execute"] is False and held["state"] == "HELD_FOR_DUAL_APPROVAL"
    assert held["approvals_required"] == 2 and held["exceeded"] == ["max_hosts"]

    blocked = playbook.decide("wipe", {"max_hosts": 1, "max_users": 0, "max_services": 0},
                              critical_asset=False, reversible=False, has_evidence=False)
    assert blocked["state"] == "DENIED_IRREVERSIBLE_WITHOUT_EVIDENCE"

    action = ReversibleAction("quarantine", "ws-01")
    assert action.prepare({"ws-01": "connected"}, rollback_token=None)["prepared"] is False
    assert action.prepare({"ws-01": "connected"}, rollback_token="rb-1")["prepared"] is True
    after = action.apply({"ws-01": "connected", "ws-02": "connected"},
                         {"ws-01": "quarantined"})
    assert after["ws-01"] == "quarantined"

    verifier = ActionVerifier()
    clean = verifier.verify({"ws-01": "connected"}, {"ws-01": "quarantined"}, ["ws-01"])
    assert clean["verified"] is True and clean["state"] == "ACTION_VERIFIED"

    collateral = verifier.verify({"ws-01": "connected", "ws-02": "connected"},
                                 {"ws-01": "quarantined", "ws-02": "quarantined"}, ["ws-01"])
    assert collateral["verified"] is False
    assert collateral["collateral_changes"] == ["ws-02"]

    report = BlastRadiusReport().evaluate([{"max_hosts": 3}, {"max_hosts": 3}])
    assert report["state"] == "BLAST_RADIUS_EXCEEDED" and report["exceeded"] == ["max_hosts"]
    assert action.rollback(after)["ws-01"] == "connected"
