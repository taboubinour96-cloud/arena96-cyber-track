from __future__ import annotations

import pytest

from study_academy.labs.stage17_byzantine_quorum_eclipse_and_gossip_lab import (
    ByzantineQuorumEngine,
    ConsensusViolation,
    EclipseResistancePeerSelector,
    GossipAntiEntropyReconciler,
)
from study_academy.labs.stage18_formal_policy_model_checker_and_capability_lab import (
    AGENT_SAFETY_INVARIANTS,
    CapabilityTokenEngine,
    PolicyViolation,
    build_agent_model,
)
from study_academy.labs.stage19_cloud_endpoint_detection_as_code_lab import (
    DetectionAsCodeEngine,
    DetectionCoverageCalculator,
    TelemetrySanitizerPipeline,
)
from study_academy.labs.stage20_autonomous_shield_remediation_and_assurance_lab import (
    AutonomousShieldOrchestrator,
    ShieldAssuranceLedger,
)


def test_stage17_byzantine_quorum_and_equivocation_evidence() -> None:
    eng = ByzantineQuorumEngine(["v1", "v2", "v3", "v4"])  # n=4, f=1, quorum=3
    assert eng.f == 1 and eng.quorum == 3
    for v in ("v1", "v2", "v3"):
        assert eng.cast_vote(v, 10, 0, "block-A") == "VOTE_RECORDED"
    cert = eng.commit_certificate(10, 0, "block-A")
    assert eng.verify_certificate(cert) is True

    # Only 2 votes for a rival value can never reach quorum
    eng.cast_vote("v4", 10, 0, "block-B")
    with pytest.raises(ConsensusViolation, match="QUORUM_NOT_REACHED"):
        eng.commit_certificate(10, 0, "block-B")

    # Equivocation: v1 signs a second, different value at same height/round
    with pytest.raises(ConsensusViolation, match="EQUIVOCATION_DETECTED"):
        eng.cast_vote("v1", 10, 0, "block-B")
    evidence = eng.equivocation_evidence()
    assert len(evidence) == 1 and evidence[0]["validator"] == "v1"
    assert len(str(evidence[0]["evidence_sha256"])) == 64


def test_stage17_eclipse_peer_diversity_and_gossip_convergence() -> None:
    selector = EclipseResistancePeerSelector(max_per_subnet=1, max_per_asn=2, min_distinct_subnets=3)
    sybil_cluster = [
        {"ip": f"203.0.113.{i}", "asn": "AS64500", "score": 100 - i} for i in range(1, 8)
    ]
    honest = [
        {"ip": "198.51.100.7", "asn": "AS64501", "score": 50},
        {"ip": "192.0.2.9", "asn": "AS64502", "score": 49},
        {"ip": "203.0.114.5", "asn": "AS64503", "score": 48},
    ]
    result = selector.select_peers(sybil_cluster + honest, want=4)
    # Per-subnet cap=1 stops the Sybil cluster from filling the peer set
    assert result["distinct_subnet_count"] >= 3
    assert result["eclipsed"] is False
    assert len([ip for ip in result["selected_ips"] if ip.startswith("203.0.113.")]) <= 1

    rec = GossipAntiEntropyReconciler()
    local = {"k1": (2, "new"), "k2": (1, "same"), "k3": (1, "aaa")}
    remote = {"k1": (1, "old"), "k2": (1, "same"), "k3": (1, "bbb"), "k4": (1, "fresh")}
    merged = rec.reconcile(local, remote)
    assert merged["merged"]["k1"] == (2, "new")  # higher version wins
    assert merged["merged"]["k4"] == (1, "fresh")  # missing key transferred
    assert merged["conflict_keys"] == ["k3"]  # same-version divergence recorded
    assert merged["merged"]["k3"] == (1, "bbb")  # deterministic tie-break
    assert len(merged["converged_digest"]) == 64


def test_stage18_model_checker_proves_safe_and_finds_buggy_counterexample() -> None:
    safe = build_agent_model(buggy_bypass=False).check_invariants("Idle", AGENT_SAFETY_INVARIANTS)
    assert safe["holds"] is True
    assert safe["reachable_count"] == 6  # SecretExfiltrated unreachable in safe model

    buggy = build_agent_model(buggy_bypass=True).check_invariants("Idle", AGENT_SAFETY_INVARIANTS)
    assert buggy["holds"] is False
    assert buggy["violated_invariant"] in AGENT_SAFETY_INVARIANTS
    assert buggy["counterexample_state"] in {"SecretExfiltrated", "ExecutedPrivileged"}
    assert buggy["counterexample_path"][0] == "Idle"


def test_stage18_capability_attenuation_only_narrows() -> None:
    engine = CapabilityTokenEngine(b"root_capability_key_32_bytes_long!")
    root = engine.issue("agent-96", ["read", "write", "execute"], "/workspace/repo/", expires_at=10_000)
    assert engine.verify(root, "read", "/workspace/repo/docs/a.md", now_ts=100) == (True, "CAPABILITY_OK")

    child = engine.attenuate(root, actions=["read"], resource_prefix="/workspace/repo/docs/")
    assert engine.verify(child, "read", "/workspace/repo/docs/a.md", now_ts=100)[0] is True
    assert engine.verify(child, "write", "/workspace/repo/docs/a.md", now_ts=100)[1] == "CAPABILITY_ACTION_NOT_GRANTED"
    assert engine.verify(child, "read", "/workspace/repo/secrets.env", now_ts=100)[1] == "CAPABILITY_RESOURCE_OUT_OF_SCOPE"
    assert engine.verify(child, "read", "/workspace/repo/docs/a.md", now_ts=20_000)[1] == "CAPABILITY_EXPIRED"

    with pytest.raises(PolicyViolation, match="WIDENING_ACTIONS"):
        engine.attenuate(child, actions=["read", "delete"])
    with pytest.raises(PolicyViolation, match="WIDENING_EXPIRY"):
        engine.attenuate(root, expires_at=99_999)

    tampered = dict(child)
    tampered["actions"] = ["read", "execute"]
    assert engine.verify(tampered, "execute", "/workspace/repo/docs/a.md", now_ts=100)[1] == "CAPABILITY_MAC_INVALID_TAMPERED"


def test_stage19_detection_as_code_sanitizer_and_coverage() -> None:
    pipe = TelemetrySanitizerPipeline()
    ok, state, clean = pipe.ingest({
        "ts": 100, "source": "cloudtrail", "principal": "ops", "action": "login",
        "note": "key ghp_" + "A" * 25, "password": "should-be-dropped",
    })
    assert ok is True and state == "TELEMETRY_INGESTED_CLEAN"
    assert "ghp_" not in str(clean["note"]) and "password" not in clean

    # Timestamp rollback / replay from same source is blocked
    ok2, state2, _ = pipe.ingest({"ts": 50, "source": "cloudtrail", "principal": "ops", "action": "login"})
    assert ok2 is False and state2 == "TELEMETRY_TIMESTAMP_ROLLBACK_BLOCKED"

    engine = DetectionAsCodeEngine()
    events = [
        {"ts": 1, "principal": "alice", "resource": "bucket-1", "action": "storage:SetPublic", "public": True},
        {"ts": 2, "principal": "alice", "resource": "bucket-1", "action": "storage:SetPublic", "public": True},
        {"ts": 3, "principal": "bob", "resource": "host-7", "parent_process": "winword.exe", "process": "powershell.exe"},
        {"ts": 4, "principal": "carol", "resource": "host-9", "cmdline": "tool --api-key ghp_" + "B" * 25},
        {"ts": 5, "principal": "dan", "resource": "vpn", "impossible_travel": True},
    ]
    result = engine.evaluate(events)
    assert result["alert_count"] == 4  # duplicate bucket event deduplicated into one alert
    bucket_alert = next(a for a in result["alerts"] if a["rule_id"] == "CLOUD-002")
    assert bucket_alert["count"] == 2 and bucket_alert["severity"] == "critical"

    cov = DetectionCoverageCalculator.coverage(
        ["T1078", "T1059", "T1567", "T1190"], DetectionAsCodeEngine.RULES
    )
    assert cov["coverage_pct"] == 75.0 and cov["gaps"] == ["T1190"]


def test_stage20_shield_guardrails_rate_limit_rollback_and_attestation() -> None:
    shield = AutonomousShieldOrchestrator(max_auto_per_hour=2)
    low_risk = {
        "action_id": "fix-public-bucket", "resource": "bucket-1",
        "confidence": 0.95, "blast_radius": "low", "reversible": True,
        "desired_state": "private",
    }
    ok, reason, entry = shield.execute(low_risk, now_ts=1000)
    assert ok is True and reason == "REMEDIATED_VIA_AUTO_REMEDIATE"
    assert shield.current_state()["bucket-1"] == "private"

    # Irreversible / high-blast actions can never auto-execute
    dangerous = {
        "action_id": "delete-db", "resource": "db-1",
        "confidence": 0.99, "blast_radius": "critical", "reversible": False,
        "desired_state": "deleted",
    }
    ok2, reason2, _ = shield.execute(dangerous, now_ts=1001)
    assert ok2 is False and "REQUIRES_OWNER_APPROVAL" in reason2
    assert "db-1" not in shield.current_state()
    ok3, _, _ = shield.execute(dangerous, now_ts=1002, approved=True)
    assert ok3 is True  # explicit owner approval unlocks it

    # Rollback restores the exact prior state and the chain still verifies
    ok_rb, rb_state = shield.rollback(str(entry["entry_sha256"]), now_ts=1003)
    assert ok_rb is True and rb_state == "ROLLBACK_OK_PRIOR_STATE_RESTORED"
    assert "bucket-1" not in shield.current_state()

    # Kill-switch halts everything, even approved automation
    shield.engage_kill_switch()
    ok4, reason4, _ = shield.execute(low_risk, now_ts=1004, approved=True)
    assert ok4 is False and "KILL_SWITCH" in reason4
    shield.disengage_kill_switch()

    att = ShieldAssuranceLedger.attest(shield.journal)
    assert att["chain_verified"] is True
    assert att["human_sovereignty_preserved"] is True
    assert att["remediations_executed"] == 2
    assert len(str(att["attestation_sha256"])) == 64
