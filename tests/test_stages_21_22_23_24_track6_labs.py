from __future__ import annotations

import pytest

from study_academy.labs.stage21_sbom_slsa_provenance_and_dependency_guard_lab import (
    DependencyConfusionGuard,
    ProvenanceVerifier,
    SBOMBuilder,
    SupplyChainViolation,
)
from study_academy.labs.stage22_ocsf_streaming_window_and_watermark_lab import (
    DataEngineeringViolation,
    StreamingWindowDetector,
    TelemetryNormalizerOCSF,
)
from study_academy.labs.stage23_stix_intel_fusion_and_ttl_detection_lab import (
    IntelToDetectionCompiler,
    ObservationRiskScorer,
    ThreatIntelFusionEngine,
)
from study_academy.labs.stage24_backup_merkle_recovery_and_assurance_fabric_lab import (
    MerkleBackupVault,
    RecoveryObjectiveSimulator,
    SovereignAssuranceFabric,
)


def test_stage21_sbom_cycle_missing_and_digest() -> None:
    sbom = SBOMBuilder()
    sbom.add_component("app", "1.0.0", b"app-bytes", depends_on=["lib"])
    sbom.add_component("lib", "2.1.0", b"lib-bytes")
    built = sbom.build()
    assert built["bom_format"] == "CycloneDX-like"
    assert len(built["sbom_sha256"]) == 64

    cyclic = SBOMBuilder()
    cyclic.add_component("a", "1", b"a", depends_on=["b"])
    cyclic.add_component("b", "1", b"b", depends_on=["a"])
    with pytest.raises(SupplyChainViolation, match="CYCLE"):
        cyclic.build()

    missing = SBOMBuilder()
    missing.add_component("x", "1", b"x", depends_on=["ghost"])
    with pytest.raises(SupplyChainViolation, match="MISSING_COMPONENT"):
        missing.build()


def test_stage21_provenance_and_dependency_confusion_guard() -> None:
    prov = ProvenanceVerifier(b"trusted_builder_key_32_bytes!!", trusted_builder="arena-ci")
    artifact = b"release-binary-v1"
    att = prov.attest_build(artifact, source_digest="src-abc", builder="arena-ci", build_params={"opt": "O2"})
    assert prov.verify(artifact, att) == (True, "PROVENANCE_VERIFIED_SLSA_STYLE")
    assert prov.verify(b"tampered-binary", att)[1] == "ARTIFACT_DIGEST_MISMATCH_TAMPERED"

    evil = prov.attest_build(artifact, source_digest="src-abc", builder="unknown-builder", build_params={})
    # Re-signing is impossible without the key; forged builder field breaks identity gate first
    assert prov.verify(artifact, evil)[1] == "UNTRUSTED_BUILDER_IDENTITY"

    guard = DependencyConfusionGuard(
        {"default": "https://registry.internal", "@corp": "https://registry.internal"},
        {"requests": "2.32.0", "@corp/agent-core": "4.0.0"},
    )
    assert guard.check("requests", "2.32.0", "https://registry.internal") == (True, "DEPENDENCY_OK_PINNED")
    assert guard.check("requests", "9.9.9", "https://pypi.org")[1] == "REGISTRY_NOT_PINNED_FOR_SCOPE_CONFUSION_RISK"
    assert "TYPOSQUAT" in guard.check("requestz", "1.0.0", "https://registry.internal")[1]
    assert guard.check("requests", "2.0.0", "https://registry.internal")[1] == "VERSION_REGRESSION_VS_LOCKFILE"


def test_stage22_normalizer_rejects_unmapped_and_streaming_windows() -> None:
    norm = TelemetryNormalizerOCSF()
    ev = norm.normalize({"source": "cloud", "action": "SetPublic", "ts": 120, "principal": "alice",
                          "resource": "bucket-1", "event_id": "e1"})
    assert ev["category"] == "storage_activity" and ev["activity"] == "expose"
    with pytest.raises(DataEngineeringViolation, match="UNMAPPED_EVENT"):
        norm.normalize({"source": "cloud", "action": "UnknownOp", "ts": 1, "principal": "x", "resource": "y"})

    det = StreamingWindowDetector(window_seconds=60, lateness_seconds=30, threshold=5)
    for i in range(5):
        raw = {"source": "endpoint", "action": "ProcessCreate", "ts": 100 + i, "principal": "mallory",
               "resource": "host-1", "event_id": f"burst-{i}"}
        assert det.ingest(norm.normalize(raw)) == "INGESTED"
    # Duplicate delivery is dropped exactly-once; excessively late event hits the watermark
    dup = norm.normalize({"source": "endpoint", "action": "ProcessCreate", "ts": 102, "principal": "mallory",
                          "resource": "host-1", "event_id": "burst-0"})
    assert det.ingest(dup) == "DUPLICATE_DROPPED_EXACTLY_ONCE"
    late = norm.normalize({"source": "endpoint", "action": "ProcessCreate", "ts": 10, "principal": "mallory",
                           "resource": "host-1", "event_id": "late-1"})
    assert det.ingest(late) == "LATE_EVENT_DROPPED_BY_WATERMARK"

    alerts = det.alerts()
    assert len(alerts) == 1 and alerts[0]["count"] == 5 and alerts[0]["actor"] == "mallory"
    stats = det.stats()
    assert stats["duplicates_dropped"] == 1 and stats["late_dropped"] == 1


def test_stage23_intel_fusion_decay_revoke_and_ttl_rules() -> None:
    fusion = ThreatIntelFusionEngine(half_life_seconds=100, confidence_floor=0.35)
    fusion.ingest_report("evil.example", source="vendor-a", reliability=0.9, confidence=0.9, observed_ts=1000)
    fusion.ingest_report("evil.example", source="vendor-b", reliability=0.8, confidence=0.8, observed_ts=1000)
    fused_now, state_now = fusion.fused_confidence("evil.example", now_ts=1000)
    assert state_now == "LIVE" and fused_now > 0.9

    # After many half-lives the same intel decays below the floor and must not fire
    fused_old, state_old = fusion.fused_confidence("evil.example", now_ts=1000 + 10_000)
    assert state_old == "BELOW_CONFIDENCE_FLOOR_STALE" and fused_old < fused_now

    compiler = IntelToDetectionCompiler(fusion)
    rules = compiler.compile_rules(["evil.example"], now_ts=1000, ttl_seconds=500)
    assert len(rules) == 1
    assert compiler.match("evil.example", rules, now_ts=1200)[0] is True
    assert compiler.match("evil.example", rules, now_ts=9999) == (False, "INTEL_RULE_EXPIRED_NO_FIRE")

    fusion.revoke("evil.example")
    assert fusion.fused_confidence("evil.example", now_ts=1000) == (0.0, "INDICATOR_REVOKED")
    assert compiler.compile_rules(["evil.example"], now_ts=1000) == []

    scorer = ObservationRiskScorer()
    assert scorer.score(0.95, "crown_jewel")["band"] == "critical"
    assert scorer.score(0.95, "sandbox")["band"] == "log_only"


def test_stage24_merkle_restore_locates_corruption() -> None:
    vault = MerkleBackupVault(chunk_size=8)
    data = b"sovereign-backup-payload-0123456789"
    snap = vault.backup(data)
    assert vault.verify_restore(snap, list(snap["chunks"])) == (True, "RESTORE_VERIFIED_MERKLE_OK")

    corrupted = list(snap["chunks"])
    corrupted[1] = b"TAMPERED"
    ok, reason = vault.verify_restore(snap, corrupted)
    assert ok is False and reason == "RESTORE_CORRUPT_CHUNK_LOCATED_1"


def test_stage24_recovery_objectives_and_assurance_fabric_gates() -> None:
    sim = RecoveryObjectiveSimulator().simulate_failover(
        last_backup_ts=900, incident_ts=1000, restore_started_ts=1010,
        service_restored_ts=1300, rpo_seconds=300, rto_seconds=600,
    )
    assert sim["objectives_met"] is True and sim["data_loss_seconds"] == 100

    breached = RecoveryObjectiveSimulator().simulate_failover(
        last_backup_ts=0, incident_ts=5000, restore_started_ts=5010,
        service_restored_ts=9000, rpo_seconds=300, rto_seconds=600,
    )
    assert breached["objectives_met"] is False and breached["rpo_met"] is False

    granted = SovereignAssuranceFabric.attest(
        {"supply_chain": 98.0, "detection": 88.0, "shield": 95.0, "recovery": 90.0}
    )
    assert granted["verdict"] == "SOVEREIGN_ASSURANCE_GRANTED"
    assert len(str(granted["attestation_sha256"])) == 64

    denied = SovereignAssuranceFabric.attest(
        {"supply_chain": 98.0, "detection": 50.0, "shield": 95.0, "recovery": 90.0}
    )
    assert denied["verdict"] == "ASSURANCE_DENIED_DOMAIN_BELOW_GATE"
    assert denied["domains"]["detection"]["passed"] is False
