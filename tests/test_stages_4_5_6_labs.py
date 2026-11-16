"""
Automated Verification Suite for Stages 4, 5, and 6 Hands-On Labs (Arena 96 - Supervised by Noor).
"""

import json
import secrets
import pytest

from study_academy.labs.stage4_packet_siem_container_lab import (
    audit_cloud_iam_policy,
    audit_container_security_context,
    build_minimal_pcap,
    correlate_security_events,
    parse_pcap_bytes,
)
from study_academy.labs.stage5_appsec_dfir_grc_lab import (
    ForensicEvidenceLocker,
    calculate_mitre_detection_coverage,
    match_sbom_components_to_advisories,
)
from study_academy.labs.stage6_detection_engineering_and_capstone_lab import (
    EnvelopeEncryptionVault,
    evaluate_sigma_rule,
    inspect_artifact_metadata,
)


def test_stage4_pcap_siem_and_cloud_container_auditors() -> None:
    raw_pcap = build_minimal_pcap([b"\xaa" * 60, b"\xbb" * 84])
    summary = parse_pcap_bytes(raw_pcap)
    assert summary.packet_count == 2
    assert summary.total_captured_bytes == 144

    events = [
        {"event_id": 4625, "source_ip": "10.0.5.99", "target_user": "alice"},
        {"event_id": 4625, "source_ip": "10.0.5.99", "target_user": "bob"},
        {"event_id": 4625, "source_ip": "10.0.5.99", "target_user": "charlie"},
        {"event_id": 4625, "source_ip": "10.0.5.99", "target_user": "dana"},
        {"event_id": 1, "parent_image": "C:\\Windows\\System32\\inetsrv\\w3wp.exe", "image": "C:\\Windows\\System32\\cmd.exe"},
    ]
    alerts = correlate_security_events(events)
    assert len(alerts) == 2

    iam_issues = audit_cloud_iam_policy(
        json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    )
    assert len(iam_issues) == 1

    container_issues = audit_container_security_context(
        {"privileged": True, "run_as_user": 0, "read_only_root_filesystem": False}
    )
    assert len(container_issues) == 3


def test_stage5_sbom_dfir_custody_and_mitre_coverage() -> None:
    hits = match_sbom_components_to_advisories(
        [{"name": "xz-utils", "version": "5.6.0"}],
        {"xz-utils@5.6.0": ["CVE-2024-3094"]},
    )
    assert hits == ["xz-utils@5.6.0 -> CVE-2024-3094"]

    locker = ForensicEvidenceLocker()
    ram_sample = b"VOLATILE_KERNEL_MEMORY_SNAPSHOT_001"
    locker.acquire_evidence("EVID-01", "RAM Snapshot", volatility_rank=1, raw_bytes=ram_sample)
    assert locker.transfer_custody("EVID-01", "Analyst_A", "Forensics_Lead", "Memory Analysis", ram_sample)

    with pytest.raises(ValueError):
        locker.transfer_custody("EVID-01", "Forensics_Lead", "Archive", "Storage", ram_sample + b"X")

    cov = calculate_mitre_detection_coverage(
        {
            "T1059": {"logged": True, "alerted": True, "prevented": True},
            "T1078": {"logged": True, "alerted": True, "prevented": False},
        }
    )
    assert cov["telemetry_pct"] == 100.0
    assert cov["alert_coverage_pct"] == 100.0
    assert cov["prevention_pct"] == 50.0


def test_stage6_sigma_entropy_and_kms_envelope_rotation() -> None:
    selection = {"ParentImage|endswith": ["\\w3wp.exe"], "Image|endswith": ["\\powershell.exe"]}
    allow_filter = {"CommandLine|contains": ["healthcheck.ps1"]}

    # Malicious behaviour triggers rule
    assert evaluate_sigma_rule(
        {"ParentImage": "C:\\w3wp.exe", "Image": "C:\\powershell.exe", "CommandLine": "whoami"},
        selection,
        allow_filter,
    ) is True

    # Documented legitimate healthcheck is suppressed cleanly (high precision!)
    assert evaluate_sigma_rule(
        {"ParentImage": "C:\\w3wp.exe", "Image": "C:\\powershell.exe", "CommandLine": "C:\\scripts\\healthcheck.ps1"},
        selection,
        allow_filter,
    ) is False

    # ELF low-entropy vs random high-entropy check
    elf_meta = inspect_artifact_metadata(b"\x7fELF" + (b"\x00\x01\x02\x03" * 256))
    assert elf_meta.binary_format == "ELF"
    assert elf_meta.likely_packed_or_encrypted is False

    packed_meta = inspect_artifact_metadata(b"MZ" + secrets.token_bytes(2048))
    assert packed_meta.binary_format == "PE"
    assert packed_meta.likely_packed_or_encrypted is True

    # KMS Envelope Encryption + O(1) KEK rotation without re-encrypting payload
    old_kek = secrets.token_bytes(32)
    new_kek = secrets.token_bytes(32)
    vault = EnvelopeEncryptionVault(old_kek)
    env = vault.encrypt_record(b"Top-Secret Financial Ledger Entry #96")
    original_payload_ct = env["payload"]["ciphertext"]

    rotated_env = vault.rotate_kek_on_envelope(env, new_kek)
    assert rotated_env["payload"]["ciphertext"] == original_payload_ct
    vault_new = EnvelopeEncryptionVault(new_kek)
    assert vault_new.decrypt_record(rotated_env) == b"Top-Secret Financial Ledger Entry #96"
