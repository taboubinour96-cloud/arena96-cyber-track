from __future__ import annotations

import pytest

from study_academy.labs.stage29_dmarc_bec_and_oauth_consent_lab import (
    BECRiskScorer,
    DMARCAlignmentEvaluator,
    OAuthConsentRiskAnalyzer,
)
from study_academy.labs.stage30_dnssec_tunneling_and_ct_monitor_lab import (
    CertificateTransparencyMonitor,
    DNSTunnelingDetector,
    DNSSECChainValidator,
)
from study_academy.labs.stage31_extension_permissions_and_device_attestation_lab import (
    BrowserExtensionRiskAnalyzer,
    MobileDeviceAttestationVerifier,
)
from study_academy.labs.stage32_canary_deception_grid_and_trip_alert_lab import (
    CanaryTokenRegistry,
    DeceptionGridPlanner,
    HoneyInteractionClassifier,
)


def test_stage29_dmarc_alignment_and_policy_enforcement() -> None:
    ev = DMARCAlignmentEvaluator()
    passed = ev.evaluate(from_domain="arena.example", spf_result="pass", spf_domain="arena.example",
                         dkim_result="none", dkim_domain="", dmarc_policy="reject")
    assert passed["dmarc_pass"] is True and passed["action"] == "DELIVER_DMARC_PASS"

    spoof = ev.evaluate(from_domain="arena.example", spf_result="pass", spf_domain="evil.example",
                        dkim_result="fail", dkim_domain="evil.example", dmarc_policy="reject")
    assert spoof["dmarc_pass"] is False and spoof["action"] == "REJECT_DMARC_FAIL_POLICY_REJECT"

    monitored = ev.evaluate(from_domain="arena.example", spf_result="fail", spf_domain="x.example",
                            dkim_result="fail", dkim_domain="x.example", dmarc_policy="none")
    assert monitored["action"] == "DELIVER_BUT_TAGGED_DMARC_MONITOR_ONLY"


def test_stage29_bec_scoring_and_oauth_consent_governance() -> None:
    scorer = BECRiskScorer(["arena.example"], ["Nour Owner"])
    bec = scorer.score(display_name="Nour Owner", from_domain="gmail.example",
                       reply_to_domain="collector.example", subject_body="Urgent wire, pay today, confidential transfer")
    assert bec["band"] == "critical" and bec["risk_score"] >= 60

    legit = scorer.score(display_name="Team Update", from_domain="arena.example",
                         reply_to_domain="arena.example", subject_body="Weekly report attached")
    assert legit["band"] == "low"

    oauth = OAuthConsentRiskAnalyzer()
    dangerous = oauth.analyze(app_name="Mail Reader Pro", publisher_verified=False,
                              scopes=["mail.read", "mail.send", "offline_access"])
    assert dangerous["decision"] == "DENY_OR_REQUIRE_ADMIN_APPROVAL"
    safe = oauth.analyze(app_name="Profile Card", publisher_verified=True, scopes=["openid", "profile"])
    assert safe["decision"] == "ALLOW_USER_CONSENT"


def test_stage30_dnssec_chain_tamper_and_ds_break() -> None:
    val = DNSSECChainValidator()
    val.register_zone("example", key_material="zone-key-1", parent_zone=".")
    rec = val.sign_record("example", "mail.example", "192.0.2.10")
    assert val.validate(rec) == (True, "DNSSEC_CHAIN_VALIDATED")

    tampered = dict(rec)
    tampered["value"] = "203.0.113.66"
    assert val.validate(tampered)[1] == "DNSSEC_RRSIG_INVALID_TAMPERED_RECORD"

    # Attacker rotates in their own key: parent DS digest no longer matches
    val.register_zone("evil", key_material="attacker-key", parent_zone=".")
    val.zone_keys["example"] = "attacker-key"
    assert val.validate(rec)[1] in {"DNSSEC_DS_DIGEST_MISMATCH_CHAIN_BROKEN", "DNSSEC_RRSIG_INVALID_TAMPERED_RECORD"}


def test_stage30_tunneling_statistics_and_ct_monitor() -> None:
    det = DNSTunnelingDetector()
    normal = det.analyze(
        [{"name": "www.arena.example", "type": "A"}, {"name": "mail.arena.example", "type": "A"}],
        watched_suffix="arena.example",
    )
    assert normal["verdict"] == "NORMAL"

    tunneled = det.analyze(
        [{"name": f"{'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'}{i}.exfil.arena.example", "type": "TXT"} for i in range(6)],
        watched_suffix="arena.example",
    )
    assert tunneled["verdict"] == "TUNNELING_LIKELY" and tunneled["score"] >= 60

    ct = CertificateTransparencyMonitor(["arena.example"], ["Arena CA", "Public CA"])
    assert ct.check_entry("login.arena.example", "Public CA") == (False, "CT_OK_WATCHED_DOMAIN_AUTHORIZED_ISSUER")
    assert ct.check_entry("login.arena.example", "Shady CA")[1].startswith("CT_ALERT_UNAUTHORIZED_ISSUER")
    assert ct.check_entry("arenaa.example", "Public CA")[1].startswith("CT_ALERT_LOOKALIKE")


def test_stage31_extension_risk_and_device_attestation() -> None:
    ext = BrowserExtensionRiskAnalyzer()
    spy = ext.analyze(name="Super Coupon", permissions=["cookies", "scripting"],
                      host_permissions=["<all_urls>"], publisher_verified=False)
    assert spy["decision"] == "BLOCK_EXTENSION" and "COOKIE_PLUS_SCRIPTING" in str(spy["signals"])

    modest = ext.analyze(name="Tab Counter", permissions=["tabs", "storage"],
                         host_permissions=[], publisher_verified=True)
    assert modest["decision"] == "ALLOW_EXTENSION"

    dev = MobileDeviceAttestationVerifier(b"device_attestation_key_32_bytes")
    good = dev.sign_attestation({"device_id": "d1", "integrity": "PASS", "jailbroken": False,
                                 "rooted": False, "os_major": 15, "patch_age_days": 10})
    assert dev.verify_enrollment(good) == (True, "DEVICE_ATTESTATION_VERIFIED_ENROLL_ALLOWED")

    rooted = dev.sign_attestation({"device_id": "d2", "integrity": "PASS", "jailbroken": False,
                                   "rooted": True, "os_major": 15, "patch_age_days": 10})
    assert dev.verify_enrollment(rooted)[1] == "ATTESTATION_COMPROMISED_OS_JAILBREAK_ROOT"

    stale = dev.sign_attestation({"device_id": "d3", "integrity": "PASS", "jailbroken": False,
                                  "rooted": False, "os_major": 15, "patch_age_days": 400})
    assert dev.verify_enrollment(stale)[1] == "ATTESTATION_SECURITY_PATCH_STALE"


def test_stage32_canary_trip_forgery_and_grid_coverage() -> None:
    registry = CanaryTokenRegistry(b"canary_registry_key_32_bytes!!")
    canary = registry.issue("credential", "finance-db", nonce="n-1")
    tripped, state, alert = registry.trigger(canary["canary_id"], source_context="198.51.100.9")
    assert tripped is True and alert["severity"] == "critical"
    assert len(str(alert["alert_sha256"])) == 64

    forged, forged_state, _ = registry.trigger("canary-forged0000000000", source_context="x")
    assert forged is False and forged_state == "CANARY_UNKNOWN_OR_FORGED_NO_ALERT"

    full = DeceptionGridPlanner.coverage(["finance-db", "agent-vault"], registry.issued_assets())
    assert full["missing"] == ["agent-vault"] and full["deception_gate_passed"] is False
    registry.issue("file", "agent-vault", nonce="n-2")
    assert DeceptionGridPlanner.coverage(["finance-db", "agent-vault"], registry.issued_assets())["deception_gate_passed"] is True

    honey = HoneyInteractionClassifier()
    assert honey.classify({"action": "connect", "payload": ""})["depth"] == "recon"
    assert honey.classify({"action": "auth_attempt", "payload": "admin"})["depth"] == "auth_attempt"
    assert honey.classify({"action": "http", "payload": "../../etc/passwd"})["severity"] == "critical"
