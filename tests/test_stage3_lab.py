"""
Automated Verification Suite for Stage 3 Hands-On Lab (Arena 96 - Supervised by Noor).
"""

from study_academy.labs.stage3_crypto_iam_and_risk_lab import (
    AccessRequestContext,
    compute_quantitative_risk,
    evaluate_zero_trust_policy,
    generate_pkce_pair,
    hash_password_scrypt,
    prioritize_vulnerability_sla,
    verify_password_scrypt,
    verify_pkce_s256,
)


def test_scrypt_password_kdf_salting_and_verification() -> None:
    h1 = hash_password_scrypt("Correct-Horse-Battery-Staple!96")
    h2 = hash_password_scrypt("Correct-Horse-Battery-Staple!96")
    # Unique random salt means identical passwords produce distinct hashes
    assert h1 != h2
    assert verify_password_scrypt("Correct-Horse-Battery-Staple!96", h1) is True
    assert verify_password_scrypt("WrongPassword", h1) is False


def test_oauth21_pkce_s256_exchange() -> None:
    verifier, challenge = generate_pkce_pair()
    assert verify_pkce_s256(verifier, challenge) is True
    assert verify_pkce_s256(verifier + "tampered", challenge) is False


def test_zero_trust_policy_engine_rbac_and_abac_signals() -> None:
    # Admin on healthy device WITH FIDO2 MFA accessing CRITICAL_PROD -> ALLOW
    ok, code = evaluate_zero_trust_policy(
        AccessRequestContext(
            user_role="security_admin",
            action="rotate_prod_keys",
            resource_classification="CRITICAL_PROD",
            device_edr_healthy=True,
            phishing_resistant_mfa=True,
            risk_score=10,
        )
    )
    assert ok is True
    assert code == "ALLOW_ZERO_TRUST_VERIFIED"

    # Same admin WITHOUT Phishing-Resistant MFA on CRITICAL_PROD -> Blocked!
    ok2, code2 = evaluate_zero_trust_policy(
        AccessRequestContext(
            user_role="security_admin",
            action="rotate_prod_keys",
            resource_classification="CRITICAL_PROD",
            device_edr_healthy=True,
            phishing_resistant_mfa=False,
            risk_score=10,
        )
    )
    assert ok2 is False
    assert code2 == "DENY_STEP_UP_FIDO2_MFA_REQUIRED"

    # Unhealthy unmanaged device -> Blocked regardless of role!
    ok3, code3 = evaluate_zero_trust_policy(
        AccessRequestContext(
            user_role="security_admin",
            action="read_logs",
            resource_classification="INTERNAL",
            device_edr_healthy=False,
            phishing_resistant_mfa=True,
            risk_score=5,
        )
    )
    assert ok3 is False
    assert code3 == "DENY_UNHEALTHY_DEVICE_POSTURE"


def test_quantitative_risk_and_rbvm_sla_prioritizer() -> None:
    sle, ale = compute_quantitative_risk(asset_value=200_000, exposure_factor=0.25, aro=0.5)
    assert sle == 50_000.0
    assert ale == 25_000.0

    # Medium CVSS (6.5) that IS actively exploited in CISA KEV -> P0 Emergency!
    assert (
        prioritize_vulnerability_sla(6.5, epss_probability=0.85, in_cisa_kev=True, internet_exposed=False)
        == "P0_EMERGENCY_24_48H"
    )
    # High CVSS (8.1) internal-only with tiny EPSS (0.01) and not in KEV -> P2 Standard 30D (not false emergency!)
    assert (
        prioritize_vulnerability_sla(8.1, epss_probability=0.01, in_cisa_kev=False, internet_exposed=False)
        == "P2_STANDARD_30D"
    )
