"""
المختبر العملي للمرحلة 3 (Stage 3 Hands-On Cryptography, IAM, Risk & Zero-Trust Lab) — أرينا 96 (بإشراف نور)

يطبق هذا المختبر ركائز المرحلة الثالثة برمجياً وبشكل قابل للاختبار الآلي:
1. اشتقاق وتوثيق كلمات المرور بدالة بطيئة مكلفة للذاكرة (`hashlib.scrypt` + ملح عشوائي 16 بايت + مقارنة زمنية ثابتة).
2. محرك التحقق من آلية `OAuth 2.1 PKCE (S256)` لمنع اعتراض أكواد التفويض.
3. محرك سياسات الثقة المعدومة الهجين (`Zero-Trust RBAC + ABAC Policy Engine` وفق `NIST SP 800-207`).
4. محرك ترتيب أولويات الثغرات المبني على المخاطر (`RBVM: CVSS + EPSS + CISA KEV + Asset Exposure`) وحساب `ALE`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Tuple


# ============================================================================
# 1. Memory-Hard Password KDF (`scrypt` + Per-User Salt + Constant-Time Check)
# ============================================================================

def hash_password_scrypt(password: str, n: int = 2**14, r: int = 8, p: int = 1) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32
    )
    return f"scrypt${n}${r}${p}${salt.hex()}${derived.hex()}"


def verify_password_scrypt(password: str, stored_record: str) -> bool:
    try:
        scheme, n_s, r_s, p_s, salt_hex, hash_hex = stored_record.split("$")
        if scheme != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n_s),
            r=int(r_s),
            p=int(p_s),
            dklen=len(expected),
        )
        return hmac.compare_digest(candidate, expected)
    except Exception:
        return False


# ============================================================================
# 2. OAuth 2.1 PKCE (Proof Key for Code Exchange - S256) Verifier
# ============================================================================

def generate_pkce_pair() -> Tuple[str, str]:
    """Generates a cryptographically random `code_verifier` and its `S256` `code_challenge`."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def verify_pkce_s256(code_verifier: str, stored_code_challenge: str) -> bool:
    if not (43 <= len(code_verifier) <= 128):
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(computed, stored_code_challenge)


# ============================================================================
# 3. Zero Trust Policy Engine (NIST SP 800-207: RBAC + ABAC Device/MFA Signals)
# ============================================================================

@dataclass
class AccessRequestContext:
    user_role: str                 # e.g., "security_admin", "developer", "viewer"
    action: str                    # e.g., "read_logs", "rotate_prod_keys"
    resource_classification: str   # "PUBLIC", "INTERNAL", "CRITICAL_PROD"
    device_edr_healthy: bool
    phishing_resistant_mfa: bool   # e.g., FIDO2/WebAuthn Passkey
    risk_score: int                # 0 (clean) to 100 (compromised anomaly)


_ROLE_PERMISSIONS = {
    "security_admin": {"read_logs", "rotate_prod_keys", "isolate_endpoint"},
    "developer": {"read_logs"},
    "viewer": set(),
}


def evaluate_zero_trust_policy(ctx: AccessRequestContext) -> Tuple[bool, str]:
    # 1. Never trust compromised session signals
    if ctx.risk_score >= 70:
        return False, "DENY_HIGH_SESSION_RISK"

    # 2. Enforce healthy managed endpoint posture (EDR/MDM signal)
    if not ctx.device_edr_healthy:
        return False, "DENY_UNHEALTHY_DEVICE_POSTURE"

    # 3. Verify RBAC baseline capability
    allowed_actions = _ROLE_PERMISSIONS.get(ctx.user_role, set())
    if ctx.action not in allowed_actions:
        return False, "DENY_RBAC_LEAST_PRIVILEGE"

    # 4. Enforce Phishing-Resistant MFA (FIDO2) for CRITICAL_PROD resources (ABAC step-up)
    if ctx.resource_classification == "CRITICAL_PROD" and not ctx.phishing_resistant_mfa:
        return False, "DENY_STEP_UP_FIDO2_MFA_REQUIRED"

    return True, "ALLOW_ZERO_TRUST_VERIFIED"


# ============================================================================
# 4. Quantitative Risk (SLE/ALE) & Risk-Based Vulnerability Prioritizer (RBVM)
# ============================================================================

def compute_quantitative_risk(asset_value: float, exposure_factor: float, aro: float) -> Tuple[float, float]:
    """Returns `(SLE, ALE)` where `SLE = AV * EF` and `ALE = SLE * ARO`."""
    if not (0.0 <= exposure_factor <= 1.0) or asset_value < 0 or aro < 0:
        raise ValueError("Invalid risk parameters.")
    sle = round(asset_value * exposure_factor, 2)
    ale = round(sle * aro, 2)
    return sle, ale


def prioritize_vulnerability_sla(
    cvss_score: float,
    epss_probability: float,
    in_cisa_kev: bool,
    internet_exposed: bool,
) -> str:
    """
    Combines CVSS + EPSS + CISA KEV + Exposure to assign realistic remediation SLAs:
    - P0_EMERGENCY_24_48H
    - P1_HIGH_7D
    - P2_STANDARD_30D
    - P3_LOW_90D
    """
    if in_cisa_kev or (internet_exposed and cvss_score >= 8.0 and epss_probability >= 0.20):
        return "P0_EMERGENCY_24_48H"
    if (cvss_score >= 7.0 and epss_probability >= 0.10) or (internet_exposed and cvss_score >= 7.0):
        return "P1_HIGH_7D"
    if cvss_score >= 4.0:
        return "P2_STANDARD_30D"
    return "P3_LOW_90D"
