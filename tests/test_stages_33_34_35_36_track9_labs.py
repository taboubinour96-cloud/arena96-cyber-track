from __future__ import annotations

from study_academy.labs.stage33_api_gateway_bola_and_rate_limit_lab import (
    APIGateway,
    SignedAPIToken,
)
from study_academy.labs.stage34_identity_governance_sod_and_access_review_lab import (
    AccessReviewEngine,
    PrivilegeCreepAnalyzer,
    SegregationOfDuties,
)
from study_academy.labs.stage35_microsegmentation_ztna_and_egress_lab import (
    EgressController,
    SegmentationPolicyEngine,
)
from study_academy.labs.stage36_data_governance_dlp_and_sovereign_privacy_lab import (
    DataClassifier,
    DLPEgressGate,
    Tokenizer,
)


def _gw(limit: int = 5):
    tokens = SignedAPIToken(b"stage33_api_signing_key_32b")
    return APIGateway(tokens, rate_limit=limit, window_seconds=60), tokens


def test_stage33_token_forgery_expiry_and_audience() -> None:
    _, tokens = _gw()
    tok = tokens.issue("user-1", "arena-api", ["orders.read"], expires_at=2000)
    assert tokens.verify(tok, "arena-api", now=1000)[0] is True
    assert tokens.verify(tok, "other-api", now=1000)[1] == "API_TOKEN_AUDIENCE_MISMATCH"
    assert tokens.verify(tok, "arena-api", now=3000)[1] == "API_TOKEN_EXPIRED"
    forged = tok[:-2] + "xx"
    assert tokens.verify(forged, "arena-api", now=1000)[1] == "API_TOKEN_SIGNATURE_INVALID"


def test_stage33_bola_scope_schema_and_rate_limit() -> None:
    gw, tokens = _gw(limit=3)
    tok = tokens.issue("user-1", "arena-api", ["orders.read"], expires_at=2000)
    ok = gw.authorize(tok, "arena-api", "orders.read", resource_owner="user-1", now=1000, client="c1")
    assert ok["allowed"] is True and ok["state"] == "API_REQUEST_AUTHORIZED"

    bola = gw.authorize(tok, "arena-api", "orders.read", resource_owner="user-2", now=1000, client="c2")
    assert bola["state"] == "API_BOLA_BLOCKED_NOT_RESOURCE_OWNER"

    no_scope = gw.authorize(tok, "arena-api", "payments.execute", resource_owner="user-1", now=1000, client="c3")
    assert no_scope["state"] == "API_SCOPE_INSUFFICIENT"

    admin = tokens.issue("ops-1", "arena-api", ["api.admin"], expires_at=2000)
    assert gw.authorize(admin, "arena-api", "orders.read", resource_owner="user-2", now=1000, client="c4")["allowed"] is True

    assert APIGateway.validate_payload({"id": "1", "qty": 2}, {"id": "string", "qty": "number"})[0] is True
    assert APIGateway.validate_payload({"id": "1", "evil": True}, {"id": "string"})[1].startswith("API_SCHEMA_UNKNOWN_FIELDS")
    assert APIGateway.validate_payload({"qty": "two"}, {"qty": "number"})[1] == "API_SCHEMA_TYPE_MISMATCH_qty"

    for i in range(3):
        assert gw.authorize(tok, "arena-api", "orders.read", resource_owner="user-1", now=1000, client="rl")["allowed"] is True
    assert gw.authorize(tok, "arena-api", "orders.read", resource_owner="user-1", now=1000, client="rl")["state"] == "API_RATE_LIMIT_EXCEEDED"


def test_stage34_sod_and_access_reviews() -> None:
    sod = SegregationOfDuties()
    assert sod.check_assignment("u1", {"payments.create"}, "payments.approve")["state"].startswith("SOD_VIOLATION")
    assert sod.check_assignment("u1", {"orders.read"}, "orders.write")["allowed"] is True
    assert sod.check_assignment("u2", {"vendor.create"}, "payments.execute")["allowed"] is False

    review = AccessReviewEngine()
    assert review.review({"user_active": False, "manager_attested": True, "last_used_days_ago": 1, "privileged": False})["state"] == "REVIEW_REVOKE_DEPARTED_USER"
    assert review.review({"user_active": True, "manager_attested": False, "last_used_days_ago": 1, "privileged": False})["decision"] == "SUSPEND"
    assert review.review({"user_active": True, "manager_attested": True, "last_used_days_ago": 120, "privileged": True})["state"] == "REVIEW_REVOKE_DORMANT_PRIVILEGE"
    assert review.review({"user_active": True, "manager_attested": True, "last_used_days_ago": 5, "privileged": True})["decision"] == "CERTIFY"


def test_stage34_privilege_creep_measurement() -> None:
    creep = PrivilegeCreepAnalyzer().analyze(
        granted={"orders.read", "orders.write", "payments.execute", "iam.grant_roles"},
        role_baseline={"orders.read", "orders.write"},
    )
    assert creep["excess_entitlements"] == ["iam.grant_roles", "payments.execute"]
    assert creep["creep_pct"] == 50.0 and creep["state"] == "PRIVILEGE_CREEP_EXCESS_PRESENT"
    clean = PrivilegeCreepAnalyzer().analyze(granted={"orders.read"}, role_baseline={"orders.read", "orders.write"})
    assert clean["state"] == "PRIVILEGE_WITHIN_BASELINE" and clean["missing_baseline"] == ["orders.write"]


def test_stage35_segmentation_default_deny_and_lateral_alert() -> None:
    eng = SegmentationPolicyEngine()
    eng.add_rule("app", "db", 5432, "orders persistence")
    assert eng.evaluate("app", "db", 5432)["allowed"] is True
    assert eng.evaluate("app", "db", 22)["state"] == "FLOW_DENIED_DEFAULT_NO_RULE"
    lateral = eng.evaluate("guest-wifi", "db", 5432, src_trust="low", dst_is_crown=True)
    assert lateral["allowed"] is False and lateral["state"] == "FLOW_DENIED_LATERAL_MOVEMENT_ALERT"

    egress = EgressController({"api.arena.example"})
    assert egress.evaluate("data", "api.arena.example", via_proxy=False)["state"] == "EGRESS_DENIED_DATA_ZONE_MUST_USE_PROXY"
    assert egress.evaluate("app", "evil.example", via_proxy=True)["state"] == "EGRESS_DENIED_DOMAIN_NOT_ALLOWLISTED"
    assert egress.evaluate("app", "api.arena.example", via_proxy=True)["allowed"] is True


def test_stage36_classification_tokenization_and_dlp_gate() -> None:
    clf = DataClassifier()
    assert clf.classify("contact me at nour@example.com")["classification"] == "INTERNAL"
    secret = clf.classify("key is sk-ABCDEFGHIJKLMNOP1234 for account 123456789012")
    assert secret["classification"] == "SECRET" and "api_key" in secret["findings"]

    tok = Tokenizer(b"stage36_tokenizer_key_32_bytes")
    t1, t2 = tok.tokenize("sk-ABCDEFGHIJKLMNOP1234"), tok.tokenize("sk-ABCDEFGHIJKLMNOP1234")
    assert t1 == t2 and t1.startswith("tok_") and "sk-" not in tok.redact("key sk-ABCDEFGHIJKLMNOP1234 end")

    gate = DLPEgressGate(["TN", "TN-EDGE"])
    assert gate.evaluate("SECRET", "TN", purpose="billing sync", is_tokenized_or_redacted=False)["state"] == "DLP_DENIED_SENSITIVE_DATA_MUST_BE_TOKENIZED"
    assert gate.evaluate("SECRET", "XX", purpose="sync", is_tokenized_or_redacted=True)["state"] == "DLP_DENIED_DESTINATION_NOT_SOVEREIGN_APPROVED"
    assert gate.evaluate("SECRET", "TN", purpose="", is_tokenized_or_redacted=True)["state"] == "DLP_DENIED_NO_DECLARED_PURPOSE"
    assert gate.evaluate("SECRET", "TN", purpose="billing sync", is_tokenized_or_redacted=True)["allowed"] is True
