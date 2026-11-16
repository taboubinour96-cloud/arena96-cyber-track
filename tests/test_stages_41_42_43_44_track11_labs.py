from __future__ import annotations

from study_academy.labs.stage41_secure_update_firmware_and_antirollback_lab import (
    RolloutGate,
    SecureUpdateVerifier,
)
from study_academy.labs.stage42_dynamic_secrets_lease_and_rotation_lab import (
    DynamicSecretBroker,
    RotationCompliance,
)
from study_academy.labs.stage43_web_session_csrf_and_cookie_defense_lab import (
    WebSessionManager,
)
from study_academy.labs.stage44_threat_hunting_detection_validation_lab import (
    DetectionValidator,
    HuntEngine,
)


def test_stage41_signed_update_and_antirollback() -> None:
    verifier = SecureUpdateVerifier(b"stage41_vendor_key_32_bytes!!")
    payload = b"firmware-v7-bytes"
    manifest = verifier.sign_manifest(version=7, payload=payload)
    assert verifier.verify(manifest, payload, installed_version=6) == (True, "UPDATE_VERIFIED_INSTALL_ALLOWED")
    assert verifier.verify(manifest, payload, installed_version=7)[1] == "UPDATE_REJECTED_ANTI_ROLLBACK"
    assert verifier.verify(manifest, payload, installed_version=9)[1] == "UPDATE_REJECTED_ANTI_ROLLBACK"
    assert verifier.verify(manifest, b"tampered-bytes", installed_version=6)[1] == "UPDATE_PAYLOAD_HASH_MISMATCH"
    forged = dict(manifest); forged["version"] = 99
    assert verifier.verify(forged, payload, installed_version=6)[1] == "UPDATE_SIGNATURE_INVALID"


def test_stage41_rollout_gate_halts_bad_ring() -> None:
    gate = RolloutGate()
    assert gate.evaluate("canary", error_rate_pct=0.5)["promote"] is True
    halted = gate.evaluate("canary", error_rate_pct=7.5)
    assert halted["promote"] is False and halted["state"] == "ROLLOUT_HALTED_RING_ERROR_RATE_BREACH"


def test_stage42_dynamic_secret_lease_lifecycle() -> None:
    broker = DynamicSecretBroker(b"stage42_broker_key_32_bytes!!!")
    lease = broker.issue("billing-svc", "db.read", now=1000, ttl_seconds=900)
    assert lease["issued"] is True and broker.use(lease, now=1200) == (True, "SECRET_USE_ALLOWED")
    assert broker.use(lease, now=1900)[1] == "SECRET_USE_DENIED_LEASE_EXPIRED"
    broker.revoke(str(lease["lease_id"]))
    assert broker.use(lease, now=1200)[1] == "SECRET_USE_DENIED_LEASE_REVOKED"
    assert broker.issue("x", "db.read", now=0, ttl_seconds=99999)["issued"] is False


def test_stage42_rotation_compliance() -> None:
    audit = RotationCompliance().audit(
        [{"name": "db-main", "age_days": 30}, {"name": "legacy-api", "age_days": 200}, {"name": "old-vpn", "age_days": 91}],
        max_age_days=90,
    )
    assert audit["overdue"] == ["legacy-api", "old-vpn"] and audit["overdue_count"] == 2
    assert RotationCompliance().audit([{"name": "fresh", "age_days": 10}])["state"] == "ROTATION_COMPLIANT"


def test_stage43_session_rotation_csrf_and_timeouts() -> None:
    mgr = WebSessionManager(b"stage43_session_key_32_bytes!")
    session = mgr.create("nour", now=1000)
    assert mgr.validate(session, str(session["session_id"]), now=1200) == (True, "SESSION_VALID")
    assert mgr.validate(session, "sess-planted-by-attacker", now=1200)[1] == "SESSION_ID_MISMATCH_POSSIBLE_FIXATION"

    rotated = mgr.rotate_on_privilege_change(session)
    assert rotated["session_id"] != session["session_id"]
    assert mgr.validate(session, str(session["session_id"]), now=1000 + 901)[1] == "SESSION_EXPIRED_IDLE_TIMEOUT"

    token = mgr.csrf_token(session)
    assert mgr.verify_csrf(session, token) == (True, "CSRF_TOKEN_VALID")
    assert mgr.verify_csrf(session, "forged-token")[1] == "CSRF_TOKEN_INVALID_REQUEST_BLOCKED"
    flags = mgr.cookie_flags()
    assert flags["Secure"] is True and flags["HttpOnly"] is True and flags["SameSite"] == "Strict"


def test_stage44_hunting_and_detection_validation() -> None:
    engine = HuntEngine()
    hits = engine.hunt_shell_children([
        {"parent": "winword.exe", "process": "powershell.exe", "host": "ws-1"},
        {"parent": "explorer.exe", "process": "notepad.exe", "host": "ws-1"},
        {"parent": "outlook.exe", "process": "cmd.exe", "host": "ws-2"},
    ])
    assert hits["hit_count"] == 2 and hits["hosts"] == ["ws-1", "ws-2"]

    beacons = engine.hunt_beaconing([{"host": "ws-1", "dst": "198.51.100.7"} for _ in range(6)]
                                    + [{"host": "ws-1", "dst": "10.0.0.5"}])
    assert beacons["beacons"] == ["ws-1->198.51.100.7"]

    def detector(event: dict) -> bool:
        return event.get("parent") in {"winword.exe", "outlook.exe"}

    result = DetectionValidator().validate(detector, [
        {"name": "word-shell", "event": {"parent": "winword.exe"}, "should_alert": True},
        {"name": "explorer-shell", "event": {"parent": "explorer.exe"}, "should_alert": False},
        {"name": "mail-shell", "event": {"parent": "outlook.exe"}, "should_alert": True},
    ])
    assert result["coverage_pct"] == 100.0 and result["state"] == "DETECTION_COVERAGE_PROVEN"

    gapped = DetectionValidator().validate(detector, [
        {"name": "wps-shell", "event": {"parent": "wps.exe"}, "should_alert": True},
    ])
    assert gapped["blind_spots"] == ["wps-shell"] and gapped["state"] == "DETECTION_GAPS_PRESENT"
