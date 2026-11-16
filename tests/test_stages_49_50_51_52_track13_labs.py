from __future__ import annotations

from study_academy.labs.stage49_threat_modeling_stride_coverage_lab import ThreatModelRegistry
from study_academy.labs.stage50_confidential_computing_attestation_lab import ConfidentialKeyBroker
from study_academy.labs.stage51_security_control_failure_drills_lab import ControlDrillEvaluator
from study_academy.labs.stage52_threat_intel_sharing_tlp_embargo_lab import TLPSharingGate


def test_stage49_stride_coverage_gate() -> None:
    registry = ThreatModelRegistry()
    partial = registry.evaluate("payments-api", ["spoofing", "tampering", "elevation_of_privilege"],
                                mitigations={"spoofing": "mTLS+SVID", "tampering": "signed payloads"},
                                accepted_risks={})
    assert partial["design_gate_passed"] is False and partial["uncovered"] == ["elevation_of_privilege"]
    full = registry.evaluate("payments-api", ["spoofing", "tampering"],
                             mitigations={"spoofing": "mTLS"},
                             accepted_risks={"tampering": "CISO-accepted until Q3, owner: platform"})
    assert full["design_gate_passed"] is True and full["coverage_pct"] == 100.0


def test_stage50_attestation_gated_key_release() -> None:
    broker = ConfidentialKeyBroker(b"stage50_platform_key_32_bytes", {"meas-v9"}, min_tcb=7)
    good = broker.make_quote("meas-v9", debug=False, tcb=8)
    assert broker.release_key(good) == (True, "KEY_RELEASED_TO_ATTESTED_ENCLAVE")
    assert broker.release_key(broker.make_quote("meas-v9", debug=True, tcb=8))[1] == "KEY_DENIED_ENCLAVE_DEBUG_ENABLED"
    assert broker.release_key(broker.make_quote("meas-rogue", debug=False, tcb=8))[1] == "KEY_DENIED_MEASUREMENT_NOT_ALLOWLISTED"
    assert broker.release_key(broker.make_quote("meas-v9", debug=False, tcb=3))[1] == "KEY_DENIED_TCB_BELOW_FLOOR"
    forged = dict(good); forged["tcb"] = 99
    assert broker.release_key(forged)[1] == "KEY_SIGNATURE_INVALID" or broker.release_key(forged)[1] == "KEY_DENIED_QUOTE_SIGNATURE_INVALID"


def test_stage51_failure_drills_fail_closed() -> None:
    evaluator = ControlDrillEvaluator()
    result = evaluator.evaluate([
        {"name": "auth-gateway", "critical": True, "on_failure": "fail_closed", "drilled": True},
        {"name": "dlp-gate", "critical": True, "on_failure": "fail_open", "drilled": True},
        {"name": "canary-svc", "critical": False, "on_failure": "fail_open", "drilled": False},
    ])
    assert result["fail_open_critical"] == ["dlp-gate"] and result["drill_gate_passed"] is False
    clean = evaluator.evaluate([{"name": "auth-gateway", "critical": True, "on_failure": "fail_closed", "drilled": True}])
    assert clean["drill_gate_passed"] is True and clean["state"] == "CONTROL_PLANE_FAILS_CLOSED"


def test_stage52_tlp_circles_and_embargo() -> None:
    gate = TLPSharingGate()
    assert gate.evaluate("RED", "room", now=100)["allowed"] is True
    assert gate.evaluate("RED", "sector", now=100)["state"] == "SHARE_DENIED_TLP_RED_CIRCLE_EXCEEDED"
    assert gate.evaluate("AMBER", "community", now=100)["allowed"] is True
    assert gate.evaluate("GREEN", "public", now=100)["allowed"] is False
    assert gate.evaluate("WHITE", "public", now=100)["allowed"] is True
    assert gate.evaluate("GREEN", "sector", now=50, embargo_until=100)["state"] == "SHARE_DENIED_UNDER_EMBARGO"
    assert gate.evaluate("GREEN", "sector", now=150, embargo_until=100)["allowed"] is True
