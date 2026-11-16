from __future__ import annotations

import hashlib

from study_academy.labs.stage45_database_access_proxy_and_masking_lab import DatabaseAccessProxy
from study_academy.labs.stage46_secure_file_exchange_and_cdr_lab import SecureFileExchange
from study_academy.labs.stage47_iot_edge_device_fleet_trust_lab import IoTDeviceFleet
from study_academy.labs.stage48_transaction_fraud_risk_engine_lab import FraudRiskEngine


def test_stage45_query_policy_and_masking() -> None:
    proxy = DatabaseAccessProxy()
    assert proxy.evaluate_query({"verb": "DELETE", "has_where": False})["state"] == "DB_DENIED_DESTRUCTIVE_WITHOUT_WHERE"
    assert proxy.evaluate_query({"verb": "SELECT", "tenant_scoped_table": True, "owner_filter": False})["state"] == "DB_DENIED_TENANT_READ_WITHOUT_OWNER_FILTER"
    assert proxy.evaluate_query({"verb": "SELECT", "tenant_scoped_table": True, "owner_filter": True, "estimated_rows": 50})["allowed"] is True
    assert proxy.evaluate_query({"verb": "SELECT", "estimated_rows": 50000})["state"] == "DB_DENIED_EXPORT_ROW_CEILING_EXCEEDED"
    assert proxy.mask("nour@example.com", "CONFIDENTIAL", "analyst") == "no***@example.com"
    assert proxy.mask("nour@example.com", "CONFIDENTIAL", "data_owner") == "nour@example.com"


def test_stage46_file_type_truth_blocklist_and_cdr() -> None:
    bad = b"%PDF-known-bad"
    exchange = SecureFileExchange({hashlib.sha256(bad).hexdigest()})
    assert exchange.inspect("evil.pdf", bad)["state"] == "FILE_DENIED_KNOWN_BAD_HASH"
    pdf = b"%PDF-1.7 clean"
    accepted = exchange.inspect("report.pdf", pdf)
    assert accepted["accepted"] is True
    assert SecureFileExchange.disarm(accepted)[1].startswith("CDR_SANITIZED")
    assert exchange.inspect("fake.pdf", b"\x89PNG image")["state"] == "FILE_DENIED_EXTENSION_MAGIC_MISMATCH"
    assert exchange.inspect("macro.docx", b"PK\x03\x04 office", has_macros=True)["state"] == "FILE_DENIED_ACTIVE_MACRO_CONTENT"
    assert exchange.inspect("big.pdf", b"%PDF" + b"x" * 6_000_000)["state"] == "FILE_DENIED_OVERSIZE"


def test_stage47_fleet_identity_firmware_heartbeat() -> None:
    fleet = IoTDeviceFleet(min_firmware="3.2.0")
    fleet.enroll("cam-1", "fp-aaa", "3.4.0")
    assert fleet.admit("cam-1", "fp-aaa", "3.4.0", heartbeat_age_seconds=60) == (True, "DEVICE_ADMITTED_TO_FLEET")
    assert fleet.admit("cam-1", "fp-xxx", "3.4.0", heartbeat_age_seconds=60)[1] == "DEVICE_QUARANTINED_UNKNOWN_IDENTITY"
    assert fleet.admit("cam-1", "fp-aaa", "2.0.0", heartbeat_age_seconds=60)[1] == "DEVICE_QUARANTINED_FIRMWARE_BELOW_FLOOR"
    assert fleet.admit("cam-1", "fp-aaa", "3.4.0", heartbeat_age_seconds=99999)[1] == "DEVICE_QUARANTINED_STALE_HEARTBEAT"
    assert fleet.admit("ghost", "fp-aaa", "3.4.0", heartbeat_age_seconds=1)[0] is False


def test_stage48_fraud_scoring_bands() -> None:
    engine = FraudRiskEngine()
    calm = engine.score({"amount": 50, "account_avg_amount": 60, "txns_last_hour": 1, "known_device": True})
    assert calm["decision"] == "ALLOW" and calm["risk_score"] == 0
    raid = engine.score({"amount": 5000, "account_avg_amount": 100, "txns_last_hour": 12,
                         "new_payee": True, "geo_mismatch": True, "known_device": False})
    assert raid["decision"] == "BLOCK" and raid["risk_score"] >= 60
    assert "AMOUNT_ANOMALY_10X" in raid["signals"] and "VELOCITY_BURST" in raid["signals"]
    mid = engine.score({"amount": 450, "account_avg_amount": 100, "txns_last_hour": 2, "new_payee": True, "geo_mismatch": True, "known_device": True})
    assert mid["decision"] == "STEP_UP_REVIEW"
