from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from study_academy.labs.stage13_shadow_memory_asan_cfi_and_wasm_sandbox_lab import (
    CapabilityWasmSandbox,
    MemorySafetyViolation,
    MiniASanShadowAllocator,
    ShadowStackAndPACGuard,
)
from study_academy.labs.stage14_ssrf_redirect_guard_leader_lease_and_arg_policy_lab import (
    FailClosedChatGateAndLeaderLease,
    SafeRedirectAndSSRFGuard,
    SubcommandArgPolicyGate,
)
from study_academy.labs.stage15_cryptanalysis_ecdsa_nonce_tvla_and_webauthn_lab import (
    ECDSANonceSecurityLab,
    TVLATimingLeakDetector,
    WebAuthnAndDPoPVerifier,
)
from study_academy.labs.stage16_security_chaos_attack_graph_and_purple_bas_lab import (
    AttackGraphChokepointAnalyzer,
    PurpleTeamBASAttestor,
    SecurityChaosEngine,
)


def test_stage13_mini_asan_catches_overflow_uaf_and_double_free() -> None:
    asan = MiniASanShadowAllocator(1024)
    ptr = asan.malloc(12)
    asan.write(ptr, b"hello_world!")
    assert asan.read(ptr, 12) == b"hello_world!"

    # Intra-granule tail overflow (writing 13 bytes into 12-byte buffer)
    with pytest.raises(MemorySafetyViolation, match="HEAP_BUFFER_OVERFLOW"):
        asan.write(ptr, b"0123456789ABC")

    # Right redzone overflow
    with pytest.raises(MemorySafetyViolation, match="HEAP_BUFFER_OVERFLOW"):
        asan.read(ptr + 16, 4)

    # Free -> Use-After-Free & Double-Free caught immediately
    asan.free(ptr)
    with pytest.raises(MemorySafetyViolation, match="USE_AFTER_FREE"):
        asan.read(ptr, 4)
    with pytest.raises(MemorySafetyViolation, match="DOUBLE_FREE_DETECTED"):
        asan.free(ptr)


def test_stage13_cet_shadow_stack_and_pac_and_wasi_capabilities() -> None:
    guard = ShadowStackAndPACGuard(b"0123456789abcdef_pac_secret")
    guard.call_function(0x401234)
    assert guard.ret_function() == 0x401234

    guard.call_function(0x401234)
    guard.simulate_stack_smash_overwrite(0xDEADBEEF)
    with pytest.raises(MemorySafetyViolation, match="CET_SHADOW_STACK_MISMATCH"):
        guard.ret_function()

    signed_fn = guard.sign_pointer(0x55AA0010, "SessionHandler::on_event")
    assert guard.auth_pointer(signed_fn, "SessionHandler::on_event") == 0x55AA0010
    with pytest.raises(MemorySafetyViolation, match="PAC_AUTHENTICATION_FAILED"):
        guard.auth_pointer(signed_fn, "AttackerFakeVtable::exec")

    wasi = CapabilityWasmSandbox(linear_pages=1, preopened_dirs={"/scratch/public"})
    assert wasi.check_linear_memory_access(0, 65536) is True
    with pytest.raises(MemorySafetyViolation, match="WASM_LINEAR_MEMORY_TRAP"):
        wasi.check_linear_memory_access(65530, 16)
    assert wasi.open_file_capability("/scratch/public/readme.md") == "/scratch/public/readme.md"
    with pytest.raises(MemorySafetyViolation, match="WASI_SECRET_DENIED"):
        wasi.open_file_capability("/scratch/public/.env")
    with pytest.raises(MemorySafetyViolation, match="WASI_PATH_ESCAPE_BLOCKED"):
        wasi.open_file_capability("/scratch/public/../../etc/passwd")


def test_stage14_ssrf_redirect_dns_rebinding_and_arg_policy(tmp_path: Path) -> None:
    dns_map = {
        "api-demo.bybit.com": [["18.65.200.10"], ["18.65.200.10"]],
        "github.com": [["140.82.121.4"], ["140.82.121.4"], ["140.82.121.4"], ["140.82.121.4"]],
        "rebind.example": [["93.184.216.34"], ["169.254.169.254"]],
        "mapped-v6.example": [["::ffff:127.0.0.1"], ["::ffff:127.0.0.1"]],
    }
    counters = {k: 0 for k in dns_map}

    def fake_dns(host: str) -> list[str]:
        seq = dns_map.get(host, [])
        if not seq:
            return []
        idx = min(counters[host], len(seq) - 1)
        counters[host] += 1
        return seq[idx]

    ssrf = SafeRedirectAndSSRFGuard(
        allowed_hosts={"api-demo.bybit.com", "github.com", "rebind.example", "mapped-v6.example"},
        dns_resolver=fake_dns,
    )
    ok, state, _ = ssrf.trace_redirect_chain("https://api-demo.bybit.com/v5/market/time", [])
    assert ok is True and state == "CHAIN_VERIFIED_SAFE"

    # 302 redirect escape from allowlisted github.com to localhost or unlisted host -> BLOCKED
    ok_red, reason_red, _ = ssrf.trace_redirect_chain(
        "https://github.com/release", ["http://127.0.0.1:3001/v1/chat/completions"]
    )
    assert ok_red is False and "NON_HTTPS_SCHEME_BLOCKED" in reason_red

    # DNS Rebinding -> BLOCKED
    ok_reb, reason_reb, _ = ssrf.validate_single_hop("https://rebind.example/data")
    assert ok_reb is False and "DNS_REBINDING_DETECTED" in reason_reb

    # IPv6-mapped IPv4 loopback -> BLOCKED
    ok_v6, reason_v6, _ = ssrf.validate_single_hop("https://mapped-v6.example/api")
    assert ok_v6 is False and "NON_PUBLIC_IP_BLOCKED" in reason_v6

    # Subcommand arg_policy gate
    script_bytes = b"print('copy_follow demo')\r\n"
    pin = SubcommandArgPolicyGate.normalized_sha256(script_bytes)
    gate = SubcommandArgPolicyGate(
        {"company/copy_follow.py": {"sha256": pin, "unprivileged_subcommands": ["list", "status"]}},
        approved_dir=tmp_path,
    )
    assert gate.authorize_execution("t1", "company/copy_follow.py", script_bytes, ["list"])[0] is True
    assert gate.authorize_execution("t2", "company/copy_follow.py", script_bytes, ["follow", "--leader", "X"])[0] is False
    (tmp_path / "t2.approved").write_text("owner-approved", encoding="utf-8")
    assert gate.authorize_execution("t2", "company/copy_follow.py", script_bytes, ["follow", "--leader", "X"])[0] is True


def test_stage15_ecdsa_nonce_reuse_vs_rfc6979_and_tvla_and_webauthn() -> None:
    priv_d = 0x1A2B3C4D5E6F77889900AABBCCDDEEFF112233445566778899AABBCCDDEEFF01
    broken_reused_k = 0x7777777777777777777777777777777777777777777777777777777777777777
    fixed_r = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF

    sig1 = ECDSANonceSecurityLab.sign_modular_model(priv_d, b"transfer_demo_1", broken_reused_k, fixed_r)
    sig2 = ECDSANonceSecurityLab.sign_modular_model(priv_d, b"transfer_demo_2", broken_reused_k, fixed_r)
    recovered_d = ECDSANonceSecurityLab.recover_private_key_from_reused_nonce(
        b"transfer_demo_1", sig1, b"transfer_demo_2", sig2
    )
    assert recovered_d == priv_d

    # RFC 6979 deterministic k produces distinct nonces for distinct messages, identical for same message
    k_det_1 = ECDSANonceSecurityLab.deterministic_rfc6979_nonce(priv_d, b"transfer_demo_1")
    k_det_2 = ECDSANonceSecurityLab.deterministic_rfc6979_nonce(priv_d, b"transfer_demo_2")
    assert k_det_1 != k_det_2
    assert k_det_1 == ECDSANonceSecurityLab.deterministic_rfc6979_nonce(priv_d, b"transfer_demo_1")

    # TVLA Welch's t-test
    leaky_a = [120.0 + (i % 3) for i in range(40)]
    leaky_b = [95.0 + (i % 3) for i in range(40)]
    _, leak_found = TVLATimingLeakDetector.welch_t_statistic(leaky_a, leaky_b)
    assert leak_found is True

    const_a = [100.0 + (i % 5) * 0.1 for i in range(40)]
    const_b = [100.0 + ((i + 1) % 5) * 0.1 for i in range(40)]
    _, const_leak = TVLATimingLeakDetector.welch_t_statistic(const_a, const_b)
    assert const_leak is False

    # WebAuthn phishing origin resistance + signCount clone detection + DPoP
    secret = b"hardware_enclave_key_32_bytes_ok"
    verifier = WebAuthnAndDPoPVerifier("https://github.com", "github.com", secret)
    good_cd = json.dumps({"type": "webauthn.get", "origin": "https://github.com", "challenge": "ch-99"})
    rp_hash = hashlib.sha256(b"github.com").digest()
    good_sig = hmac.new(
        secret, rp_hash + (1).to_bytes(4, "big") + hashlib.sha256(good_cd.encode()).digest(), hashlib.sha256
    ).hexdigest()
    assert verifier.verify_webauthn_assertion(good_cd, "github.com", 1, "ch-99", good_sig)[0] is True

    # Replayed / cloned non-increasing signCount -> BLOCKED
    assert verifier.verify_webauthn_assertion(good_cd, "github.com", 1, "ch-99", good_sig)[1] == "CLONED_AUTHENTICATOR_SIGNCOUNT_ANOMALY"

    # Reverse-proxy AiTM phishing origin -> BLOCKED
    phish_cd = json.dumps({"type": "webauthn.get", "origin": "https://g1thub-login.evil", "challenge": "ch-99"})
    assert "PHISHING_ORIGIN_MISMATCH" in verifier.verify_webauthn_assertion(phish_cd, "github.com", 2, "ch-99", good_sig)[1]

    # DPoP sender-constrained proof
    dpop_mac = hmac.new(secret, b"jti-1:POST:https://api.example/run", hashlib.sha256).hexdigest()
    assert verifier.verify_dpop_proof({"jti": "jti-1", "htm": "POST", "htu": "https://api.example/run", "mac": dpop_mac}, "POST", "https://api.example/run")[0] is True
    assert verifier.verify_dpop_proof({"jti": "jti-1", "htm": "POST", "htu": "https://api.example/run", "mac": dpop_mac}, "POST", "https://api.example/run")[1] == "DPOP_REPLAY_JTI"


def test_stage16_security_chaos_attack_graph_and_bas_attestation() -> None:
    chaos = SecurityChaosEngine().run_chaos_suite()
    assert chaos["resilience_score_pct"] == 100.0
    assert chaos["passed_experiments"] == 4

    graph = AttackGraphChokepointAnalyzer()
    graph.add_edge("Remote_Git_Task", "Unprivileged_RunScript")
    graph.add_edge("Unprivileged_RunScript", "Unfiltered_Args")
    graph.add_edge("Unfiltered_Args", "Demo_CopyFollow_Action")
    graph.add_edge("Remote_Git_Task", "Http_Get_Handler")
    graph.add_edge("Http_Get_Handler", "Unfiltered_302_Redirect")
    graph.add_edge("Unfiltered_302_Redirect", "Local_Internal_Service")

    entries = ["Remote_Git_Task"]
    jewels = {"Demo_CopyFollow_Action", "Local_Internal_Service"}
    assert len(graph.enumerate_paths(entries, jewels)) == 2

    ranked = graph.rank_chokepoint_edges(entries, jewels)
    assert len(ranked) > 0

    blocked = {("Unprivileged_RunScript", "Unfiltered_Args"), ("Http_Get_Handler", "Unfiltered_302_Redirect")}
    assert graph.enumerate_paths(entries, jewels, blocked_edges=blocked) == []

    attest = PurpleTeamBASAttestor.evaluate_and_attest(
        [
            {"id": "BAS-01", "blocked": True, "logged_cleanly": True},
            {"id": "BAS-02", "blocked": True, "logged_cleanly": True},
        ],
        tree_sha256="a" * 64,
    )
    assert attest["fail_closed_verified"] is True
    assert attest["prevention_rate_pct"] == 100.0
    assert len(str(attest["attestation_sha256"])) == 64
