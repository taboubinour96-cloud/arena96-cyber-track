"""
Automated Verification Suite for Stage 1 Hands-On Lab (Arena 96 - Supervised by Noor).
"""

from study_academy.labs.stage1_network_and_firewall_lab import (
    FirewallRule,
    LPMRouter,
    Packet,
    RouteEntry,
    StatefulFirewall,
    analyze_ipv4_subnet,
    audit_linux_file_mode,
    check_ad_tier_logon_policy,
)


def test_cidr_subnetting_and_lpm_routing() -> None:
    sub = analyze_ipv4_subnet("192.168.50.19/26")
    assert sub.cidr == "192.168.50.0/26"
    assert sub.network_address == "192.168.50.0"
    assert sub.broadcast_address == "192.168.50.63"
    assert sub.total_addresses == 64
    assert sub.usable_hosts == 62
    assert sub.is_private_rfc1918 is True

    router = LPMRouter(
        [
            RouteEntry("0.0.0.0/0", "203.0.113.1", "eth0"),
            RouteEntry("10.10.0.0/16", "10.0.0.2", "eth1"),
            RouteEntry("10.10.5.0/24", "10.0.0.9", "eth2"),
        ]
    )
    selected = router.select_route("10.10.5.42")
    assert selected is not None
    assert selected.interface == "eth2"  # Longest prefix /24 wins over /16 and /0


def test_stateful_firewall_connection_tracking() -> None:
    fw = StatefulFirewall(
        rules=[
            # Allow internal LAN (10.20.0.0/16) outbound HTTPS (443/TCP) to anywhere
            FirewallRule("OUTBOUND-HTTPS", "ALLOW", "10.20.0.0/16", "0.0.0.0/0", "TCP", 443),
        ]
    )

    # 1. Unsolicited external SYN to internal host -> Blocked by Implicit Deny!
    verdict1, reason1 = fw.inspect_packet(
        Packet("198.51.100.50", "10.20.1.15", "TCP", 51234, 443, "SYN")
    )
    assert verdict1 == "DENY"
    assert reason1 == "IMPLICIT_DENY_ALL"

    # 2. Internal host initiates outbound HTTPS SYN -> Allowed & added to Conntrack!
    verdict2, reason2 = fw.inspect_packet(
        Packet("10.20.1.15", "93.184.216.34", "TCP", 54000, 443, "SYN")
    )
    assert verdict2 == "ALLOW"
    assert reason2 == "RULE_OUTBOUND-HTTPS"

    # 3. External server replies SYN-ACK back to internal host -> Allowed via Stateful Conntrack!
    verdict3, reason3 = fw.inspect_packet(
        Packet("93.184.216.34", "10.20.1.15", "TCP", 443, 54000, "SYN-ACK")
    )
    assert verdict3 == "ALLOW"
    assert reason3 == "STATEFUL_CONNTRACK_MATCH"

    # 4. Out-of-state TCP ACK with no prior SYN -> Blocked!
    verdict4, reason4 = fw.inspect_packet(
        Packet("10.20.1.15", "93.184.216.34", "TCP", 59999, 443, "ACK")
    )
    assert verdict4 == "DENY"
    assert reason4 == "INVALID_TCP_STATE_NO_SYN"


def test_linux_permissions_and_ad_tier_guard() -> None:
    # SUID root binary flagged
    suid_issues = audit_linux_file_mode("/usr/local/bin/custom_backup", owner_uid=0, octal_mode=0o4755)
    assert any("HIGH_RISK_SUID_ROOT" in i for i in suid_issues)

    # /tmp with Sticky Bit (0o1777) should NOT be flagged as unsafe world-writable
    tmp_issues = audit_linux_file_mode("/tmp", owner_uid=0, octal_mode=0o1777)
    assert tmp_issues == []

    # World-readable /etc/shadow flagged immediately
    shadow_issues = audit_linux_file_mode("/etc/shadow", owner_uid=0, octal_mode=0o0644)
    assert any("SENSITIVE_SHADOW_EXPOSURE" in i for i in shadow_issues)

    # Active Directory Tier 0 Domain Admin logging into Tier 2 Employee Workstation -> VIOLATION!
    ok_bad, msg_bad = check_ad_tier_logon_policy(account_tier=0, workstation_tier=2)
    assert ok_bad is False
    assert "VIOLATION" in msg_bad

    # Tier 0 Admin logging into Tier 0 PAW / Domain Controller -> PERMITTED!
    ok_good, _ = check_ad_tier_logon_policy(account_tier=0, workstation_tier=0)
    assert ok_good is True
