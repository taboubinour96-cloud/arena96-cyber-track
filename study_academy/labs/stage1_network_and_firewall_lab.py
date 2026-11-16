"""
المختبر العملي للمرحلة 1 (Stage 1 Hands-On Defensive Lab) — أرينا 96 (بإشراف نور)

يطبق هذا المختبر المفاهيم الهندسية للمرحلة الأولى برمجياً وبشكل قابل للتحقق الآلي:
1. محرك حساب الشبكات الفرعية (CIDR Subnetting) والتوجيه بقاعدة التطابق الأطول (Longest-Prefix Match).
2. محاكي الجدار الناري ذي الحالة (Stateful Firewall Simulator) مع جدول تتبع الاتصالات (Conntrack).
3. مدقق صلاحيات ملفات Linux واكتشاف مخاطر بتات SUID و World-Writable.
4. مدقق منطق مصادقة Kerberos وتصنيف مستويات حماية Active Directory (Tier 0/1/2 Guard).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# ============================================================================
# 1. CIDR Subnetting & Longest-Prefix Match (LPM) Router Engine
# ============================================================================

@dataclass
class SubnetInfo:
    cidr: str
    network_address: str
    broadcast_address: str
    netmask: str
    total_addresses: int
    usable_hosts: int
    is_private_rfc1918: bool


def analyze_ipv4_subnet(cidr: str) -> SubnetInfo:
    net = ipaddress.IPv4Network(cidr, strict=False)
    total = net.num_addresses
    if net.prefixlen == 32:
        usable = 1
    elif net.prefixlen == 31:
        usable = 2
    else:
        usable = max(0, total - 2)

    return SubnetInfo(
        cidr=str(net),
        network_address=str(net.network_address),
        broadcast_address=str(net.broadcast_address),
        netmask=str(net.netmask),
        total_addresses=total,
        usable_hosts=usable,
        is_private_rfc1918=net.is_private,
    )


@dataclass
class RouteEntry:
    destination_cidr: str
    next_hop: str
    interface: str


class LPMRouter:
    """Implements IPv4 Longest-Prefix Match (LPM) packet routing."""

    def __init__(self, routes: List[RouteEntry]) -> None:
        self.routes = routes

    def select_route(self, dst_ip: str) -> Optional[RouteEntry]:
        target = ipaddress.IPv4Address(dst_ip)
        best_route: Optional[RouteEntry] = None
        best_prefix = -1

        for route in self.routes:
            net = ipaddress.IPv4Network(route.destination_cidr, strict=False)
            if target in net and net.prefixlen > best_prefix:
                best_prefix = net.prefixlen
                best_route = route

        return best_route


# ============================================================================
# 2. Stateful Inspection Firewall Simulator (5-Tuple + Conntrack State Table)
# ============================================================================

@dataclass(frozen=True)
class Packet:
    src_ip: str
    dst_ip: str
    protocol: str  # "TCP" or "UDP"
    src_port: int
    dst_port: int
    tcp_flags: str = ""  # e.g., "SYN", "SYN-ACK", "ACK"


@dataclass
class FirewallRule:
    rule_id: str
    action: str  # "ALLOW" or "DENY"
    src_cidr: str
    dst_cidr: str
    protocol: str  # "TCP", "UDP", or "ANY"
    dst_port: Optional[int] = None  # None means ANY port


class StatefulFirewall:
    """
    Demonstrates how a Stateful Firewall tracks active flows in a Conntrack table
    so return traffic is permitted automatically while unsolicited inbound traffic
    is dropped by Implicit Deny.
    """

    def __init__(self, rules: List[FirewallRule]) -> None:
        self.rules = rules
        # Stores canonical bidirectional flow tuples: (client_ip, server_ip, proto, client_port, server_port)
        self.conntrack_table: Dict[Tuple[str, str, str, int, int], str] = {}

    def inspect_packet(self, pkt: Packet) -> Tuple[str, str]:
        proto = pkt.protocol.upper()
        forward_key = (pkt.src_ip, pkt.dst_ip, proto, pkt.src_port, pkt.dst_port)
        reverse_key = (pkt.dst_ip, pkt.src_ip, proto, pkt.dst_port, pkt.src_port)

        # 1. Check existing stateful session table first!
        if forward_key in self.conntrack_table or reverse_key in self.conntrack_table:
            if reverse_key in self.conntrack_table and pkt.tcp_flags in {"SYN-ACK", "ACK", ""}:
                self.conntrack_table[reverse_key] = "ESTABLISHED"
            return "ALLOW", "STATEFUL_CONNTRACK_MATCH"

        # 2. For TCP, block mid-stream packets (non-SYN) with no state entry (Invalid State Defense)
        if proto == "TCP" and pkt.tcp_flags != "SYN":
            return "DENY", "INVALID_TCP_STATE_NO_SYN"

        # 3. Evaluate ordered ACL rules
        src_addr = ipaddress.IPv4Address(pkt.src_ip)
        dst_addr = ipaddress.IPv4Address(pkt.dst_ip)

        for rule in self.rules:
            if rule.protocol != "ANY" and rule.protocol.upper() != proto:
                continue
            if rule.dst_port is not None and rule.dst_port != pkt.dst_port:
                continue
            if src_addr not in ipaddress.IPv4Network(rule.src_cidr, strict=False):
                continue
            if dst_addr not in ipaddress.IPv4Network(rule.dst_cidr, strict=False):
                continue

            if rule.action.upper() == "ALLOW":
                self.conntrack_table[forward_key] = "NEW_SYN" if proto == "TCP" else "ACTIVE_UDP"
                return "ALLOW", f"RULE_{rule.rule_id}"
            return "DENY", f"RULE_{rule.rule_id}"

        # 4. Implicit Deny All at the bottom of every professional firewall policy
        return "DENY", "IMPLICIT_DENY_ALL"


# ============================================================================
# 3. Linux Octal Permissions & SUID/World-Writable Security Auditor
# ============================================================================

def audit_linux_file_mode(file_path: str, owner_uid: int, octal_mode: int) -> List[str]:
    """
    Evaluates a 4-digit octal permission mask (e.g., 0o4755, 0o0666, 0o1777)
    and returns concrete defensive security findings.
    """
    issues: List[str] = []
    is_suid = bool(octal_mode & 0o4000)
    is_sticky = bool(octal_mode & 0o1000)
    world_writable = bool(octal_mode & 0o0002)
    world_readable = bool(octal_mode & 0o0004)

    if is_suid and owner_uid == 0:
        issues.append(
            f"HIGH_RISK_SUID_ROOT: '{file_path}' runs with effective UID 0 (root); verify necessity or replace with granular Linux Capabilities."
        )
    if world_writable and not is_sticky:
        issues.append(
            f"WORLD_WRITABLE: '{file_path}' allows arbitrary modification by any local user without Sticky Bit protection."
        )
    if file_path in {"/etc/shadow", "/etc/gshadow"} and (world_readable or (octal_mode & 0o0077) not in {0, 0o0040}):
        issues.append(
            f"SENSITIVE_SHADOW_EXPOSURE: '{file_path}' has overly permissive group/other bits ({oct(octal_mode)})."
        )
    return issues


# ============================================================================
# 4. Active Directory Tiered Administration Access Guard Verifier
# ============================================================================

def check_ad_tier_logon_policy(account_tier: int, workstation_tier: int) -> Tuple[bool, str]:
    """
    Enforces the Microsoft Enterprise Access / Tiered Administration principle:
    A privileged account (e.g., Tier 0 Domain Admin) MUST NEVER log into a lower-trust
    machine (Tier 1 Server or Tier 2 Workstation), preventing credential theft from LSASS!
    """
    if account_tier < workstation_tier:
        return (
            False,
            f"VIOLATION: Tier {account_tier} privileged identity must NOT authenticate on a lower-trust Tier {workstation_tier} host (Credential Exposure Risk).",
        )
    return True, f"PERMITTED: Tier {account_tier} account operating within Tier {workstation_tier} boundary."


if __name__ == "__main__":
    info = analyze_ipv4_subnet("10.20.30.0/24")
    print(f"[Stage 1 Lab] Subnet {info.cidr} -> Usable Hosts: {info.usable_hosts}, Private: {info.is_private_rfc1918}")
