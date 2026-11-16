"""
المختبر العملي للمرحلة 4 (Stage 4 Hands-On Packet Forensics, SIEM, Container & Cloud Lab) — أرينا 96
"""

from __future__ import annotations

import json
import struct
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Set


# ============================================================================
# 1. Binary libpcap Parser & Builder (24-byte Global Header + 16-byte Records)
# ============================================================================

PCAP_MAGIC_LE = 0xA1B2C3D4


@dataclass
class PcapSummary:
    version_major: int
    version_minor: int
    snaplen: int
    network_link_type: int
    packet_count: int
    total_captured_bytes: int


def build_minimal_pcap(frames: List[bytes], link_type: int = 1) -> bytes:
    header = struct.pack("<IHHiIII", PCAP_MAGIC_LE, 2, 4, 0, 0, 65535, link_type)
    chunks = [header]
    for idx, frame in enumerate(frames):
        rec_hdr = struct.pack("<IIII", 1700000000 + idx, 0, len(frame), len(frame))
        chunks.append(rec_hdr + frame)
    return b"".join(chunks)


def parse_pcap_bytes(raw: bytes) -> PcapSummary:
    if len(raw) < 24:
        raise ValueError("Truncated PCAP global header.")
    magic, v_maj, v_min, _, _, snaplen, link_type = struct.unpack("<IHHiIII", raw[:24])
    if magic != PCAP_MAGIC_LE:
        raise ValueError(f"Unsupported PCAP magic: {hex(magic)}")

    offset = 24
    pkt_count = 0
    total_bytes = 0
    while offset + 16 <= len(raw):
        _, _, incl_len, _ = struct.unpack("<IIII", raw[offset : offset + 16])
        offset += 16
        if offset + incl_len > len(raw):
            raise ValueError("Truncated PCAP packet record.")
        pkt_count += 1
        total_bytes += incl_len
        offset += incl_len

    return PcapSummary(v_maj, v_min, snaplen, link_type, pkt_count, total_bytes)


# ============================================================================
# 2. SIEM Log Correlation Engine (Windows 4625 Spraying + Sysmon ID 1 WebShell)
# ============================================================================

def correlate_security_events(events: List[Dict[str, Any]]) -> List[str]:
    alerts: List[str] = []
    failed_targets_by_ip: Dict[str, Set[str]] = defaultdict(set)

    for ev in events:
        event_id = int(ev.get("event_id", 0))
        # Detect Password Spraying: 1 source IP failing across >= 4 distinct accounts
        if event_id == 4625:
            src_ip = str(ev.get("source_ip", ""))
            user = str(ev.get("target_user", ""))
            if src_ip and user:
                failed_targets_by_ip[src_ip].add(user)

        # Detect Sysmon Event ID 1: Web worker spawning command interpreter
        elif event_id == 1:
            parent = str(ev.get("parent_image", "")).lower()
            child = str(ev.get("image", "")).lower()
            if parent.endswith(("w3wp.exe", "nginx", "apache2")) and child.endswith(
                ("cmd.exe", "powershell.exe", "pwsh.exe", "/bin/sh", "/bin/bash")
            ):
                alerts.append(f"HIGH_SIEM_ALERT: Web process `{parent}` spawned shell `{child}`")

    for ip, users in failed_targets_by_ip.items():
        if len(users) >= 4:
            alerts.append(
                f"MEDIUM_SIEM_ALERT: Password spraying suspected from `{ip}` across {len(users)} distinct accounts"
            )

    return alerts


# ============================================================================
# 3. Cloud IAM Policy & Container Security Context Hardening Auditors
# ============================================================================

def audit_cloud_iam_policy(policy_json: str) -> List[str]:
    doc = json.loads(policy_json)
    findings: List[str] = []
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for idx, stmt in enumerate(statements, start=1):
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        act_list = [actions] if isinstance(actions, str) else list(actions)
        res_list = [resources] if isinstance(resources, str) else list(resources)

        if "*" in act_list and "*" in res_list:
            findings.append(f"Statement #{idx}: Wildcard Administrative Privilege (`Action: *` on `Resource: *`).")
        if stmt.get("Principal") == "*":
            findings.append(f"Statement #{idx}: Public anonymous access granted (`Principal: *`).")

    return findings


def audit_container_security_context(spec: Dict[str, Any]) -> List[str]:
    issues: List[str] = []
    if spec.get("privileged") is True:
        issues.append("CRITICAL_CONTAINER: `privileged: true` exposes host kernel.")
    if spec.get("run_as_user", 0) == 0:
        issues.append("HIGH_CONTAINER: Workload runs as UID 0 (`root`).")
    if spec.get("read_only_root_filesystem") is not True:
        issues.append("MEDIUM_CONTAINER: Root filesystem is writable; set `read_only_root_filesystem: True`.")
    if "/var/run/docker.sock" in (spec.get("volumes") or []):
        issues.append("CRITICAL_CONTAINER: Mounting `/var/run/docker.sock` grants host takeover.")
    return issues
