"""
Stage 14 Defensive Lab — Redirect-Safe SSRF Guard, Fail-Closed Single-Poller Lease & Subcommand Arg-Policy
===========================================================================================================
Directly operationalizes real-world production lessons from Nour AI Company security audits:
1. SafeRedirectAndSSRFGuard:
   - Blocks non-HTTPS schemes, URL userinfo (@), unlisted hosts, private/loopback/metadata IPs
     (including IPv6-mapped IPv4 ::ffff:127.0.0.1), DNS rebinding, and 30x redirect escapes.
2. FailClosedChatGateAndLeaderLease:
   - Enforces fail-closed chat authorization (empty/unset ALLOWED_CHAT_ID => DENY ALL).
   - Implements single-consumer heartbeat lease ("one bot => one poller") with self-healing
     against negative timestamp gaps (corrupted future timestamps).
3. SubcommandArgPolicyGate:
   - Enforces SHA-256 script pinning + granular subcommand allowlists (e.g., list/status unprivileged,
     while follow/unfollow require an out-of-repo local human approval token).
"""

from __future__ import annotations

import hashlib
import ipaddress
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse


class SafeRedirectAndSSRFGuard:
    def __init__(
        self,
        allowed_hosts: Iterable[str],
        dns_resolver: Callable[[str], List[str]],
        max_redirects: int = 3,
    ) -> None:
        self.allowed_hosts: Set[str] = {h.strip().lower() for h in allowed_hosts if h.strip()}
        self.dns_resolver = dns_resolver
        self.max_redirects = max_redirects

    @staticmethod
    def _is_global_public_ip(ip_text: str) -> bool:
        addr = ipaddress.ip_address(ip_text)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            return False
        return addr.is_global

    def validate_single_hop(self, url: str) -> Tuple[bool, str, List[str]]:
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            return False, "NON_HTTPS_SCHEME_BLOCKED", []
        if parsed.username is not None or parsed.password is not None:
            return False, "URL_USERINFO_DIFFERENTIAL_BLOCKED", []
        host = (parsed.hostname or "").lower()
        if not host or host not in self.allowed_hosts:
            return False, f"HOST_NOT_IN_ALLOWLIST:{host}", []

        resolved_ips = self.dns_resolver(host)
        if not resolved_ips:
            return False, "DNS_EMPTY_RESPONSE", []
        for ip_str in resolved_ips:
            try:
                if not self._is_global_public_ip(ip_str):
                    return False, f"NON_PUBLIC_IP_BLOCKED:{ip_str}", []
            except ValueError:
                return False, f"MALFORMED_IP:{ip_str}", []

        # Second resolution check against zero-TTL DNS rebinding
        recheck_ips = self.dns_resolver(host)
        for ip_str in recheck_ips:
            if not self._is_global_public_ip(ip_str):
                return False, f"DNS_REBINDING_DETECTED:{ip_str}", []

        return True, "HOP_VERIFIED", resolved_ips

    def trace_redirect_chain(self, initial_url: str, redirect_locations: List[str]) -> Tuple[bool, str, str]:
        if len(redirect_locations) > self.max_redirects:
            return False, "MAX_REDIRECTS_EXCEEDED", initial_url

        current = initial_url
        ok, reason, _ = self.validate_single_hop(current)
        if not ok:
            return False, reason, current

        for loc in redirect_locations:
            next_url = urljoin(current, loc)
            ok, reason, _ = self.validate_single_hop(next_url)
            if not ok:
                return False, f"REDIRECT_ESCAPE_BLOCKED->{reason}", next_url
            current = next_url

        return True, "CHAIN_VERIFIED_SAFE", current


class FailClosedChatGateAndLeaderLease:
    def __init__(self, allowed_chat_ids_csv: Optional[str], lease_ttl_seconds: int = 180) -> None:
        raw = (allowed_chat_ids_csv or "").strip()
        self.allowed_ids: Set[str] = {tok.strip() for tok in raw.split(",") if tok.strip()}
        self.lease_ttl_seconds = lease_ttl_seconds
        self.primary_heartbeat_ts: Optional[int] = None
        self.fencing_epoch: int = 0

    def is_chat_authorized(self, chat_id: int | str) -> Tuple[bool, str]:
        # Strictly FAIL-CLOSED when configuration is empty/missing
        if not self.allowed_ids:
            return False, "FAIL_CLOSED_MISSING_ALLOWLIST"
        if str(chat_id).strip() not in self.allowed_ids:
            return False, "UNAUTHORIZED_CHAT_ID"
        return True, "AUTHORIZED_OWNER"

    def record_primary_heartbeat(self, now_ts: int) -> int:
        self.fencing_epoch += 1
        self.primary_heartbeat_ts = now_ts
        return self.fencing_epoch

    def should_fallback_poller_run(self, now_ts: int) -> Tuple[bool, str]:
        if self.primary_heartbeat_ts is None:
            return True, "NO_PRIMARY_LEASE_FALLBACK_ACTIVE"
        gap = now_ts - self.primary_heartbeat_ts
        if gap < 0:
            # Self-heal corrupted future timestamp instead of deadlocking forever
            self.primary_heartbeat_ts = None
            return True, "CORRUPTED_NEGATIVE_GAP_HEALED_FALLBACK_ACTIVE"
        if gap < self.lease_ttl_seconds:
            return False, "PRIMARY_ALIVE_STANDBY_SILENT"
        return True, "PRIMARY_LEASE_EXPIRED_FALLBACK_ACTIVE"


class SubcommandArgPolicyGate:
    def __init__(self, allowlist_spec: Dict[str, Dict[str, object]], approved_dir: Path) -> None:
        self.allowlist_spec = allowlist_spec
        self.approved_dir = Path(approved_dir)

    @staticmethod
    def normalized_sha256(script_bytes: bytes) -> str:
        return hashlib.sha256(script_bytes.replace(b"\r\n", b"\n")).hexdigest()

    def authorize_execution(
        self,
        task_id: str,
        script_key: str,
        script_bytes: bytes,
        args: List[str],
    ) -> Tuple[bool, str]:
        spec = self.allowlist_spec.get(script_key)
        if spec is None:
            return False, "SCRIPT_NOT_ALLOWLISTED"

        expected_pin = str(spec.get("sha256", "")).lower()
        actual_pin = self.normalized_sha256(script_bytes).lower()
        if not expected_pin or actual_pin != expected_pin:
            return False, "SCRIPT_SHA256_PIN_MISMATCH"

        unpriv_subcommands = set(spec.get("unprivileged_subcommands", []))  # type: ignore[arg-type]
        first_arg = args[0] if args else ""
        if first_arg in unpriv_subcommands and not any(a.startswith(";") or "|" in a for a in args):
            return True, "UNPRIVILEGED_READONLY_SUBCOMMAND_ALLOWED"

        approval_file = self.approved_dir / f"{task_id}.approved"
        if approval_file.is_file():
            return True, "PRIVILEGED_SUBCOMMAND_APPROVED_BY_LOCAL_HUMAN_TOKEN"
        return False, f"PRIVILEGED_SUBCOMMAND_REFUSED_MISSING_LOCAL_APPROVAL:{first_arg or '<empty>'}"
