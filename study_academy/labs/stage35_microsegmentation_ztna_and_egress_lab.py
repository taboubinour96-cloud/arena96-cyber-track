"""
Stage 35 Defensive Lab — Microsegmentation, ZTNA Flows & Egress Control
=========================================================================
1. SegmentationPolicyEngine: east-west traffic is deny-by-default; a flow
   passes only when an explicit rule matches source group, destination
   group, port and a declared business purpose.
2. EgressController: data-zone workloads may reach the internet only via
   the proxy to allow-listed domains; direct egress is denied even if a
   segmentation rule would pass.
3. LateralMovementScout: denied attempts from low-trust zones toward crown
   assets on sensitive ports are escalated — a blocked probe is still a
   detection.
"""

from __future__ import annotations

from typing import Dict, List, Set


class SegmentationViolation(Exception):
    """Raised when a segmentation rule is violated."""


class SegmentationPolicyEngine:
    _SENSITIVE_PORTS = {22, 3389, 5432, 3306, 6379, 27017}

    def __init__(self) -> None:
        self._rules: List[Dict[str, object]] = []

    def add_rule(self, src_group: str, dst_group: str, port: int, purpose: str) -> None:
        if not purpose:
            raise SegmentationViolation("FLOW_RULE_REQUIRES_BUSINESS_PURPOSE")
        self._rules.append({"src": src_group, "dst": dst_group, "port": port, "purpose": purpose})

    def evaluate(self, src_group: str, dst_group: str, port: int,
                 src_trust: str = "standard", dst_is_crown: bool = False) -> Dict[str, object]:
        for rule in self._rules:
            if rule["src"] == src_group and rule["dst"] == dst_group and int(rule["port"]) == port:
                return {"allowed": True, "state": "FLOW_ALLOWED_BY_DECLARED_RULE", "purpose": rule["purpose"]}
        result: Dict[str, object] = {"allowed": False, "state": "FLOW_DENIED_DEFAULT_NO_RULE"}
        if src_trust == "low" and dst_is_crown and port in self._SENSITIVE_PORTS:
            result["state"] = "FLOW_DENIED_LATERAL_MOVEMENT_ALERT"
            result["alert"] = "LOW_TRUST_TO_CROWN_SENSITIVE_PORT"
        return result


class EgressController:
    def __init__(self, allowed_domains: Set[str]) -> None:
        self._allowed = {d.lower() for d in allowed_domains}

    def evaluate(self, src_zone: str, domain: str, via_proxy: bool) -> Dict[str, object]:
        if src_zone == "data" and not via_proxy:
            return {"allowed": False, "state": "EGRESS_DENIED_DATA_ZONE_MUST_USE_PROXY"}
        if domain.lower() not in self._allowed:
            return {"allowed": False, "state": "EGRESS_DENIED_DOMAIN_NOT_ALLOWLISTED"}
        if not via_proxy:
            return {"allowed": False, "state": "EGRESS_DENIED_DIRECT_INTERNET_FORBIDDEN"}
        return {"allowed": True, "state": "EGRESS_ALLOWED_VIA_PROXY_ALLOWLISTED"}
