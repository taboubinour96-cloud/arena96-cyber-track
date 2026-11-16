"""
Stage 30 Defensive Lab — DNSSEC-Style Chain Validation, DNS Tunneling Detection & CT Monitoring
=================================================================================================
1. DNSSECChainValidator (simulated):
   - Each zone's DNSKEY is digested into the parent DS record; zone records
     carry HMAC signatures under the zone key. A tampered record or a DNSKEY
     that does not match the parent DS breaks the chain (fail-closed).
2. DNSTunnelingDetector:
   - Statistical exfiltration hunting over query names: label length, Shannon
     entropy, unique-subdomain ratio and TXT share combine into a verdict.
3. CertificateTransparencyMonitor:
   - Watches CT-style issuance entries for watched domains: unauthorized
     issuers and one-edit look-alike domains raise alerts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from collections import Counter
from typing import Dict, List, Tuple


class DnsTrustViolation(Exception):
    """Raised when a DNS/web-trust rule is violated."""


def _h(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _edit_distance(a: str, b: str) -> int:
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev, dp[0] = dp[0], i
        for j, cb in enumerate(b, 1):
            prev, dp[j] = dp[j], min(dp[j] + 1, dp[j - 1] + 1, prev + (ca != cb))
    return dp[len(b)]


class DNSSECChainValidator:
    """Zones: name -> key material. DS digest = sha256(zone:key). Records signed with zone key."""

    def __init__(self) -> None:
        self.zone_keys: Dict[str, str] = {}
        self.ds_digests: Dict[str, str] = {}

    def register_zone(self, zone: str, key_material: str, parent_zone: str | None) -> None:
        self.zone_keys[zone] = key_material
        if parent_zone is not None:
            self.ds_digests[zone] = _h(f"{zone}:{key_material}")

    def sign_record(self, zone: str, record_name: str, record_value: str) -> Dict[str, object]:
        key = self.zone_keys[zone]
        payload = {"zone": zone, "name": record_name, "value": record_value}
        sig = hmac.new(key.encode(), json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        return {**payload, "signature": sig}

    def validate(self, record: Dict[str, object]) -> Tuple[bool, str]:
        zone = str(record["zone"])
        key = self.zone_keys.get(zone)
        if key is None:
            return False, "DNSSEC_UNKNOWN_ZONE"
        if zone in self.ds_digests and self.ds_digests[zone] != _h(f"{zone}:{key}"):
            return False, "DNSSEC_DS_DIGEST_MISMATCH_CHAIN_BROKEN"
        payload = {"zone": zone, "name": record["name"], "value": record["value"]}
        expect = hmac.new(key.encode(), json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, str(record["signature"])):
            return False, "DNSSEC_RRSIG_INVALID_TAMPERED_RECORD"
        return True, "DNSSEC_CHAIN_VALIDATED"


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class DNSTunnelingDetector:
    def analyze(self, queries: List[Dict[str, object]], watched_suffix: str) -> Dict[str, object]:
        relevant = [q for q in queries if str(q["name"]).endswith(watched_suffix)]
        if not relevant:
            return {"verdict": "NO_DATA", "score": 0.0, "query_count": 0}
        labels: List[str] = []
        subdomains: List[str] = []
        txt = 0
        for q in relevant:
            name = str(q["name"])
            sub = name[: -len(watched_suffix)].strip(".")
            subdomains.append(sub)
            labels.extend([p for p in sub.split(".") if p])
            if str(q.get("type", "")).upper() == "TXT":
                txt += 1
        avg_len = sum(len(x) for x in labels) / max(1, len(labels))
        max_label_len = max((len(x) for x in labels), default=0)
        avg_entropy = sum(_entropy(s.replace(".", "")) for s in subdomains) / max(1, len(subdomains))
        unique_ratio = len(set(subdomains)) / max(1, len(subdomains))
        txt_ratio = txt / len(relevant)
        score = 0.0
        if max_label_len > 25:
            score += 30
        if avg_entropy > 3.5:
            score += 30
        if unique_ratio > 0.8 and len(relevant) >= 3:
            score += 20
        if txt_ratio > 0.3:
            score += 20
        verdict = "TUNNELING_LIKELY" if score >= 60 else "SUSPICIOUS_REVIEW" if score >= 30 else "NORMAL"
        return {
            "verdict": verdict, "score": score, "query_count": len(relevant),
            "avg_label_len": round(avg_len, 2), "avg_entropy": round(avg_entropy, 2),
            "unique_ratio": round(unique_ratio, 2), "txt_ratio": round(txt_ratio, 2),
        }


class CertificateTransparencyMonitor:
    def __init__(self, watched_domains: List[str], authorized_issuers: List[str]) -> None:
        self.watched = [d.lower() for d in watched_domains]
        self.issuers = set(authorized_issuers)

    def check_entry(self, domain: str, issuer: str) -> Tuple[bool, str]:
        d = domain.lower()
        for w in self.watched:
            if d == w or d.endswith("." + w):
                if issuer not in self.issuers:
                    return True, f"CT_ALERT_UNAUTHORIZED_ISSUER_FOR_{w}"
                return False, "CT_OK_WATCHED_DOMAIN_AUTHORIZED_ISSUER"
        for w in self.watched:
            if _edit_distance(d, w) == 1:
                return True, f"CT_ALERT_LOOKALIKE_DOMAIN_OF_{w}"
        return False, "CT_OK_UNRELATED_DOMAIN"
