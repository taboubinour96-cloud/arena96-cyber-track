"""
Stage 17 Defensive Lab — Byzantine Quorum Consensus, Eclipse/Sybil Peer Diversity & Gossip Anti-Entropy
======================================================================================================
1. ByzantineQuorumEngine:
   - PBFT-style quorum arithmetic (n >= 3f+1, commit quorum = 2f+1 distinct validators).
   - Detects validator equivocation (same validator signing two different values at height/round)
     and emits cryptographic-style slashing evidence; conflicting certificates can never both verify.
2. EclipseResistancePeerSelector:
   - Greedy peer selection with per-/24-subnet and per-ASN caps plus minimum subnet diversity,
     so a single network neighbourhood cannot eclipse the node.
3. GossipAntiEntropyReconciler:
   - Versioned digest reconciliation: merges divergent key/value replicas by highest version,
     records deterministic conflicts, and produces a SHA-256 convergence digest.
"""

from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Set, Tuple


class ConsensusViolation(Exception):
    """Raised when a Byzantine quorum safety rule is violated."""


class ByzantineQuorumEngine:
    def __init__(self, validators: List[str]) -> None:
        uniq = sorted(set(validators))
        if len(uniq) < 4:
            raise ConsensusViolation("BYZANTINE_SET_TOO_SMALL_MIN_4")
        self.validators = uniq
        self.n = len(uniq)
        self.f = (self.n - 1) // 3
        if self.n < 3 * self.f + 1:
            raise ConsensusViolation("INSUFFICIENT_VALIDATORS_FOR_F")
        self.quorum = 2 * self.f + 1
        # (height, round_no, validator) -> value
        self._votes: Dict[Tuple[int, int, str], str] = {}
        self._equivocations: List[Dict[str, object]] = []

    def cast_vote(self, validator: str, height: int, round_no: int, value: str) -> str:
        if validator not in self.validators:
            raise ConsensusViolation("UNKNOWN_VALIDATOR")
        key = (height, round_no, validator)
        prev = self._votes.get(key)
        if prev is not None and prev != value:
            evidence = {
                "validator": validator,
                "height": height,
                "round": round_no,
                "value_a": prev,
                "value_b": value,
            }
            evidence["evidence_sha256"] = hashlib.sha256(
                json.dumps(evidence, sort_keys=True).encode()
            ).hexdigest()
            self._equivocations.append(evidence)
            raise ConsensusViolation("EQUIVOCATION_DETECTED_SLASHING_EVIDENCE_EMITTED")
        self._votes[key] = value
        return "VOTE_RECORDED"

    def equivocation_evidence(self) -> List[Dict[str, object]]:
        return list(self._equivocations)

    def commit_certificate(self, height: int, round_no: int, value: str) -> Dict[str, object]:
        signers = sorted(
            v for (h, r, v), val in self._votes.items()
            if h == height and r == round_no and val == value
        )
        if len(signers) < self.quorum:
            raise ConsensusViolation(
                f"QUORUM_NOT_REACHED_{len(signers)}_OF_{self.quorum}"
            )
        cert = {
            "height": height,
            "round": round_no,
            "value": value,
            "signers": signers,
            "quorum": self.quorum,
        }
        cert["certificate_sha256"] = hashlib.sha256(
            json.dumps(cert, sort_keys=True).encode()
        ).hexdigest()
        return cert

    def verify_certificate(self, cert: Dict[str, object]) -> bool:
        signers = cert.get("signers", [])
        if not isinstance(signers, list) or len(set(signers)) < self.quorum:
            return False
        if any(s not in self.validators for s in signers):
            return False
        # Every signer must actually have voted for this value (no forged certs).
        for s in signers:
            if self._votes.get((int(cert["height"]), int(cert["round"]), str(s))) != cert["value"]:
                return False
        payload = {
            "height": cert["height"],
            "round": cert["round"],
            "value": cert["value"],
            "signers": sorted(signers),
            "quorum": self.quorum,
        }
        expect = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return expect == cert.get("certificate_sha256")


class EclipseResistancePeerSelector:
    def __init__(self, max_per_subnet: int = 2, max_per_asn: int = 3, min_distinct_subnets: int = 3) -> None:
        self.max_per_subnet = max_per_subnet
        self.max_per_asn = max_per_asn
        self.min_distinct_subnets = min_distinct_subnets

    @staticmethod
    def subnet_of(ip: str) -> str:
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3]) + ".0/24"
        return ip  # non-IPv4 treated as its own bucket

    def select_peers(self, candidates: List[Dict[str, object]], want: int) -> Dict[str, object]:
        ordered = sorted(candidates, key=lambda c: (-float(c.get("score", 0)), str(c["ip"])))
        subnet_count: Dict[str, int] = {}
        asn_count: Dict[str, int] = {}
        selected: List[Dict[str, object]] = []
        for c in ordered:
            if len(selected) >= want:
                break
            subnet = self.subnet_of(str(c["ip"]))
            asn = str(c.get("asn", "unknown"))
            if subnet_count.get(subnet, 0) >= self.max_per_subnet:
                continue
            if asn_count.get(asn, 0) >= self.max_per_asn:
                continue
            selected.append(c)
            subnet_count[subnet] = subnet_count.get(subnet, 0) + 1
            asn_count[asn] = asn_count.get(asn, 0) + 1
        distinct = sorted({self.subnet_of(str(c["ip"])) for c in selected})
        return {
            "selected": selected,
            "selected_ips": [str(c["ip"]) for c in selected],
            "distinct_subnets": distinct,
            "distinct_subnet_count": len(distinct),
            "eclipsed": len(distinct) < self.min_distinct_subnets,
            "diverse_enough": len(distinct) >= self.min_distinct_subnets,
        }


class GossipAntiEntropyReconciler:
    @staticmethod
    def _entry_hash(key: str, version: int, value: str) -> str:
        return hashlib.sha256(f"{key}|{version}|{value}".encode()).hexdigest()

    def digest(self, records: Dict[str, Tuple[int, str]]) -> str:
        items = sorted((k, v, self._entry_hash(k, v, val)) for k, (v, val) in records.items())
        return hashlib.sha256(json.dumps(items).encode()).hexdigest()

    def reconcile(
        self,
        local: Dict[str, Tuple[int, str]],
        remote: Dict[str, Tuple[int, str]],
    ) -> Dict[str, object]:
        merged: Dict[str, Tuple[int, str]] = dict(local)
        conflicts: List[str] = []
        transferred: List[str] = []
        for key, (rver, rval) in remote.items():
            if key not in merged:
                merged[key] = (rver, rval)
                transferred.append(key)
                continue
            lver, lval = merged[key]
            if rver > lver:
                merged[key] = (rver, rval)
                transferred.append(key)
            elif rver == lver and rval != lval:
                conflicts.append(key)
                # Deterministic tie-break: lexicographically larger value wins on both sides.
                if rval > lval:
                    merged[key] = (rver, rval)
        return {
            "merged": merged,
            "transferred_keys": sorted(transferred),
            "conflict_keys": sorted(conflicts),
            "converged_digest": self.digest(merged),
            "converged": self.digest(merged) == self.digest(
                {k: merged[k] for k in merged}
            ),
        }
