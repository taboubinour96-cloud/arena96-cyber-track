"""
Stage 21 Defensive Lab — SBOM, SLSA-Style Provenance & Dependency-Confusion Guard
===================================================================================
1. SBOMBuilder:
   - Builds a CycloneDX-style software bill of materials with per-component
     SHA-256 digests and a transitive dependency graph; detects dependency
     cycles and produces a deterministic SBOM digest.
2. ProvenanceVerifier:
   - SLSA/in-toto-style build provenance: trusted builder identity, source
     digest and build parameters are HMAC-signed; any post-build tampering of
     the artifact or provenance fails verification (fail-closed).
3. DependencyConfusionGuard:
   - Pins allowed registries/scopes, rejects look-alike (typosquat) package
     names by edit distance, and rejects version regressions vs. the lockfile.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Dict, List, Tuple


class SupplyChainViolation(Exception):
    """Raised when a supply-chain trust rule is violated."""


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class SBOMBuilder:
    def __init__(self) -> None:
        self.components: Dict[str, Dict[str, object]] = {}
        self.edges: Dict[str, List[str]] = {}

    def add_component(self, name: str, version: str, content: bytes, depends_on: List[str] | None = None) -> None:
        self.components[name] = {
            "name": name,
            "version": version,
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        self.edges[name] = list(depends_on or [])

    def _detect_cycle(self) -> bool:
        visiting, visited = set(), set()

        def dfs(node: str) -> bool:
            if node in visiting:
                return True
            if node in visited:
                return False
            visiting.add(node)
            for nxt in self.edges.get(node, []):
                if dfs(nxt):
                    return True
            visiting.remove(node)
            visited.add(node)
            return False

        return any(dfs(n) for n in list(self.edges))

    def build(self) -> Dict[str, object]:
        if self._detect_cycle():
            raise SupplyChainViolation("DEPENDENCY_CYCLE_DETECTED_IN_SBOM")
        missing = [d for deps in self.edges.values() for d in deps if d not in self.components]
        if missing:
            raise SupplyChainViolation(f"SBOM_MISSING_COMPONENT_{sorted(missing)[0]}")
        ordered = [self.components[k] for k in sorted(self.components)]
        digest = _sha(json.dumps({"components": ordered, "edges": self.edges}, sort_keys=True))
        return {"bom_format": "CycloneDX-like", "components": ordered, "edges": self.edges, "sbom_sha256": digest}


class ProvenanceVerifier:
    def __init__(self, builder_key: bytes, trusted_builder: str) -> None:
        if len(builder_key) < 16:
            raise SupplyChainViolation("BUILDER_KEY_TOO_SHORT")
        self._key = builder_key
        self.trusted_builder = trusted_builder

    def attest_build(self, artifact: bytes, source_digest: str, builder: str, build_params: Dict[str, object]) -> Dict[str, object]:
        payload = {
            "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
            "source_digest": source_digest,
            "builder": builder,
            "build_params": build_params,
        }
        prov = dict(payload)
        prov["signature"] = hmac.new(self._key, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        return prov

    def verify(self, artifact: bytes, prov: Dict[str, object]) -> Tuple[bool, str]:
        if prov.get("builder") != self.trusted_builder:
            return False, "UNTRUSTED_BUILDER_IDENTITY"
        if prov.get("artifact_sha256") != hashlib.sha256(artifact).hexdigest():
            return False, "ARTIFACT_DIGEST_MISMATCH_TAMPERED"
        payload = {
            "artifact_sha256": prov.get("artifact_sha256"),
            "source_digest": prov.get("source_digest"),
            "builder": prov.get("builder"),
            "build_params": prov.get("build_params"),
        }
        expect = hmac.new(self._key, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, str(prov.get("signature", ""))):
            return False, "PROVENANCE_SIGNATURE_INVALID"
        return True, "PROVENANCE_VERIFIED_SLSA_STYLE"


class DependencyConfusionGuard:
    def __init__(self, allowed_registries: Dict[str, str], lockfile: Dict[str, str]) -> None:
        """allowed_registries: scope/prefix -> registry URL. lockfile: name -> pinned version."""
        self.allowed = dict(allowed_registries)
        self.lockfile = dict(lockfile)

    @staticmethod
    def _edit_distance(a: str, b: str) -> int:
        dp = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            prev, dp[0] = dp[0], i
            for j, cb in enumerate(b, 1):
                prev, dp[j] = dp[j], min(dp[j] + 1, dp[j - 1] + 1, prev + (ca != cb))
        return dp[len(b)]

    @staticmethod
    def _ver_key(v: str) -> Tuple[int, ...]:
        return tuple(int(x) for x in v.split(".") if x.isdigit())

    def check(self, name: str, version: str, registry: str) -> Tuple[bool, str]:
        scope = name.split("/")[0] if name.startswith("@") else "default"
        expected_registry = self.allowed.get(scope, self.allowed.get("default", ""))
        if registry != expected_registry:
            return False, "REGISTRY_NOT_PINNED_FOR_SCOPE_CONFUSION_RISK"
        for known in self.lockfile:
            if known != name and self._edit_distance(name.lower(), known.lower()) == 1:
                return False, f"TYPOSQUAT_LOOKALIKE_OF_{known}"
        if name in self.lockfile and self._ver_key(version) < self._ver_key(self.lockfile[name]):
            return False, "VERSION_REGRESSION_VS_LOCKFILE"
        return True, "DEPENDENCY_OK_PINNED"
