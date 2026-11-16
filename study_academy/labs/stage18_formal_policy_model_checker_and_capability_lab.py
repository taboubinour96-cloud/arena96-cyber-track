"""
Stage 18 Defensive Lab — Formal Policy Model Checking & Capability Attenuation Proofs
=======================================================================================
1. AgentPolicyModelChecker:
   - Explicit-state BFS model checking over an agent workflow graph.
   - Verifies safety invariants on EVERY reachable state and returns a shortest
     counterexample trace when an invariant is violated (buggy model must fail).
2. CapabilityTokenEngine:
   - Macaroon-style HMAC-chained capability tokens. Attenuation may only NARROW
     actions / resource prefix / expiry; any widening attempt is rejected and
     tampered tokens fail verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections import deque
from typing import Callable, Dict, List, Set, Tuple


class PolicyViolation(Exception):
    """Raised when a capability or policy rule is violated."""


State = Dict[str, object]


class AgentPolicyModelChecker:
    """Generic explicit-state checker: nodes are named states with attribute dicts."""

    def __init__(self) -> None:
        self.states: Dict[str, State] = {}
        self.edges: Dict[str, List[Tuple[str, str]]] = {}  # src -> [(action, dst)]

    def add_state(self, name: str, **attrs: object) -> None:
        self.states[name] = dict(attrs)

    def add_edge(self, src: str, action: str, dst: str) -> None:
        self.edges.setdefault(src, []).append((action, dst))

    def reachable(self, initial: str) -> Set[str]:
        seen = {initial}
        queue = deque([initial])
        while queue:
            cur = queue.popleft()
            for _action, dst in self.edges.get(cur, []):
                if dst not in seen:
                    seen.add(dst)
                    queue.append(dst)
        return seen

    def check_invariants(
        self, initial: str, invariants: Dict[str, Callable[[State], bool]]
    ) -> Dict[str, object]:
        """BFS; invariant fn returns True when the state is SAFE."""
        visited: Set[str] = {initial}
        queue: deque = deque([(initial, [initial])])
        explored = 0
        while queue:
            cur, path = queue.popleft()
            explored += 1
            state = self.states[cur]
            for inv_name, is_safe in invariants.items():
                if not is_safe(state):
                    return {
                        "holds": False,
                        "violated_invariant": inv_name,
                        "counterexample_path": path,
                        "counterexample_state": cur,
                        "states_explored": explored,
                    }
            for _action, dst in self.edges.get(cur, []):
                if dst not in visited:
                    visited.add(dst)
                    queue.append((dst, path + [dst]))
        return {
            "holds": True,
            "violated_invariant": None,
            "counterexample_path": [],
            "counterexample_state": None,
            "states_explored": explored,
            "reachable_count": len(visited),
        }


def build_agent_model(buggy_bypass: bool = False) -> AgentPolicyModelChecker:
    m = AgentPolicyModelChecker()
    m.add_state("Idle", secret_loaded=False, network_open=False, approved=False, executed_privileged=False)
    m.add_state("ReadingPublic", secret_loaded=False, network_open=True, approved=False, executed_privileged=False)
    m.add_state("SecretLoaded", secret_loaded=True, network_open=False, approved=False, executed_privileged=False)
    m.add_state("AwaitingApproval", secret_loaded=True, network_open=False, approved=False, executed_privileged=False)
    m.add_state("Approved", secret_loaded=True, network_open=False, approved=True, executed_privileged=False)
    m.add_state("ExecutedPrivileged", secret_loaded=True, network_open=False, approved=True, executed_privileged=True)
    m.add_state("SecretExfiltrated", secret_loaded=True, network_open=True, approved=False, executed_privileged=False)

    m.add_edge("Idle", "read_public", "ReadingPublic")
    m.add_edge("ReadingPublic", "close", "Idle")
    m.add_edge("Idle", "load_secret_offline", "SecretLoaded")
    m.add_edge("SecretLoaded", "request_approval", "AwaitingApproval")
    m.add_edge("AwaitingApproval", "owner_approves", "Approved")
    m.add_edge("AwaitingApproval", "owner_denies", "SecretLoaded")
    m.add_edge("Approved", "execute_privileged", "ExecutedPrivileged")
    if buggy_bypass:
        # The classic flaw: secret can reach an open network / privileged exec without approval.
        m.add_edge("SecretLoaded", "open_network_with_secret", "SecretExfiltrated")
        m.add_edge("SecretLoaded", "execute_without_approval", "ExecutedPrivileged")
    return m


AGENT_SAFETY_INVARIANTS: Dict[str, Callable[[State], bool]] = {
    "no_secret_on_open_network": lambda s: not (s.get("secret_loaded") and s.get("network_open")),
    "privileged_exec_requires_approval": lambda s: not s.get("executed_privileged") or bool(s.get("approved")),
}


class CapabilityTokenEngine:
    def __init__(self, root_key: bytes) -> None:
        if len(root_key) < 16:
            raise PolicyViolation("ROOT_KEY_TOO_SHORT")
        self._key = root_key

    def _mac(self, payload: Dict[str, object], prev_mac: str = "") -> str:
        msg = (prev_mac + json.dumps(payload, sort_keys=True)).encode()
        return hmac.new(self._key, msg, hashlib.sha256).hexdigest()

    def issue(self, holder: str, actions: List[str], resource_prefix: str, expires_at: int) -> Dict[str, object]:
        payload = {
            "holder": holder,
            "actions": sorted(set(actions)),
            "resource_prefix": resource_prefix,
            "expires_at": int(expires_at),
        }
        token = dict(payload)
        token["mac"] = self._mac(payload)
        return token

    def attenuate(self, token: Dict[str, object], *, actions=None, resource_prefix=None, expires_at=None) -> Dict[str, object]:
        if not self._mac_ok(token):
            raise PolicyViolation("TOKEN_MAC_INVALID_BEFORE_ATTENUATION")
        new_actions = sorted(set(actions)) if actions is not None else list(token["actions"])
        if not set(new_actions).issubset(set(token["actions"])):
            raise PolicyViolation("ATTENUATION_WIDENING_ACTIONS_FORBIDDEN")
        new_prefix = resource_prefix if resource_prefix is not None else str(token["resource_prefix"])
        if not new_prefix.startswith(str(token["resource_prefix"])):
            raise PolicyViolation("ATTENUATION_WIDENING_RESOURCE_FORBIDDEN")
        new_exp = int(expires_at) if expires_at is not None else int(token["expires_at"])
        if new_exp > int(token["expires_at"]):
            raise PolicyViolation("ATTENUATION_WIDENING_EXPIRY_FORBIDDEN")
        payload = {
            "holder": token["holder"],
            "actions": new_actions,
            "resource_prefix": new_prefix,
            "expires_at": new_exp,
        }
        out = dict(payload)
        out["mac"] = self._mac(payload, prev_mac=str(token["mac"]))
        out["parent_mac"] = str(token["mac"])
        return out

    def _mac_ok(self, token: Dict[str, object]) -> bool:
        # Root tokens verify directly; attenuated tokens verify via parent chain field presence + MAC recompute needs parent.
        # For this lab, attenuated tokens carry parent_mac and are verified by recomputing with it.
        payload = {
            "holder": token.get("holder"),
            "actions": token.get("actions"),
            "resource_prefix": token.get("resource_prefix"),
            "expires_at": token.get("expires_at"),
        }
        prev = str(token.get("parent_mac", ""))
        expect = self._mac(payload, prev_mac=prev) if prev else self._mac(payload)
        return hmac.compare_digest(expect, str(token.get("mac", "")))

    def verify(self, token: Dict[str, object], action: str, resource: str, now_ts: int) -> Tuple[bool, str]:
        if not self._mac_ok(token):
            return False, "CAPABILITY_MAC_INVALID_TAMPERED"
        if now_ts > int(token["expires_at"]):
            return False, "CAPABILITY_EXPIRED"
        if action not in list(token["actions"]):
            return False, "CAPABILITY_ACTION_NOT_GRANTED"
        if not resource.startswith(str(token["resource_prefix"])):
            return False, "CAPABILITY_RESOURCE_OUT_OF_SCOPE"
        return True, "CAPABILITY_OK"
