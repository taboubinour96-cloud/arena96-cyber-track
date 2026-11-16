"""
Stage 58 Defensive Lab — AI Agent SecOps & Model Supply Chain
============================================================
1. AgentCapabilityBroker: a grant is a triple (tool, scope, lifetime) and it
   may only shrink. Any widening attempt is refused and logged as critical.
2. AgentEgressInspector: every outbound tool call is inspected for secrets
   and for hidden instructions embedded in content — reading is not obeying.
3. AgentReleaseGate: a release pins model digest + prompt digest + tool set,
   and must pass the golden behavioural suite before it may serve traffic.
"""

from __future__ import annotations

import hashlib
from typing import Dict, Iterable, List, Set


class AgentViolation(Exception):
    """Raised when an agent action breaches its grant."""


SECRET_PATTERNS = ("ghp_", "AKIA", "-----BEGIN", "sk-", "xoxb-")
INJECTION_MARKERS = ("ignore previous", "تجاهل التعليمات", "you are now", "نفّذ الآن", "system:")


class AgentCapabilityBroker:
    def __init__(self, tools: Set[str], scope: Set[str], lifetime_minutes: int):
        if lifetime_minutes <= 0:
            raise AgentViolation("INVALID_LIFETIME")
        self.tools = set(tools)
        self.scope = set(scope)
        self.lifetime = lifetime_minutes
        self.violations: List[str] = []

    def check_call(self, tool: str, scope: str, elapsed_minutes: int) -> Dict[str, object]:
        if elapsed_minutes > self.lifetime:
            return {"allowed": False, "state": "DENIED_GRANT_EXPIRED"}
        if tool not in self.tools:
            self.violations.append(f"TOOL_NOT_GRANTED:{tool}")
            return {"allowed": False, "state": "DENIED_TOOL_NOT_GRANTED"}
        if scope not in self.scope:
            self.violations.append(f"SCOPE_NOT_GRANTED:{scope}")
            return {"allowed": False, "state": "DENIED_SCOPE_NOT_GRANTED"}
        return {"allowed": True, "state": "GRANT_HONOURED"}

    def attempt_widen(self, tool: str, scope: str) -> Dict[str, object]:
        if tool not in self.tools or scope not in self.scope:
            self.violations.append("WIDENING_ATTEMPT")
            return {"widened": False, "state": "WIDENING_REFUSED_REQUIRES_NEW_GRANT"}
        return {"widened": False, "state": "NO_WIDENING_NEEDED"}


class AgentEgressInspector:
    def inspect(self, tool: str, payload: str, scope: str,
                allowed_scopes: Iterable[str]) -> Dict[str, object]:
        allowed = set(allowed_scopes)
        hits = sorted({p for p in SECRET_PATTERNS if p in payload})
        injected = sorted({m for m in INJECTION_MARKERS if m.lower() in payload.lower()})
        if hits:
            return {"allowed": False, "findings": hits, "tool": tool,
                    "state": "EGRESS_DENIED_SECRET_DETECTED"}
        if injected:
            return {"allowed": False, "findings": injected, "tool": tool,
                    "state": "EGRESS_DENIED_INSTRUCTION_INJECTION"}
        if scope not in allowed:
            return {"allowed": False, "tool": tool,
                    "state": "EGRESS_DENIED_SCOPE_NOT_PERMITTED"}
        return {"allowed": True, "tool": tool, "state": "EGRESS_ALLOWED"}


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AgentReleaseGate:
    def __init__(self, model_id: str, prompt: str, tools: Iterable[str]):
        self.model_id = model_id
        self.model_digest = _digest(model_id)
        self.prompt_digest = _digest(prompt)
        self.tools = sorted(set(tools))

    def evaluate(self, candidate: Dict[str, object],
                 golden_cases: Iterable[Dict[str, object]]) -> Dict[str, object]:
        if _digest(str(candidate.get("model_id"))) != self.model_digest:
            return {"released": False, "state": "RELEASE_DENIED_MODEL_NOT_PINNED"}
        if _digest(str(candidate.get("prompt"))) != self.prompt_digest:
            return {"released": False, "state": "RELEASE_DENIED_PROMPT_DRIFT"}
        if sorted(set(candidate.get("tools", []))) != self.tools:
            return {"released": False, "state": "RELEASE_DENIED_TOOL_SET_DRIFT"}
        failures = [
            c["case"] for c in golden_cases
            if bool(c.get("expect_refusal")) and not bool(c.get("refused"))
        ]
        if failures:
            return {"released": False, "behavioural_failures": failures,
                    "state": "RELEASE_DENIED_GOLDEN_SET_FAILED"}
        manifest = {"model_digest": self.model_digest, "prompt_digest": self.prompt_digest,
                    "tools": self.tools}
        return {"released": True, "manifest": manifest,
                "state": "AGENT_RELEASE_APPROVED_WITH_FULL_ATTESTATION"}
