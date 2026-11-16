"""
مختبر المرحلة 9: أمن بروتوكول الموصلات (MCP Schema Pinning)، منع تسريب السياق، وإجماع السرب المقاوم للبيزنطيين
"""

from __future__ import annotations

import hashlib
import json
import re
from statistics import median
from typing import Any, Dict, List


class MCPToolSecurityGuard:
    """Defends against MCP Tool Description Poisoning & Rug-Pull Schema Mutations."""

    POISON_RE = re.compile(
        r"(?i)(ignore\s+previous|read\s+~/.ssh|cat\s+/etc/passwd|exfiltrate|hidden\s+parameter|do\s+not\s+tell\s+the\s+user)"
    )

    def __init__(self) -> None:
        self._pinned_hashes: Dict[str, str] = {}

    @staticmethod
    def _canonical_hash(tool_schema: Dict[str, Any]) -> str:
        blob = json.dumps(tool_schema, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def register_and_audit_tool(self, tool_schema: Dict[str, Any]) -> Dict[str, Any]:
        name = tool_schema.get("name", "unnamed")
        desc = json.dumps(tool_schema, ensure_ascii=False)
        if self.POISON_RE.search(desc):
            return {"trusted": False, "reason": "TOOL_DESCRIPTION_POISONING_DETECTED", "tool": name}

        digest = self._canonical_hash(tool_schema)
        self._pinned_hashes[name] = digest
        return {"trusted": True, "tool": name, "pinned_sha256": digest}

    def verify_before_invocation(self, current_schema: Dict[str, Any]) -> Dict[str, Any]:
        name = current_schema.get("name", "unnamed")
        if name not in self._pinned_hashes:
            return {"allowed": False, "reason": "UNREGISTERED_MCP_TOOL"}
        curr_hash = self._canonical_hash(current_schema)
        if curr_hash != self._pinned_hashes[name]:
            return {"allowed": False, "reason": "MCP_RUG_PULL_MUTATION_DETECTED", "tool": name}
        return {"allowed": True, "tool": name}


class MarkdownExfiltrationFirewall:
    """Blocks indirect prompt-injection data exfiltration via external Markdown images/links."""

    MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)")

    @classmethod
    def sanitize_agent_output(cls, text: str, allowed_domains: List[str]) -> Dict[str, Any]:
        blocked_urls: List[str] = []

        def _repl(match: re.Match) -> str:
            url = match.group(1)
            if not any(url.startswith(f"https://{dom}") for dom in allowed_domains):
                blocked_urls.append(url)
                return "[BLOCKED_UNTRUSTED_EXFILTRATION_IMAGE]"
            return match.group(0)

        cleaned = cls.MD_IMAGE_RE.sub(_repl, text)
        return {"sanitized_text": cleaned, "blocked_urls": blocked_urls, "exfiltration_prevented": bool(blocked_urls)}


class ByzantineResilientSwarmAggregator:
    """Protects multi-agent swarms (MiroFish / CyberSwarm-96) against poisoned Byzantine outlier agents."""

    @staticmethod
    def aggregate_scores(agent_scores: List[float], trim_fraction: float = 0.2) -> Dict[str, float]:
        if not agent_scores:
            raise ValueError("Empty agent_scores")
        sorted_vals = sorted(agent_scores)
        n = len(sorted_vals)
        k = int(n * trim_fraction)
        trimmed = sorted_vals[k : n - k] if (n - 2 * k) > 0 else sorted_vals
        naive_mean = round(sum(sorted_vals) / n, 4)
        trimmed_mean = round(sum(trimmed) / len(trimmed), 4)
        med = round(float(median(sorted_vals)), 4)
        return {"naive_mean": naive_mean, "byzantine_trimmed_mean": trimmed_mean, "median": med}
