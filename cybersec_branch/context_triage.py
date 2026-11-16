"""
Context Retrieval & False-Positive Triage Engine (`ContextTriageEngine`).

Inspired by `VulnLLM-R` (context-retrieving agent scaffold) and `code-audit-agent`:
1. Indexes symbol/function definitions across the codebase so the agent can inspect
   helper/callee functions before deciding whether an input is sanitized.
2. Applies deterministic context checks (test-file detection, inline sanitization hints,
   reachability notes) to cut false-positive noise ("AI slop" prevention).
3. Optionally connects to an OpenAI-compatible LLM endpoint (e.g., local `vLLM` / `Ollama`
   serving `fdtn-ai/Foundation-Sec-8B-Instruct` or `Virtue-AI-HUB/VulnLLM-R-7B`) under a
   strict defensive system prompt for deeper code-flow triage and secure patch refinement.
"""

from __future__ import annotations

import ast
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from .models import AuditFinding, Confidence, TriageStatus


@dataclass
class SymbolDefinition:
    name: str
    file_path: str
    line_start: int
    line_end: int
    source_code: str


DEFENSIVE_TRIAGE_SYSTEM_PROMPT = """You are a senior defensive application security code reviewer.
Your sole responsibility is white-box static code triage and secure remediation engineering.
STRICT RULES:
1. NEVER generate exploit payloads, attack commands, shellcode, or offensive PoCs.
2. Inspect the provided code snippet and any helper function context carefully.
3. Determine whether the static finding is:
   - CONFIRMED_CANDIDATE (real code weakness requiring human verification and patching), or
   - LIKELY_FALSE_POSITIVE (input is constant, strictly validated/parameterized, or test-only mock).
4. Provide a concise root-cause explanation and a minimal, behavior-preserving secure code fix.
Respond strictly as JSON:
{"triage_status": "CONFIRMED_CANDIDATE|NEEDS_HUMAN_REVIEW|LIKELY_FALSE_POSITIVE", "reasoning": "...", "secure_patch": "..."}
"""


class ContextTriageEngine:
    """Indexes repository functions and triages static findings to eliminate false positives."""

    def __init__(
        self,
        llm_base_url: Optional[str] = None,
        llm_api_key: Optional[str] = None,
        llm_model: Optional[str] = None,
    ) -> None:
        self.llm_base_url = llm_base_url or os.environ.get("CYBERSEC_LLM_BASE_URL")
        self.llm_api_key = llm_api_key or os.environ.get("CYBERSEC_LLM_API_KEY", "EMPTY")
        self.llm_model = llm_model or os.environ.get(
            "CYBERSEC_LLM_MODEL", "fdtn-ai/Foundation-Sec-8B-Instruct"
        )
        self._symbol_index: Dict[str, List[SymbolDefinition]] = {}

    def build_symbol_index(self, files: List[Path], root_dir: Path) -> int:
        """Indexes Python functions/methods so triage can look up helper/sanitizer bodies."""
        self._symbol_index.clear()
        count = 0
        for fpath in files:
            if fpath.suffix.lower() != ".py":
                continue
            rel = str(fpath.relative_to(root_dir))
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                tree = ast.parse(content, filename=rel)
            except (OSError, SyntaxError):
                continue

            lines = content.splitlines()
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    l_start = node.lineno
                    l_end = getattr(node, "end_lineno", l_start) or l_start
                    src = "\n".join(lines[max(0, l_start - 1) : min(len(lines), l_end)])
                    defn = SymbolDefinition(
                        name=node.name,
                        file_path=rel,
                        line_start=l_start,
                        line_end=l_end,
                        source_code=src,
                    )
                    self._symbol_index.setdefault(node.name, []).append(defn)
                    count += 1
        return count

    def lookup_symbol(self, symbol_name: str) -> List[SymbolDefinition]:
        return self._symbol_index.get(symbol_name, [])

    def triage_findings(
        self, findings: List[AuditFinding], use_llm_if_configured: bool = False
    ) -> List[AuditFinding]:
        for finding in findings:
            self._apply_deterministic_triage(finding)
            if (
                use_llm_if_configured
                and self.llm_base_url
                and finding.triage_status != TriageStatus.LIKELY_FALSE_POSITIVE
            ):
                self._apply_llm_triage(finding)
        return findings

    def _apply_deterministic_triage(self, finding: AuditFinding) -> None:
        path_lower = finding.location.file_path.lower()
        parts = Path(path_lower).parts

        # 1. Demote findings inside unit test / fixture / example directories
        if any(
            p in {"tests", "test", "__tests__", "fixtures", "mocks"}
            or p.startswith("test_")
            or p.endswith("_test.py")
            or p.endswith(".spec.ts")
            for p in parts
        ):
            finding.triage_status = TriageStatus.LIKELY_FALSE_POSITIVE
            finding.confidence = Confidence.LOW
            finding.triage_notes.append(
                "Located inside a test/fixture file rather than production runtime code."
            )
            return

        # 2. Check if referenced helper functions in snippet perform allowlisting/validation
        snippet_lower = finding.location.snippet.lower()
        for sym_name, defs in self._symbol_index.items():
            if sym_name in finding.location.snippet and sym_name != finding.location.function_name:
                for d in defs[:1]:
                    body_lower = d.source_code.lower()
                    if any(
                        guard in body_lower
                        for guard in ("allowlist", "whitelist", "shlex.quote", "ip_address", "is_global")
                    ):
                        finding.triage_notes.append(
                            f"Helper `{sym_name}` ({d.file_path}:{d.line_start}) contains validation logic; "
                            "verify manually whether all code paths are covered."
                        )
                        if finding.confidence == Confidence.HIGH:
                            finding.confidence = Confidence.MEDIUM

        # 3. Assign candidate vs review status based on deterministic confidence
        if "nosec" in snippet_lower or "# security: ignore" in snippet_lower:
            finding.triage_status = TriageStatus.LIKELY_FALSE_POSITIVE
            finding.triage_notes.append("Explicit developer suppression comment (`nosec`) present.")
        elif finding.confidence == Confidence.HIGH:
            finding.triage_status = TriageStatus.CONFIRMED_CANDIDATE
            finding.triage_notes.append(
                "High-confidence static pattern/AST match; requires human verification of runtime reachability before reporting."
            )
        else:
            finding.triage_status = TriageStatus.NEEDS_HUMAN_REVIEW
            finding.triage_notes.append(
                "Medium-confidence candidate; human auditor should trace upstream middleware and caller constraints."
            )

    def _apply_llm_triage(self, finding: AuditFinding) -> None:
        """Calls an OpenAI-compatible defensive model endpoint (e.g., vLLM / Ollama) if configured."""
        if not self.llm_base_url:
            return
        parsed_base = urllib.parse.urlparse(self.llm_base_url)
        if parsed_base.scheme not in {"http", "https"} or not parsed_base.hostname:
            return
        if parsed_base.hostname in {"169.254.169.254", "metadata.google.internal"}:
            return
        url = self.llm_base_url.rstrip("/") + "/chat/completions"
        user_prompt = (
            f"Rule: {finding.rule_id} ({finding.cwe_id})\n"
            f"Title: {finding.title}\n"
            f"File: {finding.location.file_path}:{finding.location.line_start}\n"
            f"Snippet:\n{finding.location.snippet}\n"
        )
        body = json.dumps(
            {
                "model": self.llm_model,
                "temperature": 0.1,
                "messages": [
                    {"role": "system", "content": DEFENSIVE_TRIAGE_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
            }
        ).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.llm_api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15.0) as resp:  # nosec: operator-configured LLM endpoint with metadata host block
                resp_json = json.loads(resp.read().decode("utf-8"))
            raw_text = resp_json["choices"][0]["message"]["content"]
            parsed = json.loads(raw_text)
            status_val = parsed.get("triage_status", "")
            if status_val in {s.value for s in TriageStatus}:
                finding.triage_status = TriageStatus(status_val)
            if parsed.get("reasoning"):
                finding.triage_notes.append(f"LLM Triage ({self.llm_model}): {parsed['reasoning']}")
            if parsed.get("secure_patch") and not finding.secure_code_example:
                finding.secure_code_example = str(parsed["secure_patch"])
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError, OSError):
            finding.triage_notes.append("LLM endpoint unreachable; retained deterministic triage result.")
