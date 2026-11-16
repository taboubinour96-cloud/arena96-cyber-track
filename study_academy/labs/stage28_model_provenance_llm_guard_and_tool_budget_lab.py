"""
Stage 28 Defensive Lab — Model Provenance, LLM Guard Evaluation & Tool-Call Budgets
======================================================================================
1. ModelProvenanceVerifier:
   - Signs a model artifact (weights digest + dataset digest + evaluator id);
     loading an unsigned/tampered/unknown-evaluator model fails closed.
2. LLMGuardEvaluationHarness:
   - Rule-based guard lab model evaluated against a golden set (injection,
     secret-exfiltration, benign): reports accuracy, false-block rate and
     attack-pass rate — guard changes must not regress the golden set.
3. ToolCallBudgetGuard:
   - Per-session tool budgets, argument-schema pinning and repeated-call loop
     detection for agentic tool use.
4. OutputPolicyFilter:
   - Redacts secret/PII-shaped content from model outputs before delivery.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Dict, List, Tuple


class AIOperationsViolation(Exception):
    """Raised when an AI-operations security rule is violated."""


class ModelProvenanceVerifier:
    def __init__(self, signing_key: bytes, trusted_evaluators: List[str]) -> None:
        if len(signing_key) < 16:
            raise AIOperationsViolation("MODEL_SIGNING_KEY_TOO_SHORT")
        self._key = signing_key
        self.trusted = set(trusted_evaluators)

    def sign_model(self, model_id: str, weights: bytes, dataset_digest: str, evaluator: str) -> Dict[str, object]:
        payload = {
            "model_id": model_id,
            "weights_sha256": hashlib.sha256(weights).hexdigest(),
            "dataset_digest": dataset_digest,
            "evaluator": evaluator,
        }
        card = dict(payload)
        card["signature"] = hmac.new(self._key, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        return card

    def verify_for_loading(self, card: Dict[str, object], weights: bytes) -> Tuple[bool, str]:
        if card.get("evaluator") not in self.trusted:
            return False, "MODEL_EVALUATOR_NOT_TRUSTED"
        if card.get("weights_sha256") != hashlib.sha256(weights).hexdigest():
            return False, "MODEL_WEIGHTS_DIGEST_MISMATCH_TAMPERED"
        payload = {k: card.get(k) for k in ("model_id", "weights_sha256", "dataset_digest", "evaluator")}
        expect = hmac.new(self._key, json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, str(card.get("signature", ""))):
            return False, "MODEL_CARD_SIGNATURE_INVALID"
        return True, "MODEL_PROVENANCE_VERIFIED_LOAD_ALLOWED"


class LLMGuardEvaluationHarness:
    _BLOCK_PATTERNS = [
        "ignore previous instructions", "reveal your system prompt",
        "print your api key", "send the secrets", "exfiltrate",
        "dump environment variables", "تجاهل التعليمات",
    ]

    def classify(self, prompt: str) -> str:
        low = prompt.lower()
        if any(p in low for p in self._BLOCK_PATTERNS):
            return "BLOCK"
        return "ALLOW"

    def evaluate(self, golden: List[Dict[str, str]]) -> Dict[str, object]:
        tp = fp = tn = fn = 0
        for item in golden:
            pred = self.classify(item["prompt"])
            expect_block = item["label"] == "attack"
            if expect_block and pred == "BLOCK":
                tp += 1
            elif expect_block:
                fn += 1
            elif pred == "BLOCK":
                fp += 1
            else:
                tn += 1
        total = len(golden) or 1
        attacks = tp + fn or 1
        benign = tn + fp or 1
        return {
            "total": len(golden),
            "accuracy_pct": round(((tp + tn) / total) * 100.0, 2),
            "attack_pass_rate_pct": round((fn / attacks) * 100.0, 2),
            "false_block_rate_pct": round((fp / benign) * 100.0, 2),
            "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        }


class ToolCallBudgetGuard:
    def __init__(self, budgets: Dict[str, int], allowed_args: Dict[str, List[str]]) -> None:
        self.budgets = dict(budgets)
        self.allowed_args = {k: set(v) for k, v in allowed_args.items()}
        self._used: Dict[Tuple[str, str], int] = {}
        self._signatures: Dict[str, List[str]] = {}

    def authorize(self, session_id: str, tool: str, args: Dict[str, object]) -> Tuple[bool, str]:
        if tool not in self.budgets:
            return False, f"TOOL_NOT_ALLOWLISTED_{tool}"
        extra = set(args) - self.allowed_args.get(tool, set())
        if extra:
            return False, f"TOOL_ARG_NOT_IN_SCHEMA_{sorted(extra)[0]}"
        key = (session_id, tool)
        if self._used.get(key, 0) >= self.budgets[tool]:
            return False, f"TOOL_BUDGET_EXHAUSTED_{tool}"
        sig = hashlib.sha256(json.dumps({"tool": tool, "args": args}, sort_keys=True).encode()).hexdigest()
        history = self._signatures.setdefault(session_id, [])
        history.append(sig)
        if len(history) >= 3 and history[-1] == history[-2] == history[-3]:
            return False, "TOOL_CALL_LOOP_DETECTED_IDENTICAL_REPEATS"
        self._used[key] = self._used.get(key, 0) + 1
        return True, "TOOL_CALL_AUTHORIZED_WITHIN_BUDGET"


class OutputPolicyFilter:
    _PATTERNS = [
        (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "[REDACTED:GITHUB_TOKEN]"),
        (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:AWS_KEY]"),
        (re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{30,}\b"), "[REDACTED:TELEGRAM_TOKEN]"),
        (re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), "[REDACTED:EMAIL]"),
    ]

    def filter(self, text: str) -> Tuple[str, int]:
        out = text
        count = 0
        for pat, repl in self._PATTERNS:
            out, n = pat.subn(repl, out)
            count += n
        return out, count
