"""
Stage 36 Defensive Lab — Data Governance, DLP Egress Gate & Sovereign Privacy
================================================================================
1. DataClassifier: finds regulated patterns (emails, IBAN-shaped strings,
   long national-ID/account digit runs, API-key-shaped secrets) and labels
   the payload by its most sensitive finding.
2. Tokenizer: replaces secrets with deterministic HMAC tokens so analytics
   can join on equality without ever holding the raw value.
3. DLPEgressGate: cross-border / external egress is decided by classification,
   destination residency, declared purpose and redaction state — SECRET data
   leaves only tokenized, to approved jurisdictions, for a named purpose.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Dict, List, Tuple


class DataGovernanceViolation(Exception):
    """Raised when a data-governance rule is violated."""


class DataClassifier:
    _PATTERNS: List[Tuple[str, str, "re.Pattern[str]"]] = [
        ("SECRET", "api_key", re.compile(r"\b(?:sk|key|tok)-[A-Za-z0-9]{16,}\b")),
        ("CONFIDENTIAL", "iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
        ("CONFIDENTIAL", "long_digit_id", re.compile(r"\b\d{10,16}\b")),
        ("INTERNAL", "email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ]
    _RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "SECRET": 3}

    def classify(self, text: str) -> Dict[str, object]:
        findings: List[str] = []
        level = "PUBLIC"
        for label, kind, pattern in self._PATTERNS:
            if pattern.search(text):
                findings.append(kind)
                if self._RANK[label] > self._RANK[level]:
                    level = label
        return {"classification": level, "findings": findings}


class Tokenizer:
    def __init__(self, token_key: bytes) -> None:
        if len(token_key) < 16:
            raise DataGovernanceViolation("TOKENIZER_KEY_TOO_SHORT")
        self._key = token_key

    def tokenize(self, value: str) -> str:
        return "tok_" + hmac.new(self._key, value.encode(), hashlib.sha256).hexdigest()[:24]

    def redact(self, text: str) -> str:
        out = text
        for _label, _kind, pattern in DataClassifier._PATTERNS:
            out = pattern.sub(lambda m: self.tokenize(m.group(0)), out)
        return out


class DLPEgressGate:
    def __init__(self, approved_jurisdictions: List[str]) -> None:
        self._approved = set(approved_jurisdictions)

    def evaluate(self, classification: str, destination_country: str,
                 purpose: str, is_tokenized_or_redacted: bool, external: bool = True) -> Dict[str, object]:
        if external and not purpose:
            return {"allowed": False, "state": "DLP_DENIED_NO_DECLARED_PURPOSE"}
        if external and destination_country not in self._approved:
            return {"allowed": False, "state": "DLP_DENIED_DESTINATION_NOT_SOVEREIGN_APPROVED"}
        if classification in {"SECRET", "CONFIDENTIAL"} and external and not is_tokenized_or_redacted:
            return {"allowed": False, "state": "DLP_DENIED_SENSITIVE_DATA_MUST_BE_TOKENIZED"}
        return {"allowed": True, "state": "DLP_EGRESS_ALLOWED_GOVERNED"}
