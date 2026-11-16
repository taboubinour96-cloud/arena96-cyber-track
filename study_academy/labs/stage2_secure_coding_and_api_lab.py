"""
المختبر العملي للمرحلة 2 (Stage 2 Hands-On Secure Coding & API Lab) — أرينا 96 (بإشراف نور)

يطبق هذا المختبر ركائز المرحلة الثانية برمجياً وبشكل قابل للاختبار الآلي:
1. مستودع قواعد بيانات SQL محصن بالاستعلامات المعلمية (Prepared Statements) وقوائم الترتيب البيضاء + حماية BOLA/IDOR.
2. محرك رموز جلسات موقع بـ HMAC-SHA256 مع تثبيت الخوارزمية (Algorithm Pinning) والمقارنة الزمنية الثابتة (`hmac.compare_digest`).
3. مدقق سلامة الذاكرة في لغة C (رصد الدوال غير الآمنة CWE-120 / CWE-134 واقتراح البدائل المقيدة بالطول).
4. مدقق أمن سلاسل التوريد لملفات GitHub Actions (التحقق من التثبيت بـ SHA-40 ومنع حقن تعبيرات الحدث).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


# ============================================================================
# 1. Secure SQLite Repository (Parameterized SQL + Allowlist + BOLA Ownership)
# ============================================================================

class SecureInvoiceRepository:
    """Demonstrates SQLi-immune parameterized queries and BOLA/IDOR ownership enforcement."""

    _ALLOWED_SORT_COLUMNS = {"id": "id", "amount_cents": "amount_cents", "title": "title"}

    def __init__(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """
            CREATE TABLE invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                amount_cents INTEGER NOT NULL
            )
            """
        )

    def create_invoice(self, owner_user_id: int, title: str, amount_cents: int) -> int:
        cur = self.conn.execute(
            "INSERT INTO invoices (owner_user_id, title, amount_cents) VALUES (?, ?, ?)",
            (owner_user_id, title, amount_cents),
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def get_invoice_for_user(self, invoice_id: int, requesting_user_id: int) -> Optional[Dict[str, Any]]:
        """Enforces Object-Level Authorization (prevents BOLA/IDOR by scoping query to owner_user_id)."""
        cur = self.conn.execute(
            "SELECT id, owner_user_id, title, amount_cents FROM invoices WHERE id = ? AND owner_user_id = ?",
            (invoice_id, requesting_user_id),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def search_user_invoices(
        self, requesting_user_id: int, search_term: str, sort_by: str = "id"
    ) -> List[Dict[str, Any]]:
        """Combines parameterized LIKE with strict allowlist validation for ORDER BY identifier."""
        if sort_by not in self._ALLOWED_SORT_COLUMNS:
            raise ValueError(f"Disallowed sort column: {sort_by}")
        safe_col = self._ALLOWED_SORT_COLUMNS[sort_by]
        cur = self.conn.execute(
            f"SELECT id, title, amount_cents FROM invoices WHERE owner_user_id = ? AND title LIKE ? ORDER BY {safe_col} ASC",
            (requesting_user_id, f"%{search_term}%"),
        )
        return [dict(r) for r in cur.fetchall()]


# ============================================================================
# 2. Hardened Token Manager (Algorithm Pinning + Constant-Time Signature Check)
# ============================================================================

def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode((segment + padding).encode("ascii"))


class TokenVerificationError(ValueError):
    """Raised when a token fails cryptographic, algorithm, or expiration validation."""


class HardenedTokenManager:
    """Issues and verifies compact HMAC-SHA256 tokens with strict alg/issuer/exp enforcement."""

    PINNED_ALG = "HS256"

    def __init__(self, secret_key: bytes, issuer: str = "arena96-auth") -> None:
        if len(secret_key) < 32:
            raise ValueError("HMAC secret key must be at least 32 bytes (256 bits).")
        self._secret = secret_key
        self._issuer = issuer

    def issue_token(self, subject: str, role: str, ttl_seconds: int = 300) -> str:
        header = {"alg": self.PINNED_ALG, "typ": "JWT"}
        now = int(time.time())
        payload = {
            "sub": subject,
            "role": role,
            "iss": self._issuer,
            "iat": now,
            "exp": now + ttl_seconds,
        }
        signing_input = (
            f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))}."
            f"{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))}"
        )
        sig = hmac.new(self._secret, signing_input.encode("ascii"), hashlib.sha256).digest()
        return f"{signing_input}.{_b64url_encode(sig)}"

    def verify_token(self, token: str, now_override: Optional[int] = None) -> Dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            raise TokenVerificationError("Malformed token structure.")

        header_b64, payload_b64, sig_b64 = parts
        try:
            header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
            payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
            provided_sig = _b64url_decode(sig_b64)
        except Exception as exc:
            raise TokenVerificationError("Invalid Base64URL or JSON encoding.") from exc

        # 1. Strict Algorithm Pinning (blocks 'alg: none' and algorithm confusion)
        if header.get("alg") != self.PINNED_ALG:
            raise TokenVerificationError(f"Rejected unexpected algorithm: {header.get('alg')}")

        # 2. Constant-Time HMAC Verification
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(provided_sig, expected_sig):
            raise TokenVerificationError("Invalid cryptographic signature.")

        # 3. Claims Validation (Issuer & Expiration)
        now = now_override if now_override is not None else int(time.time())
        if payload.get("iss") != self._issuer:
            raise TokenVerificationError("Untrusted token issuer.")
        if int(payload.get("exp", 0)) <= now:
            raise TokenVerificationError("Token has expired.")

        return payload


# ============================================================================
# 3. C Memory-Safety Static Checker (CWE-120 / CWE-134 Prevention)
# ============================================================================

@dataclass
class CMemorySafetyFinding:
    line_number: int
    cwe_id: str
    unsafe_call: str
    remediation: str


_C_UNSAFE_RULES = [
    (
        re.compile(r"\bgets\s*\("),
        "CWE-242",
        "gets()",
        "Remove `gets()` completely; use `fgets(buf, sizeof(buf), stdin)`.",
    ),
    (
        re.compile(r"\b(strcpy|strcat)\s*\("),
        "CWE-120",
        "strcpy()/strcat()",
        "Use bounded `snprintf(dst, sizeof(dst), \"%s\", src)` or validate `strlen(src) < sizeof(dst)`.",
    ),
    (
        re.compile(r"\bsprintf\s*\("),
        "CWE-120",
        "sprintf()",
        "Replace `sprintf()` with length-bounded `snprintf(buf, sizeof(buf), ...)`.",
    ),
    (
        re.compile(r"\bprintf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)"),
        "CWE-134",
        "printf(variable)",
        "Never pass a non-constant variable as format string; use `printf(\"%s\", variable)`.",
    ),
]


def audit_c_source_memory_safety(c_source: str) -> List[CMemorySafetyFinding]:
    findings: List[CMemorySafetyFinding] = []
    for idx, line in enumerate(c_source.splitlines(), start=1):
        code_part = line.split("//", 1)[0]
        for pattern, cwe, call_name, fix in _C_UNSAFE_RULES:
            if pattern.search(code_part):
                findings.append(CMemorySafetyFinding(idx, cwe, call_name, fix))
    return findings


# ============================================================================
# 4. GitHub Actions CI/CD Supply-Chain Auditor (SHA Pinning & Expression Safety)
# ============================================================================

def audit_github_workflow_yaml(yaml_text: str) -> List[str]:
    issues: List[str] = []
    uses_re = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
    sha40_re = re.compile(r"^[0-9a-f]{40}$")
    untrusted_expr_re = re.compile(
        r"\$\{\{\s*github\.event\.(pull_request|issue|comment|commits|head_commit)\."
    )

    for idx, line in enumerate(yaml_text.splitlines(), start=1):
        m = uses_re.match(line)
        if m:
            ref_target = m.group(1).strip("'\"")
            if "@" in ref_target and not ref_target.startswith("./"):
                _, ref_ver = ref_target.rsplit("@", 1)
                if not sha40_re.match(ref_ver):
                    issues.append(
                        f"Line {idx}: Unpinned GitHub Action `{ref_target}` — pin to a full 40-char commit SHA."
                    )
        if untrusted_expr_re.search(line) and not line.lstrip().startswith("env:"):
            issues.append(
                f"Line {idx}: Potential CI script injection via untrusted `${{{{ github.event.* }}}}` interpolation; pass via `env:` instead."
            )
    return issues
