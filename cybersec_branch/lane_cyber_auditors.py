"""
Nour AI Company — Arena 96 (Lane: Cyber / Personal Agent)
=========================================================
Specialized Defensive & Read-Only Auditors per Manager (Arena 1994) Charter:
1. SecretAndCharterAuditor:
   - Exhaustive secret & credential audit for `nour-personal-ai-agent` (and workspace).
   - Never prints raw secret values (Rule 3: redact with SHA-256 fingerprint only).
   - Verifies `trading/` inside `nour-personal-ai-agent` contains only public market data readers (Rule 5).
2. TradingLaneReadOnlyAuditor:
   - Strictly READ-ONLY security review of `ops/bridge/` and `company/copy_follow.py` (Rule 1 & Rule 4).
   - Cryptographically verifies zero file modifications before & after inspection.
   - Detects: API key/secret leakage in code/logs, withdrawal API usage, unblocked LIVE/mainnet trading endpoints,
     bridge webhook authentication/replay weaknesses, and missing kill-switch/idempotency guards.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple


SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    ".venv",
    "venv",
    "uploads",
}

TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".sh", ".env", ".md", ".txt",
}

# High-confidence secret patterns (redacted on match — never emit secret value!)
SECRET_PATTERNS: List[Tuple[str, str, str, re.Pattern]] = [
    (
        "SEC-001",
        "CRITICAL",
        "مفتاح GitHub شخصي أو رمزي مكشوف (GitHub PAT)",
        re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})\b"),
    ),
    (
        "SEC-002",
        "CRITICAL",
        "مفتاح AWS Access Key مكشوف",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "SEC-003",
        "CRITICAL",
        "مفتاح خاص مشفّر مضمّن في الكود (PEM Private Key)",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    ),
    (
        "SEC-004",
        "HIGH",
        "مفتاح مزود ذكاء اصطناعي أو واجهة برمجية مكشوف (API Key)",
        re.compile(r"\b(?:sk-(?:proj-)?[A-Za-z0-9_\-]{32,}|AIza[0-9A-Za-z_\-]{35})\b"),
    ),
    (
        "SEC-005",
        "CRITICAL",
        "توكين بوت تيليغرام أو سلاك مكشوف",
        re.compile(r"\b(?:\d{8,10}:AA[A-Za-z0-9_\-]{33}|xox[baprs]-[A-Za-z0-9\-]{20,})\b"),
    ),
    (
        "SEC-006",
        "HIGH",
        "إسناد مباشر لسر أو مفتاح تداول نصي ثابت في الكود",
        re.compile(
            r"""(?i)\b(?:api_secret|secret_key|private_key|binance_secret|bybit_secret|okx_passphrase|webhook_secret|trading_key)\s*=\s*['"][A-Za-z0-9+/=_\-]{16,}['"]"""
        ),
    ),
]

PLACEHOLDER_HINTS = (
    "example",
    "placeholder",
    "dummy",
    "sample",
    "your_",
    "changeme",
    "xxxx",
    "test_secret_not_real",
    "redacted",
    "mock",
    "simulation",
)


def _redact_fingerprint(raw_value: str) -> str:
    digest = hashlib.sha256(raw_value.encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"<REDACTED:sha256:{digest}>"


@dataclass
class AuditFinding:
    rule_id: str
    severity: str
    category: str
    file_path: str
    line: int
    title_ar: str
    evidence_redacted: str
    remediation_ar: str


class SecretAndCharterAuditor:
    """Task (أ): Exhaustive secret & charter-boundary scanner for `nour-personal-ai-agent`."""

    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root).resolve()

    def scan(self) -> Dict[str, object]:
        findings: List[AuditFinding] = []
        scanned_files = 0

        for root, dirs, files in os.walk(self.repo_root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in sorted(files):
                fpath = Path(root) / fname
                rel_path = str(fpath.relative_to(self.repo_root))

                # Check committed .env files (excluding .env.example / .env.template)
                if fname == ".env" or (fname.startswith(".env.") and not fname.endswith((".example", ".sample", ".template"))):
                    findings.append(
                        AuditFinding(
                            rule_id="SEC-ENV-001",
                            severity="CRITICAL",
                            category="secrets",
                            file_path=rel_path,
                            line=1,
                            title_ar="ملف بيئة حساس (.env) موجود داخل المستودع",
                            evidence_redacted=f"filename={fname}",
                            remediation_ar="احذف الملف من التتبع فوراً وأضفه إلى .gitignore ودوّر أي مفاتيح كانت بداخله عبر GitHub Secrets.",
                        )
                    )

                if fpath.suffix.lower() not in TEXT_EXTENSIONS and not fname.startswith(".env"):
                    continue
                # Skip test suites that intentionally synthesize fake patterns
                if rel_path.startswith("tests/"):
                    continue

                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue

                scanned_files += 1
                lines = content.splitlines()

                for idx, line in enumerate(lines, start=1):
                    lower_line = line.lower()
                    if any(h in lower_line for h in PLACEHOLDER_HINTS):
                        continue
                    for rule_id, sev, title_ar, pattern in SECRET_PATTERNS:
                        m = pattern.search(line)
                        if m:
                            findings.append(
                                AuditFinding(
                                    rule_id=rule_id,
                                    severity=sev,
                                    category="secrets",
                                    file_path=rel_path,
                                    line=idx,
                                    title_ar=title_ar,
                                    evidence_redacted=_redact_fingerprint(m.group(0)),
                                    remediation_ar="انقل القيمة السرية إلى GitHub Secrets وقم بتدوير المفتاح فوراً وفق القاعدة (3).",
                                )
                            )

                # Rule 5 check: `trading/` inside `nour-personal-ai-agent` must be public market data read-only
                if rel_path.startswith("trading/") and fpath.suffix == ".py":
                    forbidden_order_re = re.compile(
                        r"\b(?:create_order|place_order|submit_order|cancel_order|withdraw|copy_follow)\b"
                    )
                    for idx, line in enumerate(lines, start=1):
                        if forbidden_order_re.search(line):
                            findings.append(
                                AuditFinding(
                                    rule_id="CHARTER-R5",
                                    severity="CRITICAL",
                                    category="lane-boundary",
                                    file_path=rel_path,
                                    line=idx,
                                    title_ar="مخالفة القاعدة (5): منطق تنفيذ أوامر تداول داخل مستودع الوكيل الشخصي",
                                    evidence_redacted="order-execution-symbol-detected",
                                    remediation_ar="مجلد trading/ في nour-personal-ai-agent مخصص لقراءة بيانات السوق العامة فقط؛ يُحظر وجود منفّذ أوامر خارج مسار التداول.",
                                )
                            )

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            "repo_root": str(self.repo_root),
            "scanned_files": scanned_files,
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "clean": len(findings) == 0,
            "findings": [asdict(f) for f in findings],
        }


class TradingLaneReadOnlyAuditor:
    """
    Task (ب): Strictly READ-ONLY security auditor for `ops/bridge/` and `company/copy_follow.py`.
    Enforces Rule 1 (no code modification) and Rule 4 (no live trading / no withdrawals / no key leaks).
    """

    LIVE_ENDPOINT_RE = re.compile(
        r"""(?i)\b(?:api\.binance\.com|fapi\.binance\.com|api\.bybit\.com|www\.okx\.com|api\.kraken\.com|api\.coinbase\.com|live\.tradovateapi\.com)\b"""
    )
    WITHDRAW_RE = re.compile(
        r"""(?i)\b(?:withdraw|sapi/v1/capital/withdraw|asset/transfer|sub_account_transfer|enable_withdrawals|internal_transfer)\b"""
    )
    SECRET_LOG_RE = re.compile(
        r"""(?i)\b(?:logger\.(?:info|debug|warning|error|critical)|logging\.(?:info|debug|warning|error)|print)\s*\([^)]*(?:api_key|api_secret|secret|token|passphrase|signature|authorization|headers)[^)]*\)"""
    )
    INSECURE_HMAC_EQ_RE = re.compile(
        r"""(?i)(?:signature|hmac|digest|webhook_token|bridge_secret)\s*==\s*"""
    )
    LIVE_FLAG_RE = re.compile(
        r"""(?i)\b(?:testnet\s*=\s*False|sandbox\s*=\s*False|paper_trading\s*=\s*False|dry_run\s*=\s*False|LIVE_TRADING\s*=\s*True|MODE\s*=\s*['"]LIVE['"])"""
    )

    def __init__(self, trading_repo_root: Path):
        self.trading_repo_root = Path(trading_repo_root).resolve()

    def _snapshot_hashes(self) -> Dict[str, str]:
        snap: Dict[str, str] = {}
        if not self.trading_repo_root.exists():
            return snap
        for root, dirs, files in os.walk(self.trading_repo_root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in sorted(files):
                p = Path(root) / fname
                try:
                    snap[str(p.relative_to(self.trading_repo_root))] = hashlib.sha256(p.read_bytes()).hexdigest()
                except OSError:
                    continue
        return snap

    def audit_readonly(self, target_subpaths: Optional[List[str]] = None) -> Dict[str, object]:
        pre_snapshot = self._snapshot_hashes()
        targets = target_subpaths or ["ops/bridge", "company/copy_follow.py"]
        findings: List[AuditFinding] = []
        inspected_files: List[str] = []

        for rel_target in targets:
            target_path = (self.trading_repo_root / rel_target).resolve()
            if not str(target_path).startswith(str(self.trading_repo_root)) or not target_path.exists():
                continue

            candidate_files = [target_path] if target_path.is_file() else sorted(target_path.rglob("*"))
            for fpath in candidate_files:
                if not fpath.is_file() or fpath.suffix.lower() not in TEXT_EXTENSIONS:
                    continue
                rel_path = str(fpath.relative_to(self.trading_repo_root))
                inspected_files.append(rel_path)
                content = fpath.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                for idx, line in enumerate(lines, start=1):
                    # 1. Secret / Key hardcoding
                    for rule_id, sev, title_ar, pattern in SECRET_PATTERNS:
                        m = pattern.search(line)
                        if m:
                            findings.append(
                                AuditFinding(
                                    rule_id=f"TRD-{rule_id}",
                                    severity=sev,
                                    category="key-leakage",
                                    file_path=rel_path,
                                    line=idx,
                                    title_ar=f"تسريب مفتاح في مسار التداول: {title_ar}",
                                    evidence_redacted=_redact_fingerprint(m.group(0)),
                                    remediation_ar="إزالة المفتاح من الكود فوراً وتمريره حصراً عبر متغيرات بيئة الديمو المعزولة مع التدوير الفوري.",
                                )
                            )

                    # 2. Logging of keys/headers/signatures
                    if self.SECRET_LOG_RE.search(line):
                        findings.append(
                            AuditFinding(
                                rule_id="TRD-LOG-001",
                                severity="HIGH",
                                category="key-leakage",
                                file_path=rel_path,
                                line=idx,
                                title_ar="احتمال تسريب مفاتيح أو ترويسات مصادقة في السجلات (Logs)",
                                evidence_redacted="sensitive-identifier-in-log-statement",
                                remediation_ar="تطبيق فلتر تنقيح (Redaction Filter) يمنع طباعة الترويسات أو التواقيع أو المفاتيح في السجلات.",
                            )
                        )

                    # 3. Prohibited withdrawal / transfer calls (Rule 4)
                    if self.WITHDRAW_RE.search(line):
                        findings.append(
                            AuditFinding(
                                rule_id="TRD-WD-001",
                                severity="CRITICAL",
                                category="prohibited-withdrawal",
                                file_path=rel_path,
                                line=idx,
                                title_ar="استدعاء أو تعريف وظيفة سحب/تحويل أموال محظورة (مخالفة القاعدة 4)",
                                evidence_redacted="withdrawal-or-transfer-api-symbol",
                                remediation_ar="حذف أي مسار برمجي للسحب أو التحويل المالي نهائياً وحصر الصلاحيات بوضع الديمو/القراءة.",
                            )
                        )

                    # 4. Unblocked LIVE trading endpoints or flags (Rule 4)
                    if self.LIVE_ENDPOINT_RE.search(line) or self.LIVE_FLAG_RE.search(line):
                        findings.append(
                            AuditFinding(
                                rule_id="TRD-LIVE-001",
                                severity="CRITICAL",
                                category="live-trading-prohibited",
                                file_path=rel_path,
                                line=idx,
                                title_ar="إشارة لاتصال بحساب حقيقي (LIVE) أو تعطيل وضع الاختبار/الديمو (مخالفة القاعدة 4)",
                                evidence_redacted="live-endpoint-or-disabled-sandbox-flag",
                                remediation_ar="فرض قفل برمجي صلب (Hard Guard) يمنع الإقلاع إلا على بيئة DEMO/PAPER ويرفض عناوين الإنتاج الحقيقية.",
                            )
                        )

                    # 5. Non-constant-time signature check in bridge
                    if self.INSECURE_HMAC_EQ_RE.search(line) and "compare_digest" not in line:
                        findings.append(
                            AuditFinding(
                                rule_id="TRD-BRG-001",
                                severity="HIGH",
                                category="bridge-auth",
                                file_path=rel_path,
                                line=idx,
                                title_ar="مقارنة توقيع أو سر الجسر (Bridge) باستخدام == بدلاً من compare_digest",
                                evidence_redacted="non-constant-time-digest-comparison",
                                remediation_ar="استخدام hmac.compare_digest مع التحقق من الطابع الزمني (Timestamp/Nonce) لمنع هجمات التوقيت وإعادة الإرسال (Replay).",
                            )
                        )

                # AST check for missing timeout on network calls in Python files
                if fpath.suffix == ".py":
                    try:
                        tree = ast.parse(content)
                        for node in ast.walk(tree):
                            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                                if node.func.attr in {"get", "post", "put", "delete", "request"}:
                                    kw_names = {kw.arg for kw in node.keywords if kw.arg}
                                    if "timeout" not in kw_names:
                                        findings.append(
                                            AuditFinding(
                                                rule_id="TRD-NET-001",
                                                severity="MEDIUM",
                                                category="availability",
                                                file_path=rel_path,
                                                line=getattr(node, "lineno", 1),
                                                title_ar="طلب شبكي بدون مهلة زمنية صريحة (Missing timeout)",
                                                evidence_redacted=f"call={node.func.attr}(...) without timeout",
                                                remediation_ar="تحديد timeout صريح + مفتاح عدم تكرار الأمر (Idempotency Key) لمنع تعليق الجسر أو تكرار الصفقات الوهمية.",
                                            )
                                        )
                    except SyntaxError:
                        pass

        post_snapshot = self._snapshot_hashes()
        readonly_verified = pre_snapshot == post_snapshot

        return {
            "trading_repo_root": str(self.trading_repo_root),
            "targets": targets,
            "inspected_files": inspected_files,
            "readonly_integrity_verified": readonly_verified,
            "total_findings": len(findings),
            "findings": [asdict(f) for f in findings],
        }

    @staticmethod
    def render_github_issue_markdown(audit_result: Dict[str, object]) -> str:
        lines = [
            "# [Security Audit - Read Only] مراجعة أمنية لمسار التداول (`ops/bridge` + `company/copy_follow.py`)",
            "",
            "- **المُراجِع:** Arena 96 (`lane:cyber`)",
            "- **المُوجّه إليه:** المدير Arena 1994 (`المستَر/المدير`)",
            f"- **التحقق من عدم المساس بالكود (Read-Only SHA-256 Check):** `{audit_result['readonly_integrity_verified']}` (لم يُلمس أي ملف وفق القاعدة 1)",
            f"- **عدد الملفات المفحوصة:** `{len(audit_result['inspected_files'])}`",
            f"- **إجمالي الملاحظات الأمنية:** `{audit_result['total_findings']}`",
            "",
            "## جدول الملاحظات الأمنية (Findings)",
            "",
            "| المعرف | الخطورة | الملف والسطر | الوصف | التوصية الدفاعية لمالك المسار |",
            "| :---: | :---: | :--- | :--- | :--- |",
        ]
        for f in audit_result["findings"]:
            lines.append(
                f"| `{f['rule_id']}` | **{f['severity']}** | `{f['file_path']}:{f['line']}` | {f['title_ar']} (`{f['evidence_redacted']}`) | {f['remediation_ar']} |"
            )
        if not audit_result["findings"]:
            lines.append("| `-` | `CLEAN` | `-` | لا توجد مخالفات مكتشفة في الملفات المفحوصة | الاستمرار ببوابات الفحص الدوري |")
        return "\n".join(lines) + "\n"
