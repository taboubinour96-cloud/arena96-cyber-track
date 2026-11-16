"""
Stage 29 Defensive Lab — DMARC Alignment, BEC Risk & OAuth Consent Governance
================================================================================
1. DMARCAlignmentEvaluator:
   - SPF/DKIM identifier alignment against the visible From domain and the
     domain's DMARC policy (none/quarantine/reject) -> deterministic delivery
     action. Misaligned spoofing fails closed under enforcing policies.
2. BECRiskScorer:
   - Business-email-compromise heuristics: executive display-name impersonation
     from a foreign domain, Reply-To mismatch, look-alike sender domains and
     payment-urgency language, combined into triage bands.
3. OAuthConsentRiskAnalyzer:
   - Scores third-party OAuth grants by scope danger, publisher trust and
     offline access; high-risk consent requires admin approval (consent-phish
     defense).
"""

from __future__ import annotations

from typing import Dict, List, Tuple


class MailTrustViolation(Exception):
    """Raised when a mail/collaboration trust rule is violated."""


def _org_domain(domain: str) -> str:
    parts = domain.strip().lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def _edit_distance(a: str, b: str) -> int:
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        prev, dp[0] = dp[0], i
        for j, cb in enumerate(b, 1):
            prev, dp[j] = dp[j], min(dp[j] + 1, dp[j - 1] + 1, prev + (ca != cb))
    return dp[len(b)]


class DMARCAlignmentEvaluator:
    def evaluate(self, *, from_domain: str, spf_result: str, spf_domain: str,
                 dkim_result: str, dkim_domain: str, dmarc_policy: str) -> Dict[str, object]:
        spf_aligned = spf_result == "pass" and _org_domain(spf_domain) == _org_domain(from_domain)
        dkim_aligned = dkim_result == "pass" and _org_domain(dkim_domain) == _org_domain(from_domain)
        dmarc_pass = bool(spf_aligned or dkim_aligned)
        if dmarc_pass:
            action = "DELIVER_DMARC_PASS"
        elif dmarc_policy == "reject":
            action = "REJECT_DMARC_FAIL_POLICY_REJECT"
        elif dmarc_policy == "quarantine":
            action = "QUARANTINE_DMARC_FAIL_POLICY_QUARANTINE"
        elif dmarc_policy == "none":
            action = "DELIVER_BUT_TAGGED_DMARC_MONITOR_ONLY"
        else:
            raise MailTrustViolation(f"UNKNOWN_DMARC_POLICY_{dmarc_policy}")
        return {"spf_aligned": spf_aligned, "dkim_aligned": dkim_aligned,
                "dmarc_pass": dmarc_pass, "action": action}


class BECRiskScorer:
    _URGENCY = ["urgent wire", "gift cards", "confidential transfer", "pay today",
                "تحويل عاجل", "سرّي للغاية"]

    def __init__(self, protected_domains: List[str], executive_names: List[str]) -> None:
        self.protected = [d.lower() for d in protected_domains]
        self.executives = [n.lower() for n in executive_names]

    def score(self, *, display_name: str, from_domain: str, reply_to_domain: str, subject_body: str) -> Dict[str, object]:
        score = 0
        signals: List[str] = []
        from_org = _org_domain(from_domain)
        if display_name.lower() in self.executives and from_org not in self.protected:
            score += 40
            signals.append("EXECUTIVE_DISPLAY_NAME_FROM_FOREIGN_DOMAIN")
        if _org_domain(reply_to_domain) != from_org:
            score += 25
            signals.append("REPLY_TO_DOMAIN_MISMATCH")
        for protected in self.protected:
            if from_org != protected and _edit_distance(from_org, protected) == 1:
                score += 25
                signals.append(f"LOOKALIKE_DOMAIN_OF_{protected}")
        low = subject_body.lower()
        if any(k in low for k in self._URGENCY):
            score += 15
            signals.append("PAYMENT_URGENCY_LANGUAGE")
        band = "critical" if score >= 60 else "high" if score >= 40 else "review" if score >= 20 else "low"
        return {"risk_score": score, "band": band, "signals": signals}


class OAuthConsentRiskAnalyzer:
    _SCOPE_RISK = {
        "mail.read": 30, "mail.send": 25, "files.readwrite.all": 30, "offline_access": 20,
        "contacts.read": 10, "calendar.read": 10, "profile": 2, "openid": 2,
    }

    def analyze(self, *, app_name: str, publisher_verified: bool, scopes: List[str]) -> Dict[str, object]:
        unknown = [s for s in scopes if s not in self._SCOPE_RISK]
        if unknown:
            raise MailTrustViolation(f"UNKNOWN_OAUTH_SCOPE_{unknown[0]}")
        score = sum(self._SCOPE_RISK[s] for s in scopes)
        if not publisher_verified:
            score += 15
        if "offline_access" in scopes and any(s in scopes for s in ("mail.read", "files.readwrite.all")):
            score += 15  # persistent + data access = classic consent-phish prize
        if score >= 60:
            decision = "DENY_OR_REQUIRE_ADMIN_APPROVAL"
        elif score >= 35:
            decision = "REQUIRE_ADMIN_APPROVAL"
        else:
            decision = "ALLOW_USER_CONSENT"
        return {"app": app_name, "risk_score": score, "decision": decision, "scopes": sorted(scopes)}
