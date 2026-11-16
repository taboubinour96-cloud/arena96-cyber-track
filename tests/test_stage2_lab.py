"""
Automated Verification Suite for Stage 2 Hands-On Lab (Arena 96 - Supervised by Noor).
"""

import secrets
import pytest

from study_academy.labs.stage2_secure_coding_and_api_lab import (
    HardenedTokenManager,
    SecureInvoiceRepository,
    TokenVerificationError,
    audit_c_source_memory_safety,
    audit_github_workflow_yaml,
)


def test_secure_sqlite_repository_parameterization_and_bola_guard() -> None:
    repo = SecureInvoiceRepository()
    inv_alice = repo.create_invoice(owner_user_id=101, title="Cloud Security Audit", amount_cents=250000)
    repo.create_invoice(owner_user_id=202, title="Internal SOC Retainer", amount_cents=500000)

    # Alice can read her own invoice
    fetched = repo.get_invoice_for_user(invoice_id=inv_alice, requesting_user_id=101)
    assert fetched is not None
    assert fetched["title"] == "Cloud Security Audit"

    # BOLA/IDOR Check: User 202 cannot access Alice's invoice #1!
    unauthorized = repo.get_invoice_for_user(invoice_id=inv_alice, requesting_user_id=202)
    assert unauthorized is None

    # Parameterized search treats special SQL characters strictly as literal data
    literal_search = repo.search_user_invoices(101, search_term="' OR 1=1 --", sort_by="amount_cents")
    assert literal_search == []

    # Disallowed ORDER BY column is rejected by allowlist
    with pytest.raises(ValueError):
        repo.search_user_invoices(101, search_term="Audit", sort_by="id; DROP TABLE invoices")


def test_hardened_token_manager_alg_pinning_and_signature() -> None:
    key = secrets.token_bytes(32)
    mgr = HardenedTokenManager(secret_key=key, issuer="arena96-auth")

    tok = mgr.issue_token(subject="user_42", role="auditor", ttl_seconds=600)
    claims = mgr.verify_token(tok)
    assert claims["sub"] == "user_42"
    assert claims["role"] == "auditor"

    # Tampered payload must fail constant-time signature verification
    h, p, s = tok.split(".")
    with pytest.raises(TokenVerificationError):
        mgr.verify_token(f"{h}.{p[:-2]}AA.{s}")

    # Expired token must be rejected
    with pytest.raises(TokenVerificationError):
        mgr.verify_token(tok, now_override=claims["exp"] + 1)


def test_c_memory_safety_and_github_workflow_auditors() -> None:
    c_code = """
    void greet(const char *input) {
        char buf[32];
        strcpy(buf, input);
        printf(buf);
    }
    """
    c_findings = audit_c_source_memory_safety(c_code)
    cwes = {f.cwe_id for f in c_findings}
    assert "CWE-120" in cwes
    assert "CWE-134" in cwes

    workflow = """
    steps:
      - uses: actions/checkout@v4
      - run: echo "PR Title is ${{ github.event.pull_request.title }}"
    """
    wf_issues = audit_github_workflow_yaml(workflow)
    assert len(wf_issues) == 2
