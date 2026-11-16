from pathlib import Path
from cybersec_branch.lane_cyber_auditors import SecretAndCharterAuditor, TradingLaneReadOnlyAuditor


def test_secret_and_charter_auditor_redacts_secrets_and_enforces_rule5(tmp_path: Path):
    # Create a mock nour-personal-ai-agent structure with intentional violations
    (tmp_path / ".env").write_text("API_KEY=something\n", encoding="utf-8")
    (tmp_path / "agent.py").write_text(
        'TOKEN = "ghp_' + ("A" * 36) + '"\n',
        encoding="utf-8",
    )
    trading_dir = tmp_path / "trading"
    trading_dir.mkdir()
    (trading_dir / "illegal_executor.py").write_text(
        "def run():\n    return client.place_order('BTCUSDT', 'BUY', 1)\n",
        encoding="utf-8",
    )

    result = SecretAndCharterAuditor(tmp_path).scan()
    assert result["total_findings"] >= 3
    rule_ids = {f["rule_id"] for f in result["findings"]}
    assert "SEC-ENV-001" in rule_ids
    assert "SEC-001" in rule_ids
    assert "CHARTER-R5" in rule_ids

    # Ensure raw token is NEVER emitted in findings (Rule 3)
    serialized = str(result)
    assert "ghp_" + ("A" * 36) not in serialized
    assert "<REDACTED:sha256:" in serialized


def test_trading_lane_readonly_auditor_detects_risks_without_modifying_files(tmp_path: Path):
    bridge_dir = tmp_path / "ops" / "bridge"
    company_dir = tmp_path / "company"
    bridge_dir.mkdir(parents=True)
    company_dir.mkdir(parents=True)

    (bridge_dir / "server.py").write_text(
        "import logging\n"
        "def verify(signature, expected, api_secret):\n"
        "    logging.info(f'checking {api_secret}')\n"
        "    if signature == expected:\n"
        "        return True\n",
        encoding="utf-8",
    )
    (company_dir / "copy_follow.py").write_text(
        "import requests\n"
        "BASE = 'https://api.binance.com'\n"
        "def sync_trade():\n"
        "    requests.post(BASE + '/sapi/v1/capital/withdraw/apply')\n",
        encoding="utf-8",
    )

    auditor = TradingLaneReadOnlyAuditor(tmp_path)
    report = auditor.audit_readonly(["ops/bridge", "company/copy_follow.py"])

    assert report["readonly_integrity_verified"] is True
    rule_ids = {f["rule_id"] for f in report["findings"]}
    assert "TRD-LOG-001" in rule_ids
    assert "TRD-BRG-001" in rule_ids
    assert "TRD-LIVE-001" in rule_ids
    assert "TRD-WD-001" in rule_ids
    assert "TRD-NET-001" in rule_ids

    md = auditor.render_github_issue_markdown(report)
    assert "Read-Only SHA-256 Check" in md
    assert "`True`" in md
