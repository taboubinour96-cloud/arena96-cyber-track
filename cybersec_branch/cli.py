"""
Command-Line Interface for testing and running `CyberSecAuditBranch` on a local directory.

Usage:
    python -m cybersec_branch.cli /path/to/local/repo --program "My App Audit" --out-dir ./audit_reports
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent_branch import CyberSecAuditBranch
from .models import AuditScope
from .report_builder import ReportBuilder
from .scope_guard import ScopeViolationError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="White-Box Cybersecurity Code Audit Branch (Defensive SAST, Authz, IaC & OSV SCA)"
    )
    parser.add_argument("target_directory", help="Path to local authorized source code directory")
    parser.add_argument("--program", default="Authorized Local Code Audit", help="Audit scope/program title")
    parser.add_argument("--out-dir", default="", help="Directory to export Markdown, JSON, and SARIF 2.1.0 reports")
    parser.add_argument("--no-osv", action="store_true", help="Disable online OSV.dev dependency lookup")
    parser.add_argument("--llm-triage", action="store_true", help="Enable optional LLM false-positive triage via CYBERSEC_LLM_BASE_URL")

    args = parser.parse_args(argv)

    scope = AuditScope(
        target_directory=args.target_directory,
        program_name=args.program,
        enable_osv_network_lookup=not args.no_osv,
    )

    branch = CyberSecAuditBranch()
    try:
        report = branch.run_full_audit(scope=scope, use_llm_triage=args.llm_triage)
    except ScopeViolationError as exc:
        print(f"[ScopeGuard Blocked] {exc}", file=sys.stderr)
        return 2

    md_output = ReportBuilder.to_markdown(report)

    if args.out_dir:
        out_path = Path(args.out_dir).expanduser().resolve()
        out_path.mkdir(parents=True, exist_ok=True)
        (out_path / "audit_report.md").write_text(md_output, encoding="utf-8")
        (out_path / "audit_report.json").write_text(
            ReportBuilder.to_json_string(report), encoding="utf-8"
        )
        (out_path / "audit_report.sarif.json").write_text(
            json.dumps(ReportBuilder.to_sarif(report), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        counts = report.counts_by_severity()
        print(
            f"Audit completed on {report.scanned_files_count} file(s). "
            f"Active findings: {len(report.active_findings())} {counts}. "
            f"Reports written to: {out_path}"
        )
    else:
        print(md_output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
