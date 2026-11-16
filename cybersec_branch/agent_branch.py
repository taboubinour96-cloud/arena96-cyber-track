"""
Main Sub-Agent Orchestrator & Tool Interface (`CyberSecAuditBranch`).

Provides both:
1. Direct Python API (`branch.run_full_audit(...)`)
2. Standard LLM Function-Calling / Agent Tool Schemas (`AGENT_TOOLS_SCHEMA` +
   `branch.dispatch_tool_call(...)`) so any parent AI Agent (OpenAI SDK, LangGraph,
   CrewAI, Anthropic, smolagents, vLLM/Ollama serving Foundation-Sec-8B or VulnLLM-R)
   can delegate white-box security code review tasks cleanly and safely.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from .ast_sast_engine import StaticCodeAuditor
from .config_iac_auditor import ConfigIaCAuditor
from .context_triage import ContextTriageEngine
from .cvss_calculator import calculate_cvss_v31
from .dependency_osv_auditor import DependencyOSVAuditor
from .models import AuditFinding, AuditScope, AuditSummaryReport, RouteEndpoint
from .report_builder import ReportBuilder
from .route_authz_mapper import RouteAuthzMapper
from .scope_guard import ScopeGuard

CYBERSEC_BRANCH_SYSTEM_PROMPT = """You are the Cybersecurity White-Box Code Audit Specialist Branch of an AI Agent.
Your mission is to assist security engineers and authorized bug bounty researchers in reviewing
local source code repositories, configurations, API route permissions, and software dependencies.

OPERATIONAL CONSTRAINTS:
1. Operate strictly on local authorized source-code directories (White-Box SAST, Authz Review, IaC/Config Audit, OSV Dependency CVE Audit).
2. Never generate weaponized exploit payloads, active network attacks, brute-force scripts, or unauthorized target scans.
3. Prioritize high-signal, verifiable code weaknesses: trace untrusted inputs from source to sink, inspect helper functions via `lookup_symbol_context` to eliminate false positives, and verify authorization guards on state-changing routes.
4. Always provide CWE IDs, OWASP Top 10 categories, accurate CVSS v3.1 scores, and behavior-preserving defensive code patches, reminding the human researcher to manually verify runtime reachability before submitting any bug bounty report.
"""


AGENT_TOOLS_SCHEMA: List[Dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "cybersec_audit_repository",
            "description": (
                "Run a comprehensive white-box security audit (Python AST taint/SAST, multi-language "
                "rules, HTTP route authorization mapping, Dockerfile/IaC/CORS/secret checks, OSV.dev "
                "dependency CVE lookup, and false-positive context triage) on a local repository path."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_directory": {
                        "type": "string",
                        "description": "Local filesystem path to the authorized source code repository.",
                    },
                    "program_name": {
                        "type": "string",
                        "description": "Name of the project or authorized audit scope.",
                    },
                    "enable_osv_lookup": {
                        "type": "boolean",
                        "description": "Whether to query OSV.dev for dependency CVEs (default true).",
                    },
                    "output_markdown_path": {
                        "type": "string",
                        "description": "Optional workspace file path to save the Markdown audit report.",
                    },
                    "output_sarif_path": {
                        "type": "string",
                        "description": "Optional workspace file path to save the SARIF 2.1.0 report.",
                    },
                },
                "required": ["target_directory"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cybersec_map_routes_and_authz",
            "description": (
                "Extract HTTP endpoints (FastAPI, Flask, Express.js) in a local directory and "
                "identify state-changing or sensitive routes missing authentication/authorization guards."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_directory": {
                        "type": "string",
                        "description": "Local filesystem path to the repository.",
                    }
                },
                "required": ["target_directory"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cybersec_lookup_symbol_context",
            "description": (
                "Retrieve the source code definition of a Python function/method across the indexed "
                "repository to verify whether input validation or sanitization occurs (false-positive check)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_directory": {
                        "type": "string",
                        "description": "Local filesystem path to the repository.",
                    },
                    "symbol_name": {
                        "type": "string",
                        "description": "Function or method name to inspect.",
                    },
                },
                "required": ["target_directory", "symbol_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cybersec_calculate_cvss_v31",
            "description": "Calculate exact FIRST CVSS v3.1 base score and severity from a CVSS:3.1 vector string.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cvss_vector": {
                        "type": "string",
                        "description": "CVSS v3.1 vector, e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'.",
                    }
                },
                "required": ["cvss_vector"],
            },
        },
    },
]


class CyberSecAuditBranch:
    """Modular Cybersecurity Auditing Sub-Agent ready to plug into any parent AI Agent."""

    def __init__(
        self,
        llm_base_url: Optional[str] = None,
        llm_api_key: Optional[str] = None,
        llm_model: Optional[str] = None,
    ) -> None:
        self.sast_auditor = StaticCodeAuditor()
        self.route_mapper = RouteAuthzMapper()
        self.config_auditor = ConfigIaCAuditor()
        self.dep_auditor = DependencyOSVAuditor()
        self.triage_engine = ContextTriageEngine(
            llm_base_url=llm_base_url,
            llm_api_key=llm_api_key,
            llm_model=llm_model,
        )

    def run_full_audit(
        self,
        scope: AuditScope,
        task_instruction: str = "",
        use_llm_triage: bool = False,
    ) -> AuditSummaryReport:
        """Executes the complete multi-stage defensive white-box security audit pipeline."""
        ScopeGuard.validate_task_instruction(task_instruction)
        root_dir = ScopeGuard.validate_target_path(scope.target_directory)
        files = ScopeGuard.list_scoped_files(scope)

        # Stage 1: Index repository symbols for cross-function context retrieval
        indexed_symbols = self.triage_engine.build_symbol_index(files, root_dir)

        all_findings: List[AuditFinding] = []
        all_routes: List[RouteEndpoint] = []

        # Stage 2: Run SAST, Route/Authz Mapping, and Config/IaC/Secret checks per file
        for fpath in files:
            all_findings.extend(self.sast_auditor.scan_file(fpath, root_dir))
            routes, authz_findings = self.route_mapper.analyze_file(fpath, root_dir)
            all_routes.extend(routes)
            all_findings.extend(authz_findings)
            all_findings.extend(self.config_auditor.scan_file(fpath, root_dir))

        # Stage 3: Supply-Chain Dependency CVE Audit via OSV.dev
        dep_findings = self.dep_auditor.audit_manifests(
            files, root_dir, enable_network=scope.enable_osv_network_lookup
        )
        all_findings.extend(dep_findings)

        # Deduplicate findings by finding_id
        deduped_map = {f.finding_id: f for f in all_findings}
        unique_findings = list(deduped_map.values())

        # Stage 4: Context-Aware False-Positive Triage
        triaged_findings = self.triage_engine.triage_findings(
            unique_findings, use_llm_if_configured=use_llm_triage
        )
        sorted_findings = ReportBuilder.sort_findings(triaged_findings)

        return AuditSummaryReport(
            program_name=scope.program_name,
            target_directory=str(root_dir),
            scanned_files_count=len(files),
            discovered_routes=all_routes,
            findings=sorted_findings,
            human_verification_required=True,
            methodology_notes=[
                f"Indexed {indexed_symbols} Python function definitions for cross-function sanitization context.",
                "Applied AST taint/sink checks, route authorization coverage analysis, IaC/CORS/secret hygiene rules, and OSV.dev advisory lookup.",
                "All findings are static/architectural candidates requiring human verification before external bug bounty submission.",
            ],
        )

    def dispatch_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Executes a tool call emitted by a parent LLM / Agent orchestrator."""
        if tool_name == "cybersec_audit_repository":
            scope = AuditScope(
                target_directory=arguments["target_directory"],
                program_name=arguments.get("program_name", "Authorized Repository Audit"),
                enable_osv_network_lookup=bool(arguments.get("enable_osv_lookup", True)),
            )
            report = self.run_full_audit(scope=scope)
            if arguments.get("output_markdown_path"):
                md_path = Path(arguments["output_markdown_path"]).expanduser().resolve()
                md_path.parent.mkdir(parents=True, exist_ok=True)
                md_path.write_text(ReportBuilder.to_markdown(report), encoding="utf-8")
            if arguments.get("output_sarif_path"):
                sarif_path = Path(arguments["output_sarif_path"]).expanduser().resolve()
                sarif_path.parent.mkdir(parents=True, exist_ok=True)
                sarif_path.write_text(
                    json.dumps(ReportBuilder.to_sarif(report), indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            return report.to_dict()

        if tool_name == "cybersec_map_routes_and_authz":
            scope = AuditScope(target_directory=arguments["target_directory"])
            root_dir = ScopeGuard.validate_target_path(scope.target_directory)
            files = ScopeGuard.list_scoped_files(scope)
            routes: List[Dict[str, Any]] = []
            unprotected: List[Dict[str, Any]] = []
            for fpath in files:
                eps, findings = self.route_mapper.analyze_file(fpath, root_dir)
                routes.extend([ep.__dict__ for ep in eps])
                unprotected.extend([f.to_dict() for f in findings])
            return {"discovered_routes": routes, "missing_authz_candidates": unprotected}

        if tool_name == "cybersec_lookup_symbol_context":
            scope = AuditScope(target_directory=arguments["target_directory"])
            root_dir = ScopeGuard.validate_target_path(scope.target_directory)
            files = ScopeGuard.list_scoped_files(scope)
            self.triage_engine.build_symbol_index(files, root_dir)
            defs = self.triage_engine.lookup_symbol(arguments["symbol_name"])
            return {
                "symbol_name": arguments["symbol_name"],
                "matches": [d.__dict__ for d in defs],
            }

        if tool_name == "cybersec_calculate_cvss_v31":
            score, severity = calculate_cvss_v31(arguments["cvss_vector"])
            return {
                "cvss_vector": arguments["cvss_vector"],
                "base_score": score,
                "severity": severity.value,
            }

        raise ValueError(f"Unknown cybersecurity branch tool: {tool_name}")
