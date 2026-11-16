"""
Stage 36 Extension Lab — Third-Party System Tool Assessment (O&O AppBuster class)
================================================================================
An "uninstaller-class" utility is high-impact: it runs with admin rights and
rewrites system state. This lab does not model the tool itself, it models the
*decision to admit it*:

1. ToolAdmissionGate: a third-party tool enters the estate only if its source
   is official, its binary signature verifies, its digest is pinned, its scope
   is minimal, and a rollback point exists first.
2. BaselineRevalidation: stripping system components changes the baseline that
   posture/drift detection measures against, so a new baseline is mandatory —
   otherwise every later drift finding is noise.
3. RemovalImpactPlanner: removing a runtime that other software depends on
   opens an unpatched attack path, so dependency-bearing packages are refused.
"""

from __future__ import annotations

from typing import Dict, Iterable, List


class ToolPolicyViolation(Exception):
    """Raised when a tool assessment request is malformed."""


OFFICIAL_DOMAINS = {"oo-software.com", "oo-software.de"}


def _is_official(domain: str) -> bool:
    """Vendor-owned domain or any of its subdomains (dl5.oo-software.com is
    the vendor's own download host, not a third-party mirror)."""
    return any(domain == d or domain.endswith("." + d) for d in OFFICIAL_DOMAINS)
PROTECTED_PACKAGES = {
    "microsoft.webview2",
    "microsoft.vclibs.140.00",
    "microsoft.net.native.runtime",
    "microsoft.windowsstore",
    "microsoft.sechealthui",
    "microsoft.windows.defender",
}


class ToolAdmissionGate:
    """Admit a debloat/uninstaller tool only under five hard conditions."""

    def evaluate(self, tool: Dict[str, object]) -> Dict[str, object]:
        problems: List[str] = []

        source = str(tool.get("source_url", ""))
        domain = source.split("//")[-1].split("/")[0].lower()
        if not source.startswith("https://") or not _is_official(domain):
            problems.append("SOURCE_NOT_OFFICIAL_HTTPS_DOMAIN")

        if not tool.get("signature_valid"):
            problems.append("BINARY_SIGNATURE_INVALID")
        if not str(tool.get("sha256", "")).strip():
            problems.append("DIGEST_NOT_PINNED")
        if str(tool.get("run_as", "")) != "jit_admin":
            problems.append("PRIVILEGE_NOT_TIME_BOXED")
        if not tool.get("restore_point_confirmed"):
            problems.append("NO_ROLLBACK_POINT")
        if tool.get("scope") not in {"current_user", "all_users", "device"}:
            problems.append("UNKNOWN_SCOPE")

        admitted = not problems
        return {
            "admitted": admitted,
            "problems": problems,
            "scope": tool.get("scope"),
            "state": "TOOL_ADMITTED_WITH_CONTROLS" if admitted else "TOOL_DENIED",
        }


class BaselineRevalidation:
    """After a state-changing utility runs, the baseline must be re-captured."""

    def __init__(self, baseline_id: str, captured_at: int):
        if not baseline_id:
            raise ToolPolicyViolation("MISSING_BASELINE_ID")
        self.baseline_id = baseline_id
        self.captured_at = captured_at

    def evaluate(self, change_at: int, recaptured_at: int | None) -> Dict[str, object]:
        if change_at < self.captured_at:
            raise ToolPolicyViolation("CHANGE_PREDATES_BASELINE")
        if recaptured_at is None:
            return {"valid": False, "state": "BASELINE_STALE_AFTER_SYSTEM_CHANGE"}
        if recaptured_at < change_at:
            return {"valid": False, "state": "BASELINE_RECAPTURE_PREDATES_CHANGE"}
        return {"valid": True, "recaptured_at": recaptured_at,
                "state": "BASELINE_REVALIDATED"}


class RemovalImpactPlanner:
    """Refuse removals that break dependants or strip protected runtimes."""

    def __init__(self, dependants: Dict[str, Iterable[str]]):
        self.dependants = {pkg: sorted(set(deps)) for pkg, deps in dependants.items()}

    def plan(self, requested: Iterable[str]) -> Dict[str, object]:
        protected = sorted({p for p in requested if p.lower() in PROTECTED_PACKAGES})
        breaking = sorted({p for p in requested if self.dependants.get(p)})
        safe = sorted({p for p in requested
                       if p.lower() not in PROTECTED_PACKAGES and not self.dependants.get(p)})
        approved = not protected and not breaking
        return {
            "safe_to_remove": safe,
            "refused_protected": protected,
            "refused_breaks_dependants": breaking,
            "dependants_at_risk": {p: self.dependants[p] for p in breaking},
            "plan_approved": approved,
            "state": "REMOVAL_PLAN_APPROVED" if approved else "REMOVAL_PLAN_PARTIALLY_REFUSED",
        }


class DebloatEvidenceRecord:
    """The tool's own lack of an exportable log is closed here, in the estate."""

    def __init__(self):
        self.events: List[Dict[str, object]] = []

    def record(self, tool: str, version: str, digest: str, removed: Iterable[str],
               kept_protected: Iterable[str], restore_point: str) -> Dict[str, object]:
        if not tool or not version or not digest:
            raise ToolPolicyViolation("INCOMPLETE_EVIDENCE_RECORD")
        if not restore_point:
            raise ToolPolicyViolation("EVIDENCE_WITHOUT_RESTORE_POINT")
        event = {
            "tool": tool, "version": version, "digest": digest,
            "removed": sorted(set(removed)),
            "kept_protected": sorted(set(kept_protected)),
            "restore_point": restore_point,
            "seq": len(self.events) + 1,
        }
        self.events.append(event)
        return {"recorded": True, "seq": event["seq"], "state": "DEBLOAT_EVIDENCE_RECORDED"}

    def audit_trail(self) -> Dict[str, object]:
        return {"events": len(self.events), "tools": sorted({e["tool"] for e in self.events}),
                "state": "EVIDENCE_TRAIL_COMPLETE" if self.events else "NO_EVIDENCE_RECORDED"}
