"""
Stage 26 Defensive Lab — Kubernetes Admission, RBAC Escalation Graph & Runtime Allowlist
============================================================================================
1. AdmissionPolicyEngine:
   - Deny-by-default admission: privileged containers, host namespaces,
     run-as-root, writable root filesystems and unpinned registries are
     rejected before a workload ever schedules.
2. RBACPrivilegeGraph:
   - Builds who-can-do-what paths and finds privilege-escalation routes to
     cluster-admin / secret-read / pod-exec powers.
3. RuntimeAllowlistMonitor:
   - Compares live runtime events (process, file write, outbound network)
     against the workload's declared profile; every deviation is a violation.
"""

from __future__ import annotations

from collections import deque
from typing import Dict, List, Set, Tuple


class CloudNativeViolation(Exception):
    """Raised when a cloud-native policy rule is violated."""


class AdmissionPolicyEngine:
    def __init__(self, allowed_registries: List[str]) -> None:
        self.allowed_registries = list(allowed_registries)

    def admit(self, pod: Dict[str, object]) -> Tuple[bool, str]:
        spec = pod.get("spec", {})  # type: ignore[assignment]
        if spec.get("hostNetwork") or spec.get("hostPID") or spec.get("hostIPC"):
            return False, "ADMISSION_DENIED_HOST_NAMESPACE"
        for container in spec.get("containers", []):  # type: ignore[union-attr]
            sc = container.get("securityContext", {})
            if sc.get("privileged"):
                return False, "ADMISSION_DENIED_PRIVILEGED_CONTAINER"
            if sc.get("runAsUser") == 0 or sc.get("runAsNonRoot") is not True:
                return False, "ADMISSION_DENIED_ROOT_USER_REQUIRED_NONROOT"
            if sc.get("readOnlyRootFilesystem") is not True:
                return False, "ADMISSION_DENIED_WRITABLE_ROOT_FS"
            if sc.get("allowPrivilegeEscalation") is not False:
                return False, "ADMISSION_DENIED_PRIVILEGE_ESCALATION_ALLOWED"
            image = str(container.get("image", ""))
            registry = image.split("/")[0] if "/" in image else "docker.io"
            if registry not in self.allowed_registries:
                return False, f"ADMISSION_DENIED_UNPINNED_REGISTRY_{registry}"
            if ":" not in image.split("/")[-1] or image.endswith(":latest"):
                return False, "ADMISSION_DENIED_UNPINNED_IMAGE_TAG"
        return True, "ADMISSION_ALLOWED_POLICY_COMPLIANT"


class RBACPrivilegeGraph:
    POWERFUL = {"secrets:read_all", "pods:exec", "cluster-admin", "nodes:proxy"}

    def __init__(self) -> None:
        self.grants: Dict[str, Set[str]] = {}
        self.bindings: Dict[str, Set[str]] = {}

    def grant_role(self, role: str, permission: str) -> None:
        self.grants.setdefault(role, set()).add(permission)

    def bind(self, subject: str, role: str) -> None:
        self.bindings.setdefault(subject, set()).add(role)

    def effective_permissions(self, subject: str) -> Set[str]:
        perms: Set[str] = set()
        for role in self.bindings.get(subject, set()):
            perms |= self.grants.get(role, set())
        return perms

    def escalation_report(self) -> List[Dict[str, object]]:
        report = []
        for subject in sorted(self.bindings):
            powerful = sorted(self.effective_permissions(subject) & self.POWERFUL)
            if powerful:
                report.append({"subject": subject, "powerful_permissions": powerful,
                               "risk": "PRIVILEGE_ESCALATION_CAPABLE"})
        return report

    def can_reach(self, subject: str, target_permission: str) -> Tuple[bool, List[str]]:
        # BFS over subject -> role -> permission (plus role-inheritance edges via bindings of roles as subjects)
        queue = deque([(subject, [subject])])
        seen = {subject}
        while queue:
            node, path = queue.popleft()
            perms = self.grants.get(node, set()) if node in self.grants else self.effective_permissions(node)
            if target_permission in perms:
                return True, path + [target_permission]
            for role in self.bindings.get(node, set()):
                if role not in seen:
                    seen.add(role)
                    queue.append((role, path + [role]))
        return False, []


class RuntimeAllowlistMonitor:
    def __init__(self, profile: Dict[str, object]) -> None:
        self.allowed_processes = set(profile.get("processes", []))  # type: ignore[arg-type]
        self.allowed_write_prefixes = list(profile.get("write_prefixes", []))  # type: ignore[arg-type]
        self.allowed_egress = set(profile.get("egress_hosts", []))  # type: ignore[arg-type]

    def check_event(self, event: Dict[str, object]) -> Tuple[bool, str]:
        kind = event.get("kind")
        if kind == "process":
            if event.get("process") not in self.allowed_processes:
                return False, f"RUNTIME_VIOLATION_UNLISTED_PROCESS_{event.get('process')}"
        elif kind == "file_write":
            path = str(event.get("path", ""))
            if not any(path.startswith(p) for p in self.allowed_write_prefixes):
                return False, f"RUNTIME_VIOLATION_WRITE_OUTSIDE_PROFILE_{path}"
        elif kind == "network":
            if event.get("host") not in self.allowed_egress:
                return False, f"RUNTIME_VIOLATION_EGRESS_NOT_ALLOWLISTED_{event.get('host')}"
        else:
            return False, f"RUNTIME_VIOLATION_UNKNOWN_EVENT_KIND_{kind}"
        return True, "RUNTIME_EVENT_WITHIN_PROFILE"
