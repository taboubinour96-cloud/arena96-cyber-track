"""
Scope & Safety Guardrail Engine (`ScopeGuard`).

Ensures the Cybersecurity Agent Branch operates strictly within local, authorized
source-code workspaces (White-Box Auditing). Blocks remote URLs, IP addresses,
network probing targets, and offensive action requests.
"""

from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Iterable, List
from urllib.parse import urlparse

from .models import AuditScope


class ScopeViolationError(ValueError):
    """Raised when an operation attempts to leave local white-box audit scope."""


_DISALLOWED_URL_SCHEMES = {"http", "https", "ftp", "ssh", "ws", "wss", "tcp", "udp"}

# Patterns indicating requests for offensive execution or payload generation
_DISALLOWED_TASK_KEYWORDS = re.compile(
    r"\b("
    r"generate\s+exploit|weaponize|reverse\s+shell|bind\s+shell|"
    r"sqlmap|metasploit|hydra\s+-|brute[\s-]?force|credential\s+stuffing|"
    r"exfiltrate|ransomware|keylogger"
    r")\b",
    re.IGNORECASE,
)


class ScopeGuard:
    """Validates targets and enforces read-only white-box source code auditing."""

    @staticmethod
    def validate_target_path(target: str) -> Path:
        if not target or not target.strip():
            raise ScopeViolationError("Target directory path cannot be empty.")

        cleaned = target.strip()

        # Reject URLs (e.g., https://company.com)
        parsed = urlparse(cleaned)
        if parsed.scheme.lower() in _DISALLOWED_URL_SCHEMES or parsed.netloc:
            raise ScopeViolationError(
                f"External URL or network target '{cleaned}' is not permitted. "
                "This branch strictly audits local source-code directories (White-Box SAST/SCA)."
            )

        # Reject bare IPv4/IPv6 addresses
        try:
            ipaddress.ip_address(cleaned)
            raise ScopeViolationError(
                f"IP address target '{cleaned}' is not permitted. Provide a local directory path."
            )
        except ValueError as exc:
            if isinstance(exc, ScopeViolationError):
                raise

        resolved = Path(cleaned).expanduser().resolve()
        if not resolved.exists():
            raise ScopeViolationError(f"Local target path does not exist: {resolved}")
        if not resolved.is_dir():
            raise ScopeViolationError(
                f"Target path must be a local project directory, got file: {resolved}"
            )

        # Prevent scanning sensitive OS system directories
        forbidden_roots = {Path("/etc"), Path("/proc"), Path("/sys"), Path("/dev"), Path("/boot")}
        for root in forbidden_roots:
            if resolved == root or root in resolved.parents:
                raise ScopeViolationError(
                    f"Auditing operating-system directory '{resolved}' is prohibited."
                )

        return resolved

    @staticmethod
    def validate_task_instruction(instruction: str) -> None:
        """Blocks requests asking the sub-agent to generate exploits or run attacks."""
        if instruction and _DISALLOWED_TASK_KEYWORDS.search(instruction):
            raise ScopeViolationError(
                "Task rejected by ScopeGuard: Offensive exploitation, payload generation, "
                "and active target probing are outside the permitted defensive audit scope."
            )

    @classmethod
    def iter_scoped_files(cls, scope: AuditScope) -> Iterable[Path]:
        """Safely enumerates source and configuration files inside the scoped directory."""
        root = cls.validate_target_path(scope.target_directory)
        exclude_set = set(scope.exclude_dirs)
        allowed_exts = {ext.lower() for ext in scope.include_extensions if ext.startswith(".")}
        allowed_names = {name for name in scope.include_extensions if not name.startswith(".")}

        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Prune excluded directories in-place (exclude `.git`, NOT `.github`!)
            dirnames[:] = [
                d for d in sorted(dirnames) if d not in exclude_set and d != ".git"
            ]
            for fname in sorted(filenames):
                fpath = Path(dirpath) / fname
                if fpath.is_symlink():
                    continue
                try:
                    size = fpath.stat().st_size
                except OSError:
                    continue
                if size > scope.max_file_size_bytes or size == 0:
                    continue

                ext = fpath.suffix.lower()
                if (
                    ext in allowed_exts
                    or fname in allowed_names
                    or fname.startswith("Dockerfile")
                    or fname in {"requirements.txt", "package.json", "go.mod", "Cargo.toml"}
                ):
                    yield fpath

    @staticmethod
    def list_scoped_files(scope: AuditScope) -> List[Path]:
        return list(ScopeGuard.iter_scoped_files(scope))
