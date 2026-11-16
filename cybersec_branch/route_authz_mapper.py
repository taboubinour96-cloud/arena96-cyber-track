"""
Route & Authorization Coverage Mapper (`RouteAuthzMapper`).

Inspired by modern white-box code-audit agents (e.g., `code-audit-agent` & OWASP ASVS V4):
Discovers HTTP endpoints in FastAPI, Flask, and Express.js/TypeScript codebases, inspects
authentication decorators/dependencies/middleware, and flags state-changing or privileged
endpoints missing visible authorization guards (Broken Access Control - CWE-862 / OWASP A01).
"""

from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import List, Tuple

from .cvss_calculator import calculate_cvss_v31
from .models import AuditFinding, CodeLocation, Confidence, RouteEndpoint

_HTTP_METHODS = {"get", "post", "put", "delete", "patch"}
_SENSITIVE_PATH_TOKENS = (
    "admin",
    "user",
    "account",
    "billing",
    "payment",
    "export",
    "delete",
    "role",
    "permission",
    "config",
    "secret",
    "internal",
    "transfer",
)
_PUBLIC_PATH_ALLOWLIST = ("/health", "/healthz", "/ready", "/login", "/signup", "/register", "/docs", "/openapi")
_AUTH_KEYWORDS = (
    "auth",
    "login_required",
    "jwt",
    "token",
    "permission",
    "role",
    "current_user",
    "admin_required",
    "guard",
    "protect",
    "oauth",
    "apikey",
    "session",
)


def _route_finding_id(rel_path: str, line: int) -> str:
    h = hashlib.sha256(f"AUTHZ:{rel_path}:{line}".encode("utf-8")).hexdigest()[:8]
    return f"AUTHZ-{h.upper()}"


def _is_sensitive_unprotected_route(ep: RouteEndpoint) -> bool:
    if ep.has_auth_guard:
        return False
    lower_path = ep.route_path.lower()
    if any(lower_path.startswith(pub) or lower_path == pub for pub in _PUBLIC_PATH_ALLOWLIST):
        return False
    if ep.http_method.upper() in {"POST", "PUT", "DELETE", "PATCH"}:
        return True
    return any(tok in lower_path for tok in _SENSITIVE_PATH_TOKENS)


class RouteAuthzMapper:
    """Extracts web endpoints and flags missing function-level authorization candidates."""

    def analyze_file(
        self, file_path: Path, root_dir: Path
    ) -> Tuple[List[RouteEndpoint], List[AuditFinding]]:
        rel_path = str(file_path.relative_to(root_dir))
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return [], []

        ext = file_path.suffix.lower()
        lines = content.splitlines()
        routes: List[RouteEndpoint] = []

        if ext == ".py":
            routes.extend(self._extract_python_routes(content, rel_path))
        elif ext in {".js", ".ts"}:
            routes.extend(self._extract_express_routes(lines, rel_path))

        findings: List[AuditFinding] = []
        for ep in routes:
            if _is_sensitive_unprotected_route(ep):
                vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
                score, severity = calculate_cvss_v31(vector)
                start_idx = max(0, ep.line_number - 2)
                end_idx = min(len(lines), ep.line_number + 4)
                snippet = "\n".join(
                    f"{'>>' if (idx + 1) == ep.line_number else '  '} {idx + 1:4d} | {lines[idx]}"
                    for idx in range(start_idx, end_idx)
                )
                findings.append(
                    AuditFinding(
                        finding_id=_route_finding_id(rel_path, ep.line_number),
                        rule_id="AUTHZ-001",
                        title=(
                            f"Missing Visible Authentication/Authorization Guard on "
                            f"`{ep.http_method} {ep.route_path}`"
                        ),
                        category="AUTHZ",
                        cwe_id="CWE-862",
                        owasp_category="A01:2021 - Broken Access Control",
                        severity=severity,
                        confidence=Confidence.MEDIUM,
                        cvss_vector=vector,
                        cvss_score=score,
                        location=CodeLocation(
                            file_path=rel_path,
                            line_start=ep.line_number,
                            line_end=ep.line_number,
                            snippet=snippet,
                            function_name=ep.handler_name,
                        ),
                        description=(
                            f"{ep.framework} endpoint `{ep.http_method} {ep.route_path}` (handler `{ep.handler_name}`) "
                            "performs a state-changing or privileged operation without any detected authentication "
                            "decorator, dependency injection (`Depends`), or router-level security guard in this file."
                        ),
                        impact_summary=(
                            "If global middleware does not protect this route, unauthenticated or low-privileged "
                            "callers may invoke privileged actions or access unauthorized resources (IDOR / BFLA)."
                        ),
                        remediation=(
                            "Verify whether upstream router/middleware enforces authentication AND object-level "
                            "authorization. Prefer explicit per-route dependency guards (e.g., `Depends(require_role('admin'))` "
                            "in FastAPI or `@login_required` + ownership verification)."
                        ),
                        secure_code_example=(
                            '@router.delete("/users/{user_id}")\n'
                            "async def delete_user(user_id: int, actor: User = Depends(require_admin_user)):\n"
                            "    ..."
                        ),
                        references=["https://cwe.mitre.org/data/definitions/862.html"],
                    )
                )

        return routes, findings

    def _extract_python_routes(self, content: str, rel_path: str) -> List[RouteEndpoint]:
        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError:
            return []

        # Check if router itself was initialized with `dependencies=[Depends(...)]`
        router_level_auth = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                unparsed = ast.unparse(node).lower() if hasattr(ast, "unparse") else ""
                if "apirouter(" in unparsed and "dependencies=" in unparsed:
                    if any(k in unparsed for k in _AUTH_KEYWORDS):
                        router_level_auth = True

        endpoints: List[RouteEndpoint] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            auth_found: List[str] = ["router_dependencies"] if router_level_auth else []
            route_info: List[Tuple[str, str, str]] = []

            # Inspect decorators
            for dec in node.decorator_list:
                dec_text = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                dec_lower = dec_text.lower()
                if any(k in dec_lower for k in _AUTH_KEYWORDS):
                    auth_found.append(dec_text)

                if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                    attr = dec.func.attr.lower()
                    route_path = "/"
                    if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(
                        dec.args[0].value, str
                    ):
                        route_path = dec.args[0].value

                    if attr in _HTTP_METHODS:
                        route_info.append(("FastAPI/Flask", attr.upper(), route_path))
                    elif attr == "route":
                        methods = ["GET"]
                        for kw in dec.keywords:
                            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                                extracted = [
                                    elt.value.upper()
                                    for elt in kw.value.elts
                                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                                ]
                                if extracted:
                                    methods = extracted
                        for m in methods:
                            route_info.append(("Flask", m, route_path))

            # Inspect FastAPI function signature defaults (e.g. `user = Depends(get_current_user)`)
            sig_text = ""
            if hasattr(ast, "unparse"):
                sig_text = ast.unparse(node.args).lower()
            if any(k in sig_text for k in _AUTH_KEYWORDS):
                auth_found.append("signature_dependency")

            # v2.0 Upgrade: Detect Python BaseHTTPRequestHandler methods (`do_GET`, `do_POST`, etc.)
            if node.name in {"do_GET", "do_POST", "do_PUT", "do_DELETE", "do_PATCH"}:
                http_m = node.name.split("_", 1)[1].upper()
                body_src = (ast.unparse(node) if hasattr(ast, "unparse") else "").lower()
                if any(g in body_src for g in ("compare_digest", "_verify_csrf", "verify_token", "authorization", "x-arena96-token")):
                    auth_found.append("handler_token_guard")
                route_info.append(("BaseHTTPRequestHandler", http_m, f"/{node.name.lower()}"))

            for fw, method, rpath in route_info:
                endpoints.append(
                    RouteEndpoint(
                        file_path=rel_path,
                        line_number=node.lineno,
                        framework=fw,
                        http_method=method,
                        route_path=rpath,
                        handler_name=node.name,
                        auth_mechanisms=auth_found,
                        has_auth_guard=bool(auth_found),
                    )
                )

        return endpoints

    @staticmethod
    def _extract_express_routes(lines: List[str], rel_path: str) -> List[RouteEndpoint]:
        pattern = re.compile(
            r"\b(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['\"`]([^'\"`]+)['\"`](.*)"
        )
        endpoints: List[RouteEndpoint] = []
        for idx, line in enumerate(lines, start=1):
            match = pattern.search(line)
            if not match:
                continue
            method = match.group(1).upper()
            rpath = match.group(2)
            rest = match.group(3).lower()
            auths = [k for k in _AUTH_KEYWORDS if k in rest]
            endpoints.append(
                RouteEndpoint(
                    file_path=rel_path,
                    line_number=idx,
                    framework="Express.js",
                    http_method=method,
                    route_path=rpath,
                    handler_name=f"line_{idx}_handler",
                    auth_mechanisms=auths,
                    has_auth_guard=bool(auths),
                )
            )
        return endpoints
