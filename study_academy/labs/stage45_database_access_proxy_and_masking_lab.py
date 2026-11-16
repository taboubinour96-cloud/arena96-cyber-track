"""
Stage 45 Defensive Lab — Database Access Proxy: Query Policy, Row Scope & Masking
====================================================================================
1. QueryPolicyGuard: destructive statements without a WHERE clause and
   unscoped reads of tenant tables never reach the database.
2. ColumnMasking: sensitive values are masked by caller role — analysts get
   shapes, not secrets.
3. ExportLimiter: bulk export is a governed event with a hard row ceiling.
"""

from __future__ import annotations

from typing import Dict


class DatabaseViolation(Exception):
    """Raised when a database-access rule is violated."""


class DatabaseAccessProxy:
    _DESTRUCTIVE = {"DELETE", "UPDATE", "DROP", "TRUNCATE"}

    def evaluate_query(self, query: Dict[str, object]) -> Dict[str, object]:
        verb = str(query.get("verb", "")).upper()
        if verb in self._DESTRUCTIVE and not bool(query.get("has_where")):
            return {"allowed": False, "state": "DB_DENIED_DESTRUCTIVE_WITHOUT_WHERE"}
        if verb == "SELECT" and bool(query.get("tenant_scoped_table")) and not bool(query.get("owner_filter")):
            return {"allowed": False, "state": "DB_DENIED_TENANT_READ_WITHOUT_OWNER_FILTER"}
        rows = int(query.get("estimated_rows", 0))
        if rows > 10000:
            return {"allowed": False, "state": "DB_DENIED_EXPORT_ROW_CEILING_EXCEEDED"}
        return {"allowed": True, "state": "DB_QUERY_ALLOWED_GOVERNED"}

    @staticmethod
    def mask(value: str, classification: str, role: str) -> str:
        if classification in {"SECRET", "CONFIDENTIAL"} and role != "data_owner":
            if "@" in value:
                head, _, tail = value.partition("@")
                return (head[:2] + "***@" + tail) if len(head) > 2 else "***@" + tail
            return value[:2] + "***" if len(value) > 2 else "***"
        return value
