"""
Stage 53 Defensive Lab — Attack Paths & Privilege Escalation
============================================================
1. AttackPathAnalyzer: an identity graph is searched from a low-privilege
   foothold to any Tier-0 node. The answer is not "yes/no" alone but the
   exact list of edges that make the path, so the fix is provable.
2. choke_points(): which node removals cut EVERY path — the cheapest fix
   is the one that breaks the most routes, not the one that patches the
   loudest alert.
"""

from __future__ import annotations

from collections import deque
from typing import Dict, Iterable, List, Set, Tuple


class GraphViolation(Exception):
    """Raised when the identity graph is malformed."""


class AttackPathAnalyzer:
    """Finds routes from a foothold identity to Tier-0 assets."""

    def __init__(self, edges: Iterable[Tuple[str, str]]):
        self.adj: Dict[str, List[str]] = {}
        self.edges: List[Tuple[str, str]] = []
        for src, dst in edges:
            if src == dst:
                raise GraphViolation("SELF_LOOP_EDGE")
            self.adj.setdefault(src, []).append(dst)
            self.adj.setdefault(dst, [])
            self.edges.append((src, dst))
        for node in self.adj:
            self.adj[node] = sorted(set(self.adj[node]))

    def _bfs_path(self, start: str, targets: Set[str], blocked: Set[str]) -> List[str]:
        if start in blocked or not targets:
            return []
        prev: Dict[str, str] = {}
        seen = {start}
        q = deque([start])
        while q:
            node = q.popleft()
            if node in targets:
                path = [node]
                while path[-1] != start:
                    path.append(prev[path[-1]])
                return list(reversed(path))
            for nxt in self.adj.get(node, []):
                if nxt in blocked or nxt in seen:
                    continue
                seen.add(nxt)
                prev[nxt] = node
                q.append(nxt)
        return []

    def analyze(self, foothold: str, tier0: Iterable[str], blocked: Iterable[str] = ()) -> Dict[str, object]:
        tier0_set = set(tier0)
        if foothold not in self.adj:
            raise GraphViolation(f"UNKNOWN_FOOTHOLD_{foothold}")
        if not tier0_set:
            raise GraphViolation("NO_TIER0_DECLARED")
        path = self._bfs_path(foothold, tier0_set, set(blocked))
        if not path:
            return {"path_found": False, "path": [], "edges": [], "target": None,
                    "state": "NO_PATH_TO_TIER0"}
        edges = [(path[i], path[i + 1]) for i in range(len(path) - 1)]
        return {"path_found": True, "path": path, "edges": edges, "target": path[-1],
                "hop_count": len(edges), "state": "ATTACK_PATH_OPEN_TO_TIER0"}

    def choke_points(self, foothold: str, tier0: Iterable[str]) -> List[Dict[str, object]]:
        """Nodes whose removal closes every foothold->Tier-0 route."""
        tier0_set = set(tier0)
        base = self._bfs_path(foothold, tier0_set, set())
        if not base:
            return []
        # Only nodes that actually appear on a live route can be choke points,
        # and the Tier-0 target itself is never a valid "fix".
        candidates = sorted(set(base[1:]) - tier0_set)
        result: List[Dict[str, object]] = []
        for node in candidates:
            closed = not self._bfs_path(foothold, tier0_set, {node})
            if closed:
                result.append({"node": node, "cuts_all_paths": True,
                               "depth_on_path": base.index(node)})
        return result

    def privilege_escalation_edges(self, edge_weights: Dict[str, int]) -> List[Dict[str, object]]:
        """Rank dangerous edges (delegation, password reset, full control) by weight."""
        if not edge_weights:
            raise GraphViolation("NO_EDGE_WEIGHTS")
        out = []
        for edge in self.edges:
            key = f"{edge[0]}->{edge[1]}"
            weight = int(edge_weights.get(key, 0))
            if weight > 0:
                out.append({"edge": key, "weight": weight})
        return sorted(out, key=lambda e: (-e["weight"], e["edge"]))
