"""
Stage 52 Defensive Lab — Sovereign Intel Sharing: TLP Circles & Embargo Discipline
=====================================================================================
1. TLPSharingGate: intelligence moves only inside its Traffic Light
   Protocol circle — RED stays in the room, AMBER in the community,
   GREEN/WHITE travel. The label is enforced in code, not in cover letters.
2. EmbargoClock: coordinated disclosures stay sealed until the agreed
   minute; an eager share is a policy violation even to cleared eyes.
"""

from __future__ import annotations

from typing import Dict


class SharingViolation(Exception):
    """Raised when an intel-sharing rule is violated."""


_CIRCLE_RANK = {"room": 0, "community": 1, "sector": 2, "public": 3}
_TLP_MAX_CIRCLE = {"RED": "room", "AMBER": "community", "GREEN": "sector", "WHITE": "public"}


class TLPSharingGate:
    def evaluate(self, tlp: str, recipient_circle: str, now: int, embargo_until: int = 0) -> Dict[str, object]:
        if tlp not in _TLP_MAX_CIRCLE:
            raise SharingViolation(f"UNKNOWN_TLP_{tlp}")
        if now < embargo_until:
            return {"allowed": False, "state": "SHARE_DENIED_UNDER_EMBARGO"}
        if _CIRCLE_RANK[recipient_circle] > _CIRCLE_RANK[_TLP_MAX_CIRCLE[tlp]]:
            return {"allowed": False, "state": f"SHARE_DENIED_TLP_{tlp}_CIRCLE_EXCEEDED"}
        return {"allowed": True, "state": "SHARE_ALLOWED_WITHIN_TLP_CIRCLE"}
