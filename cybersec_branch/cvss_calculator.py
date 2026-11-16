"""
Official FIRST CVSS v3.1 Base Score Calculator.

Computes exact CVSS v3.1 base scores and qualitative severity ratings so audit
reports adhere to professional vulnerability management standards (HackerOne,
Bugcrowd, GitHub Security Advisories, NIST NVD).
"""

from __future__ import annotations

import math
from typing import Dict, Tuple

from .models import Severity

_AV_WEIGHTS: Dict[str, float] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_WEIGHTS: Dict[str, float] = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED: Dict[str, float] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED: Dict[str, float] = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI_WEIGHTS: Dict[str, float] = {"N": 0.85, "R": 0.62}
_CIA_WEIGHTS: Dict[str, float] = {"H": 0.56, "L": 0.22, "N": 0.00}


def _roundup_cvss(value: float) -> float:
    """FIRST CVSS v3.1 Roundup function (rounds up to nearest tenth using integer arithmetic)."""
    int_input = round(value * 100000)
    if (int_input % 10000) == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def calculate_cvss_v31(vector: str) -> Tuple[float, Severity]:
    """
    Parses a CVSS:3.1 vector string and returns `(base_score, Severity)`.
    Example: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' -> (9.8, Severity.CRITICAL)
    """
    if not vector.startswith("CVSS:3.1/"):
        raise ValueError(f"Invalid CVSS v3.1 prefix: {vector}")

    parts = vector.split("/")[1:]
    metrics: Dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            raise ValueError(f"Malformed CVSS metric '{part}' in {vector}")
        k, v = part.split(":", 1)
        metrics[k] = v

    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = required - set(metrics.keys())
    if missing:
        raise ValueError(f"Missing CVSS v3.1 metrics {sorted(missing)} in {vector}")

    scope = metrics["S"]
    if scope not in {"U", "C"}:
        raise ValueError(f"Invalid Scope metric S:{scope}")

    av = _AV_WEIGHTS[metrics["AV"]]
    ac = _AC_WEIGHTS[metrics["AC"]]
    pr = (_PR_CHANGED if scope == "C" else _PR_UNCHANGED)[metrics["PR"]]
    ui = _UI_WEIGHTS[metrics["UI"]]
    c = _CIA_WEIGHTS[metrics["C"]]
    i = _CIA_WEIGHTS[metrics["I"]]
    a = _CIA_WEIGHTS[metrics["A"]]

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

    if impact <= 0:
        return 0.0, Severity.INFO

    exploitability = 8.22 * av * ac * pr * ui
    if scope == "U":
        base_score = _roundup_cvss(min(impact + exploitability, 10.0))
    else:
        base_score = _roundup_cvss(min(1.08 * (impact + exploitability), 10.0))

    return base_score, score_to_severity(base_score)


def score_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO
