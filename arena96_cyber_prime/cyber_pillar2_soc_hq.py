"""
Cyber-Pillar #2 (Ordered Specialized Upgrade of Pillar #2):
Cyber-SOC & AppSec Autonomous Command HQ (`cyber_pillar2_soc_hq.py`)

Upgrades over standard `layer2_company_hq.py`:
  1. Cryptographic SHA-256 Hash-Chained Ledger (`verify_ledger_integrity()`) — tamper-evident!
  2. Dynamic DEFCON Readiness Level (1..5) & RBVM SLA Tracking (P0..P3).
  3. 10 Cyber Clearance Ranks (L1 Tier-1 Analyst -> L10 Principal Cyber Fellow).
  4. Optimistic Concurrency (`if_version`) + Sovereign Owner Gate for Noor.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

from arena96_os.layer2_company_hq import OptimisticLockError, format_12h_ar

TUNIS_TZ = ZoneInfo("Africa/Tunis")
CYBER_HQ_DATA_DIR = Path("/home/user/arena96_cyber_prime/data")
CYBER_BOARD_PATH = CYBER_HQ_DATA_DIR / "cyber_soc_board.json"

CYBER_CLEARANCE_RANKS = [
    (10, "زميل أمن سيبراني أعلى (Principal Fellow)", 1600),
    (9, "معماري دفاع سيبراني أول", 1250),
    (8, "قائد استجابة جنائية وعمليات SOC", 950),
    (7, "خبير تدقيق كود وهندسة اكتشاف", 700),
    (6, "قائد خلية أمنية", 500),
    (5, "مهندس أمن تطبيقات أول", 350),
    (4, "محلل تهديدات متخصص", 220),
    (3, "محلل استجابة مساعد", 120),
    (2, "مدقق أمني مبتدئ", 50),
    (1, "محلل مناوب متدرّب", 0),
]


def compute_cyber_rank(xp: int) -> Dict[str, Any]:
    for rank_num, title_ar, min_xp in CYBER_CLEARANCE_RANKS:
        if xp >= min_xp:
            return {"level": rank_num, "rank_ar": title_ar, "xp": xp}
    return {"level": 1, "rank_ar": "محلل مناوب متدرّب", "xp": xp}


def _hash_event(prev_hash: str, event_type: str, actor: str, summary: str, ts: str) -> str:
    payload = f"{prev_hash}|{event_type}|{actor}|{summary}|{ts}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class CyberSOCHQEngine:
    """Next-Gen Hash-Chained Cyber-SOC & AppSec HQ running in Arena 96's background."""

    def __init__(self, board_path: Path = CYBER_BOARD_PATH):
        self.board_path = board_path
        self._lock = threading.RLock()
        self.board_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.board_path.exists():
            self._init_board()

    def _init_board(self) -> None:
        genesis_prev = "0" * 64
        ts = datetime.now(TUNIS_TZ).isoformat()
        genesis_summary = "تفعيل مركز القيادة السيبراني المؤتمت (Cyber-SOC HQ) بسلسلة تجزئة SHA-256 غير قابلة للعبث."
        genesis_hash = _hash_event(genesis_prev, "GENESIS", "ciso-arena96", genesis_summary, ts)

        cells = [
            ("ciso-arena96", "أرينا 96 — المدير التنفيذي وقائد الأمن (CEO/CISO)", 820, "يشتغل", "قيادة إعادة التحليل الشامل وتطوير المنظومة إلى الجيل الثاني v2.0"),
            ("cell-ast-hunter", "خلية صيد الثغرات البرمجية (AST SAST v2.0)", 560, "فاضي", "فحص الكود المصدري ومسارات التفويض"),
            ("cell-supply-ai-guard", "خلية حراسة سلاسل التوريد ومهارات AI", 520, "فاضي", "فحص ملفات SKILL.md وتوليد CycloneDX SBOM"),
            ("cell-detection-sigma", "خلية هندسة الاكتشاف السلوكي (Sigma/SIEM)", 480, "فاضي", "تطوير قواعد الكشف السلوكي وتقليل الإنذارات الكاذبة"),
            ("cell-dfir-forensics", "خلية التحقيق الجنائي وسلسلة الحيازة", 490, "فاضي", "توثيق الأدلة التشفيرية وفحص سلامة السجلات"),
            ("cell-cyberswarm-wargame", "خلية التوأم الرقمي والمحاكاة القتالية (CyberSwarm-96)", 550, "فاضي", "محاكاة سلاسل القتل السيبرانية واختبار متانة الدفاعات"),
            ("cell-patch-hardening", "خلية هندسة الترقيعات والتصلب المعماري", 530, "فاضي", "بناء واختبار ترقيعات الجيل الثاني v2.0"),
        ]
        staff = []
        for cid, cname, xp, status, task in cells:
            staff.append(
                {
                    "id": cid,
                    "name_ar": cname,
                    "status": status,
                    "current_task": task,
                    **compute_cyber_rank(xp),
                    "updated_at_12h": format_12h_ar(),
                }
            )

        board = {
            "version": 1,
            "hq_title_ar": "مركز القيادة السيبراني المتطور — أرينا 96 (Cyber-Prime HQ)",
            "owner": "نور",
            "ciso_ceo": "أرينا 96",
            "defcon_level": 4,  # 5=Peace, 4=Elevated Vigilance, 3=High Readiness, 2=Active Containment, 1=Critical
            "updated_at_12h": format_12h_ar(),
            "cells": staff,
            "findings_sla_queue": [],
            "sovereign_needs": [],
            "hash_chained_ledger": [
                {
                    "seq": 1,
                    "event_type": "GENESIS",
                    "actor": "ciso-arena96",
                    "summary_ar": genesis_summary,
                    "timestamp_iso": ts,
                    "prev_hash": genesis_prev,
                    "entry_hash": genesis_hash,
                }
            ],
            "five_line_reports": [],
        }
        self.board_path.write_text(json.dumps(board, ensure_ascii=False, indent=2), encoding="utf-8")

    def read_board(self) -> Dict[str, Any]:
        with self._lock:
            return json.loads(self.board_path.read_text(encoding="utf-8"))

    def _commit(self, board: Dict[str, Any], event_type: str, actor: str, summary_ar: str, if_version: Optional[int] = None) -> Dict[str, Any]:
        with self._lock:
            current = json.loads(self.board_path.read_text(encoding="utf-8"))
            if if_version is not None and current["version"] != if_version:
                raise OptimisticLockError(f"Cyber-HQ version mismatch: expected {if_version}, got {current['version']}")
            last_entry = current["hash_chained_ledger"][-1]
            prev_hash = last_entry["entry_hash"]
            ts = datetime.now(TUNIS_TZ).isoformat()
            new_hash = _hash_event(prev_hash, event_type, actor, summary_ar, ts)
            board["hash_chained_ledger"] = current["hash_chained_ledger"] + [
                {
                    "seq": last_entry["seq"] + 1,
                    "event_type": event_type,
                    "actor": actor,
                    "summary_ar": summary_ar,
                    "timestamp_iso": ts,
                    "prev_hash": prev_hash,
                    "entry_hash": new_hash,
                }
            ]
            board["version"] = current["version"] + 1
            board["updated_at_12h"] = format_12h_ar()
            self.board_path.write_text(json.dumps(board, ensure_ascii=False, indent=2), encoding="utf-8")
            return board

    def verify_ledger_integrity(self) -> Dict[str, Any]:
        """Mathematically verifies every SHA-256 link in the Cyber-SOC operational ledger."""
        board = self.read_board()
        chain = board["hash_chained_ledger"]
        expected_prev = "0" * 64
        for entry in chain:
            if entry["prev_hash"] != expected_prev:
                return {"valid": False, "broken_at_seq": entry["seq"], "entries_checked": len(chain)}
            recomputed = _hash_event(
                entry["prev_hash"], entry["event_type"], entry["actor"], entry["summary_ar"], entry["timestamp_iso"]
            )
            if recomputed != entry["entry_hash"]:
                return {"valid": False, "broken_at_seq": entry["seq"], "entries_checked": len(chain)}
            expected_prev = entry["entry_hash"]
        return {"valid": True, "entries_checked": len(chain), "head_sha256": expected_prev}

    def log_cell_report(
        self,
        cell_id: str,
        done: str,
        artifacts: str,
        needs_owner: str = "لا شيء",
        blocked: str = "لا شيء",
        next_step: str = "مراقبة مستمرة",
    ) -> Dict[str, Any]:
        board = self.read_board()
        ver = board["version"]
        report_txt = (
            f"تم: {done}\n"
            f"الملفات / الروابط: {artifacts}\n"
            f"يحتاج المالك: {needs_owner}\n"
            f"متوقف: {blocked}\n"
            f"التالي: {next_step}"
        )
        rep = {
            "id": f"crep-{uuid.uuid4().hex[:8]}",
            "cell_id": cell_id,
            "formatted_5line": report_txt,
            "time_12h": format_12h_ar(),
        }
        board["five_line_reports"].insert(0, rep)
        for c in board["cells"]:
            if c["id"] == cell_id:
                c["xp"] += 15
                c.update(compute_cyber_rank(c["xp"]))
                c["status"] = "ينتظرك" if needs_owner != "لا شيء" else "فاضي"
                c["current_task"] = next_step
                c["updated_at_12h"] = format_12h_ar()
        self._commit(board, "CELL_REPORT", cell_id, done, if_version=ver)
        return rep

    def queue_sovereign_approval(self, cell_id: str, title_ar: str, details_ar: str, sla_tier: str = "P1") -> Dict[str, Any]:
        board = self.read_board()
        ver = board["version"]
        card = {
            "id": f"sov-{uuid.uuid4().hex[:8]}",
            "cell_id": cell_id,
            "sla_tier": sla_tier,
            "title_ar": title_ar,
            "details_ar": details_ar,
            "status": "ينتظر التفويض السيادي من نور",
            "created_at_12h": format_12h_ar(),
        }
        board["sovereign_needs"].insert(0, card)
        self._commit(board, "SOVEREIGN_GATE", cell_id, title_ar, if_version=ver)
        return card
