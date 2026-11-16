"""
Layer 2 (Ordered Pillar #2): AI Company HQ — Shared Live Board, CEO Bus, XP Levels & Owner Gate
Source Architecture: https://www.nadr.ai/ai-company-hq/

Runs the entire AI Company HQ natively inside Arena 96's background:
  - CEO single-point-of-contact: أرينا 96 (reporting exclusively to Owner: نور)
  - Shared atomic database with optimistic concurrency (`if_version`):
      staff, events, tasks, needs ("ينتظرك")
  - 7 strict Arabic employee statuses
  - 10-level XP progression engine
  - 5-line standardized department report parser & validator
  - Scheduled Rituals generator (12-hour Africa/Tunis format, read/report only)
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

TUNIS_TZ = ZoneInfo("Africa/Tunis")
HQ_DATA_DIR = Path("/home/user/arena96_os/data")
HQ_BOARD_PATH = HQ_DATA_DIR / "hq_board.json"
DAYS_DIR = Path("/home/user/days")

VALID_STAFF_STATUSES = {
    "يشتغل",
    "فاضي",
    "ينتظرك",
    "ينتظر قسم",
    "متوقف",
    "في اجتماع",
    "يتعلّم",
}

SENSITIVE_OWNER_ONLY_ACTIONS = {
    "publish",
    "send_email",
    "spend_budget",
    "payment",
    "change_settings",
    "credentials",
}

LEVEL_THRESHOLDS = [
    (10, "أسطورة", 1600),
    (9, "أستاذ", 1250),
    (8, "رئيس", 950),
    (7, "خبير", 700),
    (6, "قائد", 500),
    (5, "أول", 350),
    (4, "متخصص", 220),
    (3, "مساعد", 120),
    (2, "مبتدئ", 50),
    (1, "متدرّب", 0),
]


def format_12h_ar(dt: Optional[datetime] = None) -> str:
    """Formats timestamp in 12-hour Arabic clock (e.g. '9:30 ص' or '8:15 م') per board-protocol.md."""
    now = (dt or datetime.now(TUNIS_TZ)).astimezone(TUNIS_TZ)
    hour24 = now.hour
    suffix = "ص" if hour24 < 12 else "م"
    hour12 = hour24 % 12
    if hour12 == 0:
        hour12 = 12
    return f"{hour12}:{now.minute:02d} {suffix}"


def compute_level(xp: int) -> Dict[str, Any]:
    for level_num, title_ar, min_xp in LEVEL_THRESHOLDS:
        if xp >= min_xp:
            next_xp = None
            for higher_num, _, higher_min in reversed(LEVEL_THRESHOLDS):
                if higher_num == level_num + 1:
                    next_xp = higher_min
                    break
            return {"level": level_num, "title_ar": title_ar, "xp": xp, "next_level_xp": next_xp}
    return {"level": 1, "title_ar": "متدرّب", "xp": xp, "next_level_xp": 50}


class OptimisticLockError(RuntimeError):
    """Raised when `if_version` does not match the current board version."""


class SecretLeakBlockedError(ValueError):
    """Raised if someone attempts to write raw API keys or secrets onto the shared HQ board."""


SECRET_PATTERNS = ("sk-ant-", "sk-proj-", "AIzaSy", "ghp_", "xoxb-", "BEGIN PRIVATE KEY")


def _guard_no_secrets(payload: Any) -> None:
    serialized = json.dumps(payload, ensure_ascii=False)
    for pat in SECRET_PATTERNS:
        if pat in serialized:
            raise SecretLeakBlockedError(f"Blocked potential secret pattern ({pat}) from shared HQ board!")


class CompanyHQEngine:
    """Thread-safe Shared Office Board & CEO Governance Bus for Arena 96."""

    def __init__(self, board_path: Path = HQ_BOARD_PATH):
        self.board_path = board_path
        self._lock = threading.RLock()
        self.board_path.parent.mkdir(parents=True, exist_ok=True)
        DAYS_DIR.mkdir(parents=True, exist_ok=True)
        if not self.board_path.exists():
            self._initialize_board()

    def _initialize_board(self) -> None:
        initial_staff = [
            {
                "id": "ceo-arena96",
                "name_ar": "أرينا 96 (المدير التنفيذي)",
                "department": "الإدارة التنفيذية العليا",
                "role_type": "CEO",
                "status": "يشتغل",
                "current_task": "تنسيق الأقسام الخلفية الستة ورفع الخلاصة للمالك (نور)",
                "xp": 720,
                **compute_level(720),
                "clean_deliveries": 6,
                "jd_path": "team/README.md",
                "updated_at_12h": format_12h_ar(),
            },
            {
                "id": "cybersec-auditor",
                "name_ar": "حارس — الأمن السيبراني والتدقيق",
                "department": "الأمن السيبراني والتدقيق الأبيض",
                "role_type": "DEPARTMENT",
                "status": "فاضي",
                "current_task": "جاهز لفحص الأكواد والمهارات",
                "xp": 540,
                **compute_level(540),
                "clean_deliveries": 7,
                "jd_path": "team/jd/cybersec-auditor.md",
                "updated_at_12h": format_12h_ar(),
            },
            {
                "id": "research-trends",
                "name_ar": "راصد — البحث والترندات",
                "department": "البحث واستخبارات السوق",
                "role_type": "DEPARTMENT",
                "status": "فاضي",
                "current_task": "متابعة ترندات الأمن والذكاء الاصطناعي",
                "xp": 240,
                **compute_level(240),
                "clean_deliveries": 4,
                "jd_path": "team/jd/research-trends.md",
                "updated_at_12h": format_12h_ar(),
            },
            {
                "id": "marketing-growth",
                "name_ar": "نماء — التسويق ومجلس الخبراء (53 مهارة)",
                "department": "التسويق والنمو",
                "role_type": "DEPARTMENT",
                "status": "فاضي",
                "current_task": "تشغيل مكتبة الـ 53 مهارة ومجلس التسويق",
                "xp": 360,
                **compute_level(360),
                "clean_deliveries": 5,
                "jd_path": "team/jd/marketing-growth.md",
                "updated_at_12h": format_12h_ar(),
            },
            {
                "id": "connectors-automation",
                "name_ar": "رابط — بوابة الـ 20 موصلاً والأتمتة",
                "department": "الموصلات والأتمتة السحابية",
                "role_type": "DEPARTMENT",
                "status": "فاضي",
                "current_task": "إدارة Google Drive وبوابة الموصلات المحمية",
                "xp": 370,
                **compute_level(370),
                "clean_deliveries": 6,
                "jd_path": "team/jd/connectors-automation.md",
                "updated_at_12h": format_12h_ar(),
            },
            {
                "id": "mirofish-swarm",
                "name_ar": "عراف السرب — محرك التنبؤ MiroFish",
                "department": "محاكاة السرب والتنبؤ الاستراتيجي",
                "role_type": "DEPARTMENT",
                "status": "فاضي",
                "current_task": "بناء المخططات المعرفية ومحاكاة القرارات",
                "xp": 380,
                **compute_level(380),
                "clean_deliveries": 5,
                "jd_path": "team/jd/mirofish-swarm.md",
                "updated_at_12h": format_12h_ar(),
            },
            {
                "id": "content-publisher",
                "name_ar": "بيان — الكتابة والإخراج المشروط",
                "department": "التوثيق والإخراج والنشر",
                "role_type": "DEPARTMENT",
                "status": "فاضي",
                "current_task": "تجهيز التقارير والمسودات لمراجعة المالك",
                "xp": 260,
                **compute_level(260),
                "clean_deliveries": 5,
                "jd_path": "team/jd/content-publisher.md",
                "updated_at_12h": format_12h_ar(),
            },
        ]
        board = {
            "version": 1,
            "company_name": "مقر شركة نور وأرينا 96 للذكاء السيبراني والتنبؤي",
            "owner": "نور",
            "ceo": "أرينا 96",
            "timezone": "Africa/Tunis",
            "updated_at_12h": format_12h_ar(),
            "staff": initial_staff,
            "tasks": [],
            "events": [
                {
                    "id": f"evt-{uuid.uuid4().hex[:8]}",
                    "type": "boot",
                    "actor_id": "ceo-arena96",
                    "summary_ar": "تأسيس مقر الشركة وتفعيل الأقسام الخلفية الستة وبروتوكول اللوحة الحيّة.",
                    "time_12h": format_12h_ar(),
                }
            ],
            "needs": [],
            "recent_reports": [],
        }
        self.board_path.write_text(json.dumps(board, ensure_ascii=False, indent=2), encoding="utf-8")

    def read_board(self) -> Dict[str, Any]:
        with self._lock:
            return json.loads(self.board_path.read_text(encoding="utf-8"))

    def _write_board(self, board: Dict[str, Any], if_version: Optional[int] = None) -> Dict[str, Any]:
        _guard_no_secrets(board)
        with self._lock:
            current = json.loads(self.board_path.read_text(encoding="utf-8"))
            if if_version is not None and current["version"] != if_version:
                raise OptimisticLockError(
                    f"Version conflict: expected if_version={if_version}, actual={current['version']}"
                )
            board["version"] = current["version"] + 1
            board["updated_at_12h"] = format_12h_ar()
            self.board_path.write_text(json.dumps(board, ensure_ascii=False, indent=2), encoding="utf-8")
            return board

    def update_staff_status(
        self,
        staff_id: str,
        status: str,
        task_title: str = "",
        if_version: Optional[int] = None,
    ) -> Dict[str, Any]:
        if status not in VALID_STAFF_STATUSES:
            raise ValueError(f"Invalid staff status '{status}'. Allowed: {sorted(VALID_STAFF_STATUSES)}")
        board = self.read_board()
        ver = if_version if if_version is not None else board["version"]
        found = False
        for member in board["staff"]:
            if member["id"] == staff_id:
                member["status"] = status
                if task_title:
                    member["current_task"] = task_title
                member["updated_at_12h"] = format_12h_ar()
                found = True
                break
        if not found:
            raise KeyError(f"Unknown staff_id: {staff_id}")
        board["events"].insert(
            0,
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "type": "status_change",
                "actor_id": staff_id,
                "summary_ar": f"تحديث حالة «{staff_id}» إلى «{status}» — {task_title}",
                "time_12h": format_12h_ar(),
            },
        )
        board["events"] = board["events"][:80]
        return self._write_board(board, if_version=ver)

    def create_task(self, title_ar: str, department_id: str, stage: str = "شغّالة") -> Dict[str, Any]:
        board = self.read_board()
        ver = board["version"]
        task = {
            "id": f"tsk-{uuid.uuid4().hex[:8]}",
            "title_ar": title_ar,
            "department_id": department_id,
            "stage": stage,  # جاهزة | شغّالة | تنتظر موافقتك | مكتملة | متوقفة
            "created_at_12h": format_12h_ar(),
            "updated_at_12h": format_12h_ar(),
        }
        board["tasks"].insert(0, task)
        self._write_board(board, if_version=ver)
        return task

    def complete_task(self, task_id: str, stage: str = "مكتملة") -> None:
        board = self.read_board()
        ver = board["version"]
        for t in board["tasks"]:
            if t["id"] == task_id:
                t["stage"] = stage
                t["updated_at_12h"] = format_12h_ar()
                break
        self._write_board(board, if_version=ver)

    def request_owner_approval(
        self,
        department_id: str,
        action_category: str,
        title_ar: str,
        details_ar: str,
        artifact_path: str = "",
    ) -> Dict[str, Any]:
        """
        Enforces HQ Rule #3: External publishing, sending, spending, payments, settings, or secrets
        NEVER auto-execute. Creates a card in `needs` ('ينتظرك') and marks department 'ينتظرك'.
        """
        if action_category not in SENSITIVE_OWNER_ONLY_ACTIONS:
            action_category = "publish"
        board = self.read_board()
        ver = board["version"]
        need_card = {
            "id": f"need-{uuid.uuid4().hex[:8]}",
            "department_id": department_id,
            "action_category": action_category,
            "title_ar": title_ar,
            "details_ar": details_ar,
            "artifact_path": artifact_path,
            "status": "ينتظر قرار نور",
            "owner_quote": None,
            "created_at_12h": format_12h_ar(),
        }
        board["needs"].insert(0, need_card)
        for member in board["staff"]:
            if member["id"] == department_id:
                member["status"] = "ينتظرك"
                member["current_task"] = f"ينتظر قرار نور: {title_ar}"
                member["updated_at_12h"] = format_12h_ar()
        board["events"].insert(
            0,
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "type": "owner_gate",
                "actor_id": department_id,
                "summary_ar": f"رفع طلب إلى خانة «ينتظرك» لموافقة نور: {title_ar}",
                "time_12h": format_12h_ar(),
            },
        )
        self._write_board(board, if_version=ver)
        return need_card

    def resolve_owner_need(self, need_id: str, decision: str, exact_owner_quote: str) -> Dict[str, Any]:
        """Resolves a pending item in `needs` only with an explicit quoted decision from Noor."""
        if not exact_owner_quote.strip():
            raise ValueError("Owner approval/rejection requires quoting Noor's explicit words verbatim.")
        board = self.read_board()
        ver = board["version"]
        resolved_card = None
        for card in board["needs"]:
            if card["id"] == need_id:
                card["status"] = "تمت الموافقة" if decision == "approve" else "مرفوض من المالك"
                card["owner_quote"] = exact_owner_quote.strip()
                card["resolved_at_12h"] = format_12h_ar()
                resolved_card = card
                break
        if not resolved_card:
            raise KeyError(f"Need card not found: {need_id}")

        dept_id = resolved_card["department_id"]
        for member in board["staff"]:
            if member["id"] == dept_id:
                if decision == "approve":
                    member["xp"] += 15  # +15 XP for zero-edit owner approval!
                    lvl = compute_level(member["xp"])
                    member.update(lvl)
                member["status"] = "فاضي"
                member["updated_at_12h"] = format_12h_ar()
        self._write_board(board, if_version=ver)
        return resolved_card

    @staticmethod
    def build_five_line_report(
        done: str,
        files_or_links: str,
        needs_owner: str = "لا شيء",
        blocked: str = "لا شيء",
        next_step: str = "فاضي",
    ) -> str:
        return (
            f"تم: {done}\n"
            f"الملفات / الروابط: {files_or_links}\n"
            f"يحتاج المالك: {needs_owner}\n"
            f"متوقف: {blocked}\n"
            f"التالي: {next_step}"
        )

    def submit_department_report(
        self,
        department_id: str,
        done: str,
        files_or_links: str,
        needs_owner: str = "لا شيء",
        blocked: str = "لا شيء",
        next_step: str = "فاضي",
        checklist_passed_first_try: bool = True,
    ) -> Dict[str, Any]:
        """Submits standardized 5-line report to the CEO (أرينا 96) and awards +10 XP on clean checklist."""
        formatted = self.build_five_line_report(done, files_or_links, needs_owner, blocked, next_step)
        board = self.read_board()
        ver = board["version"]

        report_entry = {
            "id": f"rep-{uuid.uuid4().hex[:8]}",
            "department_id": department_id,
            "done": done,
            "files_or_links": files_or_links,
            "needs_owner": needs_owner,
            "blocked": blocked,
            "next_step": next_step,
            "formatted_5line": formatted,
            "time_12h": format_12h_ar(),
        }
        board["recent_reports"].insert(0, report_entry)
        board["recent_reports"] = board["recent_reports"][:40]

        for member in board["staff"]:
            if member["id"] == department_id:
                if checklist_passed_first_try:
                    member["xp"] += 10
                    member["clean_deliveries"] += 1
                    member.update(compute_level(member["xp"]))
                if needs_owner != "لا شيء":
                    member["status"] = "ينتظرك"
                elif blocked != "لا شيء":
                    member["status"] = "متوقف"
                else:
                    member["status"] = "فاضي"
                    member["current_task"] = next_step
                member["updated_at_12h"] = format_12h_ar()

        board["events"].insert(
            0,
            {
                "id": f"evt-{uuid.uuid4().hex[:8]}",
                "type": "report",
                "actor_id": department_id,
                "summary_ar": f"تقرير خماسي إلى المدير التنفيذي: {done}",
                "time_12h": format_12h_ar(),
            },
        )
        self._write_board(board, if_version=ver)
        return report_entry

    def generate_morning_brief(self, date_str: Optional[str] = None) -> Dict[str, Any]:
        """Executes the 8:00 AM Scheduled Ritual (read/report only, max 3 owner items + fallback plan)."""
        today = date_str or datetime.now(TUNIS_TZ).strftime("%Y-%m-%d")
        board = self.read_board()
        pending_needs = [n for n in board["needs"] if n["status"] == "ينتظر قرار نور"][:3]

        lines = [
            f"# ملخص الصباح التنفيذي — {today} (الساعة {format_12h_ar()})",
            "",
            f"- **المالك:** {board['owner']}  |  **المدير التنفيذي:** {board['ceo']}",
            "- **تنبيه الحوكمة:** هذا التقرير قراءة وتلخيص فقط (ممنوع النشر أو الإرسال أو الصرف التلقائي).",
            "",
            "## 1. القرارات المطلوبة من نور اليوم (بحد أقصى 3 أشياء)",
        ]
        if pending_needs:
            for idx, item in enumerate(pending_needs, 1):
                lines.append(f"{idx}. **{item['title_ar']}** ({item['department_id']}) — {item['details_ar']}")
        else:
            lines.append("1. لا توجد قرارات معلقة حالياً؛ جميع الأقسام تسير تلقائياً في الخلفية.")

        lines.extend(["", "## 2. خطة كل قسم اليوم بسطر واحد"])
        for member in board["staff"]:
            lines.append(
                f"- **{member['name_ar']}** [المستوى {member['level']} · {member['title_ar']} · الحالة: `{member['status']}`]: {member['current_task']}"
            )

        lines.extend(
            [
                "",
                "## 3. الخطة البديلة ليوم مزدحم أو طارئ",
                "- في حال انشغال نور اليوم: تستمر الأقسام الخلفية في الفحص الأمني وتحديث الأرشيف المحلي وسجل Google Drive وتجميد أي نشر خارجي في خانة «ينتظرك» دون أي مخاطرة.",
                "",
            ]
        )
        out_path = DAYS_DIR / f"{today}.md"
        content = "\n".join(lines)
        out_path.write_text(content, encoding="utf-8")
        return {"date": today, "path": str(out_path), "pending_owner_decisions_count": len(pending_needs), "markdown": content}
