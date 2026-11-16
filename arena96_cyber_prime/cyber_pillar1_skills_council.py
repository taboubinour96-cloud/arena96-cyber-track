"""
Cyber-Pillar #1 (Ordered Specialized Upgrade of Pillar #1):
CyberSkills-96 & 12-Seat Cyber Defense Council

Coexists alongside `layer1_marketing_engine.py` (which retains all 53 marketing skills),
adding Arena 96's proprietary library of 16 Cybersecurity Agent Skills, 8 zero-dependency
Cyber CLIs, and the 12-Seat Cyber Architecture & Defense Council (with mandatory Red-Team Dissenter).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

CYBER_SKILLS_ROOT = Path("/home/user/skills_library/cyberskills_96/skills")
CYBER_CLIS_ROOT = Path("/home/user/skills_library/cyberskills_96/clis")

CYBER_ADVISOR_SEATS: Dict[str, Dict[str, str]] = {
    "schneier-systems": {
        "name": "Bruce Schneier Lens",
        "title_ar": "مدرسة التفكير المنظومي وأشجار الهجوم (Schneier Lens)",
    },
    "anderson-economics": {
        "name": "Ross Anderson Lens",
        "title_ar": "مدرسة هندسة الأمن واقتصاديات الحوافز (Anderson Lens)",
    },
    "boneh-crypto": {
        "name": "Dan Boneh Lens",
        "title_ar": "مدرسة التشفير التطبيقي وسلامة الزمن والمفاتيح (Boneh Lens)",
    },
    "shostack-stride": {
        "name": "Adam Shostack Lens",
        "title_ar": "مدرسة نمذجة التهديدات STRIDE وحدود الثقة (Shostack Lens)",
    },
    "moussouris-cvd": {
        "name": "Katie Moussouris Lens",
        "title_ar": "مدرسة الإفصاح المسؤول وجودة الفرز البشري (Moussouris Lens)",
    },
    "roth-detection": {
        "name": "Florian Roth Lens",
        "title_ar": "مدرسة هندسة الكشف السلوكي Sigma/YARA (Roth Lens)",
    },
    "janca-appsec": {
        "name": "Tanya Janca Lens",
        "title_ar": "مدرسة أمن التطبيقات وبوابات DevSecOps (Janca Lens)",
    },
    "cloud-blast-radius": {
        "name": "Cloud Blast-Radius Lens",
        "title_ar": "مدرسة عزل الحاويات وتقليص نصف قطر الانفجار السحابي",
    },
    "kindervag-zerotrust": {
        "name": "John Kindervag Lens",
        "title_ar": "مدرسة معمارية الثقة المعدومة Zero Trust (Kindervag Lens)",
    },
    "sans-dfir-lead": {
        "name": "SANS DFIR Lead Lens",
        "title_ar": "مدرسة الاستجابة الجنائية وسلاسل التجزئة غير القابلة للعبث",
    },
    "owasp-genai-guard": {
        "name": "OWASP GenAI Guard Lens",
        "title_ar": "مدرسة أمن وكلاء الذكاء الاصطناعي ومكافحة حقن المهارات",
    },
    "red-team-dissenter": {
        "name": "Adversarial Red-Team Dissenter",
        "title_ar": "الفريق الأحمر المعارض الإلزامي (Red-Team Dissenter)",
    },
}

CYBER_COUNCIL_SEATING: Dict[str, List[str]] = {
    "code_audit_architecture": [
        "shostack-stride",
        "janca-appsec",
        "owasp-genai-guard",
        "boneh-crypto",
        "red-team-dissenter",
    ],
    "soc_and_detection": [
        "roth-detection",
        "sans-dfir-lead",
        "kindervag-zerotrust",
        "red-team-dissenter",
    ],
    "cloud_and_supply_chain": [
        "cloud-blast-radius",
        "janca-appsec",
        "schneier-systems",
        "red-team-dissenter",
    ],
}


@dataclass
class CyberSkillInfo:
    slug: str
    description_ar: str
    version: str
    standards: str
    mitre_technique: str
    skill_md_path: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CyberSkillsCouncilEngine:
    """Proprietary Cybersecurity Skills Router & 12-Seat Cyber Defense Council."""

    def __init__(self, skills_root: Path = CYBER_SKILLS_ROOT, clis_root: Path = CYBER_CLIS_ROOT):
        self.skills_root = skills_root
        self.clis_root = clis_root
        self._skills: Dict[str, CyberSkillInfo] = {}
        self.reload()

    def reload(self) -> Dict[str, CyberSkillInfo]:
        self._skills.clear()
        if not self.skills_root.exists():
            return self._skills
        for d in sorted(self.skills_root.iterdir()):
            md_path = d / "SKILL.md"
            if not d.is_dir() or not md_path.exists():
                continue
            txt = md_path.read_text(encoding="utf-8", errors="replace")
            desc_m = re.search(r'^description:\s*"(.+?)"', txt, re.MULTILINE)
            ver_m = re.search(r"^\s*version:\s*(.+)$", txt, re.MULTILINE)
            std_m = re.search(r'^\s*standards:\s*"(.+?)"', txt, re.MULTILINE)
            mitre_m = re.search(r'^\s*mitre_technique:\s*"(.+?)"', txt, re.MULTILINE)
            self._skills[d.name] = CyberSkillInfo(
                slug=d.name,
                description_ar=desc_m.group(1) if desc_m else d.name,
                version=ver_m.group(1).strip() if ver_m else "2.0.0",
                standards=std_m.group(1) if std_m else "NIST-CSF-2.0",
                mitre_technique=mitre_m.group(1) if mitre_m else "T1190",
                skill_md_path=str(md_path),
            )
        return self._skills

    def list_cyber_skills(self) -> List[Dict[str, Any]]:
        return [s.to_dict() for s in self._skills.values()]

    def list_cyber_clis(self) -> List[str]:
        if not self.clis_root.exists():
            return []
        return sorted(p.name for p in self.clis_root.glob("*.py"))

    def run_cyber_cli_dry_run(self, cli_name: str) -> Dict[str, Any]:
        clean = re.sub(r"[^a-z0-9_\.]", "", cli_name.lower())
        if not clean.endswith(".py"):
            clean += ".py"
        path = self.clis_root / clean
        if not path.exists():
            raise FileNotFoundError(f"Cyber CLI not found: {clean}")
        proc = subprocess.run([sys.executable, str(path), "--dry-run"], capture_output=True, text=True, timeout=10)
        return json.loads(proc.stdout.strip())

    def convene_cyber_defense_council(
        self,
        target_system: str,
        review_mode: str = "code_audit_architecture",
    ) -> Dict[str, Any]:
        """
        Convenes a 5-seat panel from the 12-Seat Cyber Defense Council, always seating the
        Adversarial Red-Team Dissenter to expose architectural blind spots for v2.0 upgrading!
        """
        seats = CYBER_COUNCIL_SEATING.get(review_mode, CYBER_COUNCIL_SEATING["code_audit_architecture"])
        advisors_dir = self.skills_root / "cyber-defense-council" / "references" / "advisors"

        reviews: List[Dict[str, Any]] = []
        for idx, adv_id in enumerate(seats, 1):
            meta = CYBER_ADVISOR_SEATS[adv_id]
            dossier_file = advisors_dir / f"{adv_id}.md"
            dossier_ok = dossier_file.exists()
            is_red_team = adv_id == "red-team-dissenter"

            if adv_id == "shostack-stride":
                finding = (
                    "نقطة تطوير #1 (حدود الثقة في المسارات): مخطط المسارات في النسخة الأولى يغطي FastAPI وFlask وExpress، "
                    "لكنه لا يفحص خوادم بايثون المعيارية BaseHTTPRequestHandler مثل hq_server.py! يجب ترقية RouteAuthzMapper فوراً."
                )
            elif adv_id == "owasp-genai-guard":
                finding = (
                    "نقطة تطوير #2 (أمن مهارات الوكلاء وسلاسل التوريد): نحن نستورد ملفات SKILL.md ومستودعات خارجية؛ "
                    "يجب إضافة كاشف لمحارف اليونيكود الخفية (Trojan Source Bidi CVE-2021-42574) وحقن البرومبت وأوامر curl|sh داخل المهارات."
                )
            elif adv_id == "janca-appsec":
                finding = (
                    "نقطة تطوير #3 (توسيع AST SAST وأنابيب CI/CD): يجب دعم كشف ثغرات ZipSlip (CWE-22)، "
                    "وطلبات الخادم المزورة SSRF (CWE-918)، وثغرة pull_request_target في مهام GitHub Actions، مع تصدير CycloneDX SBOM."
                )
            elif adv_id == "boneh-crypto":
                finding = (
                    "نقطة تطوير #4 (التشفير وسلامة السجلات): يجب كشف مقارنة التوكنات غير ثابتة الزمن (== بدل hmac.compare_digest — CWE-208)، "
                    "وترقية لوحة المقر لتعمل بسلسلة تجزئة SHA-256 تكشف أي عبث بالسجلات."
                )
            else:  # red-team-dissenter
                finding = (
                    "هجوم محاكى من الفريق الأحمر المعارض: لو أرسل مهاجم ترويسة Content-Length بحجم 500MB إلى خادم hq_server.py "
                    "أو أرسل مئات الطلبات المتتالية بدون حد معدل (Rate Limit) سيستنزف الذاكرة (CWE-400)! يجب فرض سقف حجم الطلب ومحدد معدل وترويسات أمان صارمة."
                )

            reviews.append(
                {
                    "seat": idx,
                    "advisor_id": adv_id,
                    "title_ar": meta["title_ar"],
                    "is_red_team_dissenter": is_red_team,
                    "dossier_verified": dossier_ok,
                    "architectural_finding_ar": finding,
                }
            )

        return {
            "council_name_ar": "مجلس حكماء الأمن السيبراني (Cyber Defense Council — 12 مدرسة هندسية)",
            "target_system": target_system,
            "review_mode": review_mode,
            "seated_experts": reviews,
            "upgrade_mandate_v2_ar": [
                "ترقية cybersec_branch إلى الإصدار v2.0 بدعم BaseHTTPRequestHandler، وكشف ZipSlip/SSRF/Timing-Attack، وفحص مهارات AI ضد Trojan-Source وحقن البرومبت، وفحص GitHub Actions، وربط MITRE ATT&CK وتوليد CycloneDX SBOM.",
                "ترقية خادم القيادة hq_server.py بسقف حجم الطلبات (MAX_BODY_BYTES = 64KB)، ومحدد معدل الطلبات (Rate Limiter)، وترويسات الحماية القياسية.",
                "اعتماد سلسلة التجزئة التشفيرية SHA-256 في سجل عمليات Cyber-SOC HQ لإثبات عدم القابلية للعبث.",
            ],
        }
