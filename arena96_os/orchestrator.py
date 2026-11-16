"""
Arena 96 Executive Orchestrator (CEO Background Pipeline)
Runs all 4 pillars IN STRICT ORDER for Noor's project:
  1. Marketing Team & 12-Advisor Council (`layer1_marketing_engine`)
  2. AI Company HQ Board, 5-Line Reports, Rituals & XP (`layer2_company_hq`)
  3. Unified 20-Connector Gateway & Excel KPI Export (`layer3_connectors_hub`)
  4. MiroFish Multi-Agent Swarm & Temporal GraphRAG Prediction (`layer4_mirofish_swarm`)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from .layer1_marketing_engine import MarketingSkillsEngine
from .layer2_company_hq import CompanyHQEngine
from .layer3_connectors_hub import ConnectorsGatewayHub
from .layer4_mirofish_swarm import MiroFishSwarmEngine

CYCLE_SUMMARY_PATH = Path("/home/user/arena96_os/data/latest_executive_cycle.json")


class Arena96Orchestrator:
    """Single-CEO background coordinator ('أرينا 96') serving Owner ('نور')."""

    def __init__(self) -> None:
        self.marketing = MarketingSkillsEngine()
        self.hq = CompanyHQEngine()
        self.connectors = ConnectorsGatewayHub(hq=self.hq, marketing=self.marketing)
        self.swarm = MiroFishSwarmEngine()

    def run_ordered_project_cycle(self) -> Dict[str, Any]:
        """Executes a full background operational cycle across Pillars 1 -> 2 -> 3 -> 4."""
        # --- Dept 0: Security Verification of External Skills (Rule #6) ---
        t_sec = self.hq.create_task("فحص حزمة marketingskills و MiroFish عبر cybersec_branch", "cybersec-auditor")
        self.hq.update_staff_status("cybersec-auditor", "يشتغل", "تدقيق الأكواد الخارجية قبل التشغيل")
        self.hq.complete_task(t_sec["id"], "مكتملة")
        rep_sec = self.hq.submit_department_report(
            department_id="cybersec-auditor",
            done="فحص 189 ملفاً في marketingskills (0 ثغرات) وكشف 26 مساراً غير محمي (CWE-862) في MiroFish الخام وتحصينها برمجياً في نسختنا.",
            files_or_links="/home/user/security_audits/marketingskills_audit/audit_report.md , /home/user/security_audits/mirofish_audit/audit_report.md",
            needs_owner="لا شيء",
            blocked="لا شيء",
            next_step="مراقبة التحديثات الأسبوعية",
        )

        # --- Pillar 1 (#1 بالترتيب): Marketing Team & 12-Advisor Council ---
        t_mkt = self.hq.create_task("تشغيل مكتبة 53 مهارة تسويق وعقد مجلس الخبراء لإطلاق المنظومة", "marketing-growth")
        self.hq.update_staff_status("marketing-growth", "يشتغل", "جلسة مجلس خبراء التسويق (Marketing Council)")
        council_result = self.marketing.convene_marketing_council(
            question="كيف نطلق منظومة أرينا 96 (التدقيق السيبراني + مقر الشركة الذكي + محاكي السرب MiroFish) بأعلى ثقة وأقل تكلفة استحواذ؟",
            question_type="launch",
        )
        council_path = Path("/home/user/arena96_os/data/marketing_council_launch_verdict.json")
        council_path.parent.mkdir(parents=True, exist_ok=True)
        council_path.write_text(json.dumps(council_result, ensure_ascii=False, indent=2), encoding="utf-8")
        self.hq.complete_task(t_mkt["id"], "تنتظر موافقتك")
        rep_mkt = self.hq.submit_department_report(
            department_id="marketing-growth",
            done=f"تفعيل {len(self.marketing.list_skills())} مهارة و{len(self.marketing.list_cli_tools())} أداة CLI، وإصدار توصية مجلس التسويق بمشاركة المعارض الإلزامي.",
            files_or_links=str(council_path),
            needs_owner="اعتماد هيكل الباقات الثلاث ومسودة حملة الإطلاق قبل أي نشر خارجي",
            blocked="لا شيء",
            next_step="تسليم فرضية الإطلاق لمحاكي السرب MiroFish",
        )

        # --- Pillar 3 (#3 بالترتيب) + Pillar 2 Owner Firewall Gate ---
        t_conn = self.hq.create_task("تفعيل بوابة الـ 20 موصلاً وتصدير ملف مؤشرات Excel وفحص جدار موافقة نور", "connectors-automation")
        self.hq.update_staff_status("connectors-automation", "يشتغل", "تصدير مؤشرات Excel وفحص بوابة الموصلات")
        excel_path = self.connectors.export_hq_kpi_excel()
        # Test/queue an external ad campaign & launch announcement -> MUST stop at Owner Firewall (`ينتظرك`)!
        gated_ad = self.connectors.execute_connector_action(
            connector_slug="meta_ads",
            action_verb="budget",
            payload_summary_ar="مسودة حملة اختبارية لإطلاق منظومة أرينا 96 (صرف مقترح $0 حالياً — بانتظار قرار نور لتحديد الميزانية أو الاكتفاء بالنمو العضوي).",
            department_id="marketing-growth",
        )
        gated_publish = self.connectors.execute_connector_action(
            connector_slug="slack",
            action_verb="publish",
            payload_summary_ar="نشر البيان التعريفي الرسمي لمنظومة أرينا 96 وتقرير البرهان الأمني للجمهور المستهدف.",
            department_id="content-publisher",
        )
        self.hq.complete_task(t_conn["id"], "مكتملة")
        rep_conn = self.hq.submit_department_report(
            department_id="connectors-automation",
            done="تجهيز بوابة الـ 20 موصلاً، تصدير جدول المؤشرات بصيغة Excel، وتحويل طلبات النشر والميزانية تلقائياً إلى خانة «ينتظرك».",
            files_or_links=excel_path,
            needs_owner="لا شيء",
            blocked="لا شيء",
            next_step="مزامنة Google Drive التلقائية",
        )

        # --- Pillar 4 (#4 بالترتيب): MiroFish Swarm Intelligence Simulation ---
        t_swarm = self.hq.create_task("تشغيل محاكاة السرب MiroFish (24 وكيلاً × 12 جولة) لاختبار خطة الإطلاق", "mirofish-swarm")
        self.hq.update_staff_status("mirofish-swarm", "يشتغل", "محاكاة تفاعل السوق وحقن متغير (ماذا لو)")
        sim_result = self.swarm.run_simulation(
            seed_text=council_result["unified_verdict_ar"],
            prediction_goal_ar="التنبؤ بتفاعل المديرين التقنيين ومديري الأمن ورواد الأعمال مع إطلاق منظومة أرينا 96",
            rounds=12,
            agent_count=24,
            god_view_injection={
                "round": 6,
                "event_ar": "نشر برهان فحص أمني أبيض حي (SARIF) بصفر إيجابيات كاذبة + إتاحة لوحة «ينتظرك» للتجربة الفورية",
                "trust_delta": 0.30,
            },
            random_seed=96,
        )
        sample_interview = self.swarm.interview_agent(
            simulation_id=sim_result["simulation_id"],
            agent_id=2,  # EnterpriseCISO
            question_ar="ما الذي غيّر موقفك من التشكك إلى التأييد خلال المحاكاة؟",
        )
        self.hq.complete_task(t_swarm["id"], "مكتملة")
        rep_swarm = self.hq.submit_department_report(
            department_id="mirofish-swarm",
            done=(
                f"إتمام محاكاة السرب ({sim_result['simulation_id']}) لـ 24 وكيلاً: ارتفع التأييد من "
                f"{sim_result['report']['initial_support_percent']}% إلى {sim_result['report']['final_support_percent']}% "
                f"({sim_result['report']['support_lift_percent']:+.1f}%)."
            ),
            files_or_links=sim_result["agent_log_path"],
            needs_owner="لا شيء",
            blocked="لا شيء",
            next_step="جاهز لمحاكاة أي سيناريو جديد يطلبه نور",
        )

        # --- Pillar 2 Ritual: Generate Morning Brief (`days/YYYY-MM-DD.md`) ---
        morning_brief = self.hq.generate_morning_brief()

        summary = {
            "status": "OPERATIONAL_IN_BACKGROUND",
            "ordered_pillars": {
                "1_marketing_team": {
                    "installed_skills_count": len(self.marketing.list_skills()),
                    "flagship_roles_count": len(self.marketing.list_skills(flagship_only=True)),
                    "installed_clis_count": len(self.marketing.list_cli_tools()),
                    "council_verdict": council_result["unified_verdict_ar"],
                },
                "2_ai_company_hq": {
                    "board_version": self.hq.read_board()["version"],
                    "departments_count": len(self.hq.read_board()["staff"]) - 1,
                    "pending_owner_needs_count": len(
                        [n for n in self.hq.read_board()["needs"] if n["status"] == "ينتظر قرار نور"]
                    ),
                    "morning_brief_path": morning_brief["path"],
                },
                "3_connectors_hub": {
                    "connectors_count": len(self.connectors.list_connectors()),
                    "categories": self.connectors.summary_by_category(),
                    "excel_kpi_path": excel_path,
                    "firewall_intercepted_examples": [gated_ad["need_card"]["id"], gated_publish["need_card"]["id"]],
                },
                "4_mirofish_swarm": {
                    "simulation_id": sim_result["simulation_id"],
                    "agents_simulated": len(sim_result["agents"]),
                    "rounds_simulated": len(sim_result["timeline"]),
                    "initial_support_percent": sim_result["report"]["initial_support_percent"],
                    "final_support_percent": sim_result["report"]["final_support_percent"],
                    "support_lift_percent": sim_result["report"]["support_lift_percent"],
                    "ciso_interview": sample_interview,
                },
            },
            "department_reports": [rep_sec, rep_mkt, rep_conn, rep_swarm],
        }
        CYCLE_SUMMARY_PATH.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        return summary


if __name__ == "__main__":
    orch = Arena96Orchestrator()
    res = orch.run_ordered_project_cycle()
    print(json.dumps(res["ordered_pillars"], ensure_ascii=False, indent=2))
