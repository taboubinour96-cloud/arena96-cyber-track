"""
Automated Verification Suite for Arena 96's 4 Background Pillars (Applied in Order):
  1. Pillar #1: Marketing Team (53 Skills + 12-Advisor Council + 66 CLIs)
  2. Pillar #2: AI Company HQ (CEO, Team Handbook, JDs, Optimistic Lock `if_version`, XP, Owner Gate)
  3. Pillar #3: Unified 20-Connector Gateway & Excel KPI Export + Owner Firewall
  4. Pillar #4: MiroFish Swarm Intelligence & Temporal GraphRAG Engine + Agent Interview
"""

from pathlib import Path
import pytest

from arena96_os.layer1_marketing_engine import MarketingSkillsEngine
from arena96_os.layer2_company_hq import (
    CompanyHQEngine,
    OptimisticLockError,
    SecretLeakBlockedError,
)
from arena96_os.layer3_connectors_hub import ConnectorsGatewayHub
from arena96_os.layer4_mirofish_swarm import (
    MiroFishSwarmEngine,
    to_pascal_case,
    to_upper_snake_case,
)


def test_pillar1_marketing_skills_council_and_clis():
    engine = MarketingSkillsEngine()
    all_skills = engine.list_skills()
    flagships = engine.list_skills(flagship_only=True)
    clis = engine.list_cli_tools()

    assert len(all_skills) >= 52, f"Expected >=52 installed skills, got {len(all_skills)}"
    assert len(flagships) == 12, "All 12 Nadr.ai flagship marketing roles must be mapped"
    assert len(clis) >= 60, f"Expected >=60 zero-dep CLIs, got {len(clis)}"

    routed = engine.route_query_to_skills("أريد تسعير الباقات الثلاث لمشروعي")
    assert any(r["slug"] == "pricing" for r in routed)

    council = engine.convene_marketing_council(question="تقييم خطة إطلاق المنظومة", question_type="launch")
    assert council["product_context_used"] is True
    assert len(council["seated_advisors"]) == 4
    assert any(a["is_dissenter"] for a in council["seated_advisors"]), "Must seat a Natural Dissenter"
    assert all(a["dossier_verified_on_disk"] for a in council["seated_advisors"])

    cli_res = engine.run_cli_tool_help_or_dry_run("ga4")
    assert "usage" in cli_res["output"]


def test_pillar2_company_hq_board_locking_xp_and_owner_gate(tmp_path: Path):
    hq = CompanyHQEngine(board_path=tmp_path / "hq_board.json")
    board = hq.read_board()
    assert board["owner"] == "نور"
    assert board["ceo"] == "أرينا 96"
    assert len(board["staff"]) == 7  # CEO + 6 departments

    # Verify canonical team/ directory files exist
    for rel in [
        "team/README.md",
        "team/checklists.md",
        "team/board-protocol.md",
        "team/levels.md",
        "team/rituals/README.md",
        "team/jd/cybersec-auditor.md",
        "team/jd/mirofish-swarm.md",
    ]:
        assert (Path("/home/user") / rel).exists(), f"Missing {rel}"

    # Verify optimistic concurrency (`if_version`)
    stale_ver = board["version"]
    hq.update_staff_status("cybersec-auditor", "يشتغل", "فحص أمني")
    with pytest.raises(OptimisticLockError):
        hq.update_staff_status("research-trends", "يشتغل", "تحديث متعارض", if_version=stale_ver)

    # Verify secret leak blocker on shared board
    with pytest.raises(SecretLeakBlockedError):
        hq.update_staff_status("cybersec-auditor", "يشتغل", "مفتاح مسرب sk-ant-123456")

    # Verify 5-line report + XP gain (+10 XP) + Owner approval (+15 XP)
    before_xp = [s["xp"] for s in hq.read_board()["staff"] if s["id"] == "marketing-growth"][0]
    rep = hq.submit_department_report(
        department_id="marketing-growth",
        done="إعداد مسودة التسعير",
        files_or_links="/home/user/.agents/product-marketing.md",
        needs_owner="موافقة نور على الأسعار",
    )
    assert rep["formatted_5line"].count("\n") == 4
    need = hq.request_owner_approval(
        department_id="marketing-growth",
        action_category="publish",
        title_ar="نشر صفحة الأسعار",
        details_ar="باقات $49 / $149 / $499",
    )
    hq.resolve_owner_need(need["id"], "approve", "موافقة نور الصريحة")
    after_xp = [s["xp"] for s in hq.read_board()["staff"] if s["id"] == "marketing-growth"][0]
    assert after_xp == before_xp + 25


def test_pillar3_connectors_hub_firewall_and_excel(tmp_path: Path):
    hq = CompanyHQEngine(board_path=tmp_path / "hq_board.json")
    hub = ConnectorsGatewayHub(hq=hq)
    connectors = hub.list_connectors()
    assert len(connectors) == 20

    # Safe read on Google Drive should NOT block
    safe_res = hub.execute_connector_action("google_drive", "read", "قراءة سجل مجلد ارينا 96")
    assert safe_res["executed_live"] is True
    assert safe_res["blocked_by_owner_firewall"] is False

    # External spend on Meta Ads without Noor's approval MUST be intercepted into `needs`
    blocked_res = hub.execute_connector_action("meta_ads", "spend", "صرف 200 دولار إعلانات")
    assert blocked_res["executed_live"] is False
    assert blocked_res["blocked_by_owner_firewall"] is True
    assert blocked_res["need_card"]["status"] == "ينتظر قرار نور"

    xlsx_file = tmp_path / "kpi.xlsx"
    out = hub.export_hq_kpi_excel(output_path=xlsx_file)
    assert Path(out).exists() and Path(out).stat().st_size > 3000


def test_pillar4_mirofish_swarm_temporal_graph_and_interview(tmp_path: Path):
    assert to_pascal_case("enterprise_ciso") == "EnterpriseCiso"
    assert to_upper_snake_case("adoptsPlatform") == "ADOPTS_PLATFORM"

    swarm = MiroFishSwarmEngine(storage_dir=tmp_path / "sims")
    sim = swarm.run_simulation(
        seed_text="إطلاق منظومة أرينا 96 للتدقيق السيبراني وإدارة الشركة بالذكاء الاصطناعي",
        prediction_goal_ar="اختبار تبني السوق",
        rounds=8,
        agent_count=18,
        god_view_injection={
            "round": 4,
            "event_ar": "تقديم برهان فحص أمني SARIF مجاني بصفر إيجابيات كاذبة",
            "trust_delta": 0.32,
        },
        random_seed=42,
    )

    assert len(sim["agents"]) == 18
    assert len(sim["timeline"]) == 8
    assert sim["report"]["final_support_percent"] > sim["report"]["initial_support_percent"]
    assert Path(sim["agent_log_path"]).exists()

    interview = swarm.interview_agent(sim["simulation_id"], agent_id=2, question_ar="لماذا أيدت المنصة؟")
    assert "د. سلمى" in interview["agent_name_ar"]
    assert len(interview["answer_ar"]) > 40
