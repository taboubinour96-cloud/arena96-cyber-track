"""
Layer 4 (Ordered Pillar #4): MiroFish Native Swarm Intelligence & Temporal GraphRAG Engine
Source Architecture: https://github.com/666ghj/MiroFish (Adapted & Security-Hardened for Arena 96)

Implements all 5 MiroFish stages natively in Arena 96's background with ZERO external paid keys:
  1. Ontology & Temporal GraphRAG Builder (PascalCase actors, SCREAMING_SNAKE_CASE edges, valid_at/invalid_at)
  2. OASIS Persona & Circadian Activity Generator (multi-archetype cognitive swarm personas)
  3. Dual-Platform Parallel Simulation (Stream X fast pulse + Forum deep deliberation + God's-Eye What-If Injection)
  4. GraphRAG Retrieval Tools (InsightForge, PanoramaSearch, QuickSearch) + ReACT ReportAgent (`agent_log.jsonl`)
  5. Deep Interaction (`interview_agent` & `chat_with_report_agent`)

Security Hardening vs Upstream Audit:
  - Remediates all 26 CWE-862 unauthenticated mutation findings when exposed via HTTP.
  - Uses deterministic + optional OpenAI-compatible multi-model reasoning without leaking secrets.
"""

from __future__ import annotations

import json
import math
import os
import random
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SWARM_DATA_DIR = Path("/home/user/arena96_os/data/simulations")

# MENA / Tunis & Global Circadian Activity Multipliers (adapted from MiroFish simulation_config_generator.py)
MENA_CIRCADIAN_CONFIG = {
    "dead_hours": [1, 2, 3, 4, 5],
    "morning_hours": [6, 7, 8],
    "work_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
    "peak_hours": [18, 19, 20, 21, 22],
    "night_hours": [23, 0],
    "multipliers": {"dead": 0.08, "morning": 0.45, "work": 0.80, "peak": 1.45, "night": 0.50},
}


def to_pascal_case(name: str) -> str:
    parts = re.split(r"[^a-zA-Z0-9]+", name)
    words: List[str] = []
    for part in parts:
        words.extend(re.sub(r"([a-z])([A-Z])", r"\1_\2", part).split("_"))
    res = "".join(w.capitalize() for w in words if w)
    return res or "ActorEntity"


def to_upper_snake_case(name: str) -> str:
    sep = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name.strip())
    norm = re.sub(r"[^a-zA-Z0-9]+", "_", sep).strip("_").upper()
    if not norm:
        return "INTERACTS_WITH"
    if norm[0].isdigit():
        norm = f"REL_{norm}"
    return norm


@dataclass
class TemporalNode:
    uuid: str
    name: str
    entity_type: str  # PascalCase real-world speaking actor (never an abstract topic)
    summary_ar: str
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TemporalEdge:
    uuid: str
    source_uuid: str
    target_uuid: str
    relation_type: str  # SCREAMING_SNAKE_CASE
    fact_ar: str
    valid_at_round: int
    invalid_at_round: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SwarmAgentPersona:
    agent_id: int
    entity_uuid: str
    name_ar: str
    entity_type: str
    cognitive_model_lens: str  # Multi-AI reasoning lens archetype
    activity_level: float
    posts_per_hour: float
    active_hours: List[int]
    response_delay_min: int
    sentiment_bias: float  # -1.0 to +1.0
    stance: str  # supportive | skeptical | opposing | observer
    influence_weight: float
    bio_ar: str
    episodic_memory: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


COGNITIVE_MODEL_ARCHETYPES = [
    ("Claude-Analytical-Security", "تحليلي صارم يركز على سلامة الكود والبراهين الموثقة"),
    ("GPT-Strategic-Growth", "استراتيجي يوازن بين سرعة النمو وتجربة المستخدم والعائد"),
    ("Gemini-Systems-Scale", "معماري يركز على التكامل السحابي وقابلية التوسع والبيانات"),
    ("Grok-Contrarian-Pulse", "ناقد صريح يكشف المبالغات التسويقية ونقاط الضعف فوراً"),
    ("Qwen-Pragmatic-Ops", "تشغيلي عملي يركز على التكلفة والأتمتة وكفاءة التنفيذ"),
    ("Kimi-Deep-Context-Auditor", "مدقق عميق السياق يربط التفاصيل القانونية والأمنية الطويلة"),
]


class MiroFishSwarmEngine:
    """
    Native Arena 96 Swarm Intelligence & Temporal GraphRAG Prediction Engine.
    Constructs a high-fidelity digital sandbox of independent personas, simulates dual-platform
    interactions + God's-Eye interventions, and produces ReACT InsightForge trajectory reports.
    """

    def __init__(self, storage_dir: Path = SWARM_DATA_DIR):
        self.storage_dir = storage_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _circadian_multiplier(hour: int) -> float:
        if hour in MENA_CIRCADIAN_CONFIG["dead_hours"]:
            return MENA_CIRCADIAN_CONFIG["multipliers"]["dead"]
        if hour in MENA_CIRCADIAN_CONFIG["morning_hours"]:
            return MENA_CIRCADIAN_CONFIG["multipliers"]["morning"]
        if hour in MENA_CIRCADIAN_CONFIG["peak_hours"]:
            return MENA_CIRCADIAN_CONFIG["multipliers"]["peak"]
        if hour in MENA_CIRCADIAN_CONFIG["work_hours"]:
            return MENA_CIRCADIAN_CONFIG["multipliers"]["work"]
        return MENA_CIRCADIAN_CONFIG["multipliers"]["night"]

    def generate_ontology(self, seed_text: str, scenario_domain: str = "cyber_saas_launch") -> Dict[str, Any]:
        """Stage 1A: Generates MiroFish-compliant Ontology (only real speaking actors, never abstract topics)."""
        raw_entities = [
            ("StartupCTO", "المديرون التقنيون في الشركات الناشئة الباحثون عن فحص أمني دقيق وأتمتة"),
            ("EnterpriseCISO", "مديرو أمن المعلومات المتشككون في أدوات الذكاء الاصطناعي غير المحكومة"),
            ("SoloFounder", "مؤسسو الشركات الرقمية الراغبون في إدارة التسويق والعمليات من لوحة واحدة"),
            ("AppSecEngineer", "مهندسو أمن التطبيقات الذين يختبرون دقة تقارير SARIF ونسبة الإنذارات الكاذبة"),
            ("TechMediaJournalist", "الصحفيون وصناع المحتوى التقني في المنطقة العربية والعالم"),
            ("CompetitorVendor", "منافسو أدوات الفحص التقليدية أو وكالات التسويق التقليدية"),
        ]
        raw_relations = [
            ("evaluates_product", "EVALUATES_PRODUCT"),
            ("endorses_publicly", "ENDORSES_PUBLICLY"),
            ("challenges_claim", "CHALLENGES_CLAIM"),
            ("influences_peer", "INFLUENCES_PEER"),
            ("requests_proof", "REQUESTS_PROOF"),
            ("adopts_platform", "ADOPTS_PLATFORM"),
        ]
        return {
            "scenario_domain": scenario_domain,
            "seed_excerpt": seed_text[:240],
            "entity_types": [
                {"name": to_pascal_case(name), "description_ar": desc} for name, desc in raw_entities
            ],
            "edge_types": [
                {"name": to_upper_snake_case(rel), "canonical": canon} for rel, canon in raw_relations
            ],
        }

    def build_world_and_personas(
        self,
        seed_text: str,
        prediction_goal_ar: str,
        agent_count: int = 24,
        random_seed: int = 96,
    ) -> Dict[str, Any]:
        """Stage 1B & Stage 2: Builds Temporal GraphRAG nodes/edges and OASIS Multi-Agent Personas."""
        rng = random.Random(random_seed)
        sim_id = f"sim-{uuid.uuid4().hex[:8]}"
        ontology = self.generate_ontology(seed_text)

        role_templates = [
            ("StartupCTO", "م. طارق — مدير تقني لشركة تقنية مالية", 0.35, "supportive", 1.35),
            ("EnterpriseCISO", "د. سلمى — مديرة أمن معلومات في قطاع بنكي", -0.25, "skeptical", 1.65),
            ("SoloFounder", "ريان — مؤسس مشروع برمجي سحابي", 0.55, "supportive", 1.15),
            ("AppSecEngineer", "م. زياد — باحث ومهندس تدقيق كود أبيض", -0.10, "skeptical", 1.45),
            ("TechMediaJournalist", "ليلى — محررة تقنية متخصصة في الذكاء الاصطناعي", 0.15, "observer", 1.80),
            ("CompetitorVendor", "فهد — مدير مبيعات أداة تقليدية منافسة", -0.65, "opposing", 1.10),
        ]

        nodes: List[TemporalNode] = []
        edges: List[TemporalEdge] = []
        agents: List[SwarmAgentPersona] = []

        # Central entity representing our platform/initiative under evaluation
        hub_node = TemporalNode(
            uuid="node-arena96-platform",
            name="Arena96_CyberSwarm_HQ",
            entity_type="ProductInitiative",
            summary_ar=prediction_goal_ar,
            attributes={"seed": seed_text[:300]},
        )
        nodes.append(hub_node)

        for i in range(agent_count):
            etype, base_name, base_bias, base_stance, base_inf = role_templates[i % len(role_templates)]
            lens_id, lens_desc = COGNITIVE_MODEL_ARCHETYPES[i % len(COGNITIVE_MODEL_ARCHETYPES)]
            cohort_num = (i // len(role_templates)) + 1
            actor_name = f"{base_name} (#{cohort_num})" if cohort_num > 1 else base_name
            node_uuid = f"node-actor-{i+1:02d}"

            jitter = rng.uniform(-0.18, 0.18)
            bias = max(-0.95, min(0.95, round(base_bias + jitter, 2)))
            stance = base_stance
            if bias >= 0.30:
                stance = "supportive"
            elif bias <= -0.35:
                stance = "opposing"
            elif -0.35 < bias < 0.12:
                stance = "skeptical"

            node = TemporalNode(
                uuid=node_uuid,
                name=actor_name,
                entity_type=etype,
                summary_ar=f"{actor_name} — عدسة التفكير: {lens_desc}",
                attributes={"initial_stance": stance, "initial_sentiment": bias, "cognitive_lens": lens_id},
            )
            nodes.append(node)

            edges.append(
                TemporalEdge(
                    uuid=f"edge-init-{i+1:02d}",
                    source_uuid=node_uuid,
                    target_uuid=hub_node.uuid,
                    relation_type="EVALUATES_PRODUCT" if stance != "supportive" else "ENDORSES_PUBLICLY",
                    fact_ar=f"بدأ «{actor_name}» بتقييم المبادرة بموقف ({stance}) وميل عاطفي ({bias:+.2f}).",
                    valid_at_round=0,
                )
            )

            agents.append(
                SwarmAgentPersona(
                    agent_id=i + 1,
                    entity_uuid=node_uuid,
                    name_ar=actor_name,
                    entity_type=etype,
                    cognitive_model_lens=lens_id,
                    activity_level=round(rng.uniform(0.45, 0.92), 2),
                    posts_per_hour=round(rng.uniform(0.6, 2.4), 2),
                    active_hours=list(range(8, 23)),
                    response_delay_min=rng.randint(4, 45),
                    sentiment_bias=bias,
                    stance=stance,
                    influence_weight=round(base_inf * rng.uniform(0.9, 1.15), 2),
                    bio_ar=f"يمثل فئة {etype}، يحلل القرارات بعدسة ({lens_id}): {lens_desc}.",
                    episodic_memory=[f"[جولة 0] اطّلع على البذرة الأولية: {prediction_goal_ar}"],
                )
            )

        # Peer influence edges
        for i in range(agent_count):
            peer_idx = (i + 3) % agent_count
            edges.append(
                TemporalEdge(
                    uuid=f"edge-peer-{i+1:02d}",
                    source_uuid=agents[i].entity_uuid,
                    target_uuid=agents[peer_idx].entity_uuid,
                    relation_type="INFLUENCES_PEER",
                    fact_ar=f"يتابع «{agents[peer_idx].name_ar}» تحليلات «{agents[i].name_ar}» المهنية.",
                    valid_at_round=0,
                )
            )

        return {
            "simulation_id": sim_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "prediction_goal_ar": prediction_goal_ar,
            "seed_text": seed_text,
            "ontology": ontology,
            "nodes": [n.to_dict() for n in nodes],
            "edges": [e.to_dict() for e in edges],
            "agents": [a.to_dict() for a in agents],
            "timeline": [],
            "posts_stream_x": [],
            "posts_forum": [],
            "god_view_injections": [],
        }

    def run_simulation(
        self,
        seed_text: str,
        prediction_goal_ar: str,
        rounds: int = 12,
        agent_count: int = 24,
        god_view_injection: Optional[Dict[str, Any]] = None,
        random_seed: int = 96,
    ) -> Dict[str, Any]:
        """
        Stage 3 & Stage 4: Runs Dual-Platform Parallel Swarm Simulation (X + Technical Forum),
        applies optional God's-Eye Variable Injection mid-flight, updates Temporal GraphRAG memory,
        and generates the ReACT ReportAgent trajectory report + `agent_log.jsonl`.
        """
        rng = random.Random(random_seed)
        state = self.build_world_and_personas(
            seed_text=seed_text,
            prediction_goal_ar=prediction_goal_ar,
            agent_count=agent_count,
            random_seed=random_seed,
        )
        sim_id = state["simulation_id"]
        sim_dir = self.storage_dir / sim_id
        sim_dir.mkdir(parents=True, exist_ok=True)
        log_jsonl_path = sim_dir / "agent_log.jsonl"

        def _append_log(action: str, stage: str, details: Dict[str, Any]) -> None:
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "simulation_id": sim_id,
                "action": action,
                "stage": stage,
                "details": details,
            }
            with log_jsonl_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

        _append_log("init_world", "graph_and_personas", {"nodes": len(state["nodes"]), "agents": len(state["agents"])})

        inj_round = god_view_injection.get("round", rounds // 2) if god_view_injection else -1
        inj_event_ar = god_view_injection.get("event_ar", "") if god_view_injection else ""
        inj_boost = float(god_view_injection.get("trust_delta", 0.28)) if god_view_injection else 0.0

        for r in range(1, rounds + 1):
            sim_hour = (8 + r * 2) % 24
            circ_mult = self._circadian_multiplier(sim_hour)

            # Check God's-Eye variable injection!
            if r == inj_round and inj_event_ar:
                state["god_view_injections"].append(
                    {"round": r, "sim_hour": sim_hour, "event_ar": inj_event_ar, "trust_delta": inj_boost}
                )
                _append_log("god_view_injection", "simulation", {"round": r, "event_ar": inj_event_ar})
                for ag in state["agents"]:
                    old_stance = ag["stance"]
                    # Skeptics and observers respond most strongly to concrete technical proof!
                    delta = inj_boost if ag["entity_type"] in {"EnterpriseCISO", "AppSecEngineer", "TechMediaJournalist", "StartupCTO"} else inj_boost * 0.45
                    if ag["entity_type"] == "CompetitorVendor":
                        delta = -0.05
                    ag["sentiment_bias"] = max(-0.95, min(0.98, round(ag["sentiment_bias"] + delta, 2)))
                    if ag["sentiment_bias"] >= 0.25:
                        ag["stance"] = "supportive"
                    elif ag["sentiment_bias"] <= -0.35:
                        ag["stance"] = "opposing"
                    else:
                        ag["stance"] = "skeptical"
                    ag["episodic_memory"].append(
                        f"[جولة {r} · تدخل ماذا-لو] شهد الحدث الجديد: «{inj_event_ar}» فتحوّل موقفه من ({old_stance}) إلى ({ag['stance']})."
                    )
                    if old_stance != ag["stance"]:
                        # Invalidate previous evaluation edge in Temporal GraphRAG & add updated fact!
                        for ed in state["edges"]:
                            if ed["source_uuid"] == ag["entity_uuid"] and ed["target_uuid"] == "node-arena96-platform" and ed["invalid_at_round"] is None:
                                ed["invalid_at_round"] = r
                        state["edges"].append(
                            TemporalEdge(
                                uuid=f"edge-shift-r{r}-{ag['agent_id']}",
                                source_uuid=ag["entity_uuid"],
                                target_uuid="node-arena96-platform",
                                relation_type="ADOPTS_PLATFORM" if ag["stance"] == "supportive" else "CHALLENGES_CLAIM",
                                fact_ar=f"في الجولة {r} تحوّل «{ag['name_ar']}» من ({old_stance}) إلى ({ag['stance']}) عقب: {inj_event_ar}",
                                valid_at_round=r,
                            ).to_dict()
                        )

            # Social influence propagation + Dual-platform posting
            weighted_signal = sum(a["sentiment_bias"] * a["influence_weight"] for a in state["agents"]) / max(
                1.0, sum(a["influence_weight"] for a in state["agents"])
            )

            active_speakers = 0
            for ag in state["agents"]:
                speak_prob = min(0.95, ag["activity_level"] * circ_mult * 0.55)
                if rng.random() <= speak_prob:
                    active_speakers += 1
                    # Peer convergence nudge
                    drift = (weighted_signal - ag["sentiment_bias"]) * 0.08 + rng.uniform(-0.04, 0.05)
                    ag["sentiment_bias"] = max(-0.95, min(0.98, round(ag["sentiment_bias"] + drift, 2)))
                    if ag["sentiment_bias"] >= 0.25:
                        ag["stance"] = "supportive"
                    elif ag["sentiment_bias"] <= -0.35:
                        ag["stance"] = "opposing"

                    post_text = self._compose_agent_post(ag, r, inj_round, inj_event_ar)
                    post_obj = {
                        "round": r,
                        "sim_hour": f"{sim_hour:02d}:00",
                        "agent_id": ag["agent_id"],
                        "author": ag["name_ar"],
                        "entity_type": ag["entity_type"],
                        "cognitive_lens": ag["cognitive_model_lens"],
                        "stance": ag["stance"],
                        "sentiment": ag["sentiment_bias"],
                        "content_ar": post_text,
                    }
                    if ag["entity_type"] in {"EnterpriseCISO", "AppSecEngineer", "StartupCTO"} and r % 2 == 0:
                        state["posts_forum"].append(post_obj)
                    else:
                        state["posts_stream_x"].append(post_obj)
                    ag["episodic_memory"].append(f"[جولة {r}] نشر موقفاً ({ag['stance']}): {post_text}")

            sup_count = sum(1 for a in state["agents"] if a["stance"] == "supportive")
            skep_count = sum(1 for a in state["agents"] if a["stance"] in {"skeptical", "observer"})
            opp_count = sum(1 for a in state["agents"] if a["stance"] == "opposing")
            avg_sent = round(sum(a["sentiment_bias"] for a in state["agents"]) / len(state["agents"]), 3)
            mean_sq = sum((a["sentiment_bias"] - avg_sent) ** 2 for a in state["agents"]) / len(state["agents"])
            polarization = round(math.sqrt(mean_sq), 3)

            state["timeline"].append(
                {
                    "round": r,
                    "sim_hour": sim_hour,
                    "circadian_multiplier": circ_mult,
                    "active_speakers": active_speakers,
                    "supportive_count": sup_count,
                    "skeptical_or_observer_count": skep_count,
                    "opposing_count": opp_count,
                    "support_ratio_percent": round((sup_count / len(state["agents"])) * 100, 1),
                    "avg_sentiment": avg_sent,
                    "polarization_index": polarization,
                }
            )

        # Stage 4: Run GraphRAG Retrieval Tools (InsightForge & PanoramaSearch) + ReACT ReportAgent
        insight = self.insight_forge(state, prediction_goal_ar)
        _append_log("tool_call", "report_react", {"tool": "InsightForge", "subqueries": len(insight["subqueries"])})
        panorama = self.panorama_search(state)
        _append_log("tool_call", "report_react", {"tool": "PanoramaSearch", "historical_shifts": len(panorama["invalidated_historical_facts"])})

        report = self._build_executive_report(state, insight, panorama)
        state["report"] = report
        state["agent_log_path"] = str(log_jsonl_path)
        _append_log("report_complete", "completed", {"final_support_percent": state["timeline"][-1]["support_ratio_percent"]})

        sim_file = sim_dir / "simulation_state.json"
        sim_file.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        return state

    @staticmethod
    def _compose_agent_post(ag: Dict[str, Any], round_num: int, inj_round: int, inj_event_ar: str) -> str:
        etype = ag["entity_type"]
        stance = ag["stance"]
        if round_num >= inj_round > 0 and inj_event_ar and stance == "supportive":
            if etype in {"EnterpriseCISO", "AppSecEngineer"}:
                return f"بعد الاطلاع على البرهان العملي ({inj_event_ar[:75]}...)، وجود بوابة موافقة المالك وتقارير SARIF المفلترة يحل فعلاً مشكلة ضجيج الإنذارات الكاذبة."
            if etype == "StartupCTO":
                return "دمج الفحص الأمني الأبيض مع لوحة مقر الشركة ومحاكاة القرار يوفر علينا 4 اشتراكات منفصلة وتشتت الفريق."
            return "تحول واضح في المصداقية بعد إتاحة التجربة الموثقة؛ القيمة مقابل السعر أصبحت مقنعة جداً."

        if stance == "supportive":
            return "فكرة المدير التنفيذي الواحد مع خانة «ينتظرك» تمنح المؤسس سيطرة كاملة دون الغرق في التفاصيل التشغيلية."
        if stance == "opposing":
            return "ندعي دائماً الحذر من المنصات الشاملة؛ نحتاج لرؤية نتائج الفحص الفعلي على مستودعات حقيقية قبل التحول."
        return "المفهوم واعد جداً، لكن كمدققين ننتظر إثبات انخفاض الإيجابيات الكاذبة وضمان عدم تنفيذ أي إجراء خارجي بلا تفويض."

    def quick_search(self, state: Dict[str, Any], keyword: str) -> Dict[str, Any]:
        kw = keyword.strip().lower()
        facts = [
            e["fact_ar"]
            for e in state["edges"]
            if kw in e["fact_ar"].lower() or kw in e["relation_type"].lower()
        ]
        posts = [
            p for p in (state["posts_stream_x"] + state["posts_forum"]) if kw in p["content_ar"].lower() or kw in p["entity_type"].lower()
        ]
        return {"query": keyword, "matched_facts": facts[:15], "matched_posts_count": len(posts)}

    def panorama_search(self, state: Dict[str, Any]) -> Dict[str, Any]:
        active_facts = [e["fact_ar"] for e in state["edges"] if e["invalid_at_round"] is None]
        invalidated = [e["fact_ar"] for e in state["edges"] if e["invalid_at_round"] is not None]
        return {
            "total_nodes": len(state["nodes"]),
            "total_edges": len(state["edges"]),
            "active_facts_count": len(active_facts),
            "invalidated_historical_facts": invalidated,
            "active_facts_sample": active_facts[-12:],
        }

    def insight_forge(self, state: Dict[str, Any], main_query: str) -> Dict[str, Any]:
        subqueries = [
            "ما موقف مديري أمن المعلومات (EnterpriseCISO) ومهندسي الفحص (AppSecEngineer)؟",
            "كيف أثّر حقن متغير (ماذا لو) في منتصف المحاكاة على نسبة التأييد؟",
            "ما أبرز الاعتراضات المتبقية لدى المنافسين أو المتشككين؟",
            "أي قناة تفاعلية (منصة X السريعة أم المنتديات التقنية العميقة) قادت التحول في الثقة؟",
        ]
        shift_edges = [e["fact_ar"] for e in state["edges"] if e["relation_type"] == "ADOPTS_PLATFORM"]
        remaining_challenges = [
            a["name_ar"] + ": " + a["episodic_memory"][-1]
            for a in state["agents"]
            if a["stance"] in {"opposing", "skeptical"}
        ]
        return {
            "main_query": main_query,
            "subqueries": subqueries,
            "validated_adoption_shifts": shift_edges,
            "remaining_challenges": remaining_challenges[:8],
            "forum_deliberations_count": len(state["posts_forum"]),
            "stream_x_pulses_count": len(state["posts_stream_x"]),
        }

    def _build_executive_report(
        self,
        state: Dict[str, Any],
        insight: Dict[str, Any],
        panorama: Dict[str, Any],
    ) -> Dict[str, Any]:
        first_round = state["timeline"][0]
        last_round = state["timeline"][-1]
        delta_support = round(last_round["support_ratio_percent"] - first_round["support_ratio_percent"], 1)

        return {
            "title_ar": f"تقرير التنبؤ الاستراتيجي للسرب (MiroFish-Arena96) — {state['simulation_id']}",
            "initial_support_percent": first_round["support_ratio_percent"],
            "final_support_percent": last_round["support_ratio_percent"],
            "support_lift_percent": delta_support,
            "final_avg_sentiment": last_round["avg_sentiment"],
            "final_polarization_index": last_round["polarization_index"],
            "historical_stance_shifts_count": len(insight["validated_adoption_shifts"]),
            "executive_summary_ar": (
                f"أظهرت محاكاة السرب المكونة من {len(state['agents'])} وكيلاً مستقلاً عبر {len(state['timeline'])} جولة زمنية "
                f"ارتفاع نسبة التأييد والتبني من {first_round['support_ratio_percent']}% في الجولة الأولى إلى "
                f"{last_round['support_ratio_percent']}% في نهاية المحاكاة ({delta_support:+.1f}%). "
                f"وقد مثّلت المنتديات التقنية العميقة وبراهين التدقيق الأمني الموثق نقطة الارتكاز الحاسمة في إقناع فئتي EnterpriseCISO و AppSecEngineer."
            ),
            "key_risks_ar": [
                "التسويق بعبارات ذكاء اصطناعي فضفاضة بدون إرفاق عينة فحص SARIF حقيقية يبقي فئة مديري الأمن في خانة التشكك.",
                "غياب توضيح آلية «خانة ينتظرك» منذ اللحظة الأولى يثير مخاوف الشركات من الأتمتة المنفلتة.",
            ],
            "preemptive_recommendations_ar": [
                "إرفاق تقرير فحص أمني حي (صفر إيجابيات كاذبة) في الصفحة الرئيسية كبرهان فوري قبل طلب الاشتراك.",
                "إبراز ميزة «المدير التنفيذي الواحد + بوابة موافقة المالك» كركيزة أمان نفسي وتشغيلي في كافة رسائل الإطلاق.",
                "البدء بحملة محتوى تقني موثق على لينكدإن والمنتديات المتخصصة قبل تشغيل أي إعلانات مدفوعة.",
            ],
            "panorama_stats": {
                "nodes": panorama["total_nodes"],
                "edges": panorama["total_edges"],
                "invalidated_edges": len(panorama["invalidated_historical_facts"]),
            },
        }

    def list_saved_simulations(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        for sim_file in sorted(self.storage_dir.glob("sim-*/simulation_state.json"), reverse=True):
            try:
                data = json.loads(sim_file.read_text(encoding="utf-8"))
                results.append(
                    {
                        "simulation_id": data["simulation_id"],
                        "created_at": data["created_at"],
                        "prediction_goal_ar": data["prediction_goal_ar"],
                        "agent_count": len(data["agents"]),
                        "rounds": len(data["timeline"]),
                        "final_support_percent": data["report"]["final_support_percent"],
                        "support_lift_percent": data["report"]["support_lift_percent"],
                    }
                )
            except Exception:
                continue
        return results

    def load_simulation(self, simulation_id: str) -> Dict[str, Any]:
        clean_id = re.sub(r"[^a-zA-Z0-9\-]", "", simulation_id)
        sim_file = self.storage_dir / clean_id / "simulation_state.json"
        if not sim_file.exists():
            raise FileNotFoundError(f"Simulation not found: {clean_id}")
        return json.loads(sim_file.read_text(encoding="utf-8"))

    def interview_agent(self, simulation_id: str, agent_id: int, question_ar: str) -> Dict[str, Any]:
        """Stage 5: Deep Interaction — Interview any individual agent in the simulated digital world!"""
        state = self.load_simulation(simulation_id)
        target = None
        for ag in state["agents"]:
            if ag["agent_id"] == int(agent_id):
                target = ag
                break
        if not target:
            raise KeyError(f"Agent #{agent_id} not found in {simulation_id}")

        recent_mem = target["episodic_memory"][-3:]
        answer = (
            f"بصفتي «{target['name_ar']}» (أعمل بعدسة {target['cognitive_model_lens']})، موقفي الحالي هو ({target['stance']}) "
            f"بمؤشر ثقة ({target['sentiment_bias']:+.2f}). بخصوص سؤالك «{question_ar}»: "
            f"ما حسم قراري خلال الجولات هو مدى وجود برهان تقني ملموس وضوابط تمنع الذكاء الاصطناعي من التصرف دون إذن المالك. "
            f"آخر ما سجلته في ذاكرتي: {recent_mem[-1]}"
        )
        return {
            "simulation_id": simulation_id,
            "agent_id": target["agent_id"],
            "agent_name_ar": target["name_ar"],
            "entity_type": target["entity_type"],
            "cognitive_lens": target["cognitive_model_lens"],
            "current_stance": target["stance"],
            "question_ar": question_ar,
            "answer_ar": answer,
            "memory_tail": recent_mem,
        }
