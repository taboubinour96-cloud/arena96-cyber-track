"""
Layer 1 (Ordered Pillar #1): Native Background Marketing Team & Council Engine
Source Architecture: https://marketing-team.nadr.ai/ & coreyhaines31/marketingskills (MIT)

Adapts the 53 Claude Marketing Skills, 12-Advisor Marketing Council, and 66 zero-dependency
Node.js CLI tools to run natively inside Arena 96's background Agent Mode.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

SKILLS_ROOT = Path("/home/user/skills_library/marketingskills/skills")
CLIS_ROOT = Path("/home/user/skills_library/marketingskills/tools/clis")
PRODUCT_CONTEXT_PATH = Path("/home/user/.agents/product-marketing.md")

# The 12 flagship roles highlighted in marketing-team.nadr.ai mapped in Arabic
FLAGSHIP_ROLES_AR: Dict[str, Dict[str, str]] = {
    "social": {"title_ar": "مسؤول السوشال ميديا", "icon": "📱", "focus_ar": "كتابة وجدولة وتحسين منشورات إنستقرام ولينكدإن وإكس"},
    "content-strategy": {"title_ar": "مخطط المحتوى", "icon": "🗓️", "focus_ar": "تحديد الركائز والمواضيع الأساسية لجذب العملاء حسب الأهمية"},
    "ad-creative": {"title_ar": "كاتب الإعلانات", "icon": "✍️", "focus_ar": "كتابة نسخ إعلانية متعددة الزوايا والعناوين لإعلانات ميتا وقوقل"},
    "copywriting": {"title_ar": "كاتب صفحات البيع", "icon": "📝", "focus_ar": "كتابة وتحسين نصوص الصفحات الرئيسية وصفحات الهبوط لرفع التحويل"},
    "marketing-council": {"title_ar": "مجلس خبراء التسويق", "icon": "🧑‍⚖️", "focus_ar": "محاكاة مجلس مستشارين من 12 خبيراً عالمياً مع عضو معارض إلزامي"},
    "ai-seo": {"title_ar": "خبير الظهور في الذكاء الاصطناعي", "icon": "🤖", "focus_ar": "تهيئة المحتوى ليُستشهد به في إجابات نماذج الذكاء الاصطناعي ومحركات الإجابة"},
    "seo-audit": {"title_ar": "خبير السيو", "icon": "🔎", "focus_ar": "فحص الموقع واستخراج أهم مشاكل الظهور في محركات البحث وطرق حلها"},
    "public-relations": {"title_ar": "خبير العلاقات العامة", "icon": "📣", "focus_ar": "التواصل الاحترافي مع الصحافة التقنية والإعلام لبناء الموثوقية"},
    "launch": {"title_ar": "مسؤول الإطلاق", "icon": "🚀", "focus_ar": "بناء خطة إطلاق منتج أو ميزة جديدة يوماً بيوم"},
    "pricing": {"title_ar": "خبير التسعير", "icon": "💰", "focus_ar": "تصميم هيكل التسعير وبناء الباقات الثلاث ومعادلة القيمة"},
    "emails": {"title_ar": "كاتب الإيميلات", "icon": "📧", "focus_ar": "بناء سلاسل البريد الترحيبية والتثقيفية والتحويلية"},
    "marketing-plan": {"title_ar": "مخطط التسويق", "icon": "🎯", "focus_ar": "تصميم خطة تسويق شاملة لـ 90 يوماً موزعة حسب الميزانية والقنوات"},
}

# Advisor bench metadata grounded in skills/marketing-council/SKILL.md
ADVISOR_BENCH: Dict[str, Dict[str, str]] = {
    "seth-godin": {
        "name": "Seth Godin",
        "title_ar": "سيث غودين — التفرّد وأصغر جمهور قابل للحياة والتسويق بالإذن",
        "core_heuristic": "لا تصنع منتجاً عادياً لجمهور عام؛ ابنِ شيئاً يستحق الحديث عنه (Purple Cow) لأصغر جمهور مهتم فعلاً واكسب إذنهم قبل البيع.",
    },
    "david-ogilvy": {
        "name": "David Ogilvy",
        "title_ar": "ديفيد أوجيلفي — الإعلان المبني على البحث والحقائق المحددة",
        "core_heuristic": "المستهلك ليس غبياً؛ قدّم حقائق هندسية ملموسة وأرقاماً موثّقة في العنوان الرئيسي لأن العنوان يمثل 80% من قيمة الدولار الإعلاني.",
    },
    "eugene-schwartz": {
        "name": "Eugene Schwartz",
        "title_ar": "يوجين شوارتز — مستويات وعي السوق الخمسة وتوجيه الرغبة",
        "core_heuristic": "طابق الرسالة مع مستوى وعي العميل ونضج السوق؛ في سوق مزدحم بادعاءات الذكاء الاصطناعي، انتقل إلى الآلية المميزة (Unique Mechanism).",
    },
    "claude-hopkins": {
        "name": "Claude Hopkins",
        "title_ar": "كلود هوبكنز — التسويق العلمي والقياس الصارم وتجربة العينة",
        "core_heuristic": "لا تخمّن أبداً؛ كل إعلان هو مندوب مبيعات يُقاس بالعائد المباشر، وأقوى برهان هو تقديم عينة تجريبية مجانية تثبت الكفاءة.",
    },
    "gary-halbert": {
        "name": "Gary Halbert",
        "title_ar": "غاري هالبرت — الجمهور الجائع أولاً قبل جودة النص",
        "core_heuristic": "ابحث عن الجمهور الذي يعاني من ألم فوري حاد (مثل غرق فرق التطوير في البلاغات الأمنية الكاذبة) وقدّم له عرضاً مباشراً لا يُقاوم.",
    },
    "russell-brunson": {
        "name": "Russell Brunson",
        "title_ar": "راسل برونسون — سلّم القيمة ومسارات التحويل (Hook-Story-Offer)",
        "core_heuristic": "ابدأ بأداة مجانية خاطفة تجلب العميل إلى سلّم القيمة، ثم صعّده تدريجياً من الفحص الفردي إلى باقة الشركة الكاملة.",
    },
    "alex-hormozi": {
        "name": "Alex Hormozi",
        "title_ar": "أليكس هورموزي — معادلة القيمة والعرض الذي يستحيل رفضه",
        "core_heuristic": "ارفع النتيجة الحلم واحتمال التحقق مع تقليل زمن الوصول للنتيجة والجهد المطلوب إلى الصفر تقريباً، وأضف ضماناً يعكس المخاطرة.",
    },
    "april-dunford": {
        "name": "April Dunford",
        "title_ar": "أبريل دانفورد — التموضع التنافسي الواضح مقابل البدائل الحقيقية",
        "core_heuristic": "حدّد البديل الحقيقي الذي يستخدمه العميل اليوم، ثم أبرز القدرات الفريدة لديك وضع منتجك في فئة سوقية تجعل ميزتك بديهية.",
    },
    "rory-sutherland": {
        "name": "Rory Sutherland",
        "title_ar": "روري سذرلاند — الاقتصاد السلوكي والقيمة النفسية المدركة",
        "core_heuristic": "الناس لا يشترون المنطق الهندسي وحده بل يشترون راحة البال وتجنب اللوم؛ خانة «ينتظرك» تمنح المدير أماناً نفسياً هائلاً.",
    },
    "byron-sharp": {
        "name": "Byron Sharp",
        "title_ar": "بايرون شارب — التوافر الذهني والمادي والوصول الواسع (المعارض الطبيعي)",
        "core_heuristic": "احذر من المبالغة في تضييق الشريحة؛ النمو الحقيقي يأتي من التوافر الذهني والمادي الواسع وأصول العلامة المميزة سهلة التذكر لدى المشترين الخفيفين.",
    },
    "ann-handley": {
        "name": "Ann Handley",
        "title_ar": "آن هاندلي — صناعة المحتوى الموثوق وبناء الثقة طويلة الأمد",
        "core_heuristic": "اجعل العميل هو البطل في قصتك واكتب بوضوح وصدق؛ التقارير التعليمية المتقنة تبني سلطة معرفية تتفوق على الضجيج الإعلاني.",
    },
    "gary-vaynerchuk": {
        "name": "Gary Vaynerchuk",
        "title_ar": "غاري فاينرتشوك — استثمار الانتباه غير المسعّر بالكامل وتوثيق الرحلة",
        "core_heuristic": "وثّق رحلة البناء الحقيقية بدلاً من التنظير (Document, Don't Create) وانشر محتوى أصيلاً مكثفاً على لينكدإن وإكس ويوتيوب.",
    },
}

QUESTION_SEATING_MATRIX: Dict[str, Dict[str, List[str]]] = {
    "launch": {"fits": ["april-dunford", "alex-hormozi", "seth-godin", "david-ogilvy"], "dissenters": ["byron-sharp"]},
    "pricing": {"fits": ["alex-hormozi", "april-dunford", "russell-brunson"], "dissenters": ["rory-sutherland", "seth-godin"]},
    "positioning": {"fits": ["april-dunford", "eugene-schwartz", "seth-godin"], "dissenters": ["byron-sharp"]},
    "copy": {"fits": ["david-ogilvy", "eugene-schwartz", "ann-handley"], "dissenters": ["rory-sutherland"]},
    "content": {"fits": ["ann-handley", "gary-vaynerchuk", "seth-godin"], "dissenters": ["claude-hopkins"]},
}


@dataclass
class SkillMetadata:
    slug: str
    name: str
    version: str
    description: str
    is_flagship: bool
    title_ar: str
    icon: str
    focus_ar: str
    skill_md_path: str
    reference_files_count: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _parse_frontmatter(md_text: str) -> Dict[str, str]:
    result: Dict[str, str] = {"name": "", "description": "", "version": "1.0.0"}
    if not md_text.startswith("---"):
        return result
    parts = md_text.split("---", 2)
    if len(parts) < 3:
        return result
    fm = parts[1]
    name_m = re.search(r"^name:\s*(.+)$", fm, re.MULTILINE)
    desc_m = re.search(r'^description:\s*["\']?(.+?)["\']?\s*$', fm, re.MULTILINE)
    ver_m = re.search(r"^\s*version:\s*(.+)$", fm, re.MULTILINE)
    if name_m:
        result["name"] = name_m.group(1).strip()
    if desc_m:
        result["description"] = desc_m.group(1).strip()
    if ver_m:
        result["version"] = ver_m.group(1).strip()
    return result


class MarketingSkillsEngine:
    """Native Arena 96 runtime for all 53 Marketing Skills, 12-Advisor Council, and 66 CLIs."""

    def __init__(self, skills_root: Path = SKILLS_ROOT, clis_root: Path = CLIS_ROOT):
        self.skills_root = skills_root
        self.clis_root = clis_root
        self._skills_cache: Dict[str, SkillMetadata] = {}
        self.reload_skills()

    def reload_skills(self) -> Dict[str, SkillMetadata]:
        self._skills_cache.clear()
        if not self.skills_root.exists():
            return self._skills_cache

        for entry in sorted(self.skills_root.iterdir()):
            skill_md = entry / "SKILL.md"
            if not entry.is_dir() or not skill_md.exists():
                continue
            slug = entry.name
            text = skill_md.read_text(encoding="utf-8", errors="replace")
            fm = _parse_frontmatter(text)
            refs_dir = entry / "references"
            ref_count = sum(1 for p in refs_dir.rglob("*") if p.is_file()) if refs_dir.exists() else 0
            flagship = FLAGSHIP_ROLES_AR.get(slug)
            self._skills_cache[slug] = SkillMetadata(
                slug=slug,
                name=fm["name"] or slug,
                version=fm["version"],
                description=fm["description"],
                is_flagship=flagship is not None,
                title_ar=flagship["title_ar"] if flagship else f"مهارة {slug}",
                icon=flagship["icon"] if flagship else "⚡",
                focus_ar=flagship["focus_ar"] if flagship else fm["description"][:140],
                skill_md_path=str(skill_md),
                reference_files_count=ref_count,
            )
        return self._skills_cache

    def list_skills(self, flagship_only: bool = False) -> List[Dict[str, Any]]:
        items = list(self._skills_cache.values())
        if flagship_only:
            items = [s for s in items if s.is_flagship]
        return [s.to_dict() for s in items]

    def list_cli_tools(self) -> List[str]:
        if not self.clis_root.exists():
            return []
        return sorted(p.stem for p in self.clis_root.glob("*.js"))

    def load_product_context(self) -> str:
        if PRODUCT_CONTEXT_PATH.exists():
            return PRODUCT_CONTEXT_PATH.read_text(encoding="utf-8", errors="replace")
        return ""

    def get_skill_playbook(self, slug: str, max_chars: int = 4000) -> Dict[str, Any]:
        meta = self._skills_cache.get(slug)
        if not meta:
            raise KeyError(f"Unknown marketing skill: {slug}")
        raw = Path(meta.skill_md_path).read_text(encoding="utf-8", errors="replace")
        return {
            "metadata": meta.to_dict(),
            "playbook_excerpt": raw[:max_chars],
            "product_context_loaded": PRODUCT_CONTEXT_PATH.exists(),
        }

    def route_query_to_skills(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """Routes an Arabic or English marketing request to the best matching installed skills."""
        q = query.lower()
        keyword_map = {
            "marketing-council": ["مجلس", "خبراء", "مستشار", "council", "ogilvy", "hormozi", "godin", "رأي"],
            "pricing": ["سعر", "تسعير", "باقات", "باقة", "pricing", "tier", "price"],
            "launch": ["إطلاق", "اطلاق", "launch", "تدشين", "حملة إطلاق"],
            "ai-seo": ["ذكاء", "شات جي بي تي", "chatgpt", "perplexity", "ai-seo", "aeo", "geo", "llmo"],
            "seo-audit": ["سيو", "قوقل", "جوجل", "seo", "محركات البحث"],
            "social": ["سوشال", "انستقرام", "إنستقرام", "لينكدإن", "إكس", "تويتر", "social", "linkedin"],
            "ad-creative": ["إعلان", "اعلان", "ميتا", "نسخ إعلان", "ad", "creative"],
            "copywriting": ["صفحة بيع", "هبوط", "landing", "copywriting", "نص الصفحة"],
            "emails": ["إيميل", "ايميل", "بريد", "ترحيب", "email", "newsletter"],
            "public-relations": ["صحفي", "علاقات عامة", "إعلام", "بيان صحفي", "pr", "press"],
            "content-strategy": ["محتوى", "خطة محتوى", "مواضيع", "content"],
            "marketing-plan": ["خطة تسويق", "90 يوم", "ميزانية", "marketing plan"],
            "reverse-engineer-marketing": ["منافس", "هندسة عكسية", "reverse", "teardown"],
        }
        scored: List[tuple[int, str]] = []
        for slug, meta in self._skills_cache.items():
            score = 0
            for kw in keyword_map.get(slug, []):
                if kw in q:
                    score += 5
            if slug in q:
                score += 8
            if any(tok in meta.description.lower() for tok in re.findall(r"[a-z]{4,}", q)):
                score += 2
            if score > 0:
                scored.append((score, slug))

        scored.sort(key=lambda x: (-x[0], x[1]))
        chosen = [slug for _, slug in scored[:top_k]]
        if not chosen:
            chosen = ["marketing-council", "marketing-plan", "positioning"][:top_k]
        return [self._skills_cache[s].to_dict() for s in chosen if s in self._skills_cache]

    def convene_marketing_council(
        self,
        question: str,
        question_type: str = "launch",
        stakes: str = "إطلاق منظومة أرينا 96 وبناء الثقة المؤسسية بدون هدر إعلاني",
    ) -> Dict[str, Any]:
        """
        Runs a grounded simulated Marketing Council session reading the installed advisor dossiers
        from skills/marketing-council/references/advisors/*.md and guaranteeing a Natural Dissenter.
        """
        qtype = question_type if question_type in QUESTION_SEATING_MATRIX else "launch"
        seating = QUESTION_SEATING_MATRIX[qtype]
        advisor_ids = seating["fits"][:3] + seating["dissenters"][:1]

        advisors_dir = self.skills_root / "marketing-council" / "references" / "advisors"
        perspectives: List[Dict[str, Any]] = []

        for idx, adv_id in enumerate(advisor_ids):
            info = ADVISOR_BENCH[adv_id]
            dossier_path = advisors_dir / f"{adv_id}.md"
            dossier_loaded = dossier_path.exists()
            dossier_first_line = ""
            if dossier_loaded:
                lines = [
                    ln.strip()
                    for ln in dossier_path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if ln.strip() and not ln.startswith("#")
                ]
                dossier_first_line = lines[0][:220] if lines else ""

            is_dissenter = adv_id in seating["dissenters"]
            role_tag = "معارض استراتيجي إلزامي (Natural Dissenter)" if is_dissenter else "مستشار أساسي"

            if adv_id == "april-dunford":
                recommendation = (
                    "لا تسوّق المنظومة كأداة ذكاء اصطناعي عامة؛ موضِعها كـ «غرفة عمليات تنفيذية محمية سيبرانياً» "
                    "في مقابل بديل الفوضى الحالية (تشغيل 6 جلسات منفصلة وأدوات فحص مليئة بالإنذارات الكاذبة)."
                )
            elif adv_id == "alex-hormozi":
                recommendation = (
                    "قدّم عرض إطلاق لا يُرفض: فحص أمني أبيض فوري لمستودع العميل + محاكاة سرب مجانية لقراره القادم "
                    "خلال 10 دقائق بلا إعدادات معقدة، مع ربط الباقة الأعلى بتوفير ساعات الفريق."
                )
            elif adv_id == "seth-godin":
                recommendation = (
                    "ابدأ بأصغر جمهور متعطش ومؤثر: 100 مؤسس تقني ومدير أمن برمجيات في المنطقة العربية، "
                    "وابنِ معهم ثقة عميقة عبر تقارير فحص حقيقية موثقة بدلاً من الإعلانات الباردة."
                )
            elif adv_id == "byron-sharp":
                recommendation = (
                    "اعتراض منهجي: التركيز المفرط على شريحة ضيقة جداً قد يحدّ من التوافر الذهني؛ "
                    "يجب بناء هوية بصرية وعبارة واضحة يفهمها أي صاحب شركة فوراً حتى لو لم يكن خبيراً أمنياً."
                )
            elif adv_id == "rory-sutherland":
                recommendation = (
                    "اعتراض سلوكي: لا تبرر السعر بعدد الميزات التقنية، بل بقيمة «منع الكارثة المكلفة»؛ "
                    "وجود خانة «ينتظرك» وحدها يبرر الاشتراك لأنها تحمي المالك من أخطاء الأتمتة العشوائية."
                )
            else:
                recommendation = info["core_heuristic"]

            perspectives.append(
                {
                    "seat_number": idx + 1,
                    "advisor_id": adv_id,
                    "advisor_name": info["name"],
                    "title_ar": info["title_ar"],
                    "role_in_council": role_tag,
                    "is_dissenter": is_dissenter,
                    "dossier_verified_on_disk": dossier_loaded,
                    "dossier_grounding_excerpt": dossier_first_line,
                    "recommendation_ar": recommendation,
                }
            )

        synthesis = {
            "simulation_disclaimer_ar": "محاكاة استشارية مبنية على الأطر المنشورة لخبراء التسويق داخل مكتبة marketingskills وليست تصريحات شخصية مباشرة.",
            "question": question,
            "question_type": qtype,
            "stakes": stakes,
            "product_context_used": PRODUCT_CONTEXT_PATH.exists(),
            "seated_advisors": perspectives,
            "key_tension_ar": (
                "التوتر الجوهري بين التخصص العميق لفرق الأمن والتطوير (أبريل دانفورد وسيث غودين) "
                "وبين توسيع التوافر الذهني لرواد الأعمال غير التقنيين (بايرون شارب)."
            ),
            "unified_verdict_ar": (
                "الانطلاق برسالة مزدوجة الطبقات: واجهة تنفيذية فائقة البساطة للمالك («مدير تنفيذي واحد وخانة ينتظرك تحميك»)، "
                "مدعومة في العمق ببرهان هندسي مجاني (تقرير تدقيق كود أبيض + محاكاة قرار عبر MiroFish) لرفع التحويل بلا إنفاق إعلاني متسرع."
            ),
            "next_skill_handoffs": ["positioning", "pricing", "launch", "ai-seo"],
        }
        return synthesis

    def run_cli_tool_help_or_dry_run(self, tool_name: str, extra_args: Optional[List[str]] = None) -> Dict[str, Any]:
        """Safely invokes one of the 66 zero-dependency Node.js CLI tools in help or --dry-run mode."""
        safe_name = re.sub(r"[^a-z0-9\-]", "", tool_name.lower())
        script_path = self.clis_root / f"{safe_name}.js"
        if not script_path.exists():
            raise FileNotFoundError(f"CLI tool not found: {safe_name}.js")

        args = ["node", str(script_path)]
        if extra_args:
            args.extend(extra_args)
            if "--dry-run" not in args:
                args.append("--dry-run")

        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=10,
            env={**os.environ, "NO_COLOR": "1"},
        )
        stdout = proc.stdout.strip()
        parsed: Any = stdout
        try:
            parsed = json.loads(stdout)
        except Exception:
            pass
        return {
            "tool": safe_name,
            "script_path": str(script_path),
            "mode": "dry-run" if extra_args else "usage-spec",
            "exit_code": proc.returncode,
            "output": parsed,
        }
