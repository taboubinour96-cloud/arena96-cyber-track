"""
Cyber-Pillar #3 (Ordered Specialized Upgrade of Pillar #3):
SecOps-20 Connectors & Zero-Trust Guardrail Mesh (`cyber_pillar3_secops_connectors.py`)

Coexists alongside `layer3_connectors_hub.py` (which keeps the 20 business connectors),
delivering 20 specialized Cybersecurity & SecOps connectors across 6 security domains,
with native CycloneDX 1.5 SBOM generation, Excel Security Compliance Matrix export,
and Least-Agency Sovereign Firewall gating!
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import openpyxl
from openpyxl.styles import Alignment, Font, PatternFill

from .cyber_pillar2_soc_hq import CyberSOCHQEngine


@dataclass
class SecOpsConnectorSpec:
    slug: str
    name: str
    domain_ar: str
    mode: str  # NATIVE_ACTIVE | LIVE_CLOUD_SYNC | CLI_GUARDED | SOVEREIGN_GATED
    status_ar: str
    least_agency_gate: bool
    capabilities_ar: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


SECOPS_20_CATALOG: List[SecOpsConnectorSpec] = [
    # 1. فحص الكود والمستودعات (4)
    SecOpsConnectorSpec("ast_sast_v2", "AST Taint & SAST v2.0", "فحص الكود والمستودعات", "NATIVE_ACTIVE", "مفعّل محلياً (Python/JS/Go/PHP + ZipSlip/SSRF/Timing)", False, "فحص ثابت عميق وتتبع مصادر الإدخال غير الموثوقة"),
    SecOpsConnectorSpec("route_bola_mapper", "Route & BOLA Mapper v2.0", "فحص الكود والمستودعات", "NATIVE_ACTIVE", "مفعّل محلياً (FastAPI/Flask/Express/BaseHTTP)", False, "رسم خريطة المسارات والتحقق من حراس المصادقة والتفويض"),
    SecOpsConnectorSpec("ai_skill_firewall", "AI Skill & Trojan-Source Guard", "فحص الكود والمستودعات", "NATIVE_ACTIVE", "مفعّل محلياً (فحص SKILL.md ومحارف Bidi الخفية)", False, "كشف حقن البرومبت غير المباشر ومحارف اليونيكود الخادعة"),
    SecOpsConnectorSpec("sarif_bridge", "SARIF 2.1.0 Code-Scanning Bridge", "فحص الكود والمستودعات", "NATIVE_ACTIVE", "مفعّل محلياً (مخرجات قياسية متوافقة مع GitHub)", True, "توليد ملفات SARIF موحدة وموقعة ببصمة SHA-256"),
    # 2. سلاسل التوريد والحاويات (4)
    SecOpsConnectorSpec("cyclonedx_sbom", "CycloneDX 1.5 SBOM Engine", "سلاسل التوريد والحاويات", "NATIVE_ACTIVE", "مفعّل محلياً بالكامل", False, "توليد جرد مكونات البرمجيات وبصمات الملفات التشفيرية"),
    SecOpsConnectorSpec("osv_vuln_feed", "OSV.dev Vulnerability Matcher", "سلاسل التوريد والحاويات", "NATIVE_ACTIVE", "مفعّل عبر dependency_osv_auditor", False, "مطابقة الحزم مع قواعد الثغرات المفتوحة بدون تسريب الكود"),
    SecOpsConnectorSpec("docker_cis_guard", "Docker & CIS Container Auditor", "سلاسل التوريد والحاويات", "NATIVE_ACTIVE", "مفعّل محلياً", False, "كشف تشغيل root وصلاحيات privileged وتثبيت الصور"),
    SecOpsConnectorSpec("cicd_actions_guard", "CI/CD Workflow Supply-Chain Guard", "سلاسل التوريد والحاويات", "NATIVE_ACTIVE", "مفعّل محلياً (v2.0)", False, "كشف pull_request_target والإجراءات غير المثبتة ببصمة SHA"),
    # 3. الرصد وهندسة الاكتشاف SIEM/EDR (4)
    SecOpsConnectorSpec("sigma_engine", "Sigma Behavioral Rule Engine", "الرصد وهندسة الاكتشاف", "NATIVE_ACTIVE", "مفعّل عبر مختبر المرحلة 6", False, "تشغيل واختبار قواعد Sigma السلوكية مع فلاتر الاستثناء"),
    SecOpsConnectorSpec("pcap_forensics", "libpcap Network Forensics Analyzer", "الرصد وهندسة الاكتشاف", "NATIVE_ACTIVE", "مفعّل عبر مختبر المرحلة 4", False, "تحليل الحزم الثنائية وكشف أنفاق DNS والنبضات الدورية"),
    SecOpsConnectorSpec("pe_elf_entropy", "PE/ELF Header & Shannon Entropy Triage", "الرصد وهندسة الاكتشاف", "NATIVE_ACTIVE", "مفعّل عبر مختبر المرحلة 6", False, "فحص الترويسات التنفيذية وكشف الضغط والتشفير المشبوه"),
    SecOpsConnectorSpec("siem_correlator", "SIEM Multi-Event Correlator", "الرصد وهندسة الاكتشاف", "NATIVE_ACTIVE", "مفعّل عبر مختبر المرحلة 4", False, "ربط محاولات الاختراق المتسلسلة وإصدار تنبيهات عالية الدقة"),
    # 4. استخبارات التهديدات وتسعير المخاطر (3)
    SecOpsConnectorSpec("mitre_attack_matrix", "MITRE ATT&CK v15 Coverage Mapper", "استخبارات التهديدات والمخاطر", "NATIVE_ACTIVE", "مفعّل محلياً", False, "ربط النتائج بتكتيكات وتقنيات المهاجمين وقياس التغطية"),
    SecOpsConnectorSpec("cvss_rbvm_engine", "CVSS v3.1 + RBVM SLA Prioritizer", "استخبارات التهديدات والمخاطر", "NATIVE_ACTIVE", "مفعّل محلياً", False, "حساب الشدة الكمية وتحديد أولويات المعالجة P0–P3"),
    SecOpsConnectorSpec("cyberswarm_twin", "CyberSwarm-96 Threat Predictor", "استخبارات التهديدات والمخاطر", "NATIVE_ACTIVE", "مفعّل في الخلفية", False, "محاكاة مسارات الهجوم والدفاع عبر التوأم الرقمي"),
    # 5. الأدلة الجنائية والحوكمة والتوثيق (3)
    SecOpsConnectorSpec("dfir_custody_vault", "DFIR SHA-256 Chain-of-Custody Vault", "الأدلة الجنائية والحوكمة", "NATIVE_ACTIVE", "مفعّل بسلسلة تجزئة مترابطة", False, "حفظ الأدلة وتقارير التدقيق بختم زمني وبصمة غير قابلة للعبث"),
    SecOpsConnectorSpec("gdrive_cyber_ledger", "Google Drive Secure Sync (ارينا 96)", "الأدلة الجنائية والحوكمة", "LIVE_CLOUD_SYNC", "متصل حياً بمجلد ارينا 96", False, "مزامنة سجل التقدم والمحادثات تلقائياً مع Google Drive"),
    SecOpsConnectorSpec("excel_grc_exporter", "Excel GRC & NIST CSF 2.0 Exporter", "الأدلة الجنائية والحوكمة", "NATIVE_ACTIVE", "مفعّل محلياً (.xlsx)", False, "تصدير مصفوفة الامتثال والضوابط بصيغة إكسل عربية"),
    # 6. الترقيع المحكوم والإفصاح السيادي (2)
    SecOpsConnectorSpec("defensive_patch_synth", "Defensive Patch Synthesizer", "الترقيع والإفصاح السيادي", "SOVEREIGN_GATED", "يجهز الترقيعات محلياً وينتظر تفويض نور للنشر", True, "توليد ترقيعات تحافظ على سلوك البرنامج وتمنع الثغرة"),
    SecOpsConnectorSpec("cvd_disclosure_gate", "Coordinated Disclosure Portal Gate", "الترقيع والإفصاح السيادي", "SOVEREIGN_GATED", "مقفل ببوابة التفويض السيادي لنور (HITL إلزامي)", True, "مراجعة بشرية إلزامية ومنع إرسال أي بلاغ خارجي تلقائياً"),
]


class SecOpsConnectorsMesh:
    """Arena 96's specialized 20-Connector Cybersecurity & Supply-Chain Mesh."""

    def __init__(self, cyber_hq: CyberSOCHQEngine):
        self.cyber_hq = cyber_hq
        self._map = {c.slug: c for c in SECOPS_20_CATALOG}

    def list_secops_connectors(self) -> List[Dict[str, Any]]:
        return [c.to_dict() for c in SECOPS_20_CATALOG]

    def generate_workspace_cyclonedx_sbom(
        self,
        target_root: Path = Path("/home/user"),
        out_path: Path = Path("/home/user/arena96_cyber_prime/data/arena96_cyclonedx_sbom.json"),
    ) -> Dict[str, Any]:
        """Generates a real CycloneDX 1.5 JSON SBOM with cryptographic SHA-256 hashes of our Python modules."""
        out_path.parent.mkdir(parents=True, exist_ok=True)
        components: List[Dict[str, Any]] = []
        tracked_pkgs = ["cybersec_branch", "arena96_os", "arena96_cyber_prime"]

        for pkg in tracked_pkgs:
            pkg_dir = target_root / pkg
            if not pkg_dir.exists():
                continue
            for py_file in sorted(pkg_dir.glob("*.py")):
                digest = hashlib.sha256(py_file.read_bytes()).hexdigest()
                components.append(
                    {
                        "type": "library",
                        "bom-ref": f"pkg:arena96/{pkg}/{py_file.name}@2.0.0",
                        "group": pkg,
                        "name": py_file.name,
                        "version": "2.0.0",
                        "hashes": [{"alg": "SHA-256", "content": digest}],
                    }
                )

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "component": {
                    "type": "application",
                    "name": "Arena96-Cyber-And-Swarm-Suite",
                    "version": "2.0.0",
                    "authors": [{"name": "نور & أرينا 96"}],
                },
            },
            "components": components,
        }
        out_path.write_text(json.dumps(sbom, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"path": str(out_path), "components_count": len(components), "spec": "CycloneDX 1.5"}

    def export_cyber_compliance_excel(
        self,
        reanalysis_metrics: Dict[str, Any],
        out_path: Path = Path("/home/user/arena96_cyber_prime/data/مصفوفة_الأمن_والتطوير_الجيل_الثاني_أرينا_96.xlsx"),
    ) -> str:
        """Exports an Arabic RTL .xlsx Cybersecurity Upgrade & SecOps-20 Matrix."""
        out_path.parent.mkdir(parents=True, exist_ok=True)
        wb = openpyxl.Workbook()
        ws1 = wb.active
        ws1.title = "مقارنة_الجيل_الأول_والثاني"
        ws1.sheet_view.rightToLeft = True

        hdr_fill = PatternFill(start_color="064E3B", end_color="064E3B", fill_type="solid")
        hdr_font = Font(color="FFFFFF", bold=True, size=11)

        headers1 = ["المحور الهندسي", "قبل التطوير (الجيل الأول v1.0)", "بعد إعادة التحليل والتطوير (الجيل الثاني v2.0)", "الأثر الأمني المحقق"]
        ws1.append(headers1)
        for col in range(1, 5):
            c = ws1.cell(row=1, column=col)
            c.fill = hdr_fill
            c.font = hdr_font
            c.alignment = Alignment(horizontal="right")

        for row in reanalysis_metrics.get("comparison_rows", []):
            ws1.append([row["axis"], row["v1"], row["v2"], row["impact"]])

        ws2 = wb.create_sheet("موصلات_الأمن_السيبراني_20")
        ws2.sheet_view.rightToLeft = True
        headers2 = ["الموصل الأمني", "المجال", "الوضع التشغيلي", "الحالة", "بوابة التفويض السيادي", "الوظيفة"]
        ws2.append(headers2)
        for col in range(1, 7):
            c = ws2.cell(row=1, column=col)
            c.fill = hdr_fill
            c.font = hdr_font
            c.alignment = Alignment(horizontal="right")

        for spec in SECOPS_20_CATALOG:
            ws2.append([
                spec.name,
                spec.domain_ar,
                spec.mode,
                spec.status_ar,
                "مقفل بتفويض نور" if spec.least_agency_gate else "فحص دفاعي محلي آمن",
                spec.capabilities_ar,
            ])

        wb.save(str(out_path))
        return str(out_path)
