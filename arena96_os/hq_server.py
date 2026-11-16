"""
Arena 96 Live Background Command Center & Daemon v2.0 (`hq_server.py`)
Serves BOTH:
  - Suite A (Original 4 Business & Growth Pillars): Marketing (53 skills), Business HQ, 20 Connectors, MiroFish Market Swarm
  - Suite B (Proprietary 4 Cybersecurity-Specialized Pillars): CyberSkills-96 & 12-Seat Cyber Council,
    Hash-Chained Cyber-SOC HQ, SecOps-20 + CycloneDX SBOM, and CyberSwarm-96 Digital Twin Wargaming!

v2.0 Security Hardening (Driven by Cyber Defense Council Re-Analysis):
  - Enforces `MAX_BODY_BYTES = 65_536` (HTTP 413 against CWE-400 memory exhaustion).
  - Enforces Sliding-Window Per-Client Rate Limiting (HTTP 429 against flood/abuse).
  - Emits Defensive HTTP Security Headers (`X-Content-Type-Options: nosniff`, `Referrer-Policy`, iframe-compatible `Content-Security-Policy`).
  - Enforces Constant-Time CSRF/Session Guard (`hmac.compare_digest` on `X-Arena96-Token`).
"""

from __future__ import annotations

import collections
import hmac
import json
import os
import secrets
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Deque, Dict
from urllib.parse import parse_qs, urlparse

from arena96_os.layer1_marketing_engine import MarketingSkillsEngine
from arena96_os.layer2_company_hq import CompanyHQEngine, format_12h_ar
from arena96_os.layer3_connectors_hub import ConnectorsGatewayHub
from arena96_os.layer4_mirofish_swarm import MiroFishSwarmEngine

from arena96_cyber_prime.cyber_pillar1_skills_council import CyberSkillsCouncilEngine
from arena96_cyber_prime.cyber_pillar2_soc_hq import CyberSOCHQEngine
from arena96_cyber_prime.cyber_pillar3_secops_connectors import SecOpsConnectorsMesh
from arena96_cyber_prime.cyber_pillar4_cyberswarm_twin import CyberSwarmTwinEngine

PORT = int(os.environ.get("ARENA96_PORT", "8096"))
MAX_BODY_BYTES = 65_536  # 64 KB hard cap (CWE-400 mitigation)
RATE_LIMIT_PER_MIN = 90
SESSION_CSRF_TOKEN = secrets.token_hex(24)

# Original 4 Pillars
marketing_engine = MarketingSkillsEngine()
hq_engine = CompanyHQEngine()
connectors_hub = ConnectorsGatewayHub(hq=hq_engine, marketing=marketing_engine)
swarm_engine = MiroFishSwarmEngine()

# Specialized 4 Cyber-Prime Pillars
cyber_skills_engine = CyberSkillsCouncilEngine()
cyber_soc_hq = CyberSOCHQEngine()
secops_mesh = SecOpsConnectorsMesh(cyber_hq=cyber_soc_hq)
cyberswarm_engine = CyberSwarmTwinEngine()

_RATE_BUCKETS: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)
_RATE_LOCK = threading.Lock()

DAEMON_STATE: Dict[str, Any] = {
    "version": "2.0.0-cyber-prime",
    "started_at_12h": format_12h_ar(),
    "last_heartbeat_12h": format_12h_ar(),
    "heartbeat_ticks": 0,
    "ledger_integrity_verified": True,
}


def _check_rate_limit(client_ip: str) -> bool:
    now = time.monotonic()
    with _RATE_LOCK:
        dq = _RATE_BUCKETS[client_ip]
        while dq and (now - dq[0]) > 60.0:
            dq.popleft()
        if len(dq) >= RATE_LIMIT_PER_MIN:
            return False
        dq.append(now)
        return True


def _background_ritual_daemon() -> None:
    while True:
        DAEMON_STATE["heartbeat_ticks"] += 1
        DAEMON_STATE["last_heartbeat_12h"] = format_12h_ar()
        DAEMON_STATE["ledger_integrity_verified"] = cyber_soc_hq.verify_ledger_integrity()["valid"]
        time.sleep(30)


DASHBOARD_HTML_V2 = """<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>أرينا 96 v2.0 — القيادة المزدوجة (الأعمال + Cyber-Prime)</title>
<style>
  :root {
    --bg: #070d19; --panel: #0f172a; --panel2: #1e293b; --border: #334155;
    --text: #f8fafc; --muted: #94a3b8; --emerald: #10b981; --cyan: #06b6d4;
    --amber: #f59e0b; --danger: #ef4444;
  }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: system-ui, -apple-system, Tahoma, Arial, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
  header {
    background: linear-gradient(135deg, #042f2e 0%, #0f172a 55%, #1e1b4b 100%);
    border-bottom: 1px solid var(--border); padding: 18px 24px;
    display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px;
  }
  .brand h1 { margin: 0; font-size: 1.22rem; }
  .brand p { margin: 3px 0 0; font-size: 0.85rem; color: var(--muted); }
  .pill { padding: 5px 12px; border-radius: 999px; font-size: 0.78rem; font-weight: 700; background: rgba(16,185,129,0.16); color: #34d399; border: 1px solid rgba(16,185,129,0.4); }
  .pill.cyan { background: rgba(6,182,212,0.16); color: #22d3ee; border-color: rgba(6,182,212,0.4); }
  nav { display: flex; gap: 8px; padding: 11px 24px; background: #0b1120; border-bottom: 1px solid var(--border); overflow-x: auto; }
  nav button {
    background: var(--panel2); color: var(--text); border: 1px solid var(--border);
    padding: 8px 14px; border-radius: 8px; cursor: pointer; font-weight: 700; font-size: 0.86rem; white-space: nowrap;
  }
  nav button.active { background: var(--emerald); color: #022c22; border-color: var(--emerald); }
  main { max-width: 1320px; margin: 0 auto; padding: 20px 24px 48px; }
  .tab { display: none; } .tab.active { display: block; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(275px, 1fr)); gap: 15px; margin-bottom: 18px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px; margin-bottom: 16px; }
  .card h3 { margin: 0 0 8px; font-size: 0.98rem; }
  .stat-num { font-size: 1.7rem; font-weight: 800; color: var(--emerald); }
  .stat-num.cyan { color: var(--cyan); }
  input, select { width: 100%; background: #070d19; color: var(--text); border: 1px solid var(--border); border-radius: 8px; padding: 8px 11px; margin-bottom: 9px; font-family: inherit; }
  .btn { background: var(--emerald); color: #022c22; border: none; padding: 9px 15px; border-radius: 8px; font-weight: 800; cursor: pointer; }
  .btn.cyan { background: var(--cyan); color: #083344; }
  pre { background: #020617; border: 1px solid var(--border); border-radius: 8px; padding: 11px; overflow-x: auto; font-size: 0.82rem; white-space: pre-wrap; color: #cbd5e1; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { border-bottom: 1px solid var(--border); padding: 8px; text-align: right; }
</style>
</head>
<body>
<header>
  <div class="brand">
    <h1>🛡️👑 منظومة نور وأرينا 96 (الإصدار المطور v2.0 — 8 محركات خلفية نشطة)</h1>
    <p>نحتفظ بالمنظومات الأربع الأصلية للأعمال + 4 منظومات سيبرانية متطورة خاصة بنا (Cyber-Prime) بسجل SHA-256 غير قابل للعبث</p>
  </div>
  <div style="display:flex;gap:8px;flex-wrap:wrap;">
    <span class="pill" id="hbPill">الخلفية نشطة v2.0</span>
    <span class="pill cyan" id="shaPill">سلسلة SHA-256: موثقة</span>
  </div>
</header>

<nav>
  <button class="active" onclick="showTab('cyber-hq', this)">🛡️ الترسانة السيبرانية الخاصة (Cyber-Prime 1–3)</button>
  <button onclick="showTab('cyberswarm', this)">⚔️ التوأم الرقمي القتالي (CyberSwarm-96 #4)</button>
  <button onclick="showTab('orig-hq', this)">🏢 المنظومات الأربع الأصلية المحفوظة (الأعمال + MiroFish)</button>
</nav>

<main>
  <!-- CYBER PRIME 1-3 -->
  <section id="tab-cyber-hq" class="tab active">
    <div class="grid" id="cyberTopStats"></div>
    <div class="grid">
      <div class="card">
        <h3>🧠 مجلس حكماء الأمن السيبراني الـ 12 (مع الفريق الأحمر المعارض)</h3>
        <select id="cyberCouncilMode">
          <option value="code_audit_architecture">مراجعة هندسة فحص الكود وتحصين الخوادم</option>
          <option value="soc_and_detection">هندسة الكشف السلوكي والاستجابة الجنائية</option>
          <option value="cloud_and_supply_chain">تصلب الحاويات وسلاسل توريد مهارات AI</option>
        </select>
        <button class="btn cyan" onclick="runCyberCouncil()">اعقد جلسة حكماء الأمن</button>
        <div id="cyberCouncilOut" style="margin-top:10px;"></div>
      </div>
      <div class="card">
        <h3>⛓️ خلايا Cyber-SOC الست وسلسلة التجزئة SHA-256</h3>
        <div id="cyberCellsBox"></div>
      </div>
    </div>
    <div class="card">
      <h3>🔌 شبكة الموصلات السيبرانية العشرين (SecOps-20 + CycloneDX SBOM)</h3>
      <table>
        <thead><tr><th>الموصل السيبراني</th><th>المجال الأمني</th><th>الحالة</th><th>الوظيفة التخصصية</th></tr></thead>
        <tbody id="secopsTable"></tbody>
      </table>
    </div>
  </section>

  <!-- CYBERSWARM 4 -->
  <section id="tab-cyberswarm" class="tab">
    <div class="grid">
      <div class="card">
        <h3>⚔️ تشغيل مناورة التوأم الرقمي (CyberSwarm-96 — هجوم محاكى ضد دفاع آلي)</h3>
        <input id="wgArch" value="اختبار حصانة البنية المحدثة v2.0 أمام هجمات سلاسل التوريد واستنزاف الذاكرة" />
        <input id="wgUpgrade" value="تفعيل فحص Bidi/SKILL.md + كشف مسارات BaseHTTP + سقف 64KB ومحدد المعدل + سلسلة SHA-256" />
        <button class="btn cyan" onclick="runWargame()">شغّل مناورة CyberSwarm-96</button>
      </div>
      <div class="card">
        <h3>🎙️ استجواب مباشر للمهاجم المحاكى أو المدافع الآلي</h3>
        <input id="wgId" placeholder="معرف المناورة" />
        <select id="wgPersona">
          <option value="1">الوكيل #1 — مهاجم محاكى (تسميم مهارات AI ومحارف Bidi)</option>
          <option value="2">الوكيل #2 — مهاجم محاكى (استنزاف ذاكرة HTTP وتجاوز المسارات)</option>
          <option value="4">الوكيل #4 — مدافع آلي (فاحص AST SAST v2.0)</option>
        </select>
        <button class="btn" onclick="interrogatePersona()">استجوب الوكيل الآن</button>
        <div id="wgInterrogateOut" style="margin-top:10px;"></div>
      </div>
    </div>
    <div class="card">
      <h3>📊 نتائج انخفاض احتمالية الاختراق وتحسن MTTD / MTTR</h3>
      <div id="wargameReportBox"></div>
    </div>
  </section>

  <!-- ORIGINAL 4 KEPT INTACT -->
  <section id="tab-orig-hq" class="tab">
    <div class="grid" id="origStats"></div>
    <div class="card">
      <h3>✅ المنظومات الأربع الأصلية تعمل جنباً إلى جنب دون أي حذف</h3>
      <div id="origReports"></div>
    </div>
  </section>
</main>

<script>
const CSRF_TOKEN = "__SESSION_CSRF_TOKEN__";

function showTab(id, btn) {
  document.querySelectorAll('.tab').forEach(e => e.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  btn.classList.add('active');
}

async function apiGet(p) { return await (await fetch(p)).json(); }
async function apiPost(p, b) {
  return await (await fetch(p, {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Arena96-Token': CSRF_TOKEN},
    body: JSON.stringify(b)
  })).json();
}

async function refresh() {
  const d = await apiGet('/api/overview');
  document.getElementById('hbPill').textContent = 'نشط v2.0 · نبضة ' + d.daemon.last_heartbeat_12h;
  document.getElementById('shaPill').textContent = 'سجل SHA-256: ' + (d.cyber.ledger_integrity.valid ? 'سليم (' + d.cyber.ledger_integrity.entries_checked + ' كتل)' : 'تحذير');

  const latestWg = d.cyber.wargames[0];
  document.getElementById('cyberTopStats').innerHTML = `
    <div class="card"><h3>المهارات السيبرانية الخاصة</h3><div class="stat-num cyan">${d.cyber.skills_count}</div><div style="color:var(--muted);font-size:0.83rem;">+ ${d.cyber.clis_count} أدوات CLI أمنية + مجلس 12 خبيراً</div></div>
    <div class="card"><h3>خلايا Cyber-SOC والسجل</h3><div class="stat-num cyan">DEFCON ${d.cyber.board.defcon_level}</div><div style="color:var(--muted);font-size:0.83rem;">بصمة الرأس: ${d.cyber.ledger_integrity.head_sha256.slice(0,12)}...</div></div>
    <div class="card"><h3>شبكة SecOps-20 + SBOM</h3><div class="stat-num cyan">${d.cyber.secops_connectors.length}</div><div style="color:var(--muted);font-size:0.83rem;">إجمالي الموصلات المزدوجة: 40 موصلاً</div></div>
    <div class="card"><h3>المرونة الدفاعية (CyberSwarm-96)</h3><div class="stat-num">${latestWg ? latestWg.post_upgrade_resilience_percent + '%' : '—'}</div><div style="color:var(--muted);font-size:0.83rem;">هبوط خطر الاختراق: ${latestWg ? latestWg.pre_upgrade_breach_prob_percent + '% ← ' + latestWg.post_upgrade_breach_prob_percent + '%' : '—'}</div></div>
  `;

  document.getElementById('cyberCellsBox').innerHTML = d.cyber.board.cells.map(c =>
    `<div style="padding:7px 0;border-bottom:1px solid var(--border);font-size:0.86rem;">
      <strong>${c.name_ar}</strong> — <span style="color:#22d3ee;">المستوى ${c.level} (${c.rank_ar})</span><br/>
      <span style="color:var(--muted);">${c.current_task}</span>
    </div>`
  ).join('');

  document.getElementById('secopsTable').innerHTML = d.cyber.secops_connectors.map(s =>
    `<tr><td><strong>${s.name}</strong></td><td>${s.domain_ar}</td><td>${s.status_ar}</td><td style="color:var(--muted);">${s.capabilities_ar}</td></tr>`
  ).join('');

  if (latestWg) {
    document.getElementById('wgId').value = latestWg.wargame_id;
    document.getElementById('wargameReportBox').innerHTML = `
      <p><strong>${latestWg.executive_verdict_ar}</strong></p>
      <p>⏱️ زمن الاكتشاف (MTTD): <strong>${latestWg.mttd_improved_from_to_min}</strong> &nbsp;|&nbsp; زمن الاحتواء (MTTR): <strong>${latestWg.mttr_improved_from_to_min}</strong></p>
    `;
  }

  document.getElementById('origStats').innerHTML = `
    <div class="card"><h3>مهارات التسويق الأصلية المحفوظة</h3><div class="stat-num">${d.marketing.total_skills}</div><div style="color:var(--muted);font-size:0.83rem;">+ ${d.marketing.total_clis} أداة CLI (إجمالي المهارات المزدوجة: ${d.marketing.total_skills + d.cyber.skills_count})</div></div>
    <div class="card"><h3>مقر الشركة العام (team/)</h3><div class="stat-num">v${d.board.version}</div><div style="color:var(--muted);font-size:0.83rem;">6 أقسام أعمال + خانة ينتظرك</div></div>
    <div class="card"><h3>موصلات الأعمال الأصلية</h3><div class="stat-num">${d.connectors.length}</div><div style="color:var(--muted);font-size:0.83rem;">Google Drive + Excel متصلة</div></div>
    <div class="card"><h3>تأييد السوق المحدث (MiroFish)</h3><div class="stat-num">${d.simulations[0] ? d.simulations[0].final_support_percent + '%' : '—'}</div><div style="color:var(--muted);font-size:0.83rem;">قفزة التبني بعد الترقية السيبرانية</div></div>
  `;
  document.getElementById('origReports').innerHTML = d.board.recent_reports.slice(0, 4).map(r => `<pre>${r.formatted_5line}</pre>`).join('');
}

async function runCyberCouncil() {
  const mode = document.getElementById('cyberCouncilMode').value;
  const res = await apiPost('/api/cyber/council', {review_mode: mode});
  document.getElementById('cyberCouncilOut').innerHTML = res.seated_experts.map(e =>
    `<div style="padding:8px 0;border-bottom:1px solid var(--border);font-size:0.85rem;">
      <strong style="color:${e.is_red_team_dissenter ? '#f59e0b' : '#34d399'};">${e.title_ar}</strong><br/>${e.architectural_finding_ar}
    </div>`
  ).join('');
}

async function runWargame() {
  const arch = document.getElementById('wgArch').value;
  const upg = document.getElementById('wgUpgrade').value;
  const res = await apiPost('/api/cyber/wargame', {architecture_name: arch, upgrade_summary_ar: upg});
  document.getElementById('wgId').value = res.wargame_id;
  await refresh();
}

async function interrogatePersona() {
  const wid = document.getElementById('wgId').value;
  const pid = parseInt(document.getElementById('wgPersona').value, 10);
  const res = await apiPost('/api/cyber/interrogate', {wargame_id: wid, persona_id: pid, question_ar: 'كيف أثر الجيل الثاني v2.0 على مسارك؟'});
  document.getElementById('wgInterrogateOut').innerHTML = `<pre>${res.answer_ar}</pre>`;
}

refresh();
</script>
</body>
</html>
"""


class Arena96HQRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _add_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self' 'unsafe-inline'; frame-ancestors *;",
        )
        self.send_header("Cache-Control", "no-store")

    def _send_json(self, payload: Any, status: int = HTTPStatus.OK) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self._add_security_headers()
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, html: str) -> None:
        raw = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self._add_security_headers()
        self.end_headers()
        self.wfile.write(raw)

    def _verify_csrf_guard(self) -> bool:
        provided = self.headers.get("X-Arena96-Token", "")
        return hmac.compare_digest(provided, SESSION_CSRF_TOKEN)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self._send_html(DASHBOARD_HTML_V2.replace("__SESSION_CSRF_TOKEN__", SESSION_CSRF_TOKEN))
            return

        if parsed.path == "/api/health":
            self._send_json({"status": "ok", "daemon": DAEMON_STATE})
            return

        if parsed.path == "/api/overview":
            self._send_json(
                {
                    "daemon": DAEMON_STATE,
                    "board": hq_engine.read_board(),
                    "marketing": {
                        "total_skills": len(marketing_engine.list_skills()),
                        "total_clis": len(marketing_engine.list_cli_tools()),
                        "flagship": marketing_engine.list_skills(flagship_only=True),
                    },
                    "connectors": connectors_hub.list_connectors(),
                    "simulations": swarm_engine.list_saved_simulations(),
                    "cyber": {
                        "skills_count": len(cyber_skills_engine.list_cyber_skills()),
                        "clis_count": len(cyber_skills_engine.list_cyber_clis()),
                        "board": cyber_soc_hq.read_board(),
                        "ledger_integrity": cyber_soc_hq.verify_ledger_integrity(),
                        "secops_connectors": secops_mesh.list_secops_connectors(),
                        "wargames": cyberswarm_engine.list_wargames(),
                    },
                }
            )
            return

        self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        client_ip = self.client_address[0] if self.client_address else "unknown"
        if not _check_rate_limit(client_ip):
            self._send_json({"error": "Rate limit exceeded"}, status=HTTPStatus.TOO_MANY_REQUESTS)
            return

        if not self._verify_csrf_guard():
            self._send_json({"error": "Unauthorized: missing or invalid X-Arena96-Token"}, status=HTTPStatus.FORBIDDEN)
            return

        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_BODY_BYTES or length < 0:
            self._send_json({"error": f"Payload exceeds {MAX_BODY_BYTES} bytes limit"}, status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return

        body_bytes = self.rfile.read(length) if length > 0 else b"{}"
        payload = json.loads(body_bytes.decode("utf-8") or "{}")
        parsed = urlparse(self.path)

        if parsed.path == "/api/cyber/council":
            res = cyber_skills_engine.convene_cyber_defense_council(
                target_system="Arena 96 Unified Architecture v2.0",
                review_mode=payload.get("review_mode", "code_audit_architecture"),
            )
            self._send_json(res)
            return

        if parsed.path == "/api/cyber/wargame":
            wg = cyberswarm_engine.run_cyber_wargame(
                architecture_name=payload.get("architecture_name", "مناورة CyberSwarm-96"),
                rounds=10,
                persona_count=24,
                v2_countermeasure_injection={
                    "round": 4,
                    "upgrade_summary_ar": payload.get("upgrade_summary_ar", "ترقيات الجيل الثاني v2.0"),
                },
            )
            self._send_json(wg)
            return

        if parsed.path == "/api/cyber/interrogate":
            ans = cyberswarm_engine.interrogate_persona(
                wargame_id=payload["wargame_id"],
                persona_id=int(payload.get("persona_id", 1)),
                question_ar=payload.get("question_ar", "ما تقييمك؟"),
            )
            self._send_json(ans)
            return

        if parsed.path == "/api/marketing/council":
            res = marketing_engine.convene_marketing_council(
                question=payload.get("question", "تقييم خطة النمو"),
                question_type=payload.get("question_type", "launch"),
            )
            self._send_json(res)
            return

        self._send_json({"error": "Not found"}, status=HTTPStatus.NOT_FOUND)


def main() -> None:
    daemon_thread = threading.Thread(target=_background_ritual_daemon, daemon=True)
    daemon_thread.start()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Arena96HQRequestHandler)
    print(f"[Arena96 Dual Command Center v2.0] Listening on http://0.0.0.0:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
