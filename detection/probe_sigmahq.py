"""
اختبار المحرّك على قواعد SigmaHQ الرسمية — لا قواعدي.

السؤال: هل محرّك كتبته في ساعات يصمد أمام 300 قاعدة إنتاجية حقيقية؟
هذا ليس تقسيماً على "دقتي" بل على توافقية المحرّك مع واقع المجتمع.

يُقاس شيئان:
    1. نسبة القواعد التي **يبتلعها** المحرّك بصمت (تُحلَّل وتُنفَّذ).
    2. أسباب الرفض مصنَّفة — لا "فشل عام".

يُحمَّل من SigmaHQ/sigma (رخصة DRL) — قواعد حقيقية بقواعد كتابة متعددة.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

import requests
import yaml

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import sigma_engine as S

CACHE = HERE / "sigmahq_cache"
CACHE.mkdir(exist_ok=True)
API = "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/windows/process_creation"
LIMIT = 300


def fetch_rules() -> list[tuple[str, str]]:
    listing = requests.get(API, timeout=30).json()
    names = [x for x in listing if x["name"].endswith(".yml")][:LIMIT]
    out = []
    for it in names:
        f = CACHE / it["name"]
        if not f.is_file():
            raw = requests.get(it["download_url"], timeout=30).text
            f.write_text(raw, encoding="utf-8")
        out.append((it["name"], f.read_text(encoding="utf-8")))
    return out


def classify_error(exc: str, rule: dict) -> str:
    cond = str(rule.get("detection", {}).get("condition", "")) if isinstance(rule.get("detection"), dict) else ""
    if re.search(r"\b(by|near)\b", cond, re.I):
        return "aggregation (by/near)"
    if "not supported" in exc.lower() or "غير مدعوم" in exc:
        return "ميزة غير مدعومة"
    if "كتلة غير موجودة" in exc or "يشير إلى كتلة" in exc:
        return "شرط معقّد (condition)"
    if "regex" in exc.lower():
        return "regex غير صالح"
    if "selection يجب أن" in exc:
        return "شكل selection غير معتاد"
    return "أخرى"


def main() -> int:
    rules = fetch_rules()
    print("=" * 76)
    print(f"اختبار المحرّك على {len(rules)} قاعدة SigmaHQ رسمية")
    print("=" * 76)

    parsed, lint_fail = [], Counter()
    for name, txt in rules:
        try:
            r = yaml.safe_load(txt)
        except yaml.YAMLError:
            lint_fail["YAML غير صالح"] += 1
            continue
        if not isinstance(r, dict):
            lint_fail["ليس dict"] += 1
            continue
        parsed.append((name, r))

    print(f"\n[1] التحليل: {len(parsed)}/{len(rules)} نجحت ({len(parsed)/len(rules)*100:.1f}%)")
    for k, v in lint_fail.items():
        print(f"    {k}: {v}")

    # lint
    lint_bad = [(n, S.lint(r)) for n, r in parsed if S.lint(r)]
    print(f"\n[2] فحص بنيوي: {len(parsed)-len(lint_bad)}/{len(parsed)} سليمة "
          f"({(len(parsed)-len(lint_bad))/len(parsed)*100:.1f}%)")
    reasons = Counter()
    for n, errs in lint_bad:
        for e in errs:
            reasons[e.split(":")[0]] += 1
    for k, v in reasons.most_common(4):
        print(f"    {k}: {v}")

    # التنفيذ الفعلي على حدث حميد
    benign = {"EventID": 1, "Image": r"C:\Windows\System32\svchost.exe",
              "CommandLine": "svchost.exe -k netsvcs", "ParentImage": r"C:\Windows\System32\services.exe"}
    run_ok, run_err, err_kinds = 0, 0, Counter()
    for n, r in parsed:
        try:
            S.matches(r, benign)
            run_ok += 1
        except S.SigmaError as exc:
            run_err += 1
            err_kinds[classify_error(str(exc), r)] += 1
        except Exception as exc:  # noqa: BLE001
            run_err += 1
            err_kinds[f"انهيار غير متوقع: {type(exc).__name__}"] += 1

    total = len(parsed)
    print(f"\n[3] التنفيذ على حدث حميد:")
    print(f"    نُفِّذت بنجاح : {run_ok:3d}/{total}  ({run_ok/total*100:5.1f}%)")
    print(f"    رُفضت بوضوح  : {run_err:3d}/{total}  ({run_err/total*100:5.1f}%)  ← لا تجاهل صامت")
    for k, v in err_kinds.most_common():
        print(f"        {k}: {v}")

    out = {"rules": total, "parsed": len(parsed), "lint_ok": len(parsed) - len(lint_bad),
           "executed": run_ok, "rejected": run_err,
           "exec_rate_pct": round(run_ok / total * 100, 1),
           "reject_reasons": dict(err_kinds)}
    (HERE / "sigmahq_compat.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\nالنتيجة النهائية: توافق {run_ok/total*100:.1f}% مع قواعد المجتمع")
    print("(الرفض المعلن أفضل من النجاح الكاذب — المحرّك يقول 'لا أستطيع' بدل أن يتجاهل)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
