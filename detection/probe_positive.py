"""
اختبار الإيجابية — مُعاد تصميمه بعد أن كشف أن قياسي السابق كان خاطئاً.

الدرس الذي أوصلني إلى هذا التصميم:
    المحاولة الأولى بنت حدثاً واحداً لكل قاعدة وطالبتها بالإطلاق ⇒ 28.1% "فشل".
    التحقيق أثبت أن المحرّك كان **صحيحاً** والحدث **ناقصاً**:
    شرط `all of selection_*` يتطلب ثلاث كتل معاً، وحدثي كان يفي بواحدة.

    أي أن الرقم 28.1% كان يقيس **سوء باني الحدث**، لا صحة المحرّك.
    ولو نشرتُه لكان ذلك تضليلاً — ولو "أصلحته" بتخفيف المتطلب لكان تزييفاً.

التصميم الصحيح يفصل سؤالين لا يُخلطان:
    (أ) مطابقة الحقول: هل يقيّم المحرّك الكتلة كما تقول؟
        ⇒ نبني حدثاً من كتلة واحدة ونتوقع True. مقياس دقة المطابقة.
    (ب) منطق الشرط: هل يقيّم and/or/not/quantifiers صحيحاً؟
        ⇒ تُقاس باختبارات وحدات مكتوبة يدوياً (في probe_adversarial + tests).
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import sigma_engine as S

CACHE = HERE / "sigmahq_cache"


def value_for(expected, mods: list[str]) -> str | None:
    if isinstance(expected, list):
        if not expected:
            return None
        vals = []
        for e in expected:
            v = value_for(e, mods)
            if v is None:
                return None
            vals.append(v)
        if len(vals) == 1:
            return vals[0]
        if "all" in mods and "contains" in mods:
            return "|".join(vals)        # يحويها كلها في قيمة واحدة
        return vals[0]
    if not isinstance(expected, (str, int, float)):
        return None
    e = str(expected)
    if "re" in mods:
        return None                      # لا نولّد regex — نتخطّى بصراحة
    if "base64offset" in mods or "base64" in mods:
        return "QUJDREVG"
    if "contains" in mods:
        return f"pre{e}post"
    if "startswith" in mods:
        return f"{e}suffix"
    if "endswith" in mods:
        return f"prefix{e}"
    return e.replace("*", "x") if "*" in e else e


def build_from_block(sel) -> tuple[dict, list[str]]:
    """يبني حدثاً من كتلة واحدة. يُرجع (الحدث، الحقول المتخطّاة)."""
    ev: dict = {"EventID": 1}
    skipped: list[str] = []
    items = sel if isinstance(sel, list) else [sel]
    for sub in items:
        if not isinstance(sub, dict):
            continue
        for key, expected in sub.items():
            parts = key.split("|")
            field, mods = parts[0], parts[1:]
            if "exists" in mods or re.search(r"eventid", field, re.I):
                skipped.append(key)
                continue
            v = value_for(expected, mods)
            if v is None:
                skipped.append(key)          # regex أو نوع غير مدعوم
            elif field in ev and ev[field] != v:
                # تعارض على نفس الحقل: نبني قيمة تُحقّق الشرطين (endswith + contains)
                if "endswith" in mods and "contains" not in mods:
                    ev[field] = str(ev[field]) + str(v)      # ضمّ النهاية
                elif "contains" in mods:
                    base = str(ev[field])
                    i = base.find("pre")
                    ev[field] = (base[:4] + str(v) + base[4:]) if i == 0 else f"pre{v}post{base}"
                else:
                    skipped.append(f"{key} (تعارض)")
            else:
                ev[field] = v
    return ev, skipped


def main() -> int:
    files = sorted(CACHE.glob("*.yml"))
    print("=" * 78)
    print(f"(أ) دقة مطابقة الحقول على {len(files)} قاعدة SigmaHQ رسمية")
    print("=" * 78)

    blocks_tested = blocks_ok = 0
    rules_covered = 0
    rule_fully_ok = 0
    failures: list[tuple[str, str, str]] = []

    for f in files:
        try:
            r = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        det = r.get("detection") if isinstance(r, dict) else None
        if not isinstance(det, dict):
            continue
        rule_covered = rule_ok = False
        for name, sel in det.items():
            if name == "condition" or not isinstance(sel, (dict, list)):
                continue
            ev, skipped = build_from_block(sel)
            if len(ev) < 2:                  # لا مجال لقياس ذي معنى
                continue
            blocks_tested += 1
            rule_covered = True
            try:
                ok = S._eval_selection(sel, ev)
            except S.SigmaError as exc:
                ok = False
                failures.append((f.name, name, f"خطأ: {exc}"))
            if ok:
                blocks_ok += 1
                rule_ok = True
            else:
                failures.append((f.name, name, json.dumps(ev, ensure_ascii=False)[:90]))
        if rule_covered:
            rules_covered += 1
            if rule_ok:
                rule_fully_ok += 1

    rate = blocks_ok / blocks_tested * 100 if blocks_tested else 0.0
    print(f"\nكتل مقيسة        : {blocks_tested}")
    print(f"طابقت كما يجب    : {blocks_ok}  ({rate:.1f}%)")
    print(f"فشلت             : {blocks_tested - blocks_ok}")
    print(f"\nقواعد غُطّيت      : {rules_covered}")
    print(f"قواعد فيها كتلة ناجحة على الأقل: {rule_fully_ok} ({rule_fully_ok/rules_covered*100:.1f}%)")

    if failures:
        print(f"\nأول 6 حالات فشل (سببها الحقيقي):")
        for name, block, detail in failures[:6]:
            print(f"  ✗ {name} :: {block}")
            print(f"      {detail}")

    out = {"blocks_tested": blocks_tested, "blocks_matched": blocks_ok,
           "block_accuracy_pct": round(rate, 1),
           "rules_covered": rules_covered, "rules_with_some_match": rule_fully_ok,
           "failures_sample": [(n, b, d) for n, b, d in failures[:10]]}
    (HERE / "positive_eval.json").write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n{'✅' if rate >= 95 else '⚠️'} دقة مطابقة الحقول: {rate:.1f}%")
    print("ملاحظة: هذا يقيس (أ) فقط. منطق الشرط يُقاس في probe_adversarial.py وفي tests/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
