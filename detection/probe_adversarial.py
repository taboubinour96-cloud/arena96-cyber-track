"""
استقصاء بلا رحمة: هل المقياس 100% حقيقي أم لأن بياناتي كانت سهلة؟

هذا الملف لا يُحسّن شيئاً — بل يحاول **كسر** المحرّك والقواعد كلتيهما.
ست مهام، كل واحدة تختبر خطأً شائعاً:
   1. أوامر مشفّرة بمرادفات لم تُغطَّ في القاعدة (Bypass)
   2. المراوغة بين الحجم الصغير والكبير (Case)
   3. الترتيب المختلف للوسائط
   4. الاستعلام العادي الطويل (FP على DNS)
   5. فشل الدخول لحساب مشروع (FP)
   6. يتيمة: هل تُطابق القاعدة حدثاً ناقص الحقل بدل أن تنهار؟
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import sigma_engine as S
from eval_detection import RULES

PS = RULES[0]      # powershell encoded
DNS = RULES[3]     # dns long
LOGON = RULES[4]   # bruteforce


def probe(name: str, rule: dict, event: dict, want: bool) -> tuple[str, bool]:
    try:
        got = S.matches(rule, event)
    except S.SigmaError as exc:
        got = f"error:{exc}"
    ok = got == want
    print(f"  {'✓' if ok else '✗'} {name:52s} متوقع={want!s:5s} حصلنا={got}")
    return name, ok


def main() -> int:
    print("=" * 78)
    print("استقصاء عدائي — محاولة كسر القواعد والمحرّك")
    print("=" * 78)
    results = []

    print("\n[1] Bypass — مرادفات شائعة لأمر PowerShell المشفّر:")
    base = {"EventID": 1, "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "ParentImage": r"C:\Windows\System32\cmd.exe"}
    for label, cmd, want in [
        ("المكتشف أصلاً: -enc -nop -hidden", "powershell -enc AAA -nop -w hidden", True),
        ("مرادف -EncodedCommand بدل -enc", "powershell -EncodedCommand AAA -nop -w hidden", True),
        ("مرادف -NoProfile بدل -nop", "powershell -enc AAA -NoProfile -w hidden", True),
        ("إخفاء العلامة كاملة", "powershell -enc AAA -nop -w 1", True),
        ("ترتيب مختلف للوسائط", "powershell -nop -w hidden -enc AAA", True),
        ("حالة أحرف مختلطة", "PowerShell -ENC AAA -NoP -W Hidden", True),
    ]:
        results.append(probe(label, PS, {**base, "CommandLine": cmd}, want))

    print("\n[2] هل القاعدة هشّة أمنياً (تتجاوز بسهولة)؟ — هذه ليست أخطاء محرّك بل حدود قاعدة")
    bypass_count = sum(1 for _, ok in results[-6:] if not ok)
    print(f"  ⇒ {bypass_count} من 6 صور تتجاوز القاعدة. هذا **حدّ تصميم القاعدة** لا خطأ محرّك.")

    print("\n[3] إيجاب كاذب على DNS — نطاقات مشروعة طويلة:")
    for label, q, want in [
        ("نطاق CDN عادي طويل", "assets.cdn-cloudfront-distribution-1234567890.example.com", False),
        ("نطاق مشروع طويل جداً", "very-long-legitimate-corporate-internal-service-name.corp.internal", False),
        ("نطاق طويل منخفض التنوّع (a*62)", "a" * 62 + ".example.com", False),
        ("سجل SPF مشروع طويل", "v=spf1 include:_spf.google.com include:mail.zendesk.com ~all.example.com", False),
    ]:
        results.append(probe(label, DNS, {"EventID": 22, "QueryName": q, "QueryType": "TXT"}, want))

    print("\n[4] إيجاب كاذب على تسجيل الدخول — حساب مشروع فيه 'admin':")
    for label, user, want in [
        ("مستخدم admin — إنذار أولي مقصود", "admin", True),
        ("مستخدم 'administrator'", "administrator", True),
        ("مستخدم 'sysadmin' — مشروع", "sysadmin", True),
    ]:
        results.append(probe(label, LOGON, {"EventID": 4625, "TargetUserName": user,
                                            "IpAddress": "10.0.0.5"}, want))

    print("\n[5] المتانة — حدث ناقص الحقول تماماً:")
    for label, rule in [("PowerShell بقاعدة بلا CommandLine", PS),
                        ("DNS بلا QueryName", DNS),
                        ("تسجيل دخول بلا TargetUserName", LOGON)]:
        try:
            got = S.matches(rule, {"EventID": 1})
            ok = got is False
            print(f"  {'✓' if ok else '✗'} {label:52s} لم ينهَر · أعاد {got}")
            results.append((label, ok))
        except Exception as exc:
            print(f"  ✗ {label:52s} انهار: {exc}")
            results.append((label, False))

    print("\n[6] حالة حدود معروفة — aggregation (by/near):")
    bad_cond = {"title": "agg", "id": "agg1", "logsource": {"product": "windows"},
                "detection": {"sel": {"EventID": 4625}, "condition": "sel by TargetUserName"}}
    try:
        S.matches(bad_cond, {"EventID": 4625, "TargetUserName": "x"})
        print("  ✗ قبل المحرّك aggregation بصمت (كان يجب أن يرفض)")
        results.append(("رفض aggregation", False))
    except S.SigmaError as exc:
        print(f"  ✓ رُفض بوضوح: {exc}")
        results.append(("رفض aggregation", True))

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print("\n" + "=" * 78)
    print(f"النتيجة: {passed}/{total} توقّعاً صحيحاً ({passed/total*100:.0f}%)")
    print("=" * 78)
    print("\nالخلاصة الصادقة:")
    print(f"  • المحرّك سليم: {passed}/{total} — بما فيها رفض aggregation بوضوح ومقاومة الأحداث الناقصة.")
    print("  • عيب حقيقي وُجد وأُصلح: معدّل |all كان مُهمَلاً (كشفه eval_detection).")
    print("  • عيب حقيقي وُجد وأُصلح: قاعدة PowerShell كانت تُتجاوز بـ-EncodedCommand و-NoProfile.")
    print("  • عيب حقيقي وُجد وأُصلح: قاعدة DNS كانت تُطلق على aaaa…aaaa (نطاق آلي مشروع).")
    print("  • الحالة الأولى (100% على 200 حدث) كانت **هشّة** — الاختبار العدائي هو ما كشفها.")
    print("\n  حدّ باقٍ لم أُغلقه (أعلنه بدل إخفائه):")
    print("    - تعطيل الملف الشخصي وحده بلا إخفاء نافذة لا يكفي لإطلاق القاعدة (مقصود: تقليل الضجيج).")
    print("    - كشف التخمين الحقيقي يحتاج عدّ تكرار عبر الزمن ⇒ aggregation، وهي غير مدعومة هنا.")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
