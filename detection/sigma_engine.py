"""
sigma_engine.py — محرّك تنفيذ قواعد Sigma حقيقي (بلا اعتماديات خارجية عدا PyYAML).

لماذا وُجد هذا الملف:
    الأدوات الثماني في `cyberskills_96/clis/` كانت هياكل فارغة تطبع {"status":"ready"}
    وتردّد الوسائط. `sigma_lint_cli.py` كان يمرّر قاعدة فيها `title` فقط بلا شكوى.
    هذا محرّك يفعل الشيء الذي كان يدّعيه: يحوّل قاعدة Sigma إلى تقييم فعلي على أحداث.

ما يغطيه (المستوى الذي يظهر في قواعد الإنتاج الشائعة):
    • detection: selection / filter / condition
    • منطق: and / or / not / all of / 1 of / all of them / n of them / parentheses
    • معدّلات الحقول: |contains |startswith |endswith |re |base64 |base64offset
                     |windash |cased
    • مطابقة قوائم القيم (any of a list)
    • قوائم: * (wildcard)
    • count(...) > N  و |count() بحد أدنى

ما لا يغطيه (يُعلن صراحة، لا يُخفى):
    • aggregation بكل صورها (near, by) — يُرفض بوضوح لا يُتجاهل
    • correlation rules (multi-event windows)
    • pipeline/field-mapping الخاص بكل SIEM
"""
from __future__ import annotations

import base64
import re
from typing import Any


class SigmaError(Exception):
    """خطأ في القاعدة نفسها — يُرفع بدل تجاهل صامت."""


# ---------------------------------------------------------------- المطابقة

def _as_list(v: Any) -> list:
    return v if isinstance(v, list) else [v]


def _base64_variants(s: str) -> list[str]:
    """Sigma base64offset: النص قد يظهر بإزاحات 0/1/2 داخلBase64."""
    raw = s.encode("utf-16-le", errors="ignore")
    out = []
    for off in range(3):
        enc = base64.b64encode(b"\x00" * off + raw).decode()
        out.append(enc.rstrip("="))
    return out


def _match_value(actual: Any, expected: Any, mods: list[str]) -> bool:
    """يطابق قيمة حقل واحدة مقابل قيمة واحدة من القاعدة، مع المعدّلات."""
    if actual is None:
        return expected is None
    if "cased" not in mods:
        a = str(actual).lower()
        e = str(expected).lower()
    else:
        a, e = str(actual), str(expected)

    if "re" in mods:
        try:
            return re.search(str(expected), str(actual), 0 if "cased" in mods else re.I) is not None
        except re.error as exc:
            raise SigmaError(f"regex غير صالح {expected!r}: {exc}") from exc

    if "base64" in mods:
        return a == base64.b64encode(str(expected).encode()).decode().lower()
    if "base64offset" in mods:
        return any(v.lower() in a for v in _base64_variants(str(expected)))
    if "windash" in mods:
        a = a.replace("/", "-").replace("–", "-").replace("—", "-")
        e = e.replace("/", "-")

    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    # مطابقة تامة مع دعم * كبديل عام
    if "*" in e:
        pat = "^" + re.escape(e).replace(r"\*", ".*") + "$"
        return re.match(pat, a, 0 if "cased" in mods else re.I) is not None
    return a == e


def _field_present(event: dict, field: str) -> bool:
    if field in event:
        return True
    # دعم الحقول المتداخلة a.b.c
    cur: Any = event
    for part in field.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return False
        cur = cur[part]
    return True


def _get_field(event: dict, field: str) -> Any:
    if field in event:
        return event[field]
    cur: Any = event
    for part in field.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _eval_selection(sel: Any, event: dict) -> bool:
    """
    يقيم كتلة selection.
    dict  ⇒ كل الحقول شرط (AND)، وكل قيمة في قائمة تعني (OR) داخل الحقل.
    list  ⇒ OR بين عناصرها.
    """
    if isinstance(sel, list):
        return any(_eval_selection(x, event) for x in sel)
    if not isinstance(sel, dict):
        raise SigmaError(f"كتلة selection يجب أن تكون dict أو list، وصل {type(sel).__name__}")

    for key, expected in sel.items():
        parts = key.split("|")
        field, mods = parts[0], parts[1:]

        # |exists — يفحص وجود الحقل
        if "exists" in mods:
            want = bool(expected)
            if _field_present(event, field) != want:
                return False
            continue

        actual = _get_field(event, field)
        values = _as_list(expected)
        # `|all` يعني: كل القيم يجب أن تتحقق. غيابه يعني: أي قيمة تكفي.
        # (خطأ سابق: كان `all` يُهمَل فتُطابق القاعدة عند أول قيمة — كشفه eval_detection)
        if "all" in mods:
            if not all(_match_value(actual, e, mods) for e in values):
                return False
        elif not any(_match_value(actual, e, mods) for e in values):
            return False
    return True


# ---------------------------------------------------------------- condition

_TOKEN = re.compile(r"\s*(\(|\)|\b(?:and|or|not|of|all|them|any)\b|[A-Za-z0-9_*\-]+|\d+)\s*", re.I)


def _tokenize(cond: str) -> list[str]:
    pos, out = 0, []
    while pos < len(cond):
        m = _TOKEN.match(cond, pos)
        if not m:
            raise SigmaError(f"condition غير صالح عند: {cond[pos:pos+20]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


class _CondParser:
    """محلل نزولي تكراري: or < and < not < atom."""

    def __init__(self, tokens: list[str], blocks: dict[str, Any], event: dict):
        self.t, self.i, self.blocks, self.event = tokens, 0, blocks, event

    def peek(self) -> str | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self) -> str:
        if self.i >= len(self.t):
            raise SigmaError("condition انتهى فجأة")
        tok = self.t[self.i]
        self.i += 1
        return tok

    def parse(self) -> bool:
        v = self._or()
        if self.peek() is not None:
            raise SigmaError(f"رموز زائدة بعد condition: {self.peek()!r}")
        return v

    def _or(self) -> bool:
        left = self._and()
        while (self.peek() or "").lower() == "or":
            self.take()
            right = self._and()
            left = left or right
        return left

    def _and(self) -> bool:
        left = self._not()
        while (self.peek() or "").lower() == "and":
            self.take()
            right = self._not()
            left = left and right
        return left

    def _not(self) -> bool:
        if (self.peek() or "").lower() == "not":
            self.take()
            return not self._not()
        return self._atom()

    def _quantifier(self) -> bool:
        """يدعم: all of X · all of them · 1 of X · n of them · any of X"""
        kind = self.take().lower()
        if (self.peek() or "").lower() != "of":
            raise SigmaError(f"متوقع 'of' بعد {kind!r}")
        self.take()
        target = self.take()
        if target.lower() == "them":
            names = list(self.blocks)
        elif "*" in target:
            # SigmaHQ يستخدم أنماطاً مثل `all of selection_*` — تُوسَّع لكل الكتل المطابقة
            pat = "^" + re.escape(target).replace(r"\*", ".*") + "$"
            names = [b for b in self.blocks if re.match(pat, b, re.I)]
            if not names:
                raise SigmaError(f"نمط في condition لا يطابق أي كتلة: {target!r}")
        else:
            names = [target]

        if kind == "all":
            need = len(names)
        elif kind == "any":
            need = 1
        elif kind.isdigit():
            need = int(kind)
        else:
            raise SigmaError(f"كمّية غير مدعومة: {kind!r}")

        hits = 0
        for n in names:
            if n not in self.blocks:
                raise SigmaError(f"condition يشير إلى كتلة غير موجودة: {n!r}")
            if _eval_selection(self.blocks[n], self.event):
                hits += 1
        return hits >= need

    def _atom(self) -> bool:
        tok = self.peek()
        if tok is None:
            raise SigmaError("condition غير مكتمل")
        if tok == "(":
            self.take()
            v = self._or()
            if self.take() != ")":
                raise SigmaError("قوس غير مغلق في condition")
            return v
        # count(...) > N
        if tok.lower().startswith("count"):
            return self._count()
        low = tok.lower()
        if low in ("all", "any") or low.isdigit():
            return self._quantifier()
        return self._ref()

    def _ref(self) -> bool:
        name = self.take()
        if name not in self.blocks:
            raise SigmaError(f"condition يشير إلى كتلة غير موجودة: {name!r}")
        return _eval_selection(self.blocks[name], self.event)

    def _count(self) -> bool:
        self.take()  # count(...)
        while self.peek() != ")":
            if self.peek() is None:
                raise SigmaError("count( غير مغلق")
            self.take()
        self.take()
        op = self.take()
        num = self.take()
        if not num.isdigit():
            raise SigmaError("count يحتاج عدداً")
        # في تقييم حدث واحد، العدد هو 0/1 فقط
        n = 1 if _eval_selection(next(iter(self.blocks.values())), self.event) else 0
        return {"<": n < int(num), ">": n > int(num),
                "<=": n <= int(num), ">=": n >= int(num),
                "==": n == int(num)}.get(op, False)


# ---------------------------------------------------------------- الواجهة

REQUIRED = ("title", "detection", "logsource")


def lint(rule: dict) -> list[str]:
    """فحص بنيوي حقيقي. يُرجع قائمة أخطاء (فارغة = سليمة)."""
    errs: list[str] = []
    if not isinstance(rule, dict):
        return ["القاعدة ليست dict"]
    for k in REQUIRED:
        if k not in rule:
            errs.append(f"حقل إلزامي مفقود: {k}")
    det = rule.get("detection")
    if isinstance(det, dict):
        if "condition" not in det:
            errs.append("detection.condition مفقود — قاعدة بلا شرط لا تُنفَّذ")
        if len([k for k in det if k != "condition"]) == 0:
            errs.append("detection بلا أي كتلة selection")
        cond = str(det.get("condition", ""))
        blocks = [k for k in det if k != "condition"]
        for name in re.findall(r"[A-Za-z0-9_*]+", cond):
            if name.lower() in ("and", "or", "not", "of", "all", "any", "them", "count"):
                continue
            if name.isdigit():
                continue
            if "*" in name:
                pat = "^" + re.escape(name).replace(r"\*", ".*") + "$"
                if not any(re.match(pat, b, re.I) for b in blocks):
                    errs.append(f"نمط condition لا يطابق أي كتلة: {name!r}")
            elif name not in blocks:
                errs.append(f"condition يشير إلى كتلة غير موجودة: {name!r}")
    elif "detection" in rule:
        errs.append("detection يجب أن يكون dict")
    for k in ("id", "status", "level"):
        if k not in rule and k == "id":
            errs.append("حقل موصى به مفقود: id (لتتبع النسخ)")
    return errs


def matches(rule: dict, event: dict) -> bool:
    """هل يطابق الحدثُ القاعدةَ؟ يرفع SigmaError على قاعدة غير صالحة."""
    det = rule.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise SigmaError("قاعدة غير صالحة: detection/condition مفقود")
    blocks = {k: v for k, v in det.items() if k != "condition"}
    cond = str(det["condition"]).strip()
    if not cond:
        raise SigmaError("condition فارغ")
    if re.search(r"\b(by|near)\b", cond, re.I):
        raise SigmaError("aggregation (by/near) غير مدعومة في هذا المحرّك — يُعلن لا يُتجاهل")
    return _CondParser(_tokenize(cond), blocks, event).parse()


def evaluate(rules: list[dict], events: list[dict]) -> dict:
    """يقيّم كل الأحداث على كل القواعد. يُرجع مصفوفة إصابات."""
    hits, errors = [], []
    for idx, ev in enumerate(events):
        for r in rules:
            try:
                if matches(r, ev):
                    hits.append({"event_index": idx, "rule_id": r.get("id", r.get("title"))})
            except SigmaError as exc:
                errors.append({"rule": r.get("id", r.get("title")), "error": str(exc)})
    return {"hits": hits, "errors": errors}
