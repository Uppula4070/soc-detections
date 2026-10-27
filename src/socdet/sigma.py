"""A small, tested subset of the Sigma rule format.

Supported:
- selections as a map (all fields must match) or a list of maps (any map matches)
- field modifiers: contains, startswith, endswith, all; plain values with * and ? wildcards
- conditions: and, or, not, parentheses, "1 of sel_*", "all of sel_*", "1 of them"
- Sigma v1 aggregation: "selection | count() by Field > N" and "count(Field) by Group > N" (distinct values),
  evaluated over the rule's `timeframe` window
Matching is case-insensitive, as in Sigma.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import yaml

MODIFIERS = {"contains", "startswith", "endswith", "all"}
LEVELS = ["informational", "low", "medium", "high", "critical"]
AGG_PATTERN = re.compile(r"^count\((\w*)\)(?:\s+by\s+([\w.]+))?\s*(>=|>)\s*(\d+)$")
TIMESTAMP_FIELDS = {"windows": "TimeCreated", "aws": "eventTime"}


class RuleError(Exception):
    pass


@dataclass
class FieldTest:
    field: str
    modifiers: list[str]
    values: list


@dataclass
class Aggregation:
    distinct_field: str  # "" means count events
    group_by: str  # "" means no grouping
    op: str
    threshold: int


@dataclass
class Rule:
    path: Path
    id: str
    title: str
    level: str
    product: str
    service: str
    tags: list[str]
    description: str
    falsepositives: list[str]
    selections: dict[str, list[list[FieldTest]]]  # name -> alternatives -> all-of tests
    condition: tuple
    aggregation: Aggregation | None = None
    timeframe: timedelta | None = None
    raw: dict = field(default_factory=dict)

    @property
    def techniques(self) -> list[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if re.match(r"attack\.t\d{4}", t)]

    @property
    def tactics(self) -> list[str]:
        return [t.split(".", 1)[1] for t in self.tags if t.startswith("attack.") and not re.match(r"attack\.t\d", t)]


# ---------------------------------------------------------------- parsing


def _field_tests(mapping: dict, where: str) -> list[FieldTest]:
    tests = []
    for key, value in mapping.items():
        name, *mods = str(key).split("|")
        unknown = set(mods) - MODIFIERS
        if unknown:
            raise RuleError(f"{where}: unsupported modifier(s) {', '.join(sorted(unknown))}")
        values = value if isinstance(value, list) else [value]
        tests.append(FieldTest(name, mods, values))
    return tests


def _parse_timeframe(text: str | None) -> timedelta | None:
    if not text:
        return None
    m = re.fullmatch(r"(\d+)([smhd])", str(text))
    if not m:
        raise RuleError(f"timeframe '{text}' must look like 30s, 5m, 1h or 1d")
    unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[m.group(2)]
    return timedelta(**{unit: int(m.group(1))})


def _tokens(text: str) -> list[str]:
    return re.findall(r"\(|\)|[^\s()]+", text)


def parse_condition(text: str, names: list[str]) -> tuple:
    """Recursive-descent parser producing ('and', a, b) / ('or', a, b) / ('not', a) / ('sel', name)."""
    toks = _tokens(text)
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take(expected=None):
        nonlocal pos
        tok = peek()
        if tok is None or (expected and tok.lower() != expected):
            raise RuleError(f"condition '{text}': expected {expected or 'more input'} at position {pos}")
        pos += 1
        return tok

    def expand(pattern: str) -> list[str]:
        matched = names if pattern == "them" else [n for n in names if fnmatch.fnmatchcase(n, pattern)]
        if not matched:
            raise RuleError(f"condition '{text}': '{pattern}' matches no selection")
        return matched

    def factor():
        tok = peek()
        if tok is None:
            raise RuleError(f"condition '{text}' ends unexpectedly")
        if tok.lower() == "not":
            take()
            return ("not", factor())
        if tok == "(":
            take()
            node = expr()
            take(")")
            return node
        if tok.lower() in ("1", "all") and pos + 1 < len(toks) and toks[pos + 1].lower() == "of":
            quant = take().lower()
            take("of")
            parts = [("sel", n) for n in expand(take())]
            node = parts[0]
            for p in parts[1:]:
                node = ("or" if quant == "1" else "and", node, p)
            return node
        name = take()
        if name not in names:
            raise RuleError(f"condition '{text}': unknown selection '{name}'")
        return ("sel", name)

    def term():
        node = factor()
        while peek() and peek().lower() == "and":
            take()
            node = ("and", node, factor())
        return node

    def expr():
        node = term()
        while peek() and peek().lower() == "or":
            take()
            node = ("or", node, term())
        return node

    tree = expr()
    if peek() is not None:
        raise RuleError(f"condition '{text}': unexpected '{peek()}'")
    return tree


def load_rule(path: str | Path) -> Rule:
    path = Path(path)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    where = path.name
    for key in ("title", "id", "logsource", "detection", "level", "tags"):
        if not data.get(key):
            raise RuleError(f"{where}: missing '{key}'")
    if data["level"] not in LEVELS:
        raise RuleError(f"{where}: level must be one of {', '.join(LEVELS)}")
    detection = dict(data["detection"])
    condition_text = str(detection.pop("condition", ""))
    timeframe = _parse_timeframe(detection.pop("timeframe", None))
    if not condition_text:
        raise RuleError(f"{where}: detection needs a condition")
    selections = {}
    for name, body in detection.items():
        alternatives = body if isinstance(body, list) else [body]
        if not all(isinstance(a, dict) for a in alternatives):
            raise RuleError(f"{where}: selection '{name}' must be a map or a list of maps")
        selections[name] = [_field_tests(a, f"{where}:{name}") for a in alternatives]

    expr_text, _, agg_text = condition_text.partition("|")
    aggregation = None
    if agg_text.strip():
        m = AGG_PATTERN.match(agg_text.strip())
        if not m:
            raise RuleError(f"{where}: unsupported aggregation '{agg_text.strip()}'")
        aggregation = Aggregation(m.group(1), m.group(2) or "", m.group(3), int(m.group(4)))
        if timeframe is None:
            raise RuleError(f"{where}: an aggregation needs a timeframe")

    logsource = data["logsource"]
    return Rule(
        path=path,
        id=str(data["id"]),
        title=str(data["title"]),
        level=data["level"],
        product=str(logsource.get("product", "")),
        service=str(logsource.get("service", "")),
        tags=[str(t).lower() for t in data["tags"]],
        description=str(data.get("description", "")).strip(),
        falsepositives=[str(f) for f in data.get("falsepositives") or []],
        selections=selections,
        condition=parse_condition(expr_text.strip(), list(selections)),
        aggregation=aggregation,
        timeframe=timeframe,
        raw=data,
    )


def load_rules(folder: str | Path) -> list[Rule]:
    rules = [load_rule(p) for p in sorted(Path(folder).rglob("*.yml"))]
    ids = [r.id for r in rules]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise RuleError(f"duplicate rule id(s): {', '.join(dupes)}")
    return rules


# ---------------------------------------------------------------- matching


def get_field(event: dict, name: str):
    """Exact key first, then a dotted path into nested objects (CloudTrail style)."""
    if name in event:
        return event[name]
    current = event
    for part in name.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _value_matches(actual, expected, mods: list[str]) -> bool:
    if expected is None:
        return actual is None
    if actual is None:
        return False
    a, e = str(actual).lower(), str(expected).lower()  # also makes True/"true" and 4625/"4625" compare equal
    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    if "*" in e or "?" in e:
        return fnmatch.fnmatchcase(a, e)
    return a == e


def _test_matches(event: dict, test: FieldTest) -> bool:
    actual = get_field(event, test.field)
    hits = (_value_matches(actual, v, test.modifiers) for v in test.values)
    return all(hits) if "all" in test.modifiers else any(hits)


def selection_matches(event: dict, alternatives: list[list[FieldTest]]) -> bool:
    return any(all(_test_matches(event, t) for t in tests) for tests in alternatives)


def _eval(node: tuple, event: dict, rule: Rule) -> bool:
    kind = node[0]
    if kind == "sel":
        return selection_matches(event, rule.selections[node[1]])
    if kind == "not":
        return not _eval(node[1], event, rule)
    if kind == "and":
        return _eval(node[1], event, rule) and _eval(node[2], event, rule)
    return _eval(node[1], event, rule) or _eval(node[2], event, rule)


def event_matches(rule: Rule, event: dict) -> bool:
    return _eval(rule.condition, event, rule)


def _timestamp(event: dict, product: str) -> datetime:
    raw = get_field(event, TIMESTAMP_FIELDS.get(product, "timestamp"))
    if raw is None:
        raise RuleError(f"event has no {TIMESTAMP_FIELDS.get(product, 'timestamp')} field")
    return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))


@dataclass
class Alert:
    rule: Rule
    time: datetime
    events: list[dict]
    group: str = ""
    count: int = 1


def evaluate(rule: Rule, events: list[dict]) -> list[Alert]:
    """Run a rule over events. Plain rules alert per event; aggregations alert per group and window."""
    matched = [e for e in events if event_matches(rule, e)]
    if rule.aggregation is None:
        return [Alert(rule, _timestamp(e, rule.product), [e]) for e in matched]

    agg = rule.aggregation
    groups: dict[str, list[dict]] = {}
    for e in matched:
        key = str(get_field(e, agg.group_by)) if agg.group_by else ""
        groups.setdefault(key, []).append(e)

    alerts = []
    for key, group in groups.items():
        group.sort(key=lambda e: _timestamp(e, rule.product))
        start = 0
        fired_until = None
        for end in range(len(group)):
            t_end = _timestamp(group[end], rule.product)
            while _timestamp(group[start], rule.product) < t_end - rule.timeframe:
                start += 1
            window = group[start : end + 1]
            n = (
                len({str(get_field(e, agg.distinct_field)).lower() for e in window})
                if agg.distinct_field
                else len(window)
            )
            hit = n > agg.threshold if agg.op == ">" else n >= agg.threshold
            # One alert per burst: don't re-alert until the window has moved past the last alert.
            if hit and (fired_until is None or _timestamp(window[0], rule.product) > fired_until):
                alerts.append(Alert(rule, t_end, list(window), group=key, count=n))
                fired_until = t_end
    return alerts
