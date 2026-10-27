import pytest
from conftest import RULE_HEADER

from socdet.ruletest import run_cases
from socdet.sigma import RuleError, evaluate, event_matches, get_field, load_rule, load_rules, parse_condition


def rule_with(write_rule, detection: str):
    return load_rule(write_rule(RULE_HEADER + "detection:\n" + detection))


def test_every_shipped_rule_passes_its_scenarios(root):
    rules = load_rules(root / "rules")
    assert len(rules) == 12
    failures = [(r.path.stem, c.name) for r in rules for c in run_cases(r, root / "tests" / "cases") if not c.ok]
    assert failures == []


def test_modifiers_and_case_insensitivity(write_rule):
    rule = rule_with(
        write_rule,
        "  sel:\n    Image|endswith: '\\cmd.exe'\n    CommandLine|contains|all: [whoami, /all]\n  condition: sel\n",
    )
    assert event_matches(rule, {"Image": "C:\\Windows\\System32\\CMD.EXE", "CommandLine": "WHOAMI /ALL"})
    assert not event_matches(rule, {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "whoami"})


def test_wildcards_and_lists(write_rule):
    rule = rule_with(write_rule, "  sel:\n    User: ['adm_*', 'root']\n  condition: sel\n")
    assert event_matches(rule, {"User": "ADM_jane"})
    assert event_matches(rule, {"User": "root"})
    assert not event_matches(rule, {"User": "jane"})


def test_list_of_maps_is_or(write_rule):
    rule = rule_with(write_rule, "  sel:\n    - {A: 1, B: 2}\n    - {C: 3}\n  condition: sel\n")
    assert event_matches(rule, {"A": 1, "B": 2})
    assert event_matches(rule, {"C": 3})
    assert not event_matches(rule, {"A": 1})


def test_nested_fields():
    assert get_field({"a": {"b": {"c": 5}}}, "a.b.c") == 5
    assert get_field({"a.b": 7}, "a.b") == 7  # flattened keys win
    assert get_field({"a": 1}, "a.b") is None


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        ("a and not b", ("and", ("sel", "a"), ("not", ("sel", "b")))),
        ("a or b and c", ("or", ("sel", "a"), ("and", ("sel", "b"), ("sel", "c")))),  # and binds tighter
        ("(a or b) and c", ("and", ("or", ("sel", "a"), ("sel", "b")), ("sel", "c"))),
        ("1 of sel_*", ("or", ("sel", "sel_x"), ("sel", "sel_y"))),
        ("all of sel_*", ("and", ("sel", "sel_x"), ("sel", "sel_y"))),
    ],
)
def test_condition_parser(condition, expected):
    assert parse_condition(condition, ["a", "b", "c", "sel_x", "sel_y"]) == expected


@pytest.mark.parametrize("bad", ["a and", "a or (b", "missing", "1 of nothing_*", "a b"])
def test_condition_parser_errors(bad):
    with pytest.raises(RuleError):
        parse_condition(bad, ["a", "b"])


def test_rule_validation(write_rule):
    with pytest.raises(RuleError, match="unsupported modifier"):
        rule_with(write_rule, "  sel:\n    A|re: x\n  condition: sel\n")
    with pytest.raises(RuleError, match="needs a timeframe"):
        rule_with(write_rule, "  sel:\n    A: 1\n  condition: sel | count() by B > 3\n")
    with pytest.raises(RuleError, match="missing 'tags'"):
        load_rule(write_rule("title: x\nid: y\nlevel: low\nlogsource: {product: windows}\ndetection: {a: {b: 1}}\n"))


def test_aggregation_window_and_single_alert_per_burst(write_rule):
    rule = rule_with(write_rule, "  sel:\n    EventID: 4625\n  timeframe: 1m\n  condition: sel | count() by Ip > 2\n")
    burst = [{"EventID": 4625, "Ip": "1.2.3.4", "TimeCreated": f"2026-01-01T00:00:{s:02d}Z"} for s in range(0, 50, 5)]
    assert len(evaluate(rule, burst)) == 1  # ten failures in 50s is one incident, not eight alerts
    slow = [{"EventID": 4625, "Ip": "1.2.3.4", "TimeCreated": f"2026-01-01T00:{m:02d}:00Z"} for m in range(0, 10)]
    assert evaluate(rule, slow) == []
