"""Run each rule's test scenarios: every rule must fire on its attack examples and stay quiet on look-alikes.

A case file (tests/cases/<rule file name>.yml) holds scenarios:

    scenarios:
      - name: twelve failures from one IP
        expect: 1                  # number of alerts the rule must raise
        start: 2026-10-27T10:00:00Z
        every_seconds: 10          # spacing between events that have no timestamp of their own
        events:
          - {EventID: 4625, IpAddress: 203.0.113.7, TargetUserName: "user{i}", _repeat: 12}

`_repeat: N` expands one event into N copies, replacing {i} with 1..N in string values.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from .sigma import TIMESTAMP_FIELDS, Rule, evaluate


@dataclass
class CaseResult:
    rule: Rule
    name: str
    expected: int
    got: int

    @property
    def ok(self) -> bool:
        return self.expected == self.got


def _fill(value, i: int):
    if isinstance(value, str):
        return value.replace("{i}", str(i))
    if isinstance(value, dict):
        return {k: _fill(v, i) for k, v in value.items()}
    return value


def expand_events(scenario: dict, product: str) -> list[dict]:
    start = datetime.fromisoformat(str(scenario.get("start", "2026-10-27T10:00:00Z")).replace("Z", "+00:00"))
    step = timedelta(seconds=float(scenario.get("every_seconds", 1)))
    ts_field = TIMESTAMP_FIELDS[product]
    events = []
    for template in scenario.get("events", []):
        template = dict(template)
        repeat = int(template.pop("_repeat", 1))
        for i in range(1, repeat + 1):
            events.append(_fill(template, i) if repeat > 1 else template)
    for n, event in enumerate(events):
        event.setdefault(ts_field, (start + n * step).isoformat().replace("+00:00", "Z"))
    return events


def case_path(rule: Rule, cases_dir: Path) -> Path:
    return cases_dir / f"{rule.path.stem}.yml"


def run_cases(rule: Rule, cases_dir: str | Path) -> list[CaseResult]:
    path = case_path(rule, Path(cases_dir))
    if not path.exists():
        return [CaseResult(rule, "missing test file " + path.name, 1, 0)]
    scenarios = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("scenarios", [])
    results = []
    for sc in scenarios:
        alerts = evaluate(rule, expand_events(sc, rule.product))
        results.append(CaseResult(rule, str(sc.get("name", "unnamed")), int(sc["expect"]), len(alerts)))
    if not any(r.expected > 0 for r in results) or not any(r.expected == 0 for r in results):
        results.append(CaseResult(rule, "needs at least one firing and one quiet scenario", 1, 0))
    return results
