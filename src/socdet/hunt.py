"""Run every rule over log files and build an alert timeline."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .attack import TECHNIQUES, technique_url
from .sigma import LEVELS, Alert, Rule, evaluate, get_field

DETAIL_FIELDS = {
    "windows": ["Computer", "SubjectUserName", "TargetUserName", "IpAddress", "NewProcessName", "CommandLine"],
    "aws": ["userIdentity.userName", "userIdentity.type", "sourceIPAddress", "eventName", "requestParameters"],
}


def load_events(path: str | Path) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{n}: not valid JSON ({exc})") from exc
    return events


def hunt(rules: list[Rule], logs: dict[str, list[dict]]) -> list[Alert]:
    """logs maps a product name (windows, aws) to its events."""
    alerts = []
    for rule in rules:
        if rule.product in logs:
            alerts += evaluate(rule, logs[rule.product])
    return sorted(alerts, key=lambda a: a.time)


def details(alert: Alert) -> str:
    if alert.rule.aggregation:
        agg = alert.rule.aggregation
        what = f"{alert.count} distinct {agg.distinct_field}" if agg.distinct_field else f"{alert.count} events"
        users = sorted({str(get_field(e, "TargetUserName")) for e in alert.events if get_field(e, "TargetUserName")})
        extra = f"; accounts: {', '.join(users[:6])}{'…' if len(users) > 6 else ''}" if users else ""
        window = alert.rule.raw["detection"]["timeframe"]
        return f"{agg.group_by} {alert.group}: {what} within {window}{extra}"
    event = alert.events[0]
    parts = []
    for name in DETAIL_FIELDS.get(alert.rule.product, []):
        value = get_field(event, name)
        if value in (None, "", {}):
            continue
        if isinstance(value, dict):
            value = ", ".join(f"{k}={v}" for k, v in value.items())
        parts.append(f"{name.split('.')[-1]}: {str(value)[:90]}")
    return "; ".join(parts)


def _md(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def markdown(alerts: list[Alert], event_count: int) -> str:
    levels = Counter(a.rule.level for a in alerts)
    order = sorted(levels, key=LEVELS.index, reverse=True)
    lines = [
        "# Hunt results",
        "",
        f"{event_count:,} events searched, **{len(alerts)} alerts** "
        f"({', '.join(f'{levels[lv]} {lv}' for lv in order) or 'none'}).",
        "",
        "## Timeline",
        "",
        "| Time (UTC) | Level | Detection | Details |",
        "|---|---|---|---|",
    ]
    for a in alerts:
        lines.append(
            f"| {a.time.strftime('%Y-%m-%d %H:%M:%S')} | {a.rule.level} | {_md(a.rule.title)} | {_md(details(a))} |"
        )
    seen = sorted({t for a in alerts for t in a.rule.techniques})
    if seen:
        lines += ["", "## ATT&CK techniques observed", ""]
        lines += [f"- [{t}]({technique_url(t)}) {TECHNIQUES.get(t, '')}" for t in seen]
    return "\n".join(lines) + "\n"


def to_json(alerts: list[Alert]) -> str:
    return json.dumps(
        [
            {
                "time": a.time.isoformat(),
                "rule_id": a.rule.id,
                "title": a.rule.title,
                "level": a.rule.level,
                "techniques": a.rule.techniques,
                "details": details(a),
                "event_count": len(a.events),
            }
            for a in alerts
        ],
        indent=2,
    )
