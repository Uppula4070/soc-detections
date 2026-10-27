"""Convert rules to Splunk SPL and Microsoft Sentinel KQL.

Field names differ per platform, so each backend has a mapping. The Windows mappings assume the
Splunk Add-on for Microsoft Windows (EventCode) and Sentinel's SecurityEvent table; AWS assumes
the Splunk Add-on for AWS (aws:cloudtrail) and Sentinel's AWSCloudTrail table.
"""

from __future__ import annotations

import re

from .sigma import FieldTest, Rule

SPLUNK_BASE = {
    "windows": 'index=wineventlog source="WinEventLog:Security"',
    "aws": "index=aws sourcetype=aws:cloudtrail",
}
SPLUNK_FIELDS = {"windows": {"EventID": "EventCode"}, "aws": {}}

SENTINEL_TABLE = {"windows": "SecurityEvent", "aws": "AWSCloudTrail"}
SENTINEL_FIELDS = {
    "windows": {},
    "aws": {
        "eventName": "EventName",
        "eventSource": "EventSource",
        "sourceIPAddress": "SourceIpAddress",
        "userIdentity.type": "UserIdentityType",
        "userIdentity.arn": "UserIdentityArn",
        "userIdentity.userName": "UserIdentityUserName",
        "errorCode": "ErrorCode",
        "eventType": "EventTypeName",
        "awsRegion": "AWSRegion",
    },
}
# AWSCloudTrail renames almost every field, so an unmapped AWS field is an error rather than a silent miss.
SENTINEL_STRICT = {"aws"}
# Columns that hold a JSON document in Sentinel; anything beneath them is read with parse_json.
SENTINEL_JSON_COLUMNS = {
    "requestParameters": "RequestParameters",
    "responseElements": "ResponseElements",
    "additionalEventData": "AdditionalEventData",
}


class ConversionError(Exception):
    pass


def _span(rule: Rule) -> str:
    seconds = int(rule.timeframe.total_seconds())
    for size, unit in ((86400, "d"), (3600, "h"), (60, "m")):
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def _combine(parts: list[str], op: str) -> str:
    return parts[0] if len(parts) == 1 else "(" + f" {op} ".join(parts) + ")"


def _walk(node: tuple, rule: Rule, selection_fn, ops: tuple[str, str, str]) -> str:
    and_, or_, not_ = ops
    kind = node[0]
    if kind == "sel":
        return selection_fn(rule.selections[node[1]])
    if kind == "not":
        inner = _walk(node[1], rule, selection_fn, ops)
        return f"not({inner})" if not_ == "not" else f"{not_} {inner}"  # KQL negation is a function
    left = _walk(node[1], rule, selection_fn, ops)
    right = _walk(node[2], rule, selection_fn, ops)
    return f"({left} {and_ if kind == 'and' else or_} {right})"


# ---------------------------------------------------------------- Splunk


def _spl_str(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _spl_test(test: FieldTest, product: str) -> str:
    name = SPLUNK_FIELDS.get(product, {}).get(test.field, test.field)
    parts = []
    for v in test.values:
        if v is None:
            parts.append(f"NOT {name}=*")
            continue
        text = str(v)
        if "contains" in test.modifiers:
            text = f"*{text}*"
        elif "startswith" in test.modifiers:
            text = f"{text}*"
        elif "endswith" in test.modifiers:
            text = f"*{text}"
        parts.append(f"{name}={_spl_str(text)}")
    return _combine(parts, "AND" if "all" in test.modifiers else "OR")


def to_splunk(rule: Rule) -> str:
    def selection(alternatives):
        return _combine([_combine([_spl_test(t, rule.product) for t in alt], "AND") for alt in alternatives], "OR")

    query = f"{SPLUNK_BASE.get(rule.product, 'index=*')} {_walk(rule.condition, rule, selection, ('AND', 'OR', 'NOT'))}"
    agg = rule.aggregation
    if agg:
        by = ", ".join(x for x in ("_time", SPLUNK_FIELDS.get(rule.product, {}).get(agg.group_by, agg.group_by)) if x)
        measure = f"dc({agg.distinct_field})" if agg.distinct_field else "count"
        query += (
            f"\n| bin _time span={_span(rule)}"
            f"\n| stats {measure} as hits by {by}"
            f"\n| where hits {agg.op} {agg.threshold}"
        )
    return query


# ---------------------------------------------------------------- Sentinel (KQL)


def _kql_str(value: str) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _kql_field(name: str, product: str) -> str:
    mapped = SENTINEL_FIELDS.get(product, {}).get(name)
    if mapped:
        return mapped
    head, _, rest = name.partition(".")
    if rest and head in SENTINEL_JSON_COLUMNS:
        path = "".join(f".{p}" for p in rest.split("."))
        return f"tostring(parse_json({SENTINEL_JSON_COLUMNS[head]}){path})"
    if "." in name or product in SENTINEL_STRICT:
        raise ConversionError(f"no Sentinel mapping for {product} field '{name}'")
    return name


def _kql_test(test: FieldTest, product: str) -> str:
    name = _kql_field(test.field, product)
    parts = []
    for v in test.values:
        if v is None:
            parts.append(f"isempty({name})")
        elif isinstance(v, int) and not isinstance(v, bool) and not test.modifiers:
            parts.append(f"{name} == {v}")
        elif "contains" in test.modifiers:
            parts.append(f"{name} contains {_kql_str(v)}")
        elif "startswith" in test.modifiers:
            parts.append(f"{name} startswith {_kql_str(v)}")
        elif "endswith" in test.modifiers:
            parts.append(f"{name} endswith {_kql_str(v)}")
        elif "*" in str(v) or "?" in str(v):
            pattern = "^" + re.escape(str(v)).replace(r"\*", ".*").replace(r"\?", ".") + "$"
            parts.append(f'{name} matches regex @"(?i){pattern}"')
        else:
            parts.append(f"{name} =~ {_kql_str(v)}")  # =~ is case-insensitive equality
    return _combine(parts, "and" if "all" in test.modifiers else "or")


def to_sentinel(rule: Rule) -> str:
    def selection(alternatives):
        return _combine([_combine([_kql_test(t, rule.product) for t in alt], "and") for alt in alternatives], "or")

    table = SENTINEL_TABLE.get(rule.product)
    if not table:
        raise ConversionError(f"no Sentinel table for product '{rule.product}'")
    query = f"{table}\n| where {_walk(rule.condition, rule, selection, ('and', 'or', 'not'))}"
    agg = rule.aggregation
    if agg:
        measure = f"dcount({_kql_field(agg.distinct_field, rule.product)})" if agg.distinct_field else "count()"
        by = ", ".join(x for x in (_kql_field(agg.group_by, rule.product) if agg.group_by else "",) if x)
        by = f"{by}, " if by else ""
        query += (
            f"\n| summarize Hits = {measure} by {by}bin(TimeGenerated, {_span(rule)})"
            f"\n| where Hits {agg.op} {agg.threshold}"
        )
    return query


BACKENDS = {"splunk": to_splunk, "sentinel": to_sentinel}
