from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .backends import BACKENDS, ConversionError
from .docs import coverage_md, rules_md
from .hunt import hunt, load_events, markdown, to_json
from .phish import analyze_file, ticket
from .ruletest import run_cases
from .sigma import RuleError, load_rule, load_rules


def cmd_test(args) -> int:
    rules = load_rules(args.rules)
    failed = 0
    for rule in rules:
        results = run_cases(rule, args.cases)
        bad = [r for r in results if not r.ok]
        failed += len(bad)
        mark = "PASS" if not bad else "FAIL"
        print(f"{mark}  {rule.path.stem:<38} {len(results) - len(bad)}/{len(results)} scenarios")
        for r in bad:
            print(f"        - {r.name}: expected {r.expected} alert(s), got {r.got}")
        for name, convert in BACKENDS.items():
            try:
                convert(rule)
            except ConversionError as exc:
                failed += 1
                print(f"        - {name} conversion failed: {exc}")
    print(f"\n{len(rules)} rules, {'all passing' if not failed else f'{failed} problem(s)'}")
    return 1 if failed else 0


def cmd_convert(args) -> int:
    rules = [load_rule(p) for p in args.rule] if args.rule else load_rules(args.rules)
    for rule in rules:
        print(f"// {rule.title}  ({rule.path.as_posix()})")
        print(BACKENDS[args.to](rule))
        print()
    return 0


def cmd_hunt(args) -> int:
    logs: dict[str, list[dict]] = {}
    for spec in args.logs:
        product, _, path = spec.partition("=")
        if not path:
            print(f"--logs expects product=path, got '{spec}'", file=sys.stderr)
            return 2
        logs.setdefault(product, []).extend(load_events(path))
    alerts = hunt(load_rules(args.rules), logs)
    report = markdown(alerts, sum(map(len, logs.values())))
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(to_json(alerts), encoding="utf-8")
    print(report if not args.output else f"{len(alerts)} alerts written to {args.output}")
    return 0


def cmd_docs(args) -> int:
    rules = load_rules(args.rules)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "rules.md").write_text(rules_md(rules), encoding="utf-8")
    (out / "coverage.md").write_text(coverage_md(rules), encoding="utf-8")
    print(f"wrote {out / 'rules.md'} and {out / 'coverage.md'}")
    return 0


def cmd_phish(args) -> int:
    protected = [d.strip().lower() for d in args.protect.split(",") if d.strip()]
    worst = 0
    for path in args.eml:
        report = analyze_file(path, protected)
        worst = max(worst, report.score)
        if args.json:
            print(json.dumps({"file": path, "verdict": report.verdict, "score": report.score,
                              "findings": [f.detail for f in report.findings]}, indent=2))  # fmt: skip
        else:
            print(ticket(report, Path(path).name))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="socdet", description="Detection-as-code toolkit for SOC analysts.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--rules", default="rules", help="rules folder (default: rules)")
    sub = p.add_subparsers(dest="command", required=True)

    t = sub.add_parser("test", help="run every rule against its test scenarios")
    t.add_argument("--cases", default="tests/cases")
    t.set_defaults(func=cmd_test)

    c = sub.add_parser("convert", help="print rules as Splunk SPL or Sentinel KQL")
    c.add_argument("--to", choices=sorted(BACKENDS), required=True)
    c.add_argument("rule", nargs="*", help="rule files (default: all)")
    c.set_defaults(func=cmd_convert)

    h = sub.add_parser("hunt", help="run all rules over JSON-lines logs and build a timeline")
    h.add_argument("--logs", action="append", required=True, metavar="PRODUCT=FILE", help="e.g. windows=security.jsonl")
    h.add_argument("-o", "--output", help="write the Markdown report here")
    h.add_argument("--json", help="also write alerts as JSON")
    h.set_defaults(func=cmd_hunt)

    d = sub.add_parser("docs", help="regenerate docs/rules.md and docs/coverage.md")
    d.add_argument("--out", default="docs")
    d.set_defaults(func=cmd_docs)

    ph = sub.add_parser("phish", help="triage reported .eml files")
    ph.add_argument("eml", nargs="+")
    ph.add_argument("--protect", required=True, help="your own domains, comma separated, e.g. example.com")
    ph.add_argument("--json", action="store_true")
    ph.set_defaults(func=cmd_phish)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (RuleError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
