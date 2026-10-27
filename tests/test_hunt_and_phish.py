import pytest

from socdet.attack import coverage
from socdet.cli import main
from socdet.hunt import hunt, load_events
from socdet.phish import analyze, analyze_file, edit_distance, lookalike_of
from socdet.sigma import load_rules

PROTECT = ["samplelending.example"]


def test_hunt_finds_the_whole_attack_and_nothing_else(root):
    rules = load_rules(root / "rules")
    logs = {
        "windows": load_events(root / "samples" / "windows-security.jsonl"),
        "aws": load_events(root / "samples" / "cloudtrail.jsonl"),
    }
    titles = [a.rule.title for a in hunt(rules, logs)]
    assert len(titles) == 10
    assert titles[0].startswith("Password Spray")
    assert "Brute Force - Many Failed Logons From One Source" not in titles  # nine tries is a spray, not brute force
    assert titles[-1].startswith("AWS GuardDuty")


def test_coverage_respects_attack_tactics(root):
    cov = coverage(load_rules(root / "rules"))
    assert "T1059.001" in cov["execution"] and "T1059.001" not in cov["defense_evasion"]
    assert "T1027" in cov["defense_evasion"] and "T1027" not in cov["execution"]
    assert cov["discovery"] == {}


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("sarnplelending.example", "samplelending.example"),  # rn looks like m
        ("samplelendlng.example", "samplelending.example"),
        ("samplelending.example.login-check.net", "samplelending.example"),
        ("mail.samplelending.example", None),  # our own subdomain
        ("samplelending.example", None),
        ("unrelated.example", None),
    ],
)
def test_lookalike_domains(domain, expected):
    assert lookalike_of(domain, PROTECT) == expected


def test_edit_distance():
    assert edit_distance("kitten", "sitting") == 3


@pytest.mark.parametrize(
    ("name", "verdict"),
    [
        ("phish-lookalike-invoice.eml", "malicious"),
        ("suspicious-shared-document.eml", "suspicious"),
        ("benign-newsletter.eml", "likely benign"),
    ],
)
def test_sample_emails(root, name, verdict):
    assert analyze_file(root / "samples" / "emails" / name, PROTECT).verdict == verdict


def test_phish_findings_detail(root):
    keys = {f.key for f in analyze_file(root / "samples" / "emails" / "phish-lookalike-invoice.eml", PROTECT).findings}
    assert {"dmarc_fail", "lookalike_sender", "link_text_mismatch", "double_extension", "reply_to_mismatch"} <= keys


def test_minimal_message_without_auth_header():
    raw = b"From: a@samplelending.example\r\nSubject: hi\r\n\r\nhello\r\n"
    report = analyze(raw, PROTECT)
    assert report.auth == {"spf": "none", "dkim": "none", "dmarc": "none"}
    assert report.verdict == "likely benign"


def test_cli_end_to_end(root, tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(root)
    assert main(["test"]) == 0
    out = tmp_path / "hunt.md"
    assert main(["hunt", "--logs", "windows=samples/windows-security.jsonl", "--logs", "aws=samples/cloudtrail.jsonl",
                 "-o", str(out)]) == 0  # fmt: skip
    assert "**10 alerts**" in out.read_text(encoding="utf-8")
    assert main(["convert", "--to", "sentinel", "rules/windows/win_security_log_cleared.yml"]) == 0
    assert "EventID == 1102" in capsys.readouterr().out
    assert main(["phish", "samples/emails/benign-newsletter.eml", "--protect", "samplelending.example"]) == 0
    assert main(["hunt", "--logs", "nofile"]) == 2
