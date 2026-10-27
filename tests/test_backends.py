import pytest
from conftest import RULE_HEADER

from socdet.backends import ConversionError, to_sentinel, to_splunk
from socdet.sigma import load_rule, load_rules


def test_every_rule_converts(root):
    for rule in load_rules(root / "rules"):
        assert to_splunk(rule).startswith("index=")
        assert to_sentinel(rule).split("\n")[0] in ("SecurityEvent", "AWSCloudTrail")


def test_splunk_windows_mapping_and_escaping(root):
    rule = load_rule(root / "rules" / "windows" / "win_shadow_copy_deletion.yml")
    spl = to_splunk(rule)
    assert 'EventCode="4688"' in spl  # EventID is EventCode in the Splunk Windows add-on
    assert 'NewProcessName="*\\\\vssadmin.exe"' in spl  # backslash escaped for SPL
    assert '(CommandLine="*delete*" AND CommandLine="*shadows*")' in spl  # |all becomes AND


def test_aggregation_queries(root):
    rule = load_rule(root / "rules" / "windows" / "win_password_spray.yml")
    assert "| stats dc(TargetUserName) as hits by _time, IpAddress\n| where hits > 5" in to_splunk(rule)
    kql = to_sentinel(rule)
    assert "summarize Hits = dcount(TargetUserName) by IpAddress, bin(TimeGenerated, 10m)" in kql


def test_sentinel_aws_fields(root):
    rule = load_rule(root / "rules" / "aws" / "aws_console_login_without_mfa.yml")
    kql = to_sentinel(rule)
    assert 'EventName =~ "ConsoleLogin"' in kql
    assert 'tostring(parse_json(AdditionalEventData).MFAUsed) =~ "No"' in kql


def test_sentinel_negation_is_a_function(root):
    kql = to_sentinel(load_rule(root / "rules" / "aws" / "aws_root_account_usage.yml"))
    assert 'not(EventTypeName =~ "AwsServiceEvent")' in kql


def test_unmapped_aws_field_is_an_error(write_rule):
    text = (
        RULE_HEADER.replace("product: windows", "product: aws")
        + "detection:\n  sel:\n    madeUpField: x\n  condition: sel\n"
    )
    with pytest.raises(ConversionError, match="madeUpField"):
        to_sentinel(load_rule(write_rule(text)))
