from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def root() -> Path:
    return ROOT


@pytest.fixture
def write_rule(tmp_path):
    """Write a rule YAML string to a temp file and return its path."""

    def _write(text: str, name: str = "rule.yml") -> Path:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        return path

    return _write


RULE_HEADER = """
title: Test rule
id: 00000000-0000-4000-8000-000000000001
level: medium
tags: [attack.execution, attack.t1059.001]
logsource: {product: windows, service: security}
"""
