"""MITRE ATT&CK names for the techniques and tactics these rules use, and the coverage map."""

from __future__ import annotations

from .sigma import Rule

TACTICS = [
    ("initial_access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege_escalation", "Privilege Escalation"),
    ("defense_evasion", "Defense Evasion"),
    ("credential_access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral_movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]
TECHNIQUES = {
    "T1027": "Obfuscated Files or Information",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1098": "Account Manipulation",
    "T1098.003": "Account Manipulation: Additional Cloud Roles",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1136.001": "Create Account: Local Account",
    "T1490": "Inhibit System Recovery",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1562.008": "Impair Defenses: Disable or Modify Cloud Logs",
}
# The tactics each technique belongs to in ATT&CK. A rule tagged with two techniques and two tactics
# must not pair every technique with every tactic.
TECHNIQUE_TACTICS = {
    "T1027": {"defense_evasion"},
    "T1059.001": {"execution"},
    "T1070.001": {"defense_evasion"},
    "T1078.004": {"initial_access", "persistence", "privilege_escalation", "defense_evasion"},
    "T1098": {"persistence", "privilege_escalation"},
    "T1098.003": {"persistence", "privilege_escalation"},
    "T1110.001": {"credential_access"},
    "T1110.003": {"credential_access"},
    "T1136.001": {"persistence"},
    "T1490": {"impact"},
    "T1562.001": {"defense_evasion"},
    "T1562.008": {"defense_evasion"},
}


def technique_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def coverage(rules: list[Rule]) -> dict[str, dict[str, list[Rule]]]:
    """tactic -> technique -> rules.

    A technique is listed under the tactics the rule is tagged with, but only those that the technique
    really belongs to in ATT&CK.
    """
    out: dict[str, dict[str, list[Rule]]] = {key: {} for key, _ in TACTICS}
    for rule in rules:
        for tech in rule.techniques:
            valid = TECHNIQUE_TACTICS.get(tech, set(rule.tactics))
            for tactic in (set(rule.tactics) & valid) or valid:
                out.setdefault(tactic, {}).setdefault(tech, []).append(rule)
    return out
