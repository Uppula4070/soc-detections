# Detection rules

Generated from `rules/` by `socdet docs`. Do not edit by hand.

| Rule | Level | Log source | ATT&CK |
|---|---|---|---|
| [AWS AdministratorAccess Policy Attached](#aws-admin-policy-attached) | high | aws/cloudtrail | T1098.003 |
| [AWS CloudTrail Logging Stopped or Trail Deleted](#aws-cloudtrail-logging-stopped) | high | aws/cloudtrail | T1562.008 |
| [AWS Console Login Without MFA](#aws-console-login-without-mfa) | medium | aws/cloudtrail | T1078.004 |
| [AWS GuardDuty Detector Deleted or Monitoring Stopped](#aws-guardduty-disabled) | high | aws/cloudtrail | T1562.001 |
| [AWS Root Account Used](#aws-root-account-usage) | high | aws/cloudtrail | T1078.004 |
| [Brute Force - Many Failed Logons From One Source](#win-bruteforce-failed-logons) | medium | windows/security | T1110.001 |
| [PowerShell Started With an Encoded Command](#win-encoded-powershell) | high | windows/security | T1059.001, T1027 |
| [User Account Created](#win-local-account-created) | medium | windows/security | T1136.001 |
| [Password Spray - Failed Logons to Many Accounts From One Source](#win-password-spray) | high | windows/security | T1110.003 |
| [Windows Security Event Log Cleared](#win-security-log-cleared) | high | windows/security | T1070.001 |
| [Volume Shadow Copies Deleted](#win-shadow-copy-deletion) | high | windows/security | T1490 |
| [Account Added to a Privileged Group](#win-user-added-to-admin-group) | high | windows/security | T1098 |

<a id="aws-admin-policy-attached"></a>

## AWS AdministratorAccess Policy Attached

`rules/aws/aws_admin_policy_attached.yml` · level **high** · id `0d5a7b39-2e8c-4f61-8b3d-4c5e6f7a8b9b`

The AdministratorAccess managed policy was attached to a user, role or group, granting full control
of the account.

**ATT&CK:** [T1098.003](https://attack.mitre.org/techniques/T1098/003/) Account Manipulation: Additional Cloud Roles

**False positives:** Infrastructure-as-code pipelines creating admin roles; exclude the pipeline role after review

**Splunk (SPL)**

```spl
index=aws sourcetype=aws:cloudtrail (eventSource="iam.amazonaws.com" AND (eventName="AttachUserPolicy" OR eventName="AttachRolePolicy" OR eventName="AttachGroupPolicy") AND requestParameters.policyArn="*/AdministratorAccess")
```

**Microsoft Sentinel (KQL)**

```kql
AWSCloudTrail
| where (EventSource =~ "iam.amazonaws.com" and (EventName =~ "AttachUserPolicy" or EventName =~ "AttachRolePolicy" or EventName =~ "AttachGroupPolicy") and tostring(parse_json(RequestParameters).policyArn) endswith "/AdministratorAccess")
```

<a id="aws-cloudtrail-logging-stopped"></a>

## AWS CloudTrail Logging Stopped or Trail Deleted

`rules/aws/aws_cloudtrail_logging_stopped.yml` · level **high** · id `4b8e6f23-1c7d-4a95-9f02-3d4e5f6a7b2a`

CloudTrail logging was stopped or a trail was deleted. Attackers do this to blind defenders before
acting in the account.

**ATT&CK:** [T1562.008](https://attack.mitre.org/techniques/T1562/008/) Impair Defenses: Disable or Modify Cloud Logs

**False positives:** Planned trail migration; confirm with a change ticket

**Splunk (SPL)**

```spl
index=aws sourcetype=aws:cloudtrail (eventSource="cloudtrail.amazonaws.com" AND (eventName="StopLogging" OR eventName="DeleteTrail"))
```

**Microsoft Sentinel (KQL)**

```kql
AWSCloudTrail
| where (EventSource =~ "cloudtrail.amazonaws.com" and (EventName =~ "StopLogging" or EventName =~ "DeleteTrail"))
```

<a id="aws-console-login-without-mfa"></a>

## AWS Console Login Without MFA

`rules/aws/aws_console_login_without_mfa.yml` · level **medium** · id `7e4c2b16-8d9a-4f53-a2e1-6b7c8d9e0f19`

A successful AWS console sign-in where MFA was not used. A stolen password alone is enough to get in.

**ATT&CK:** [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts: Cloud Accounts

**False positives:** Federated SSO logins where MFA is enforced by the identity provider rather than AWS

**Splunk (SPL)**

```spl
index=aws sourcetype=aws:cloudtrail (eventName="ConsoleLogin" AND additionalEventData.MFAUsed="No" AND responseElements.ConsoleLogin="Success")
```

**Microsoft Sentinel (KQL)**

```kql
AWSCloudTrail
| where (EventName =~ "ConsoleLogin" and tostring(parse_json(AdditionalEventData).MFAUsed) =~ "No" and tostring(parse_json(ResponseElements).ConsoleLogin) =~ "Success")
```

<a id="aws-guardduty-disabled"></a>

## AWS GuardDuty Detector Deleted or Monitoring Stopped

`rules/aws/aws_guardduty_disabled.yml` · level **high** · id `e6f1a2b3-4c5d-4e7f-9a0b-1c2d3e4f5a6c`

A GuardDuty detector was deleted or member monitoring was stopped, switching off threat detection.

**ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/) Impair Defenses: Disable or Modify Tools

**False positives:** Decommissioning an unused region; confirm with a change ticket

**Splunk (SPL)**

```spl
index=aws sourcetype=aws:cloudtrail (eventSource="guardduty.amazonaws.com" AND (eventName="DeleteDetector" OR eventName="StopMonitoringMembers"))
```

**Microsoft Sentinel (KQL)**

```kql
AWSCloudTrail
| where (EventSource =~ "guardduty.amazonaws.com" and (EventName =~ "DeleteDetector" or EventName =~ "StopMonitoringMembers"))
```

<a id="aws-root-account-usage"></a>

## AWS Root Account Used

`rules/aws/aws_root_account_usage.yml` · level **high** · id `3a9d1e7c-5f2b-4c86-b4a0-8e7d6c5b4a38`

An API call or console action made with the root user. AWS recommends locking the root user away;
any use outside break-glass procedures should be investigated.

**ATT&CK:** [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts: Cloud Accounts

**False positives:** Documented break-glass use, or the few tasks that require root (such as closing the account)

**Splunk (SPL)**

```spl
index=aws sourcetype=aws:cloudtrail (userIdentity.type="Root" AND NOT eventType="AwsServiceEvent")
```

**Microsoft Sentinel (KQL)**

```kql
AWSCloudTrail
| where (UserIdentityType =~ "Root" and not(EventTypeName =~ "AwsServiceEvent"))
```

<a id="win-bruteforce-failed-logons"></a>

## Brute Force - Many Failed Logons From One Source

`rules/windows/win_bruteforce_failed_logons.yml` · level **medium** · id `5b0f1c34-8e2a-4d55-9c71-0a6e2f4b7d11`

More than 10 failed logons (event 4625) from the same source IP within 5 minutes. Typical of
password guessing against RDP, SMB or other network logons.

**ATT&CK:** [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing

**False positives:** A service account with an expired password retrying in a loop; Vulnerability scanners running authenticated checks

**Splunk (SPL)**

```spl
index=wineventlog source="WinEventLog:Security" EventCode="4625"
| bin _time span=5m
| stats count as hits by _time, IpAddress
| where hits > 10
```

**Microsoft Sentinel (KQL)**

```kql
SecurityEvent
| where EventID == 4625
| summarize Hits = count() by IpAddress, bin(TimeGenerated, 5m)
| where Hits > 10
```

<a id="win-encoded-powershell"></a>

## PowerShell Started With an Encoded Command

`rules/windows/win_encoded_powershell.yml` · level **high** · id `c7e21b9d-4a6f-4f83-a1d2-3e5c9b0d8a63`

PowerShell launched with -EncodedCommand (or a short form such as -enc). Base64 encoding hides the
real command from simple command-line review and is common in malware loaders. Needs process
creation auditing (event 4688) with command line logging turned on.

**ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell, [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files or Information

**False positives:** Some management and deployment tools encode their own scripts; baseline and exclude by parent process

**Splunk (SPL)**

```spl
index=wineventlog source="WinEventLog:Security" ((EventCode="4688" AND (NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe")) AND (CommandLine="* -enc*" OR CommandLine="* -ec *" OR CommandLine="* -encodedcommand*"))
```

**Microsoft Sentinel (KQL)**

```kql
SecurityEvent
| where ((EventID == 4688 and (NewProcessName endswith "\\powershell.exe" or NewProcessName endswith "\\pwsh.exe")) and (CommandLine contains " -enc" or CommandLine contains " -ec " or CommandLine contains " -encodedcommand"))
```

<a id="win-local-account-created"></a>

## User Account Created

`rules/windows/win_local_account_created.yml` · level **medium** · id `8c2e5f91-7a4d-4b38-9e16-2c3f4a5b6d07`

A new user account was created (event 4720). Worth reviewing on servers, where new accounts are
unusual outside of an approved change.

**ATT&CK:** [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local Account

**False positives:** Help desk creating accounts for new starters

**Splunk (SPL)**

```spl
index=wineventlog source="WinEventLog:Security" EventCode="4720"
```

**Microsoft Sentinel (KQL)**

```kql
SecurityEvent
| where EventID == 4720
```

<a id="win-password-spray"></a>

## Password Spray - Failed Logons to Many Accounts From One Source

`rules/windows/win_password_spray.yml` · level **high** · id `9a3d7e60-1f4b-4c2e-8d05-6b9e3a1c2f42`

Failed logons for more than 5 different user names from one source IP within 10 minutes. A spray
tries one common password against many accounts to stay under lockout thresholds, so it is missed
by per-account brute force rules.

**ATT&CK:** [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying

**False positives:** A shared jump host where several users mistype passwords at the same time

**Splunk (SPL)**

```spl
index=wineventlog source="WinEventLog:Security" EventCode="4625"
| bin _time span=10m
| stats dc(TargetUserName) as hits by _time, IpAddress
| where hits > 5
```

**Microsoft Sentinel (KQL)**

```kql
SecurityEvent
| where EventID == 4625
| summarize Hits = dcount(TargetUserName) by IpAddress, bin(TimeGenerated, 10m)
| where Hits > 5
```

<a id="win-security-log-cleared"></a>

## Windows Security Event Log Cleared

`rules/windows/win_security_log_cleared.yml` · level **high** · id `6d4b9c02-3e7a-4f15-8c6d-9a0b1e2f3c05`

The Security log was cleared (event 1102). Attackers clear logs to remove evidence; legitimate
clearing is rare on servers that forward logs to a SIEM.

**ATT&CK:** [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Indicator Removal: Clear Windows Event Logs

**False positives:** Planned maintenance on a test machine

**Splunk (SPL)**

```spl
index=wineventlog source="WinEventLog:Security" EventCode="1102"
```

**Microsoft Sentinel (KQL)**

```kql
SecurityEvent
| where EventID == 1102
```

<a id="win-shadow-copy-deletion"></a>

## Volume Shadow Copies Deleted

`rules/windows/win_shadow_copy_deletion.yml` · level **high** · id `2e8f4a17-6c3b-4d90-b5e8-7f1a2c4d9e84`

vssadmin or wmic used to delete volume shadow copies. Ransomware does this right before
encrypting files so the victim cannot restore from local snapshots.

**ATT&CK:** [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit System Recovery

**False positives:** Rare. Some backup software prunes old snapshots; confirm the parent process

**Splunk (SPL)**

```spl
index=wineventlog source="WinEventLog:Security" ((EventCode="4688" AND NewProcessName="*\\vssadmin.exe" AND (CommandLine="*delete*" AND CommandLine="*shadows*")) OR (EventCode="4688" AND NewProcessName="*\\wmic.exe" AND (CommandLine="*shadowcopy*" AND CommandLine="*delete*")))
```

**Microsoft Sentinel (KQL)**

```kql
SecurityEvent
| where ((EventID == 4688 and NewProcessName endswith "\\vssadmin.exe" and (CommandLine contains "delete" and CommandLine contains "shadows")) or (EventID == 4688 and NewProcessName endswith "\\wmic.exe" and (CommandLine contains "shadowcopy" and CommandLine contains "delete")))
```

<a id="win-user-added-to-admin-group"></a>

## Account Added to a Privileged Group

`rules/windows/win_user_added_to_admin_group.yml` · level **high** · id `1f7c3a58-9b2d-4e64-a0f3-5d8e6c7b1a26`

A member was added to Administrators, Domain Admins or Enterprise Admins (events 4728, 4732, 4756).
Attackers add accounts they control to admin groups to keep elevated access.

**ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation

**False positives:** Approved admin onboarding; correlate with a change ticket

**Splunk (SPL)**

```spl
index=wineventlog source="WinEventLog:Security" ((EventCode="4728" OR EventCode="4732" OR EventCode="4756") AND (TargetUserName="Administrators" OR TargetUserName="Domain Admins" OR TargetUserName="Enterprise Admins"))
```

**Microsoft Sentinel (KQL)**

```kql
SecurityEvent
| where ((EventID == 4728 or EventID == 4732 or EventID == 4756) and (TargetUserName =~ "Administrators" or TargetUserName =~ "Domain Admins" or TargetUserName =~ "Enterprise Admins"))
```
