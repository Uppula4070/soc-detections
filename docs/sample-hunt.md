# Hunt results

1,002 events searched, **10 alerts** (8 high, 2 medium).

## Timeline

| Time (UTC) | Level | Detection | Details |
|---|---|---|---|
| 2026-10-26 09:14:05 | high | Password Spray - Failed Logons to Many Accounts From One Source | IpAddress 203.0.113.66: 6 distinct TargetUserName within 10m; accounts: asmith, lchen, mbrown, pkumar, rgarcia, tnguyen |
| 2026-10-26 09:31:00 | high | PowerShell Started With an Encoded Command | Computer: WS-042.corp.example; SubjectUserName: jmiller; NewProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe; CommandLine: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA |
| 2026-10-26 09:40:00 | medium | User Account Created | Computer: WS-042.corp.example; SubjectUserName: jmiller; TargetUserName: svc_sync |
| 2026-10-26 09:41:00 | high | Account Added to a Privileged Group | Computer: WS-042.corp.example; SubjectUserName: jmiller; TargetUserName: Administrators |
| 2026-10-26 10:05:00 | high | Volume Shadow Copies Deleted | Computer: FS-01.corp.example; SubjectUserName: svc_sync; NewProcessName: C:\Windows\System32\vssadmin.exe; CommandLine: vssadmin.exe delete shadows /all /quiet |
| 2026-10-26 10:07:00 | high | Windows Security Event Log Cleared | Computer: FS-01.corp.example; SubjectUserName: svc_sync |
| 2026-10-26 11:00:00 | medium | AWS Console Login Without MFA | userName: jmiller; type: IAMUser; sourceIPAddress: 203.0.113.66; eventName: ConsoleLogin |
| 2026-10-26 11:05:00 | high | AWS AdministratorAccess Policy Attached | userName: jmiller; type: IAMUser; sourceIPAddress: 203.0.113.66; eventName: AttachUserPolicy; requestParameters: userName=jmiller, policyArn=arn:aws:iam::aws:policy/AdministratorAccess |
| 2026-10-26 11:08:00 | high | AWS CloudTrail Logging Stopped or Trail Deleted | userName: jmiller; type: IAMUser; sourceIPAddress: 203.0.113.66; eventName: StopLogging; requestParameters: name=org-trail |
| 2026-10-26 11:10:00 | high | AWS GuardDuty Detector Deleted or Monitoring Stopped | userName: jmiller; type: IAMUser; sourceIPAddress: 203.0.113.66; eventName: DeleteDetector; requestParameters: detectorId=12abc34d567e8fa901bc2d34e56789f0 |

## ATT&CK techniques observed

- [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files or Information
- [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell
- [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Indicator Removal: Clear Windows Event Logs
- [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts: Cloud Accounts
- [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation
- [T1098.003](https://attack.mitre.org/techniques/T1098/003/) Account Manipulation: Additional Cloud Roles
- [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Brute Force: Password Spraying
- [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local Account
- [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit System Recovery
- [T1562.001](https://attack.mitre.org/techniques/T1562/001/) Impair Defenses: Disable or Modify Tools
- [T1562.008](https://attack.mitre.org/techniques/T1562/008/) Impair Defenses: Disable or Modify Cloud Logs
