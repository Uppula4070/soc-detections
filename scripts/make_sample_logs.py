"""Generate the synthetic sample logs in samples/.

Seeded, so the files are identical on every run. A day of ordinary activity (logons, process starts,
routine AWS API calls) with one intrusion woven through it:

  09:12  password spray from 203.0.113.66 against many accounts
  09:31  encoded PowerShell on a workstation
  09:40  new local account created and added to Administrators
  10:05  shadow copies deleted on a file server, then the Security log is cleared
  11:00  AWS console login without MFA from the same IP
  11:05  AdministratorAccess attached, CloudTrail stopped, GuardDuty detector deleted

All hosts, users, account IDs and IPs are made up (IPs come from documentation ranges).
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

DAY = datetime(2026, 10, 26, tzinfo=timezone.utc)
ATTACKER_IP = "203.0.113.66"
USERS = ["jmiller", "asmith", "pkumar", "lchen", "rgarcia", "tnguyen", "mbrown", "kwilson", "dlee", "sjones"]
HOSTS = ["WS-011", "WS-027", "WS-042", "WS-058", "FS-01", "DC-01"]
ACCOUNT = "111122223333"
NORMAL_PROCS = [
    (r"C:\Windows\explorer.exe", "explorer.exe"),
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --type=renderer"),
    (r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs"),
    (r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "OUTLOOK.EXE"),
    (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"powershell.exe -File C:\scripts\inventory.ps1"),
]
NORMAL_API = [
    ("s3.amazonaws.com", "GetObject"),
    ("s3.amazonaws.com", "ListBuckets"),
    ("ec2.amazonaws.com", "DescribeInstances"),
    ("cloudwatch.amazonaws.com", "GetMetricData"),
    ("sts.amazonaws.com", "AssumeRole"),
]


def ts(t: datetime) -> str:
    return t.isoformat().replace("+00:00", "Z")


def win(t: datetime, event_id: int, host: str, **fields) -> dict:
    return {"TimeCreated": ts(t), "EventID": event_id, "Computer": f"{host}.corp.example", **fields}


def trail(t: datetime, source: str, name: str, user: str, ip: str, **extra) -> dict:
    identity = {"type": "IAMUser", "userName": user, "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}"}
    return {
        "eventTime": ts(t),
        "eventSource": source,
        "eventName": name,
        "eventType": "AwsApiCall",
        "awsRegion": "us-east-1",
        "sourceIPAddress": ip,
        "userIdentity": identity,
        **extra,
    }


def main() -> None:
    rng = random.Random(1102)
    windows, cloud = [], []

    # Background: a working day of logons, typos and process starts.
    for _ in range(400):
        t = DAY + timedelta(hours=rng.uniform(7, 19))
        user, host = rng.choice(USERS), rng.choice(HOSTS)
        windows.append(
            win(
                t,
                4624,
                host,
                TargetUserName=user,
                IpAddress=f"10.0.{rng.randint(1, 9)}.{rng.randint(2, 250)}",
                LogonType=rng.choice([2, 3, 10]),
            )
        )
    for _ in range(25):  # a few mistyped passwords from the office network
        t = DAY + timedelta(hours=rng.uniform(7, 19))
        windows.append(
            win(
                t,
                4625,
                rng.choice(HOSTS),
                TargetUserName=rng.choice(USERS),
                IpAddress=f"10.0.{rng.randint(1, 9)}.{rng.randint(2, 250)}",
                LogonType=2,
            )
        )
    for _ in range(300):
        t = DAY + timedelta(hours=rng.uniform(7, 19))
        image, cmd = rng.choice(NORMAL_PROCS)
        windows.append(
            win(t, 4688, rng.choice(HOSTS), SubjectUserName=rng.choice(USERS), NewProcessName=image, CommandLine=cmd)
        )
    windows.append(
        win(
            DAY + timedelta(hours=8, minutes=3),
            4688,
            "FS-01",
            SubjectUserName="svc_backup",
            NewProcessName=r"C:\Windows\System32\vssadmin.exe",
            CommandLine="vssadmin list shadows",
        )
    )

    # The intrusion.
    t = DAY + timedelta(hours=9, minutes=12)
    for i, user in enumerate(USERS[1:]):  # spray: one password against nine accounts
        windows.append(
            win(t + timedelta(seconds=25 * i), 4625, "DC-01", TargetUserName=user, IpAddress=ATTACKER_IP, LogonType=3)
        )
    windows.append(
        win(t + timedelta(minutes=6), 4624, "DC-01", TargetUserName="jmiller", IpAddress=ATTACKER_IP, LogonType=3)
    )
    windows.append(
        win(
            DAY + timedelta(hours=9, minutes=31),
            4688,
            "WS-042",
            SubjectUserName="jmiller",
            NewProcessName=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        )
    )
    windows.append(
        win(DAY + timedelta(hours=9, minutes=40), 4720, "WS-042", TargetUserName="svc_sync", SubjectUserName="jmiller")
    )
    windows.append(
        win(
            DAY + timedelta(hours=9, minutes=41),
            4732,
            "WS-042",
            TargetUserName="Administrators",
            MemberSid="S-1-5-21-1004336348-1177238915-682003330-1601",
            SubjectUserName="jmiller",
        )
    )
    windows.append(
        win(
            DAY + timedelta(hours=10, minutes=5),
            4688,
            "FS-01",
            SubjectUserName="svc_sync",
            NewProcessName=r"C:\Windows\System32\vssadmin.exe",
            CommandLine="vssadmin.exe delete shadows /all /quiet",
        )
    )
    windows.append(win(DAY + timedelta(hours=10, minutes=7), 1102, "FS-01", SubjectUserName="svc_sync"))

    # Background AWS activity.
    for _ in range(250):
        t = DAY + timedelta(hours=rng.uniform(0, 24))
        source, name = rng.choice(NORMAL_API)
        cloud.append(trail(t, source, name, rng.choice(USERS), f"10.20.{rng.randint(1, 9)}.{rng.randint(2, 250)}"))
    for user in USERS[:6]:
        t = DAY + timedelta(hours=rng.uniform(7, 10))
        cloud.append(
            trail(
                t,
                "signin.amazonaws.com",
                "ConsoleLogin",
                user,
                f"10.20.0.{rng.randint(2, 250)}",
                eventType="AwsConsoleSignIn",
                additionalEventData={"MFAUsed": "Yes"},
                responseElements={"ConsoleLogin": "Success"},
            )
        )
    cloud.append(
        {
            "eventTime": ts(DAY + timedelta(hours=3)),
            "eventSource": "health.amazonaws.com",
            "eventName": "AWSHealthEvent",
            "eventType": "AwsServiceEvent",
            "awsRegion": "us-east-1",
            "userIdentity": {"type": "Root"},
        }
    )

    # The intrusion moves to AWS with the same stolen password.
    t = DAY + timedelta(hours=11)
    cloud.append(
        trail(
            t,
            "signin.amazonaws.com",
            "ConsoleLogin",
            "jmiller",
            ATTACKER_IP,
            eventType="AwsConsoleSignIn",
            additionalEventData={"MFAUsed": "No"},
            responseElements={"ConsoleLogin": "Success"},
        )
    )
    cloud.append(
        trail(
            t + timedelta(minutes=5),
            "iam.amazonaws.com",
            "AttachUserPolicy",
            "jmiller",
            ATTACKER_IP,
            requestParameters={"userName": "jmiller", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        )
    )
    cloud.append(
        trail(
            t + timedelta(minutes=8),
            "cloudtrail.amazonaws.com",
            "StopLogging",
            "jmiller",
            ATTACKER_IP,
            requestParameters={"name": "org-trail"},
        )
    )
    cloud.append(
        trail(
            t + timedelta(minutes=10),
            "guardduty.amazonaws.com",
            "DeleteDetector",
            "jmiller",
            ATTACKER_IP,
            requestParameters={"detectorId": "12abc34d567e8fa901bc2d34e56789f0"},
        )
    )

    out = Path(__file__).resolve().parent.parent / "samples"
    for name, events, key in (
        ("windows-security.jsonl", windows, "TimeCreated"),
        ("cloudtrail.jsonl", cloud, "eventTime"),
    ):
        events.sort(key=lambda e: e[key])
        with open(out / name, "w", encoding="utf-8", newline="\n") as fh:
            for e in events:
                fh.write(json.dumps(e) + "\n")
        print(f"wrote {len(events)} events to samples/{name}")


if __name__ == "__main__":
    main()
