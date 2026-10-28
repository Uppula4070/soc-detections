# Roadmap

Small, self-contained improvements. Each one is a single commit (or one pull request) and keeps CI green.
Size: 🟢 under an hour · 🟡 an evening · 🔴 a weekend.

## New detections

Each new rule needs: the rule in `rules/`, a scenario file in `tests/cases/` (at least one firing and one quiet
scenario), the technique name in `src/socdet/attack.py`, the rule count in `tests/test_sigma.py`, and
regenerated docs (`socdet docs`).

- [ ] 🟢 **Scheduled task created** (Windows event 4698, ATT&CK T1053.005). *Good first task: step-by-step guide below.*
- [ ] 🟢 **AWS access key created for a different user** (`CreateAccessKey` where the target user is not the caller, T1098.001)
- [ ] 🟢 **AWS S3 bucket policy or ACL changed** (`PutBucketPolicy`, `PutBucketAcl`, `DeletePublicAccessBlock`)
- [ ] 🟡 **New Windows service installed** (System log event 7045, T1543.003). Needs a `service: system` log source.
- [ ] 🟡 **Cloud discovery burst**: many `List*` / `Describe*` calls from one new IP in 5 minutes (aggregation rule, Discovery tactic)
- [ ] 🟡 **RDP from a workstation to a server** (4624 with LogonType 10, Lateral Movement tactic)

## Engine and tooling

- [ ] 🟡 Support the Sigma `|re` (regular expression) modifier in the engine and both backends
- [ ] 🟡 Add an Elastic (ES|QL) backend next to Splunk and Sentinel
- [ ] 🔴 Run a handful of public SigmaHQ rules through the engine and document what is and isn't supported

## Phishing triage

- [ ] 🟢 Flag `.zip` attachments that contain an executable (inspect the archive's file list)
- [ ] 🟡 Read `Received:` headers and show the hop path in the ticket

---

## Step-by-step: your first detection (scheduled task created)

Attackers create scheduled tasks so their code keeps running after a reboot. Windows logs event **4698** when a
task is created. Built-in Windows tasks live under `\Microsoft\`, so those are excluded to avoid noise.

**1. Get the latest code and install the tool** (run inside the repo folder)

```bash
git pull
pip install -e ".[dev]"
```

**2. Make a new ID for the rule**

```bash
python -c "import uuid; print(uuid.uuid4())"
```

**3. Create `rules/windows/win_scheduled_task_created.yml`** (put your new ID on the `id:` line)

```yaml
title: Scheduled Task Created
id: PASTE-YOUR-NEW-ID-HERE
status: experimental
description: |
  A scheduled task was created (event 4698). Attackers use scheduled tasks to keep their code running after a
  reboot. Built-in Windows tasks under \Microsoft\ are excluded.
author: Vaishnavi U
date: 2026-10-28
tags:
  - attack.persistence
  - attack.t1053.005
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
  filter_builtin:
    TaskName|startswith: '\Microsoft\'
  condition: selection and not filter_builtin
falsepositives:
  - Software installers and IT management tools that create their own update tasks
level: medium
```

**4. Create `tests/cases/win_scheduled_task_created.yml`**

```yaml
scenarios:
  - name: user creates a task
    expect: 1
    events:
      - {EventID: 4698, TaskName: '\Updater', SubjectUserName: jmiller}
  - name: built-in Windows task is ignored
    expect: 0
    events:
      - {EventID: 4698, TaskName: '\Microsoft\Windows\Defrag\ScheduledDefrag', SubjectUserName: SYSTEM}
  - name: other events are ignored
    expect: 0
    events:
      - {EventID: 4624, TargetUserName: jmiller}
```

**5. Tell the ATT&CK map about the new technique.** In `src/socdet/attack.py`, add this line to `TECHNIQUES`:

```python
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
```

and this line to `TECHNIQUE_TACTICS`:

```python
    "T1053.005": {"execution", "persistence", "privilege_escalation"},
```

**6. Update the rule count.** In `tests/test_sigma.py`, change `assert len(rules) == 12` to `13`.

**7. Test and regenerate the docs**

```bash
socdet test
```

```bash
socdet docs
```

```bash
python -m pytest -q
```

All three must pass. `socdet docs` updates `docs/rules.md` and `docs/coverage.md`; CI checks they match the rules.

**8. Commit and push**

```bash
git add rules tests src docs ROADMAP.md
```

```bash
git commit -m "Add scheduled task creation detection (T1053.005)"
```

```bash
git push
```

Then open the repo's **Actions** tab and check the run goes green. Finally, tick the box at the top of this file
in your next commit.
