# Detection 1 - Failed Logon Attempts

## Objective
Detect failed logon attempts (Event ID 4625) to identify potential brute force or credential guessing attacks.

## Why This Matters
- Attackers use brute force to guess passwords
- Failed logons are early indicator of attack
- Real-time detection allows quick response

## Data Source
Windows Security Event Logs

## Event ID
**4625** - An account failed to log on

## KQL Query

```kql
Event
| where EventID == 4625
| where TimeGenerated > ago(30m)
| project TimeGenerated, Computer, EventID, RenderedDescription
| sort by TimeGenerated desc
```

## How It Works
1. Filters for Event ID 4625 (failed logon)
2. Looks back 30 minutes
3. Returns time, computer, and description
4. Sorts by most recent first

## MITRE ATT&CK
- **Tactic:** Credential Access
- **Technique:** Brute Force (T1110.001)

## Severity
**Medium** - Failed logons require investigation but not immediately critical

## Investigation Steps

1. **Review the event** - What account was targeted? What was the failure reason?
2. **Check for multiple failures** - Is this a single mistake or repeated attack?
3. **Check for success** - Did the attacker eventually get in?
4. **Check source IP** - Is it internal or external?
5. **Take action** - Close if benign, block/reset if suspicious

## Screenshots
---
