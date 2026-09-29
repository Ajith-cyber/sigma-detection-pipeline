# 🔍 Detection-as-Code Pipeline

Automated security detection engineering pipeline using Sigma rules with multi-SIEM deployment.

## What This Does

1. **Write** vendor-neutral Sigma detection rules (YAML)
2. **Validate** syntax automatically on every PR
3. **Convert** to SPL (Splunk) + KQL (Sentinel) + CQL (CrowdStrike LogScale)
4. **Test** against golden log samples (known attack data)
5. **Map** coverage to MITRE ATT&CK framework
6. **Deploy** to production SIEMs via API (on merge to main)

## Detection Rules

| Rule | MITRE Technique | Severity |
|------|----------------|----------|
| PowerShell Download Cradle | T1059.001, T1105 | Medium |
| Certutil Download Abuse | T1105, T1218 | High |
| Mimikatz Execution | T1003.001, T1003.002 | Critical |
| Scheduled Task Persistence | T1053.005 | High |
| Registry Run Key Persistence | T1547.001 | High |
| Encoded PowerShell | T1059.001, T1027 | High |
| LSASS Memory Access | T1003.001 | Critical |
| Suspicious DNS Query | T1071.004 | Low |
| Linux Reverse Shell | T1059.004 | Critical |
| Linux Cron Persistence | T1053.003 | High |

## MITRE ATT&CK Coverage

Upload `coverage/mitre-navigator.json` to [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to see the heatmap.

## Pipeline Architecture