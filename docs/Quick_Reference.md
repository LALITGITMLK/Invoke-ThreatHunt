# Invoke-ThreatHunt: Quick Reference Cheat Sheet

## 🚀 Quick Start

```powershell
# Import the tool
Import-Module .\Invoke-ThreatHunt.psm1

# Basic usage (last 24 hours)
Invoke-ThreatHunt

# Full investigation with all features
Invoke-ThreatHunt -HuntProfile Comprehensive -Hours 48 -ShowAnomalies -CorrelateEvents -ExportTimeline -GenerateReport
```

## 🎯 Hunt Profiles

| Profile | Use Case | Example |
|---------|----------|---------|
| Quick | Fast triage, routine checks | `Invoke-ThreatHunt -HuntProfile Quick` |
| Comprehensive | Deep investigation, full spectrum | `Invoke-ThreatHunt -HuntProfile Comprehensive -Hours 72` |
| Lateral | Lateral movement detection | `Invoke-ThreatHunt -HuntProfile Lateral -CorrelateEvents` |
| Persistence | Finding persistence mechanisms | `Invoke-ThreatHunt -HuntProfile Persistence -ShowAnomalies` |
| Exfiltration | Data theft indicators | `Invoke-ThreatHunt -HuntProfile Exfiltration -Hours 48` |
| Malware | Malware execution artifacts | `Invoke-ThreatHunt -HuntProfile Malware -ExportTimeline` |
| Custom | Specific Event IDs | `Invoke-ThreatHunt -HuntProfile Custom -EventIDs 4688,7045` |

## 🔍 Critical Event IDs (Top 20)

| Event ID | Description | Threat Level |
|----------|-------------|--------------|
| 1102 | Audit log cleared | 🔴 CRITICAL |
| 104 | System log cleared | 🔴 CRITICAL |
| 4720 | User account created | 🔴 HIGH |
| 4732 | Admin group member added | 🔴 HIGH |
| 4672 | Special privileges assigned | 🟠 HIGH |
| 4698 | Scheduled task created | 🟠 HIGH |
| 7045 | Service installed | 🟠 HIGH |
| 4625 | Failed logon | 🟡 MEDIUM |
| 4648 | Explicit credentials (RunAs) | 🟡 MEDIUM |
| 4688 | Process created | 🟡 MEDIUM |
| 4768/4769 | Kerberos tickets | 🟡 MEDIUM |
| 4104 | PowerShell script block | 🟠 HIGH |
| 5140 | Network share accessed | 🟡 MEDIUM |
| Sysmon 1 | Process creation (enhanced) | 🟡 MEDIUM |
| Sysmon 3 | Network connection | 🟡 MEDIUM |
| Sysmon 10 | ProcessAccess (LSASS) | 🔴 HIGH |
| 4778/4779 | RDP session | 🟡 MEDIUM |
| 4673 | Sensitive privilege use | 🟠 HIGH |
| 4719 | Audit policy changed | 🔴 CRITICAL |
| 4740 | Account lockout | 🟡 MEDIUM |

## ⏱️ Time Windows

```powershell
# Last 24 hours (default)
Invoke-ThreatHunt

# Last 48 hours
Invoke-ThreatHunt -Hours 48

# Last 7 days
Invoke-ThreatHunt -Hours 168

# Specific time range
Invoke-ThreatHunt -StartTime "2024-01-15 08:00" -EndTime "2024-01-15 18:00"

# Yesterday's activity
$yesterday = (Get-Date).AddDays(-1).Date
Invoke-ThreatHunt -StartTime $yesterday -EndTime $yesterday.AddDays(1)
```

## 🖥️ Remote Investigation

```powershell
# Single remote system
Invoke-ThreatHunt -ComputerName "DC01"

# Multiple systems
Invoke-ThreatHunt -ComputerName "DC01","WEB01","DB01"

# All domain controllers
$dcs = (Get-ADDomainController -Filter *).Name
Invoke-ThreatHunt -ComputerName $dcs -HuntProfile Quick
```

## 📊 Analysis Options

```powershell
# Enable anomaly detection
Invoke-ThreatHunt -ShowAnomalies

# Enable event correlation
Invoke-ThreatHunt -CorrelateEvents

# Export timeline to CSV
Invoke-ThreatHunt -ExportTimeline

# Generate HTML report
Invoke-ThreatHunt -GenerateReport

# All features combined
Invoke-ThreatHunt -ShowAnomalies -CorrelateEvents -ExportTimeline -GenerateReport
```

## 🔬 Common Hunting Scenarios

### Brute Force Detection
```powershell
Invoke-ThreatHunt -HuntProfile Custom -EventIDs 4625,4740,4776 -Hours 24 -ShowAnomalies
```

### Privilege Escalation
```powershell
Invoke-ThreatHunt -HuntProfile Custom -EventIDs 4672,4673,4728,4732 -CorrelateEvents
```

### Lateral Movement
```powershell
Invoke-ThreatHunt -HuntProfile Lateral -Hours 48 -CorrelateEvents -ExportTimeline
```

### PowerShell Abuse
```powershell
Invoke-ThreatHunt -LogNames 'Microsoft-Windows-PowerShell/Operational' -HuntProfile Custom -EventIDs 4103,4104
```

### Log Tampering
```powershell
Invoke-ThreatHunt -HuntProfile Custom -EventIDs 1102,104,1100,4719 -Hours 720
```

## 🎨 Output Filtering

```powershell
# Store results for filtering
$results = Invoke-ThreatHunt -HuntProfile Quick

# Filter by severity
$results | Where-Object Severity -eq 'Critical'

# Filter by event category
$results | Where-Object Category -eq 'Authentication'

# Filter by specific user
$results | Where-Object SubjectUserName -eq 'DOMAIN\user'

# Find failed logins from specific IP
$results | Where-Object {$_.EventID -eq 4625 -and $_.IpAddress -eq '192.168.1.100'}

# Export filtered results
$results | Where-Object Severity -in @('Critical','High') | Export-Csv "critical_findings.csv"
```

## 🛡️ Pre-Deployment Checklist

```powershell
# 1. Verify Administrator privileges
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# 2. Check PowerShell version (need 5.1+)
$PSVersionTable.PSVersion

# 3. Verify audit policies are enabled
auditpol /get /category:*

# 4. Check if Sysmon is installed
Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue

# 5. Test event log access
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 1
```

## 🎯 Investigation Workflow Template

```powershell
# STEP 1: Quick Triage
$triage = Invoke-ThreatHunt -HuntProfile Quick -Hours 24 -ShowAnomalies

# STEP 2: Identify Critical Findings
$critical = $triage | Where-Object Severity -in @('Critical','High')
$critical | Format-Table TimeCreated, EventID, Description, SubjectUserName

# STEP 3: Expand Time Window
$expanded = Invoke-ThreatHunt -HuntProfile Comprehensive -Hours 72 -CorrelateEvents

# STEP 4: Focus on Categories
$lateral = Invoke-ThreatHunt -HuntProfile Lateral -Hours 48 -ExportTimeline

# STEP 5: Generate Final Report
Invoke-ThreatHunt -HuntProfile Comprehensive -StartTime $incidentStart -EndTime $incidentEnd -ShowAnomalies -CorrelateEvents -GenerateReport
```

## 🔑 Critical Flags

### 🚨 IMMEDIATE INVESTIGATION REQUIRED
- Event 1102/104: Log clearing
- Event 4720: New account creation
- Event 4732: Local admin group addition
- Event 4719: Audit policy changed
- Event Sysmon 10: LSASS access (Mimikatz indicator)

### ⚠️ HIGH PRIORITY
- Event 4625: 10+ failed logins from same source
- Event 4672: SeDebugPrivilege assignment
- Event 4698: Scheduled task creation
- Event 7045: Service installation
- Event 4104: Suspicious PowerShell scripts

## 💡 Pro Tips

1. Always start with Quick profile for initial triage
2. Use -ShowAnomalies to highlight statistical outliers
3. Enable -CorrelateEvents for attack chain detection
4. Export everything with -ExportTimeline for documentation
5. Cross-reference with other logs (firewall, proxy, EDR)
6. Establish baselines of normal activity before hunting
7. Use Sysmon for enhanced visibility
8. Keep exports organized by case/incident number
9. Document your methodology for reproducibility
10. Validate findings with system owners before escalating

**Happy hunting! 🔍**
