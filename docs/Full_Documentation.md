# Invoke-ThreatHunt: Comprehensive Documentation

## 📋 Table of Contents

1. [Overview](#overview)
2. [Event ID Coverage](#event-id-coverage)
3. [Installation & Setup](#installation--setup)
4. [Usage Examples](#usage-examples)
5. [Hunt Profiles Explained](#hunt-profiles-explained)
6. [Timeline Analysis](#timeline-analysis)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

## 🎯 Overview

Invoke-ThreatHunt is a comprehensive PowerShell-based threat hunting and forensic timeline analysis tool designed for Security Operations Centers (SOCs), incident responders, and threat hunters.

### Key Capabilities

- ✅ **Timeline Reconstruction** – Build chronological attack timelines across multiple log sources
- ✅ **Multi-Source Analysis** – Correlate events from Security, System, Application, PowerShell, and Sysmon logs
- ✅ **Anomaly Detection** – Statistical analysis to identify outliers and suspicious patterns
- ✅ **Event Correlation** – Link related events by time, user, and context
- ✅ **Automated Reporting** – Generate HTML reports and CSV exports for documentation
- ✅ **Remote Investigation** – Analyze multiple systems simultaneously
- ✅ **Pre-built Hunt Profiles** – Quick-start templates for common investigation scenarios

## 🔍 Event ID Coverage

### Complete Event ID Catalog (100+ Events)

#### AUTHENTICATION & ACCOUNT MANAGEMENT (17 Events)

| Event ID | Description | Threat Context | Key Fields |
|----------|-------------|----------------|------------|
| **4624** | Successful logon | Baseline activity; suspicious from unusual locations | TargetUserName, IpAddress, LogonType, WorkstationName |
| **4625** | Failed logon attempt | Password spray, brute force, credential stuffing | TargetUserName, IpAddress, FailureReason, SubStatus |
| **4648** | Logon using explicit credentials (RunAs) | Lateral movement, privilege escalation | SubjectUserName, TargetUserName, TargetServerName |
| **4672** | Special privileges assigned | Administrator/SYSTEM logon; SeDebugPrivilege abuse | SubjectUserName, PrivilegeList |
| **4768** | Kerberos TGT requested | Golden Ticket detection; unusual encryption types | TargetUserName, IpAddress, TicketEncryptionType |
| **4769** | Kerberos service ticket requested | Silver Ticket, Kerberoasting detection | TargetUserName, ServiceName, IpAddress |
| **4776** | Domain controller credential validation | NTLM authentication; password spray detection | TargetUserName, Workstation |
| **4720** | User account created | Unauthorized account creation; persistence | TargetUserName, SubjectUserName |
| **4722** | User account enabled | Dormant account activation | TargetUserName, SubjectUserName |
| **4724** | Password reset attempted | Unauthorized password reset | TargetUserName, SubjectUserName |
| **4728** | Member added to global group | Privilege escalation via group membership | TargetUserName, MemberName, SubjectUserName |
| **4732** | Member added to local group | Local admin addition; persistence mechanism | TargetUserName, MemberName, SubjectUserName |
| **4738** | User account changed | Account modification for privilege escalation | TargetUserName, SubjectUserName |
| **4740** | User account locked out | Brute force attack result; DoS attempt | TargetUserName, SubjectUserName |
| **4767** | User account unlocked | Follow-up to lockout events | TargetUserName, SubjectUserName |
| **4778** | RDP session reconnected | RDP lateral movement tracking | AccountName, ClientName, ClientAddress |
| **4779** | RDP session disconnected | RDP session termination tracking | AccountName, ClientName, ClientAddress |

#### PROCESS EXECUTION & CODE EXECUTION (10 Events)

| Event ID | Description | Threat Context | Key Fields |
|----------|-------------|----------------|------------|
| **4688** | New process created | Malware execution, LOLBins abuse | NewProcessName, CommandLine, ParentProcessName, SubjectUserName |
| **4689** | Process terminated | Process lifetime tracking; anti-forensics detection | ProcessName, SubjectUserName |
| **4103** | PowerShell module logging | PowerShell command execution tracking | HostApplication, CommandLine |
| **4104** | PowerShell script block logging | Full PowerShell script content; malware analysis | ScriptBlockText, Path |
| **400** | PowerShell engine started | PowerShell session initiation | HostApplication |
| **403** | PowerShell engine stopped | PowerShell session termination | - |
| **Sysmon 1** | Process creation (enhanced) | Enhanced process tracking with file hashes | Image, CommandLine, ParentImage, Hashes, User |
| **Sysmon 7** | Image loaded (DLL) | DLL injection; malicious library loading | Image, ImageLoaded, Hashes |
| **Sysmon 8** | CreateRemoteThread | Process injection technique detection | SourceImage, TargetImage, StartFunction |
| **Sysmon 10** | ProcessAccess | LSASS access; credential dumping (Mimikatz) | SourceImage, TargetImage, GrantedAccess |

#### LATERAL MOVEMENT & NETWORK (6 Events)

| Event ID | Description | Threat Context | Key Fields |
|----------|-------------|----------------|------------|
| **5140** | Network share accessed | Lateral movement via SMB; data exfiltration | SubjectUserName, ShareName, IpAddress |
| **5145** | Network share object accessed | File access on network shares | SubjectUserName, ShareName, RelativeTargetName, IpAddress |
| **5156** | Windows Firewall connection allowed | Network connection tracking; C2 communication | Application, SourceAddress, DestAddress, DestPort |
| **5157** | Windows Firewall connection blocked | Blocked malicious connection attempts | Application, SourceAddress, DestAddress, DestPort |
| **Sysmon 3** | Network connection | Detailed connection tracking; C2 detection | Image, DestinationIp, DestinationPort, User |
| **Sysmon 22** | DNS query | DNS-based C2 detection; data exfiltration | Image, QueryName, QueryResults |

#### PERSISTENCE MECHANISMS (10 Events)

| Event ID | Description | Threat Context | Key Fields |
|----------|-------------|----------------|------------|
| **4698** | Scheduled task created | Scheduled task persistence mechanism | TaskName, SubjectUserName |
| **4699** | Scheduled task deleted | Cleanup of persistence mechanism | TaskName, SubjectUserName |
| **4702** | Scheduled task updated | Modification of existing task for persistence | TaskName, SubjectUserName |
| **7045** | Service installed | Service-based persistence; malware installation | ServiceName, ServiceFileName, ServiceType |
| **7040** | Service start type changed | Service modification for persistence | ServiceName, StartType |
| **7036** | Service started or stopped | Service execution tracking | ServiceName, State |
| **4657** | Registry value modified | Registry persistence; configuration tampering | SubjectUserName, ObjectName, ObjectValueName |
| **Sysmon 12** | Registry object added/deleted | Registry-based persistence tracking | Image, TargetObject, EventType |
| **Sysmon 13** | Registry value set | Registry modification tracking | Image, TargetObject, Details |
| **Sysmon 11** | File created | Malware dropper activity detection | Image, TargetFilename |

#### LOG TAMPERING & ANTI-FORENSICS (3 Events)

| Event ID | Description | Threat Context | Key Fields |
|----------|-------------|----------------|------------|
| **1102** | Security audit log cleared | **CRITICAL** - Evidence destruction attempt | SubjectUserName |
| **104** | System event log cleared | **CRITICAL** - Evidence destruction attempt | SubjectUserName |
| **1100** | Event logging service shutdown | **CRITICAL** - Disabling security logging | - |

## 🛠️ Installation & Setup

### Prerequisites

```powershell
# Check PowerShell version (requires 5.1+)
$PSVersionTable.PSVersion

# Verify Administrator privileges
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

### Installation

**Option 1: Direct Import**
```powershell
# Download and import
Import-Module .\Invoke-ThreatHunt.ps1
```

**Option 2: Install as Module**
```powershell
# Copy to PowerShell modules directory
$modulePath = "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\ThreatHunt"
New-Item -Path $modulePath -ItemType Directory -Force
Copy-Item .\Invoke-ThreatHunt.psm1 $modulePath

# Import module
Import-Module ThreatHunt
```

### Enable Advanced Logging

```powershell
# Enable command-line process auditing (Event 4688 with CommandLine)
auditpol /set /category:"Detailed Tracking" /subcategory:"Process Creation" /success:enable /failure:enable

# Enable PowerShell Script Block Logging
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1

# Enable PowerShell Module Logging
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableModuleLogging" -Value 1

# Enable Process Creation with CommandLine
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
```

## 💻 Usage Examples

### Basic Usage

```powershell
# Quick triage of last 24 hours (default)
Invoke-ThreatHunt

# Quick hunt with verbose output
Invoke-ThreatHunt -Verbose

# Store results for further analysis
$results = Invoke-ThreatHunt -HuntProfile Quick
$results | Export-Csv "my_hunt_results.csv" -NoTypeInformation
```

### Time-Based Hunts

```powershell
# Last 48 hours
Invoke-ThreatHunt -Hours 48

# Last 7 days
Invoke-ThreatHunt -Hours 168

# Specific time window
Invoke-ThreatHunt -StartTime "2024-01-15 08:00" -EndTime "2024-01-15 18:00"

# Overnight activity (previous night)
$yesterday = (Get-Date).Date.AddDays(-1)
Invoke-ThreatHunt -StartTime "$yesterday 18:00" -EndTime "$yesterday 08:00"
```

### Hunt Profile Examples

```powershell
# Quick triage (most common indicators)
Invoke-ThreatHunt -HuntProfile Quick

# Comprehensive hunt (all event categories)
Invoke-ThreatHunt -HuntProfile Comprehensive -Hours 72

# Lateral movement focus
Invoke-ThreatHunt -HuntProfile Lateral -ShowAnomalies -CorrelateEvents

# Persistence mechanism hunting
Invoke-ThreatHunt -HuntProfile Persistence -ExportTimeline

# Data exfiltration indicators
Invoke-ThreatHunt -HuntProfile Exfiltration -GenerateReport

# Malware execution artifacts
Invoke-ThreatHunt -HuntProfile Malware -Hours 24
```

## 🎯 Hunt Profiles Explained

### 1. Quick Profile (Fast Triage)

**Use Case:** Initial investigation, routine checks, incident triage

**Events Covered:**
- 4624, 4625 - Login success/failure
- 4648 - Explicit credentials (RunAs)
- 4672 - Special privileges
- 4688 - Process creation
- 4720 - Account creation
- 4740 - Account lockout
- 1102 - Log clearing

**When to Use:**
- ✅ First response to an alert
- ✅ Daily/weekly security checks
- ✅ Quick system health assessment
- ✅ When time is limited

**Example:**
```powershell
# Morning security check
Invoke-ThreatHunt -HuntProfile Quick -Hours 24 -ShowAnomalies
```

### 2. Lateral Profile (Lateral Movement Detection)

**Use Case:** Detecting adversary movement between systems

**Events Covered:**
- 4624 - Successful logons (especially Type 3, 10)
- 4648 - Explicit credentials
- 4778, 4779 - RDP sessions
- 5140, 5145 - Network share access
- 4768, 4769 - Kerberos tickets

**Attack Techniques Detected:**
- Pass-the-Hash (PtH)
- Pass-the-Ticket (PtT)
- RDP hijacking
- SMB lateral movement
- PSRemoting abuse

**Example:**
```powershell
# Investigate suspected lateral movement
Invoke-ThreatHunt -HuntProfile Lateral -StartTime "2024-01-15 14:00" -EndTime "2024-01-15 16:00" -CorrelateEvents
```

### 3. Persistence Profile (Persistence Mechanism Hunting)

**Use Case:** Finding how attackers maintain access

**Events Covered:**
- 4698, 4699, 4702 - Scheduled tasks
- 7045, 7040, 7036 - Services
- 4720, 4728, 4732 - Account/group modifications
- 4657, Sysmon 12, 13 - Registry changes

**Attack Techniques Detected:**
- Scheduled task backdoors
- Service installation
- Registry Run keys
- Account creation
- Startup folder modifications

**Example:**
```powershell
# Hunt for persistence after compromise
Invoke-ThreatHunt -HuntProfile Persistence -Hours 72 -ShowAnomalies -ExportTimeline
```

## 📊 Timeline Analysis

### Understanding Timeline Output

The tool builds a chronological timeline of all events, sorted by TimeCreated.

### Timeline Analysis Techniques

#### 1. Identify First Compromise
```powershell
$results = Invoke-ThreatHunt -HuntProfile Comprehensive -Hours 168

# Find earliest suspicious activity
$results | Where-Object {
    $_.EventID -in @(4625, 4648, 4672) -and
    $_.LogonType -in @(3, 10)
} | Sort-Object TimeCreated | Select-Object -First 5
```

#### 2. Track Attacker Movement
```powershell
# Follow a specific user's activity chronologically
$suspiciousUser = "DOMAIN\compromised_user"
$results | Where-Object SubjectUserName -eq $suspiciousUser |
           Sort-Object TimeCreated |
           Select-Object TimeCreated, EventID, Description, ProcessName, IpAddress
```

#### 3. Detect Time Gaps (Evidence Deletion)
```powershell
# Find suspicious gaps in logging
$timeDiffs = for ($i = 1; $i -lt $results.Count; $i++) {
    $gap = ($results[$i].TimeCreated - $results[$i-1].TimeCreated).TotalMinutes
    if ($gap -gt 30) {
        [PSCustomObject]@{
            GapStart = $results[$i-1].TimeCreated
            GapEnd = $results[$i].TimeCreated
            GapMinutes = $gap
        }
    }
}
```

## ✅ Best Practices

### Before Investigation

1. **Document Everything**
   ```powershell
   # Create case folder structure
   $caseID = "INC-2024-001"
   $casePath = "C:\Investigations\$caseID"
   New-Item -Path $casePath -ItemType Directory -Force
   ```

2. **Preserve Original Logs**
   ```powershell
   # Backup logs before analysis
   wevtutil epl Security "$casePath\Logs\Security_Original.evtx"
   wevtutil epl System "$casePath\Logs\System_Original.evtx"
   ```

3. **Establish Timeline Boundaries**
   - First suspicious indicator timestamp
   - Last known good backup timestamp
   - Current investigation time

### During Investigation

1. **Use Incremental Hunting**
   ```powershell
   # Start with Quick profile
   Invoke-ThreatHunt -HuntProfile Quick -Hours 24 -ShowAnomalies
   
   # Expand based on findings
   Invoke-ThreatHunt -HuntProfile Lateral -Hours 48 -CorrelateEvents
   ```

2. **Validate Findings**
   - Cross-reference with other data sources
   - Verify timestamps (check time zones)
   - Confirm user legitimacy
   - Check business context

3. **Maintain Chain of Custody**
   ```powershell
   # Document and hash exports
   Get-FileHash "$casePath\Evidence\*.csv" | Export-Csv "$casePath\Evidence\Hashes.csv"
   ```

## ⚠️ Do's and Don'ts

### ✅ DO:

1. **DO run with appropriate privileges**
2. **DO use appropriate time windows** (24-72 hours recommended)
3. **DO filter and refine results**
4. **DO correlate with business context**
5. **DO export and preserve evidence**
6. **DO validate anomalies**

### ❌ DON'T:

1. **DON'T run on production without testing**
2. **DON'T ignore time zones**
3. **DON'T hunt without a hypothesis**
4. **DON'T modify logs during investigation**
5. **DON'T rely solely on automated detection**
6. **DON'T share raw data insecurely**

## 🐛 Troubleshooting

### Issue 1: "Access Denied" or No Events

**Solutions:**
```powershell
# Check Administrator privileges
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Verify event log service
Get-Service -Name EventLog
```

### Issue 2: Performance Issues

**Solutions:**
```powershell
# Use shorter time windows
Invoke-ThreatHunt -Hours 24  # Instead of -Hours 168

# Use specific hunt profiles
Invoke-ThreatHunt -HuntProfile Quick  # Instead of Comprehensive
```

### Issue 3: Missing Sysmon Events

**Solutions:**
```powershell
# Check if Sysmon is installed
Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue

# Verify Sysmon log exists
Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational
```

## 📚 Additional Resources

- **MITRE ATT&CK Framework**: https://attack.mitre.org/
- **Windows Security Log Encyclopedia**: https://www.ultimatewindowssecurity.com/
- **Sysmon Documentation**: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

---

**MIT Licensed – fork it, improve it, share it.**

**Happy Hunting! 🎯🔍**
