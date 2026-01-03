# Invoke-ThreatHunt

**Lightweight, fast PowerShell tool for threat hunting and forensic timeline analysis on Windows event logs.**

Perfect for SOC analysts and incident responders who want quick, actionable insights without a full SIEM.

## 🎯 Features

- 🔍 Pre-built hunt profiles: Quick, Lateral, Persistence, Malware, and more
- 🚨 Anomaly detection: login spikes, suspicious processes, log clearing, privilege abuse
- 📊 Event correlation and timeline building
- 📁 CSV and HTML report export
- 🖥️ Remote analysis across multiple systems
- ⚡ Pure PowerShell – no agents, no dependencies

## 🚀 Quick Start
```powershell
# Import the module
Import-Module .\Invoke-ThreatHunt.psm1

# Quick triage (last 24 hours)
Invoke-ThreatHunt -HuntProfile Quick

# Full hunt with report
Invoke-ThreatHunt -HuntProfile Comprehensive -Hours 72 -ExportTimeline -GenerateReport

# Hunt for lateral movement
Invoke-ThreatHunt -HuntProfile Lateral -CorrelateEvents
```

## 📚 Documentation

- [Quick Reference Cheat Sheet](docs/Quick_Reference_Complete.md)
- [Full Documentation](docs/Full_Documentation_Complete.md)

## 🛠️ Installation
```powershell
# Clone or download this repository
git clone https://github.com/YourUsername/Invoke-ThreatHunt.git

# Import the module
Import-Module .\Invoke-ThreatHunt.psm1

# Start hunting!
Invoke-ThreatHunt -HuntProfile Quick
```

## 📋 Requirements

- PowerShell 5.1 or higher
- Administrator privileges (for event log access)
- Windows Event Logs enabled

## 🎯 Hunt Profiles

| Profile | Use Case |
|---------|----------|
| **Quick** | Fast triage, routine checks |
| **Comprehensive** | Deep investigation, full spectrum |
| **Lateral** | Lateral movement detection |
| **Persistence** | Finding persistence mechanisms |
| **Exfiltration** | Data theft indicators |
| **Malware** | Malware execution artifacts |
| **Custom** | Specify your own Event IDs |

## 🔍 What It Detects

- ✅ Failed login attempts (brute force, password spray)
- ✅ Privilege escalation attempts
- ✅ Lateral movement via RDP, SMB, PSRemoting
- ✅ Persistence mechanisms (scheduled tasks, services)
- ✅ Suspicious process execution
- ✅ Log tampering and clearing
- ✅ Kerberos attacks (Golden/Silver Ticket indicators)
- ✅ PowerShell abuse

## 📖 Examples
```powershell
# Brute force detection
Invoke-ThreatHunt -HuntProfile Custom -EventIDs 4625,4740,4776 -Hours 24 -ShowAnomalies

# Lateral movement investigation
Invoke-ThreatHunt -HuntProfile Lateral -Hours 48 -CorrelateEvents -ExportTimeline

# Remote system hunt
Invoke-ThreatHunt -ComputerName "DC01","WEB01" -HuntProfile Quick
```

## 🤝 Contributing

Contributions welcome! Feel free to:
- Report bugs
- Suggest new features
- Submit pull requests

## 📄 License

MIT Licensed – use it, share it, improve it.

## ⭐ Support

If this tool helped you, please star the repository! ⭐

**Happy hunting! 🔍**
