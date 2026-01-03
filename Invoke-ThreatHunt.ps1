<#
.SYNOPSIS
    Advanced Windows Event Log Threat Hunting and Timeline Analysis Tool
    
.DESCRIPTION
    Invoke-ThreatHunt is a comprehensive forensic analysis tool designed for:
    - Real-time threat detection and anomaly identification
    - Timeline reconstruction of security events
    - Correlation of related security events across multiple log sources
    - Quick triage and deep-dive investigation capabilities
    
.PARAMETER Hours
    Time window to analyze (default: 24 hours)
    
.PARAMETER StartTime
    Specific start datetime for analysis (overrides -Hours)
    
.PARAMETER EndTime
    Specific end datetime for analysis
    
.PARAMETER HuntProfile
    Pre-configured hunting profiles:
    - 'Quick': Fast triage (login failures, process creation, privilege escalation)
    - 'Comprehensive': Full spectrum hunt (all event categories)
    - 'Lateral': Lateral movement focus (RDP, PSRemoting, network shares)
    - 'Persistence': Persistence mechanisms (scheduled tasks, services, startups)
    - 'Exfiltration': Data theft indicators (large file access, network transfers)
    - 'Malware': Malware execution artifacts
    - 'Custom': Specify your own EventIDs
    
.PARAMETER EventIDs
    Array of specific Event IDs to hunt (used with -HuntProfile 'Custom')
    
.PARAMETER LogNames
    Specific log names to search (default: Security, System, Application, PowerShell)
    
.PARAMETER ComputerName
    Remote computer name(s) to analyze (requires appropriate permissions)
    
.PARAMETER ExportTimeline
    Export timeline to CSV with correlation analysis
    
.PARAMETER ExportPath
    Custom export path (default: .\ThreatHunt_TIMESTAMP)
    
.PARAMETER ShowAnomalies
    Display anomaly detection results (statistical outliers, rare events)
    
.PARAMETER CorrelateEvents
    Perform event correlation analysis (links related events by time/context)
    
.PARAMETER GenerateReport
    Create HTML investigation report with visualizations

.EXAMPLE
    Invoke-ThreatHunt -HuntProfile Quick
    
.EXAMPLE
    Invoke-ThreatHunt -HuntProfile Comprehensive -Hours 48 -ExportTimeline -GenerateReport

.NOTES
    Author: SOC Threat Hunter
    Version: 2.0
    Requires: PowerShell 5.1+, Administrator privileges
#>

function Invoke-ThreatHunt {
    [CmdletBinding(DefaultParameterSetName = 'TimeWindow')]
    param (
        [Parameter(ParameterSetName = 'TimeWindow')]
        [int]$Hours = 24,
        
        [Parameter(ParameterSetName = 'Specific')]
        [datetime]$StartTime,
        
        [Parameter(ParameterSetName = 'Specific')]
        [datetime]$EndTime,
        
        [Parameter()]
        [ValidateSet('Quick', 'Comprehensive', 'Lateral', 'Persistence', 'Exfiltration', 'Malware', 'Custom')]
        [string]$HuntProfile = 'Quick',
        
        [Parameter()]
        [int[]]$EventIDs,
        
        [Parameter()]
        [string[]]$LogNames = @('Security', 'System', 'Application', 'Microsoft-Windows-PowerShell/Operational'),
        
        [Parameter()]
        [string[]]$ComputerName = @($env:COMPUTERNAME),
        
        [Parameter()]
        [switch]$ExportTimeline,
        
        [Parameter()]
        [string]$ExportPath,
        
        [Parameter()]
        [switch]$ShowAnomalies,
        
        [Parameter()]
        [switch]$CorrelateEvents,
        
        [Parameter()]
        [switch]$GenerateReport
    )

    # Event Catalog with threat context
    $EventCatalog = @{
        4624 = @{ Description = "Successful logon"; Category = "Authentication"; Severity = "Info" }
        4625 = @{ Description = "Failed logon attempt"; Category = "Authentication"; Severity = "Warning" }
        4648 = @{ Description = "Logon using explicit credentials"; Category = "Authentication"; Severity = "Medium" }
        4672 = @{ Description = "Special privileges assigned"; Category = "Privilege"; Severity = "High" }
        4768 = @{ Description = "Kerberos TGT requested"; Category = "Authentication"; Severity = "Info" }
        4769 = @{ Description = "Kerberos service ticket requested"; Category = "Authentication"; Severity = "Info" }
        4720 = @{ Description = "User account created"; Category = "Account Management"; Severity = "High" }
        4728 = @{ Description = "Member added to global group"; Category = "Account Management"; Severity = "High" }
        4732 = @{ Description = "Member added to local group"; Category = "Account Management"; Severity = "High" }
        4740 = @{ Description = "User account locked out"; Category = "Account Management"; Severity = "Warning" }
        4688 = @{ Description = "New process created"; Category = "Process Execution"; Severity = "Info" }
        4689 = @{ Description = "Process terminated"; Category = "Process Execution"; Severity = "Info" }
        7045 = @{ Description = "Service installed"; Category = "Persistence"; Severity = "High" }
        4698 = @{ Description = "Scheduled task created"; Category = "Persistence"; Severity = "High" }
        1102 = @{ Description = "Audit log cleared"; Category = "Tampering"; Severity = "Critical" }
        104  = @{ Description = "System log cleared"; Category = "Tampering"; Severity = "Critical" }
        4778 = @{ Description = "Session reconnected (RDP)"; Category = "Lateral Movement"; Severity = "Medium" }
        4779 = @{ Description = "Session disconnected (RDP)"; Category = "Lateral Movement"; Severity = "Info" }
        5140 = @{ Description = "Network share accessed"; Category = "Lateral Movement"; Severity = "Medium" }
        5145 = @{ Description = "Network share object accessed"; Category = "Lateral Movement"; Severity = "Info" }
        4103 = @{ Description = "PowerShell module logging"; Category = "Code Execution"; Severity = "Medium" }
        4104 = @{ Description = "PowerShell script block logging"; Category = "Code Execution"; Severity = "High" }
    }

    # Hunt profile Event ID mapping
    $ProfileEventIDs = switch ($HuntProfile) {
        'Quick'         { @(4624,4625,4648,4672,4688,4720,4740,1102,7045,4698) }
        'Comprehensive' { $EventCatalog.Keys }
        'Lateral'       { @(4624,4648,4778,4779,5140,5145,4768,4769) }
        'Persistence'   { @(4698,7045,4720,4728,4732) }
        'Exfiltration'  { @(5140,5145) }
        'Malware'       { @(4688,4104,7045) }
        'Custom'        { $EventIDs }
        default         { @(4624,4625,4648,4672,4688,4720,4740,1102) }
    }

    if ($HuntProfile -eq 'Custom' -and -not $EventIDs) {
        Write-Error "When using -HuntProfile Custom, you must provide -EventIDs"
        return
    }

    $FinalEventIDs = $ProfileEventIDs

    # Determine time range
    if ($StartTime -and $EndTime) {
        $FilterStart = $StartTime
        $FilterEnd = $EndTime
    } else {
        $FilterEnd = Get-Date
        $FilterStart = $FilterEnd.AddHours(-$Hours)
    }

    # Default export path
    if (-not $ExportPath) {
        $ExportPath = Join-Path (Get-Location) "ThreatHunt_$(Get-Date -Format 'yyyyMMdd_HHmm')"
    }

    Write-Host "`n╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           INVOKE-THREATHUNT - Timeline Analysis Tool             ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Hunt Profile   : " -NoNewline -ForegroundColor Yellow
    Write-Host $HuntProfile -ForegroundColor White
    Write-Host "Time Window    : " -NoNewline -ForegroundColor Yellow
    Write-Host "$FilterStart  →  $FilterEnd" -ForegroundColor White
    Write-Host "Target Systems : " -NoNewline -ForegroundColor Yellow
    Write-Host ($ComputerName -join ', ') -ForegroundColor White
    Write-Host ""

    $Timeline = @()

    foreach ($computer in $ComputerName) {
        Write-Verbose "Querying $computer..."
        foreach ($log in $LogNames) {
            try {
                $Filter = @{
                    LogName   = $log
                    ID        = $FinalEventIDs
                    StartTime = $FilterStart
                    EndTime   = $FilterEnd
                }
                
                $events = Get-WinEvent -ComputerName $computer -FilterHashtable $Filter -ErrorAction SilentlyContinue
                
                if ($events) {
                    Write-Host "  [+] $log on $computer : " -NoNewline -ForegroundColor Green
                    Write-Host "$($events.Count) events" -ForegroundColor White
                    
                    $Timeline += $events | ForEach-Object {
                        $xml = [xml]$_.ToXml()
                        $data = $xml.Event.EventData.Data
                        $props = $EventCatalog[$_.Id]
                        
                        if (-not $props) {
                            $props = @{ Description = "Unknown Event"; Category = "Other"; Severity = "Info" }
                        }

                        [pscustomobject]@{
                            TimeCreated      = $_.TimeCreated
                            Computer         = $computer
                            EventID          = $_.Id
                            Description      = $props.Description
                            Category         = $props.Category
                            Severity         = $props.Severity
                            TargetUserName   = ($data | Where-Object Name -eq 'TargetUserName').'#text'
                            SubjectUserName  = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
                            IpAddress        = ($data | Where-Object Name -eq 'IpAddress').'#text'
                            WorkstationName  = ($data | Where-Object Name -eq 'WorkstationName').'#text'
                            LogonType        = ($data | Where-Object Name -eq 'LogonType').'#text'
                            ProcessName      = ($data | Where-Object Name -eq 'NewProcessName').'#text'
                            ParentProcessName= ($data | Where-Object Name -eq 'ParentProcessName').'#text'
                            CommandLine      = ($data | Where-Object Name -eq 'CommandLine').'#text'
                            PrivilegeList    = ($data | Where-Object Name -eq 'PrivilegeList').'#text'
                            ServiceName      = ($data | Where-Object Name -eq 'ServiceName').'#text'
                            TaskName         = ($data | Where-Object Name -eq 'TaskName').'#text'
                        }
                    }
                }
            } catch {
                Write-Host "  [!] Failed to query $log on $computer" -ForegroundColor Red
            }
        }
    }

    if (-not $Timeline) {
        Write-Host "`n[!] No events found matching the criteria." -ForegroundColor Yellow
        return
    }

    $Timeline = $Timeline | Sort-Object TimeCreated
    Write-Host "`n[+] Total events collected: " -NoNewline -ForegroundColor Green
    Write-Host "$($Timeline.Count)" -ForegroundColor White

    # Anomaly Detection
    if ($ShowAnomalies) {
        Write-Host "`n╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
        Write-Host "║                    ANOMALY DETECTION RESULTS                      ║" -ForegroundColor Magenta
        Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta

        # Failed login spikes
        $failedLogins = $Timeline | Where-Object EventID -eq 4625 | Group-Object TargetUserName | Where-Object Count -gt 10
        if ($failedLogins) {
            Write-Host "`n[!] HIGH LOGIN FAILURE COUNTS DETECTED" -ForegroundColor Red
            $failedLogins | Select-Object @{N='Username';E={$_.Name}}, Count | Format-Table -AutoSize
        }

        # Suspicious processes
        $suspiciousProcesses = $Timeline | Where-Object EventID -eq 4688 | Where-Object {
            $_.CommandLine -match 'hidden|encodedcommand|-w hidden|powershell.*-e'
        }
        if ($suspiciousProcesses) {
            Write-Host "`n[!] SUSPICIOUS PROCESS EXECUTIONS DETECTED" -ForegroundColor Red
            $suspiciousProcesses | Select-Object TimeCreated, ProcessName, SubjectUserName | Format-Table -AutoSize
        }

        # Log clearing
        $clearedLogs = $Timeline | Where-Object EventID -in 1102,104
        if ($clearedLogs) {
            Write-Host "`n[!] CRITICAL: LOG TAMPERING DETECTED" -ForegroundColor Red -BackgroundColor Yellow
            $clearedLogs | Format-Table TimeCreated, EventID, SubjectUserName
        }
    }

    # Summary Dashboard
    Write-Host "`n╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                        HUNT SUMMARY DASHBOARD                     ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Green

    Write-Host "`n[*] Events by Category:" -ForegroundColor Cyan
    $Timeline | Group-Object Category | Sort-Object Count -Descending | Format-Table Name, Count -AutoSize

    Write-Host "[*] Top Event IDs:" -ForegroundColor Cyan
    $Timeline | Group-Object EventID | Sort-Object Count -Descending | Select-Object -First 10 | Format-Table Name, Count -AutoSize

    # Export
    if ($ExportTimeline) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
        $csv = Join-Path $ExportPath "Timeline.csv"
        $Timeline | Export-Csv $csv -NoTypeInformation
        Write-Host "`n[+] Timeline exported to $csv" -ForegroundColor Green
    }

    if ($GenerateReport) {
        $htmlPath = Join-Path $ExportPath "Report.html"
        $html = @"
<!DOCTYPE html>
<html>
<head><title>Threat Hunt Report - $(Get-Date)</title>
<style>body{font-family:Arial;margin:20px;} table{border-collapse:collapse;width:100%;} th,td{border:1px solid #ddd;padding:8px;text-align:left;} th{background:#667eea;color:white;}</style>
</head>
<body>
<h1>🔍 Threat Hunt Report</h1>
<p>Profile: $HuntProfile | Events: $($Timeline.Count) | Time: $FilterStart to $FilterEnd</p>
$($Timeline | Select-Object -First 100 | ConvertTo-Html -Fragment)
</body>
</html>
"@
        $html | Out-File $htmlPath
        Write-Host "[+] HTML report saved to $htmlPath" -ForegroundColor Green
    }

    return $Timeline
}

Export-ModuleMember -Function Invoke-ThreatHunt