@{
    RootModule        = 'Invoke-ThreatHunt.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'd5e1b3c4-5678-90ab-cdef-1234567890ab'
    Author            = 'LALITGITMLK'
    CompanyName       = 'Independent'
    Copyright         = '(c) 2026. All rights reserved.'
    Description       = 'Advanced PowerShell threat hunting and forensic timeline tool for Windows event logs'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-ThreatHunt')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('threat-hunting', 'security', 'powershell', 'soc', 'dfir', 'forensics', 'windows', 'event-logs')
            LicenseUri = 'https://github.com/YourUsername/Invoke-ThreatHunt/blob/main/LICENSE'
            ProjectUri = 'https://github.com/YourUsername/Invoke-ThreatHunt'
        }
    }
}
