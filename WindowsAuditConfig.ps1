<#

.SYNOPSIS
    Windows Advanced Audit Policy Configuration Script
.DESCRIPTION
    Configures comprehensive Windows audit policies for security monitoring, DFIR, and threat hunting.
    Enables detailed logging for detection of malicious activity, lateral movement, and persistence.
.AUTHOR
    Yasser_Janboubi
.VERSION
    1.5
.NOTES
    Run as Administrator on target systems
    Test in lab environment before production deployment
    Some settings may impact performance on resource-constrained systems
#>
 
#Requires -RunAsAdministrator
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Audit_Config","Sysmon_Setup","PowerShell_Logging","All")]
    [string]$AuditProfile = $null,

    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

#region Hlep & usage
function Write-Usage {
    Write-Host @"
Usage: .\Script.ps1 -AuditProfile <Profile> [-WhatIf] [-Force]

-AuditProfile    Specifies the audit configuration profile to apply.
                 Valid values:
                 Audit_Config          : Configure Windows audit policies
                 Sysmon_Setup          : Install and configure Sysmon
                 PowerShell_Logging    : Enable PowerShell logging
                 All                   : Apply all configurations

-WhatIf          Shows what would happen without applying changes.

Example:
.\Script.ps1 -AuditProfile All -WhatIf
"@ -ForegroundColor Yellow
}   

if ([string]::IsNullOrEmpty($AuditProfile)) {
    Write-Usage
    exit
}
#endregion

#region Initialization and Logging
$Audit = "$env:SystemDrive\Audit"
    if (-not (Test-Path $)) {
        New-Item -Path $Audit -ItemType Directory -Force | Out-Null
    }

$ScriptVersion = "1.5"
$ExecutionTime = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile = "$Audit\AuditPolicyConfig-$ExecutionTime.log"


function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO","WARNING","ERROR","SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "$Timestamp [$Level] $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    
    switch ($Level) {
        "ERROR"   { Write-Host $LogMessage -ForegroundColor Red }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
        default   { Write-Host $LogMessage -ForegroundColor Cyan }
    }
}

function Test-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check for administrator privileges
if (-not (Test-Admin)) {
    Write-Host "This script requires Administrator privileges!" -ForegroundColor Red
    Write-Host "Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
    exit 1
}

Write-Log "Starting Windows Advanced Audit Policy Configuration Script v$ScriptVersion"
Write-Log "Audit Profile: $AuditProfile"
Write-Log "Computer: $env:COMPUTERNAME"
Write-Log "User: $env:USERNAME"
Write-Log "Log file: $LogFile"
#endregion

#region Audit Policy Functions
function Set-AdvancedAuditPolicy {
    param(
        [string]$Subcategory,
        [string]$Value
    )
    
    $Command = "auditpol /set /subcategory:`"$Subcategory`" /success:$($Value.Split(':')[0]) /failure:$($Value.Split(':')[1])"
    
    if ($WhatIf) {
        Write-Log "WhatIf: Would execute: $Command"
        return
    }
    
    try {
        $Result = Invoke-Expression $Command 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Configured audit policy: $Subcategory = $Value" -Level SUCCESS
        } else {
            Write-Log "Failed to configure audit policy: $Subcategory. Error: $Result" -Level ERROR
        }
    }
    catch {
        Write-Log "Error configuring audit policy $Subcategory : $_" -Level ERROR
    }
}

function Enable-BaseAuditPolicies {
    Write-Log "Enabling base audit policies..."
    
    # Critical for all systems
    $BasePolicies = @{
        # Everything in Aggressive plus:
        "Logon/Logoff" = @{
            # Event ID 4624, 4625, 4634 - User logon attempts (Security channel)
            "Logon" = "enable:enable"
            # Event ID 4634 - User logoff (Security channel)
            "Logoff" = "enable:disable"
            # Event ID 4625 - Account lockout events (Security channel)
            "Account Lockout" = "enable:disable"
            # Event ID 4672 - Special privileges assigned for logon (Security channel)
            "Special Logon" = "enable:disable"
            # Event ID 4798, 4799 - User added/removed from security groups (Security channel)
            "Group Membership" = "enable:disable"
            # Event ID 6272-6278 - Network Policy Server events (Security channel)
            "Network Policy Server" = "enable:enable"
        }
        "Object Access" = @{
            # Event ID 4864 - Central Access Policy staging (Security channel)
            "Central Policy Staging" = "enable:enable"
            # Event ID 4663 - Removable storage device access (Security channel)
            "Removable Storage" = "enable:enable"
        }
        "Policy Change" = @{
            # Event ID 4715, 4719, 4902, 4904, 4905, 4906, 4907, 4908 - Audit policy changes (Security channel)
            "Audit Policy Change" = "enable:enable"
            # Event ID 4670, 4817, 4818 - Authentication policy changes (Security channel)
            "Authentication Policy Change" = "enable:enable"
            # Event ID 4944-4954 - Windows Firewall policy changes (Security channel)
            "MPSSVC Rule-Level Policy Change" = "enable:enable"
        }
        "System" = @{
            # Event ID 4616, 5038 - Violations of system integrity (Security channel)
            "System Integrity" = "enable:enable"
            # Event ID 5024-5029 - Other system-level events (Security channel)
            "Other System Events" = "enable:enable"
            # Event ID 4608, 4609 - Security state changes (Security channel)
            "Security State Change" = "enable:disable"
        }
        "Account Management" = @{
            # Event ID 4741-4743 - Computer account management (Security channel)
            "Computer Account Management" = "enable:enable"
            # Event ID 4731-4735 - Security group management (Security channel)
            "Security Group Management" = "enable:enable"
            # Event ID 4720-4728, 4738-4740 - User account management (Security channel)
            "User Account Management" = "enable:enable"
        }
        "Account Logon" = @{
            # Event ID 4769, 4770 - Kerberos service ticket operations (Security channel)
            "Kerberos Service Ticket Operations" = "enable:enable"
            # Event ID 4768 - Kerberos Authentication Service tickets (Security channel)
            "Kerberos Authentication Service" = "enable:enable"
            # Event ID 4776 - Credential validation events (Security channel)
            "Credential Validation" = "enable:enable"
        }
    }  

    foreach ($Category in $BasePolicies.Keys) {
        foreach ($Subcategory in $BasePolicies[$Category].Keys) {
            Set-AdvancedAuditPolicy -Subcategory "$Subcategory" -Value $BasePolicies[$Category][$Subcategory]
        }
    }
}
#endregion

#region PowerShell Logging Configuration
function Enable-PowerShellLogging {
    Write-Host "Enabling PowerShell Logging..." -ForegroundColor Green

    try {
        # Enable Module Logging
        $moduleLoggingPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        if (-not (Test-Path $moduleLoggingPath)) {
            New-Item -Path $moduleLoggingPath -Force | Out-Null
        }
        Set-ItemProperty -Path $moduleLoggingPath -Name "EnableModuleLogging" -Value 1 -Force

        # Enable logging for all modules
        $modulesKey = Join-Path $moduleLoggingPath "ModuleNames"
        if (-not (Test-Path $modulesKey)) {
            New-Item -Path $modulesKey -Force | Out-Null
        }
        New-ItemProperty -Path $modulesKey -Name "*" -PropertyType String -Value "*" -Force | Out-Null

        # Enable Script Block Logging
        $scriptBlockPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $scriptBlockPath)) {
            New-Item -Path $scriptBlockPath -Force | Out-Null
        }
        Set-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -Force

        Write-Host "PowerShell logging has been enabled successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host "Error enabling PowerShell logging: $_" -ForegroundColor Red
    }
}
#endregion

#region Sysmon Configuration
function Install-Sysmon {
    Write-Log "Installing and configuring Sysmon..."
    $SysmonConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
    $SysmonPath = "$Audit\Sysmon"
    $SysmonConfigPath = "$SysmonPath\sysmon-config.xml"
    $SysmonExePath = "$SysmonPath\Sysmon64.exe"
    
    # Ensure Sysmon directory exists
    if (-not (Test-Path $SysmonPath)) {
        New-Item -Path $SysmonPath -ItemType Directory -Force | Out-Null
    }

    if ($WhatIf) {
        Write-Log "WhatIf: Would download and install Sysmon with SwiftOnSecurity configuration"
        return
    }

    try {
        # Download Sysmon from Microsoft
        Write-Log "Downloading Sysmon..."
        $SysmonDownloadUrl = "https://download.sysinternals.com/files/Sysmon.zip"
        Invoke-WebRequest -Uri $SysmonDownloadUrl -OutFile "$env:TEMP\Sysmon.zip" -UseBasicParsing
            
        # Extract Sysmon
        Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath $env:TEMP -Force
        # Move Sysmon executable to SysmonPath
        Move-Item -Path "$env:TEMP\Sysmon64.exe" -Destination $SysmonExePath -Force


        # Download configuration
        Write-Log "Downloading latest SwiftOnSecurity Sysmon configuration..."
        Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $SysmonConfigPath -UseBasicParsing
        
        # Install Sysmon with config
        
        $sysmonService = Get-Service -Name Sysmon* -ErrorAction SilentlyContinue
        $sysmonInstalled = $null -ne $sysmonService
        if ($sysmonInstalled) {
            Write-Log "Updating configuration..."
            & $SysmonExePath -c $SysmonConfigPath 2>$null
        }
        else {
            Write-Log "Installing Sysmon with configuration..."
            & $SysmonExePath -accepteula -i $SysmonConfigPath 2>$null
        }

        Write-Log "Sysmon installed with SwiftOnSecurity configuration" -Level SUCCESS
        Write-Log "Binary and config saved in $SysmonPath" -Level SUCCESS
    }
    catch {
        Write-Log "Error installing Sysmon: $_" -Level ERROR
        Write-Log "You may need to manually download and install $SysmonConfigPath " -Level WARNING
    }
}
#endregion

#region GPO Audit Policy Backup and Application
function Backup-CurrentAuditPolicy {
   
   
    Write-Log "Backing up current audit policy..."
    $BackupFile = "$Audit\AuditPolicyBackup-$ExecutionTime.txt"
    # Ensure Sysmon directory exists

    if ($WhatIf) {
        Write-Log "WhatIf: Would backup audit policy to $BackupFile"
        return $null
    }
    
    try {
        # Backup current audit policy
        auditpol /backup /file:$BackupFile 2>&1 | Out-Null
        Write-Log "Current audit policy backed up to: $BackupFile" -Level SUCCESS
        return $BackupFile
    }
    catch {
        Write-Log "Error backing up audit policy: $_" -Level ERROR
        return $null
    }
}
#endregion

#region Validation and Testing
function Test-AuditConfiguration {
    Write-Log "Validating audit configuration..."
    
    $Tests = @(
        @{
            Name = "PowerShell ScriptBlock Logging"; 
            Command = {
                $path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
                if (Test-Path $path) {
                    $value = Get-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
                    return [bool]$value.EnableScriptBlockLogging
                }
                return $false
            }; 
            Expected = $true
        },
        @{
            Name = "PowerShell Module Logging";
            Command = {
                $path = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
                if (Test-Path $path) {
                    $value = Get-ItemProperty -Path $path -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
                    return [bool]$value.EnableModuleLogging
                }
                return $false
            };
            Expected = $true
        },
        @{
            Name = "Sysmon Log Exists";
            Command = {
                $log = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
                return [bool]$log
            };
            Expected = $true
        }
    )
    
    $Results = @()
    foreach ($Test in $Tests) {
        try {
            $Result = & $Test.Command
            $Pass = $false
            
            if ($Test.ContainsKey("Expected")) {
                $Pass = $Result -eq $Test.Expected
            } elseif ($Test.ContainsKey("MinValue")) {
                $Pass = $Result -ge $Test.MinValue
            } else {
                $Pass = $Result -eq $true
            }
            
            $Status = if ($Pass) { "PASS" } else { "FAIL" }
            
            # Format the value for display
            $DisplayValue = $Result
            if ($Test.Name -match "Log Size") {
                $DisplayValue = "{0:N2} GB" -f ($Result / 1GB)
            } elseif ($Test.ContainsKey("Expected")) {
                $DisplayValue = $Result.ToString()
            }
            
            $Results += [PSCustomObject]@{
                Test = $Test.Name
                Status = $Status
                Value = $DisplayValue
                RawValue = $Result
            }
            
            Write-Log "$($Test.Name): $Status (Value: $DisplayValue)" -Level $(if ($Pass) { "SUCCESS" } else { "WARNING" })
        }
        catch {
            Write-Log "$($Test.Name): ERROR - $_" -Level ERROR
            $Results += [PSCustomObject]@{
                Test = $Test.Name
                Status = "ERROR"
                Value = $_.Exception.Message
                RawValue = $null
            }
        }
    }
    
    
    # Calculate pass/fail count
    $PassCount = ($Results | Where-Object {$_.Status -eq "PASS"}).Count
    $TotalCount = $Results.Count
    Write-Log "Validation Summary: $PassCount/$TotalCount tests passed" -Level $(if ($PassCount -eq $TotalCount) { "SUCCESS" } else { "WARNING" })
}
#endregion

#region Main Execution
function Main {
        
    # Apply selected audit profile
    switch ($AuditProfile) {
        "Audit_Config" {
            # Backup current configuration
            $BackupFile = Backup-CurrentAuditPolicy  
            Write-Log "Applying Audit Configuration..."
            Enable-BaseAuditPolicies
        }
        "Sysmon_Setup" {
            Write-Log "Setting up Sysmon..."
            Install-Sysmon
        }
        "PowerShell_Logging" {
            Write-Log "Configuring PowerShell logging..."
            Enable-PowerShellLogging
        }
        "All" {
            Write-Log "Applying all configurations..."
            
            # Backup current configuration
            $BackupFile = Backup-CurrentAuditPolicy
            
            # Apply base audit policies
            Enable-BaseAuditPolicies
            
            # Configure PowerShell logging
            Enable-PowerShellLogging
            
            # Install Sysmon
            Install-Sysmon
        }
    }
    
    # Summary
    if ($BackupFile) {
        Write-Log "Backup Location: $BackupFile" -Level INFO
    }

    # Validate configuration for "All" or "Audit_Config" profiles
    if ($AuditProfile -eq "All") {
        Test-AuditConfiguration
    }

    Write-Log "Important checks after configuration:" -Level INFO
    Write-Log "1. Reboot the system to ensure all audit policies are fully applied" -Level INFO
    Write-Log "2. Monitor event logs for any issues" -Level INFO
    
    if ($AuditProfile -in @("All", "PowerShell_Logging")) {
        Write-Log "3. Check PowerShell logs for operational monitoring" -Level INFO
    }
    
    if ($AuditProfile -in @("All", "Sysmon_Setup")) {
        Write-Log "4. Check Sysmon logs in Event Viewer under Applications & Services" -Level INFO
    }
    
    Write-Log "Configuration completed!" -Level SUCCESS
}

# Execute main function
try {
    Main
}
catch {
    Write-Log "Script execution failed: $_" -Level ERROR
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level ERROR
    exit 1
}
#endregion




