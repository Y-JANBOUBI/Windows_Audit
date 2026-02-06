# Windows Audit Policy Configuration

This project provides a PowerShell script for configuring Windows audit policies, Sysmon, and PowerShell logging to enhance security monitoring, threat detection, and forensic capabilities. This Script enables security teams to deploy consistent audit configurations across Windows environments for improved visibility into security events.

---
## Prerequisites

* Windows PowerShell **5.1 or later**
* **Administrator privileges**
* **Internet access** (for downloading Sysmon and its configuration)

---

## Installation

**Option 1: Clone the repository**

```powershell
git clone https://github.com/yourusername/Windows-Audit-Policy.git
cd Windows-Audit-Policy/scripts
```

**Option 2: Download the script directly**

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yourusername/windows-audit-config/main/WindowsAuditConfig.ps1" -OutFile "WindowsAuditConfig.ps1"
```
---

## Usage
<img width="1033" height="440" alt="image" src="https://github.com/user-attachments/assets/2c9c8444-e089-4324-a2d1-ce328b8bdedd" />

```powershell
.\WindowsAuditConfig.ps1 -AuditProfile <Profile> [-WhatIf]
```

**Profiles:**

* `Audit_Config` – Configure Windows audit policies
* `Sysmon_Setup` – Install and configure Sysmon
* `PowerShell_Logging` – Enable PowerShell logging
* `All` – Apply all configurations (recommended for new systems)

**Examples:**

```powershell
# Apply minimal audit configuration
.\WindowsAuditConfig.ps1 -AuditProfile Audit_Config

# Install Sysmon
.\WindowsAuditConfig.ps1 -AuditProfile Sysmon_Setup

# Enable PowerShell logging
.\WindowsAuditConfig.ps1 -AuditProfile PowerShell_Logging

# Apply all configurations (dry-run)
.\WindowsAuditConfig.ps1 -AuditProfile All -WhatIf
```

---

## Post-Installation Verification

```powershell
# Check audit policies
auditpol /get /category:*

# Verify Sysmon service
Get-Service Sysmon*

# Check PowerShell logging settings
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\*"
```
---


