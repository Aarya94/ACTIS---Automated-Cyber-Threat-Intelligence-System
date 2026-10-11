<#
.SYNOPSIS
    Uninstalls the ACTIS Protection Service from Windows Service Control Manager (SCM).

.DESCRIPTION
    Safely stops and unregisters the ACTIS service from Windows SCM.
    Explicitly preserves user data, databases, and logs.
    Supports -DryRun for non-destructive pre-flight checks.

.PARAMETER ServiceName
    The internal SCM service name. Default: "ACTISProtectionService".

.PARAMETER DryRun
    When specified, verifies status and elevation without making any system changes.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\uninstall_windows_service.ps1 -DryRun
    powershell -ExecutionPolicy Bypass -File scripts\uninstall_windows_service.ps1
#>

[CmdletBinding()]
param(
    [string]$ServiceName = "ACTISProtectionService",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  ACTIS Windows Service Uninstaller" -ForegroundColor Cyan
Write-Host "  Target Service: $ServiceName" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Platform Verification
if ($env:OS -notlike "*Windows*") {
    Write-Error "ERROR: This uninstaller is intended exclusively for Microsoft Windows."
    exit 1
}

# 2. Check Existing Service Registration
$ExistingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if (-not $ExistingService) {
    Write-Host "[*] Service '$ServiceName' is not installed in Windows SCM. Nothing to remove." -ForegroundColor Green
    exit 0
}

Write-Host "[*] Located service: $($ExistingService.Name) [Status: $($ExistingService.Status)]"

# 3. Check Administrative Privileges
$IsAdmin = $false
try {
    $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)
    $IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $IsAdmin = $false
}

Write-Host "[*] Elevated Administrator: $IsAdmin"

if ($DryRun) {
    Write-Host ""
    Write-Host "[DRY-RUN] Uninstall Pre-Flight Successful!" -ForegroundColor Green
    Write-Host "  - Service Name:        $ServiceName"
    Write-Host "  - Current Status:      $($ExistingService.Status)"
    Write-Host "  - Administrator Token: $IsAdmin"
    Write-Host "  - Action Planned:      Stop service (if running), then execute sc.exe delete $ServiceName"
    Write-Host "  - Data Preservation:   Logs (logs/) and Threat Database (data/) are PRESERVED."
    Write-Host "[DRY-RUN] No system changes made." -ForegroundColor Green
    exit 0
}

if (-not $IsAdmin) {
    Write-Error "ERROR: Administrative privileges are required to remove a Windows Service from SCM. Please launch PowerShell as Administrator."
    exit 1
}

# 4. Stop Service if Running
if ($ExistingService.Status -eq "Running") {
    Write-Host "[*] Stopping '$ServiceName' before removal..."
    try {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        Start-Sleep -Seconds 2
    } catch {
        Write-Warning "Failed to stop service gracefully: $_. Proceeding with deletion."
    }
}

# 5. Delete Service Registration
try {
    Write-Host "[*] Deleting service registration via sc.exe delete..."
    $deleteResult = sc.exe delete $ServiceName
    Write-Host $deleteResult

    Start-Sleep -Seconds 1
    $verifyCheck = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $verifyCheck) {
        Write-Host ""
        Write-Host "[+] Service '$ServiceName' successfully uninstalled from SCM." -ForegroundColor Green
        Write-Host "[+] User configuration, threat databases, and logs have been safely preserved." -ForegroundColor Cyan
        exit 0
    } else {
        Write-Warning "Service marked for deletion (may require SCM refresh or reboot if handles are open)."
        exit 0
    }
} catch {
    Write-Error "ERROR: Failed to delete service: $_"
    exit 1
}
