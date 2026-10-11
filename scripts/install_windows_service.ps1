<#
.SYNOPSIS
    Installs the ACTIS Protection Service into Windows Service Control Manager (SCM).

.DESCRIPTION
    Safely registers ACTIS as a native Windows Service using standard Windows SCM facilities.
    Supports -DryRun for validation without requiring Administrator elevation.
    Does NOT use stealth persistence, registry run keys, or covert persistence.

.PARAMETER ServiceName
    The internal SCM service name. Default: "ACTISProtectionService".

.PARAMETER DisplayName
    The human-readable display name. Default: "ACTIS Endpoint Protection Service".

.PARAMETER StartupType
    The startup type: Automatic, Manual, or Disabled. Default: "Automatic".

.PARAMETER DryRun
    When specified, validates paths, environment, and configuration without modifying SCM.

.PARAMETER Force
    When specified, allows updating/replacing an existing service registration.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install_windows_service.ps1 -DryRun
    powershell -ExecutionPolicy Bypass -File scripts\install_windows_service.ps1
#>

[CmdletBinding()]
param(
    [string]$ServiceName = "ACTISProtectionService",
    [string]$DisplayName = "ACTIS Endpoint Protection Service",
    [string]$StartupType = "Automatic",
    [switch]$DryRun,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  ACTIS Windows Service Installer" -ForegroundColor Cyan
Write-Host "  Target Service: $ServiceName" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Platform Verification
if ($env:OS -notlike "*Windows*") {
    Write-Error "ERROR: This installer is intended exclusively for Microsoft Windows."
    exit 1
}

# 2. Path Resolution & Validation
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$PythonExe = Join-Path $ProjectRoot "venv\Scripts\python.exe"
$EntryPoint = Join-Path $ProjectRoot "main.py"

Write-Host "[*] Project Root:   $ProjectRoot"
Write-Host "[*] Python Path:    $PythonExe"
Write-Host "[*] Entry Point:    $EntryPoint"

if (-not (Test-Path $PythonExe)) {
    Write-Error "ERROR: Project virtual environment Python not found at: $PythonExe. Please initialize venv first."
    exit 1
}

if (-not (Test-Path $EntryPoint)) {
    Write-Error "ERROR: Service entry point not found at: $EntryPoint"
    exit 1
}

# 3. Formulate Binary Path
# Quotes around paths ensure robust handling of whitespace in path names
$ServiceArgs = "`"$PythonExe`" `"$EntryPoint`" --service"
Write-Host "[*] SCM BinaryPath: $ServiceArgs"

# 4. Check Existing Service Registration
$ExistingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($ExistingService) {
    Write-Host "[!] Service '$ServiceName' is already registered in SCM (Status: $($ExistingService.Status))." -ForegroundColor Yellow
    if (-not $Force -and -not $DryRun) {
        Write-Warning "Use -Force to reconfigure the existing service, or uninstall it first."
        exit 2
    }
}

# 5. Check Administrative Privileges
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
    Write-Host "[DRY-RUN] Validation Successful!" -ForegroundColor Green
    Write-Host "  - Operating System:      $($env:OS)"
    Write-Host "  - Service Name:          $ServiceName"
    Write-Host "  - Display Name:          $DisplayName"
    Write-Host "  - Binary Path:           $ServiceArgs"
    Write-Host "  - Startup Type:          $StartupType"
    Write-Host "  - Existing Registration: $(if ($ExistingService) { 'Yes (' + $ExistingService.Status + ')' } else { 'No' })"
    Write-Host "  - Administrator Token:   $IsAdmin"
    Write-Host "[DRY-RUN] No system changes made." -ForegroundColor Green
    exit 0
}

if (-not $IsAdmin) {
    Write-Error "ERROR: Administrative privileges are required to register a Windows Service in SCM. Please launch PowerShell as Administrator."
    exit 1
}

# 6. SCM Registration / Update
try {
    if ($ExistingService -and $Force) {
        Write-Host "[*] Stopping existing service before reconfiguration..."
        if ($ExistingService.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force
            Start-Sleep -Seconds 2
        }
        Write-Host "[*] Updating service configuration with sc.exe config..."
        $configResult = sc.exe config $ServiceName binPath= $ServiceArgs start= $(if ($StartupType -eq "Automatic") { "auto" } else { "demand" })
        Write-Host $configResult
    } else {
        Write-Host "[*] Registering service with sc.exe create..."
        $startMode = if ($StartupType -eq "Automatic") { "auto" } else { "demand" }
        $createResult = sc.exe create $ServiceName binPath= $ServiceArgs DisplayName= $DisplayName start= $startMode
        Write-Host $createResult

        # Set service description
        $description = "ACTIS Automated Cyber Threat Intelligence & Real-time Protection Service"
        sc.exe description $ServiceName $description | Out-Null
    }

    $InstalledService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($InstalledService) {
        Write-Host ""
        Write-Host "[+] Service successfully registered!" -ForegroundColor Green
        Write-Host "    Name:         $($InstalledService.Name)"
        Write-Host "    Display Name: $($InstalledService.DisplayName)"
        Write-Host "    Status:       $($InstalledService.Status)"
        Write-Host "    Startup Type: $($InstalledService.StartType)"
        Write-Host ""
        Write-Host "To start the service:" -ForegroundColor Cyan
        Write-Host "    Start-Service -Name $ServiceName" -ForegroundColor White
        Write-Host "To check status:" -ForegroundColor Cyan
        Write-Host "    .\scripts\status_windows_service.ps1" -ForegroundColor White
        exit 0
    } else {
        Write-Error "ERROR: Service creation command completed but service '$ServiceName' was not found in SCM."
        exit 1
    }
} catch {
    Write-Error "ERROR: Failed to register service: $_"
    exit 1
}
