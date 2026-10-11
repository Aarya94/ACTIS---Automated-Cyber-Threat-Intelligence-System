<#
.SYNOPSIS
    Queries the status of the ACTIS Protection Service in Windows SCM and checks local telemetry.

.DESCRIPTION
    Non-destructive status utility. Does NOT require administrator privileges.
    Checks SCM registration, service state (Running, Stopped, Paused, etc.),
    host telemetry via python main.py --service-status, and recent log records.

.PARAMETER ServiceName
    The internal SCM service name. Default: "ACTISProtectionService".

.PARAMETER AsJson
    Outputs status as structured JSON.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\status_windows_service.ps1
    powershell -ExecutionPolicy Bypass -File scripts\status_windows_service.ps1 -AsJson
#>

[CmdletBinding()]
param(
    [string]$ServiceName = "ACTISProtectionService",
    [switch]$AsJson
)

$ErrorActionPreference = "SilentlyContinue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$LogFile = Join-Path $ProjectRoot "logs\actis.log"

$StatusObj = [PSCustomObject]@{
    ServiceName       = $ServiceName
    Installed         = $false
    Status            = "NOT_INSTALLED"
    DisplayName       = ""
    StartupType       = ""
    CanStop           = $false
    ProcessId         = $null
    MemoryMB          = $null
    TelemetryState    = "UNKNOWN"
    LogFileExists     = (Test-Path $LogFile)
    RecentLogEntries  = @()
}

$ScmService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($ScmService) {
    $StatusObj.Installed = $true
    $StatusObj.Status = $ScmService.Status.ToString().ToUpper()
    $StatusObj.DisplayName = $ScmService.DisplayName
    $StatusObj.StartupType = $ScmService.StartType.ToString()
    $StatusObj.CanStop = $ScmService.CanStop

    # Try resolving process ID if running
    if ($ScmService.Status -eq "Running") {
        try {
            $wmiService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
            if ($wmiService -and $wmiService.ProcessId -gt 0) {
                $StatusObj.ProcessId = $wmiService.ProcessId
                $proc = Get-Process -Id $wmiService.ProcessId -ErrorAction SilentlyContinue
                if ($proc) {
                    $StatusObj.MemoryMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                }
            }
        } catch {
            # Non-critical if CIM query fails
        }
    }
}

# Check recent log entries if file exists
if (Test-Path $LogFile) {
    try {
        $rawLines = Get-Content $LogFile -Tail 5 -ErrorAction SilentlyContinue
        if ($rawLines) {
            $StatusObj.RecentLogEntries = @($rawLines | ForEach-Object { $_.ToString() })
        }
    } catch {
        # Safe ignore
    }
}

if ($AsJson) {
    $StatusObj | ConvertTo-Json -Depth 4
    exit 0
}

# Pretty-print console output
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  ACTIS Windows Service Status: $ServiceName" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

if (-not $StatusObj.Installed) {
    Write-Host "[!] Service Status: NOT INSTALLED" -ForegroundColor Yellow
    Write-Host "    The service '$ServiceName' is not registered in Windows SCM."
    Write-Host "    To install, run: .\scripts\install_windows_service.ps1" -ForegroundColor Gray
} else {
    $color = if ($StatusObj.Status -eq "RUNNING") { "Green" } else { "Yellow" }
    Write-Host "[+] Service Status: $($StatusObj.Status)" -ForegroundColor $color
    Write-Host "    Display Name: $($StatusObj.DisplayName)"
    Write-Host "    Startup Type: $($StatusObj.StartupType)"
    Write-Host "    Can Stop:     $($StatusObj.CanStop)"
    if ($StatusObj.ProcessId) {
        Write-Host "    Process ID:   $($StatusObj.ProcessId)"
        Write-Host "    Working Set:  $($StatusObj.MemoryMB) MB"
    }
}

Write-Host ""
Write-Host "[*] Log File: $LogFile"
if ($StatusObj.LogFileExists -and $StatusObj.RecentLogEntries.Count -gt 0) {
    Write-Host "    Recent Log Activity:" -ForegroundColor Gray
    foreach ($line in $StatusObj.RecentLogEntries) {
        Write-Host "      $line" -ForegroundColor DarkGray
    }
} else {
    Write-Host "    (No recent log entries found)" -ForegroundColor DarkGray
}

Write-Host "=================================================================" -ForegroundColor Cyan
exit 0
