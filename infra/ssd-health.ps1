<#
.SYNOPSIS
  Reports SSD health for all physical disks, with focus on D: (VM disks + pagefile).

.DESCRIPTION
  The 4-VM lab places VM disks and a 16 GB pagefile on D:. Continuous swap
  + VM I/O will accelerate SSD wear. Run this script monthly to track:
    - Wear (% of estimated remaining life consumed)
    - Temperature
    - Read/write error counters
    - HealthStatus reported by the storage stack

  Output is a table; non-zero exit code if any disk reports Unhealthy or
  Wear >= 90 %.

.NOTES
  Non-admin. Some counters require Windows Server SKUs or recent Windows 10/11.
  Missing values render as 'n/a' and are not treated as failures.

  Usage:
    Set-Location "D:\Robotics Security platform\opus 4.7 output\infra"
    powershell -ExecutionPolicy Bypass -File .\ssd-health.ps1
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [int]$WearWarnPct  = 80,
    [int]$WearFailPct  = 90,
    [int]$TempWarnC    = 60,
    [int]$TempFailC    = 70
)

$Script:Failures = 0
$Script:Warnings = 0

function Pass { param([string]$Msg) Write-Host "    [ OK ] $Msg" -ForegroundColor Green }
function Warn { param([string]$Msg) Write-Host "    [WARN] $Msg" -ForegroundColor Yellow; $Script:Warnings++ }
function Fail { param([string]$Msg) Write-Host "    [FAIL] $Msg" -ForegroundColor Red; $Script:Failures++ }

Write-Host ""
Write-Host "=========================================================" -ForegroundColor White
Write-Host " Robotics Security Platform - SSD Health Check           " -ForegroundColor White
Write-Host "=========================================================" -ForegroundColor White

# Map drive letters -> physical disks via partitions.
$letterToDisk = @{}
try {
    $parts = Get-Partition -ErrorAction Stop | Where-Object { $_.DriveLetter }
    foreach ($p in $parts) {
        $letterToDisk[[string]$p.DriveLetter] = $p.DiskNumber
    }
} catch {
    Warn "Could not enumerate partitions: $($_.Exception.Message)"
}

try {
    $disks = Get-PhysicalDisk -ErrorAction Stop
} catch {
    Fail "Get-PhysicalDisk unavailable on this system: $($_.Exception.Message)"
    exit 1
}

$rows = @()
foreach ($disk in $disks) {
    $rel = $null
    try {
        $rel = $disk | Get-StorageReliabilityCounter -ErrorAction Stop
    } catch {
        # Counters not exposed by some firmware (e.g. older USB/SATA bridges).
    }

    # Find drive letters mapped to this disk number, if any.
    $letters = @()
    foreach ($k in $letterToDisk.Keys) {
        if ($letterToDisk[$k] -eq $disk.DeviceId -or $letterToDisk[$k] -eq $disk.DiskNumber) {
            $letters += $k
        }
    }
    $letterStr = if ($letters.Count) { ($letters -join ',') } else { '-' }

    $row = [PSCustomObject]@{
        DiskNumber   = $disk.DeviceId
        FriendlyName = $disk.FriendlyName
        Letters      = $letterStr
        MediaType    = $disk.MediaType
        BusType      = $disk.BusType
        SizeGB       = if ($disk.Size) { [math]::Round($disk.Size / 1GB, 1) } else { 'n/a' }
        Health       = $disk.HealthStatus
        OpStatus     = ($disk.OperationalStatus -join ',')
        Wear         = if ($rel -and $null -ne $rel.Wear) { "$($rel.Wear)%" } else { 'n/a' }
        TempC        = if ($rel -and $null -ne $rel.Temperature) { $rel.Temperature } else { 'n/a' }
        ReadErrTot   = if ($rel -and $null -ne $rel.ReadErrorsTotal)  { $rel.ReadErrorsTotal  } else { 'n/a' }
        WriteErrTot  = if ($rel -and $null -ne $rel.WriteErrorsTotal) { $rel.WriteErrorsTotal } else { 'n/a' }
    }
    $rows += $row

    # Threshold checks per disk
    $tag = "Disk $($disk.DeviceId) ($($disk.FriendlyName))"

    if ($disk.HealthStatus -ne 'Healthy') {
        Fail "$tag : HealthStatus = $($disk.HealthStatus)."
    } else {
        Pass "$tag : Healthy."
    }

    if ($rel -and $null -ne $rel.Wear) {
        if ($rel.Wear -ge $WearFailPct) {
            Fail "$tag : Wear $($rel.Wear)% >= fail threshold $WearFailPct%. Replace soon."
        } elseif ($rel.Wear -ge $WearWarnPct) {
            Warn "$tag : Wear $($rel.Wear)% >= warn threshold $WearWarnPct%."
        } else {
            Pass "$tag : Wear $($rel.Wear)%."
        }
    }

    if ($rel -and $null -ne $rel.Temperature) {
        if ($rel.Temperature -ge $TempFailC) {
            Fail "$tag : Temp $($rel.Temperature)C >= fail $TempFailC C."
        } elseif ($rel.Temperature -ge $TempWarnC) {
            Warn "$tag : Temp $($rel.Temperature)C >= warn $TempWarnC C."
        } else {
            Pass "$tag : Temp $($rel.Temperature)C."
        }
    }
}

Write-Host ""
$rows | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "=========================================================" -ForegroundColor White
if ($Script:Failures -eq 0 -and $Script:Warnings -eq 0) {
    Write-Host " RESULT: All disks healthy." -ForegroundColor Green
    exit 0
} elseif ($Script:Failures -eq 0) {
    Write-Host " RESULT: $($Script:Warnings) warning(s)." -ForegroundColor Yellow
    exit 0
}
Write-Host " RESULT: $($Script:Failures) failure(s), $($Script:Warnings) warning(s). Investigate." -ForegroundColor Red
exit 1
