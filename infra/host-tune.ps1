<#
.SYNOPSIS
  One-time host tuning for the Robotics Security Platform 4-VM lab.

.DESCRIPTION
  Configures the Windows host so the 4-VM VirtualBox lab can run on 16 GB RAM
  and 95 GB free on D: without unexpected failures. Idempotent: safe to re-run.

  Actions:
    1. Verify running as Administrator (required to set pagefile and power plan).
    2. Verify D: drive exists and has enough free space.
    3. Create D:\VirtualBox if missing.
    4. Set VBOX_USER_HOME=D:\VirtualBox (User-scope environment variable).
    5. Disable automatic-managed pagefile and set 16 GB pagefile on D:.
       Reduce C: pagefile to a small system-managed value.
    6. Switch active power plan to High Performance.
    7. Verify VT-x / AMD-V is enabled in BIOS/UEFI.
    8. Report current free RAM and free disk for D:.
    9. Tell the user whether a reboot is required.

.NOTES
  Run from an elevated PowerShell:
    Set-Location "D:\Robotics Security platform\opus 4.7 output\infra"
    powershell -ExecutionPolicy Bypass -File .\host-tune.ps1
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$VboxUserHome = 'D:\VirtualBox',
    [int]$PagefileSizeMB  = 16384,   # 16 GB
    [int]$MinFreeDiskGB   = 50,
    [int]$MinFreeRamGB    = 8        # warn-only threshold; fail-only at <4 GB
)

# ---------- helpers ----------------------------------------------------------

$Script:RebootRequired = $false
$Script:HasError       = $false

function Write-Step {
    param([string]$Msg)
    Write-Host ""
    Write-Host "==> $Msg" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Msg)
    Write-Host "    [ OK ] $Msg" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Msg)
    Write-Host "    [WARN] $Msg" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Msg)
    Write-Host "    [FAIL] $Msg" -ForegroundColor Red
    $Script:HasError = $true
}

function Test-IsAdmin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($current)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------- main -------------------------------------------------------------

Write-Host ""
Write-Host "=========================================================" -ForegroundColor White
Write-Host " Robotics Security Platform - Host Tuning (one-time)     " -ForegroundColor White
Write-Host "=========================================================" -ForegroundColor White

# Step 1: admin check ---------------------------------------------------------
Write-Step "Step 1/8: Verify Administrator rights"
if (-not (Test-IsAdmin)) {
    Write-Err "Not running as Administrator. Right-click PowerShell -> Run as Administrator."
    exit 1
}
Write-Ok  "Running as Administrator."

# Step 2: D: drive sanity -----------------------------------------------------
Write-Step "Step 2/8: Verify D: drive and free space"
try {
    $d = Get-PSDrive -Name 'D' -PSProvider FileSystem -ErrorAction Stop
    $freeGB = [math]::Round($d.Free / 1GB, 1)
    if ($freeGB -lt $MinFreeDiskGB) {
        Write-Err "D: free space is $freeGB GB but at least $MinFreeDiskGB GB is required."
    } else {
        Write-Ok "D: free space is $freeGB GB (need >= $MinFreeDiskGB GB)."
    }
} catch {
    Write-Err "D: drive not found. The lab requires a D: volume for VM disks and pagefile."
}

# Step 3: VBOX_USER_HOME directory -------------------------------------------
Write-Step "Step 3/8: Create $VboxUserHome if missing"
try {
    if (-not (Test-Path -LiteralPath $VboxUserHome)) {
        New-Item -ItemType Directory -Path $VboxUserHome -Force | Out-Null
        Write-Ok "Created $VboxUserHome."
    } else {
        Write-Ok "$VboxUserHome already exists."
    }
} catch {
    Write-Err "Could not create $VboxUserHome : $($_.Exception.Message)"
}

# Step 4: VBOX_USER_HOME env var (user scope) --------------------------------
Write-Step "Step 4/8: Set VBOX_USER_HOME (User-scope environment variable)"
try {
    $current = [Environment]::GetEnvironmentVariable('VBOX_USER_HOME', 'User')
    if ($current -eq $VboxUserHome) {
        Write-Ok "VBOX_USER_HOME already set to $VboxUserHome."
    } else {
        [Environment]::SetEnvironmentVariable('VBOX_USER_HOME', $VboxUserHome, 'User')
        Write-Ok "VBOX_USER_HOME set to $VboxUserHome (was: '$current')."
        Write-Warn "Open a fresh PowerShell window for the new value to be visible."
    }
} catch {
    Write-Err "Could not set VBOX_USER_HOME: $($_.Exception.Message)"
}

# Step 5: pagefile (16 GB on D:, small system-managed on C:) -----------------
Write-Step "Step 5/8: Configure pagefile (16 GB on D:)"
try {
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($cs.AutomaticManagedPagefile) {
        Set-CimInstance -InputObject $cs -Property @{ AutomaticManagedPagefile = $false } | Out-Null
        Write-Ok "Disabled Windows automatic-managed pagefile."
        $Script:RebootRequired = $true
    } else {
        Write-Ok "Automatic-managed pagefile already disabled."
    }

    # Win32_PageFileSetting requires UInt32 (not Int32) for InitialSize/MaximumSize.
    $sizeU32 = [UInt32]$PagefileSizeMB
    $existingD = Get-CimInstance -ClassName Win32_PageFileSetting -Filter "Name='D:\\\\pagefile.sys'" -ErrorAction SilentlyContinue
    if ($null -eq $existingD) {
        try {
            New-CimInstance -ClassName Win32_PageFileSetting -Property @{
                Name        = 'D:\pagefile.sys'
                InitialSize = $sizeU32
                MaximumSize = $sizeU32
            } -ErrorAction Stop | Out-Null
            Write-Ok "Created D:\pagefile.sys at $PagefileSizeMB MB (initial=max=$PagefileSizeMB)."
            $Script:RebootRequired = $true
        } catch {
            # Fallback: use the legacy WMI accelerator which accepts Int32 implicitly.
            try {
                $cls = [WmiClass]'\\.\root\cimv2:Win32_PageFileSetting'
                $newPf = $cls.CreateInstance()
                $newPf.Name        = 'D:\pagefile.sys'
                $newPf.InitialSize = $PagefileSizeMB
                $newPf.MaximumSize = $PagefileSizeMB
                [void]$newPf.Put()
                Write-Ok "Created D:\pagefile.sys at $PagefileSizeMB MB (legacy WMI fallback)."
                $Script:RebootRequired = $true
            } catch {
                Write-Err "Could not create D:\pagefile.sys via either CIM or legacy WMI: $($_.Exception.Message)"
            }
        }
    } else {
        if ($existingD.InitialSize -ne $PagefileSizeMB -or $existingD.MaximumSize -ne $PagefileSizeMB) {
            try {
                Set-CimInstance -InputObject $existingD -Property @{
                    InitialSize = $sizeU32
                    MaximumSize = $sizeU32
                } -ErrorAction Stop | Out-Null
                Write-Ok "Updated D:\pagefile.sys to $PagefileSizeMB MB."
                $Script:RebootRequired = $true
            } catch {
                Write-Err "Could not update D:\pagefile.sys size: $($_.Exception.Message)"
            }
        } else {
            Write-Ok "D:\pagefile.sys already sized at $PagefileSizeMB MB."
        }
    }

    # Leave C: pagefile alone if present; just report it.
    $existingC = Get-CimInstance -ClassName Win32_PageFileSetting -Filter "Name='C:\\\\pagefile.sys'" -ErrorAction SilentlyContinue
    if ($existingC) {
        Write-Ok "C:\pagefile.sys present (initial=$($existingC.InitialSize) MB, max=$($existingC.MaximumSize) MB) -- left as-is."
    } else {
        Write-Ok "No C: pagefile configured (D: pagefile is sufficient)."
    }
} catch {
    Write-Err "Pagefile configuration failed: $($_.Exception.Message)"
}

# Step 6: power plan ---------------------------------------------------------
Write-Step "Step 6/8: Switch active power plan to High Performance"
try {
    # GUID of the built-in High Performance plan.
    $highPerfGuid = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    $plans = powercfg /list 2>$null
    if ($plans -match $highPerfGuid) {
        & powercfg /setactive $highPerfGuid | Out-Null
        Write-Ok "Active power plan set to High Performance."
    } else {
        Write-Warn "High Performance plan not present on this SKU; leaving current plan unchanged."
        Write-Warn "Current plan: $((powercfg /getactivescheme) -replace '.*\((.*)\).*', '$1')"
    }
} catch {
    Write-Err "Could not switch power plan: $($_.Exception.Message)"
}

# Step 7: VT-x / AMD-V check -------------------------------------------------
# Use the same 3-source detection as preflight.ps1 because Win32_Processor
# alone returns false whenever Hyper-V or VBS/Memory Integrity is loaded.
Write-Step "Step 7/8: Verify CPU virtualization (VT-x / AMD-V) is enabled in BIOS"
try {
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    $cpuSays = $cpu.VirtualizationFirmwareEnabled
    $sysinfoLines = systeminfo 2>$null
    $hvDetected   = $sysinfoLines | Select-String -SimpleMatch 'A hypervisor has been detected'
    $vtFirmware   = $sysinfoLines | Select-String -SimpleMatch 'Virtualization Enabled In Firmware'

    if ($cpuSays -eq $true) {
        Write-Ok "VT-x / AMD-V enabled (Win32_Processor)."
    } elseif ($hvDetected) {
        Write-Ok "VT-x / AMD-V enabled (hypervisor already running on host)."
    } elseif ($vtFirmware -and $vtFirmware -match ':\s*Yes') {
        Write-Ok "VT-x / AMD-V enabled (systeminfo)."
    } elseif ($vtFirmware -and $vtFirmware -match ':\s*No') {
        Write-Err "VT-x / AMD-V DISABLED in firmware. Reboot, enter BIOS/UEFI, enable virtualization."
    } else {
        Write-Warn "VT-x state could not be confirmed via Win32_Processor or systeminfo."
        Write-Warn "   Definitive test: 'vagrant up' will fail loudly if VT-x is truly off."
    }

    $hv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
    if ($hv -and $hv.State -eq 'Enabled') {
        Write-Warn "Hyper-V is enabled. VirtualBox 7 supports Hyper-V hosts but performance is reduced."
        Write-Warn "   If 'vagrant up' fails with VT-x errors: bcdedit /set hypervisorlaunchtype off ; reboot."
    }
} catch {
    Write-Warn "Could not check virtualization state: $($_.Exception.Message)"
}

# Step 8: report current free RAM + disk --------------------------------------
Write-Step "Step 8/8: Current host resources (informational)"
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    $freeGB  = [math]::Round($os.FreePhysicalMemory     / 1MB, 1)
    Write-Ok "RAM: $freeGB GB free of $totalGB GB total."
    # Demoted to WARN: free RAM is something the user fixes at 'vagrant up' time,
    # not at host-tune time. host-tune.ps1 only configures the host.
    if ($freeGB -lt $MinFreeRamGB) {
        Write-Warn "Free RAM is $freeGB GB; close apps before 'vagrant up' (need >= $MinFreeRamGB GB free)."
    }

    Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null } | ForEach-Object {
        $u = [math]::Round($_.Used / 1GB, 1)
        $f = [math]::Round($_.Free / 1GB, 1)
        Write-Ok "Drive $($_.Name): used $u GB, free $f GB."
    }
} catch {
    Write-Warn "Could not report resources: $($_.Exception.Message)"
}

# ---------- summary ----------------------------------------------------------
Write-Host ""
Write-Host "=========================================================" -ForegroundColor White
if ($Script:HasError) {
    Write-Host " RESULT: ONE OR MORE STEPS FAILED. See [FAIL] lines above." -ForegroundColor Red
    Write-Host "=========================================================" -ForegroundColor White
    exit 2
}
if ($Script:RebootRequired) {
    Write-Host " RESULT: Host tuned. **REBOOT REQUIRED** for pagefile change." -ForegroundColor Yellow
    Write-Host "         After reboot, run: .\preflight.ps1" -ForegroundColor Yellow
} else {
    Write-Host " RESULT: Host already tuned. No reboot needed." -ForegroundColor Green
    Write-Host "         You can now run: .\preflight.ps1" -ForegroundColor Green
}
Write-Host "=========================================================" -ForegroundColor White
exit 0
