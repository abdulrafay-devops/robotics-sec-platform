<#
.SYNOPSIS
  Pass/fail verifier for the Robotics Security Platform 4-VM lab host.

.DESCRIPTION
  Non-admin script. Verifies that the Windows host is correctly prepared
  before any 'vagrant up' is attempted. Each check produces [ OK ], [WARN],
  or [FAIL]. Exits 0 only if every required check passes.

  Required checks (any FAIL aborts):
    - VirtualBox 7.0 or newer
    - Vagrant 2.4 or newer
    - VBOX_USER_HOME set, on D:, directory exists
    - Free RAM >= 8 GB (recommended 10+)
    - Free D: space >= 50 GB
    - VT-x / AMD-V enabled in firmware

  Warn-only checks:
    - Pagefile on D: at least 12 GB
    - Active power plan = High Performance
    - Hyper-V state (warns if enabled)

.NOTES
  Run anytime, no admin needed:
    Set-Location "D:\Robotics Security platform\opus 4.7 output\infra"
    powershell -ExecutionPolicy Bypass -File .\preflight.ps1
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [int]$MinVboxMajor   = 7,
    [int]$MinVboxMinor   = 0,
    [int]$MinVagrantMaj  = 2,
    [int]$MinVagrantMin  = 4,
    [int]$MinFreeRamGB   = 8,
    [int]$MinFreeDiskGB  = 50,
    [int]$MinPagefileMB  = 12288   # 12 GB warn floor (16 GB target)
)

$Script:Failures = 0
$Script:Warnings = 0

# ---------- helpers ----------------------------------------------------------

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host "==> $Title" -ForegroundColor Cyan
}

function Pass {
    param([string]$Msg)
    Write-Host "    [ OK ] $Msg" -ForegroundColor Green
}

function Warn {
    param([string]$Msg)
    Write-Host "    [WARN] $Msg" -ForegroundColor Yellow
    $Script:Warnings++
}

function Fail {
    param([string]$Msg)
    Write-Host "    [FAIL] $Msg" -ForegroundColor Red
    $Script:Failures++
}

function Compare-Version {
    # returns -1, 0, 1 like (a vs b)
    param([Version]$a, [Version]$b)
    if ($a -lt $b) { return -1 }
    elseif ($a -gt $b) { return 1 }
    else { return 0 }
}

# ---------- main -------------------------------------------------------------

Write-Host ""
Write-Host "=========================================================" -ForegroundColor White
Write-Host " Robotics Security Platform - Preflight Verifier         " -ForegroundColor White
Write-Host "=========================================================" -ForegroundColor White

function Resolve-Executable {
    <#
    .SYNOPSIS
      Resolve an executable on PATH or in a list of candidate absolute paths.
      Returns the absolute path if found, or $null.
    #>
    param(
        [Parameter(Mandatory)] [string]$Name,
        [string[]]$Candidates = @()
    )
    $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd -and $cmd.Source -and (Test-Path -LiteralPath $cmd.Source)) {
        return $cmd.Source
    }
    foreach ($p in $Candidates) {
        if (-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path -LiteralPath $p)) {
            return $p
        }
    }
    return $null
}

# Check 1: VirtualBox ---------------------------------------------------------
Write-Header "Check 1/8: VirtualBox >= $MinVboxMajor.$MinVboxMinor"
$vboxExe = Resolve-Executable -Name 'VBoxManage.exe' -Candidates @(
    (Join-Path $env:ProgramFiles            'Oracle\VirtualBox\VBoxManage.exe'),
    (Join-Path ${env:ProgramFiles(x86)}     'Oracle\VirtualBox\VBoxManage.exe')
)
if (-not $vboxExe) {
    Fail "VirtualBox is not installed (VBoxManage.exe not found on PATH or default location)."
    Fail "    Download: https://www.virtualbox.org/wiki/Downloads"
} else {
    try {
        $raw = & $vboxExe --version 2>$null
        # Output looks like '7.0.18r162988' -- strip the build suffix.
        $clean = ($raw -split 'r')[0].Trim()
        $v = [Version]$clean
        $required = [Version]"$MinVboxMajor.$MinVboxMinor.0"
        if ((Compare-Version $v $required) -ge 0) {
            Pass "VirtualBox $clean (>= $MinVboxMajor.$MinVboxMinor required) at $vboxExe."
        } else {
            Fail "VirtualBox $clean is too old. Need >= $MinVboxMajor.$MinVboxMinor."
        }
    } catch {
        Fail "Could not parse VirtualBox version output ('$raw'): $($_.Exception.Message)"
    }
}

# Check 2: Vagrant ------------------------------------------------------------
Write-Header "Check 2/8: Vagrant >= $MinVagrantMaj.$MinVagrantMin"
$vagrantExe = Resolve-Executable -Name 'vagrant.exe' -Candidates @(
    (Join-Path $env:ProgramFiles            'Vagrant\bin\vagrant.exe'),
    (Join-Path ${env:ProgramFiles(x86)}     'Vagrant\bin\vagrant.exe'),
    (Join-Path 'C:\HashiCorp'               'Vagrant\bin\vagrant.exe')
)
if (-not $vagrantExe) {
    Fail "Vagrant is not installed (vagrant.exe not found on PATH or default location)."
    Fail "    Download: https://developer.hashicorp.com/vagrant/install"
} else {
    try {
        $raw = & $vagrantExe --version 2>$null
        # 'Vagrant 2.4.1'
        $clean = ($raw -replace '^Vagrant\s+', '').Trim()
        $v = [Version]$clean
        $required = [Version]"$MinVagrantMaj.$MinVagrantMin.0"
        if ((Compare-Version $v $required) -ge 0) {
            Pass "Vagrant $clean (>= $MinVagrantMaj.$MinVagrantMin required) at $vagrantExe."
        } else {
            Fail "Vagrant $clean is too old. Need >= $MinVagrantMaj.$MinVagrantMin."
        }
    } catch {
        Fail "Could not parse Vagrant version output ('$raw'): $($_.Exception.Message)"
    }
}

# Check 3: VBOX_USER_HOME -----------------------------------------------------
Write-Header "Check 3/8: VBOX_USER_HOME set and on D:"
$vbHome = [Environment]::GetEnvironmentVariable('VBOX_USER_HOME', 'User')
if ([string]::IsNullOrWhiteSpace($vbHome)) {
    Fail "VBOX_USER_HOME is not set. Run host-tune.ps1 (Administrator)."
} elseif ($vbHome -notmatch '^[Dd]:') {
    Fail "VBOX_USER_HOME = '$vbHome' is not on D:. VM disks would land on C:."
} elseif (-not (Test-Path -LiteralPath $vbHome)) {
    Fail "VBOX_USER_HOME = '$vbHome' is set but the directory does not exist."
} else {
    Pass "VBOX_USER_HOME = $vbHome (on D:, exists)."
}

# Check 4: free RAM -----------------------------------------------------------
Write-Header "Check 4/8: Free RAM >= $MinFreeRamGB GB"
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    $freeGB  = [math]::Round($os.FreePhysicalMemory     / 1MB, 1)
    if ($freeGB -ge $MinFreeRamGB) {
        Pass "Free RAM: $freeGB GB of $totalGB GB total (>= $MinFreeRamGB GB required)."
    } elseif ($freeGB -ge 4) {
        Warn "Free RAM: $freeGB GB of $totalGB GB. Below recommended $MinFreeRamGB GB. Close apps before 'vagrant up'."
    } else {
        Fail "Free RAM: $freeGB GB. Too low even with swap; close apps and retry."
    }
} catch {
    Warn "Could not read RAM stats: $($_.Exception.Message)"
}

# Check 5: free D: space ------------------------------------------------------
Write-Header "Check 5/8: Free D: space >= $MinFreeDiskGB GB"
try {
    $d = Get-PSDrive -Name 'D' -PSProvider FileSystem -ErrorAction Stop
    $freeGB = [math]::Round($d.Free / 1GB, 1)
    if ($freeGB -ge $MinFreeDiskGB) {
        Pass "D: free $freeGB GB (>= $MinFreeDiskGB GB required)."
    } else {
        Fail "D: free $freeGB GB is below $MinFreeDiskGB GB. Free disk before continuing."
    }
} catch {
    Fail "D: drive not present: $($_.Exception.Message)"
}

# Check 6: pagefile on D: -----------------------------------------------------
# We deliberately do NOT use a WQL -Filter here. The Name property contains
# backslashes ('D:\pagefile.sys') and the double-escape rules (PowerShell
# string -> WQL parser) are easy to get wrong, which silently returns $null
# and reports "no pagefile" even when one exists. Enumerating the (tiny)
# collection and matching in PowerShell is bulletproof.
Write-Header "Check 6/8: Pagefile on D: >= $MinPagefileMB MB"
try {
    $allPf = @(Get-CimInstance -ClassName Win32_PageFileSetting -ErrorAction SilentlyContinue)
    $pf = $allPf | Where-Object { $_.Name -and $_.Name.ToLower() -like 'd:\*pagefile.sys' } | Select-Object -First 1

    # System-managed pagefiles do not appear in Win32_PageFileSetting; check the
    # runtime view too via Win32_PageFileUsage so we don't false-warn.
    $runtimeOnD = $null
    try {
        $runtimeOnD = @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction SilentlyContinue) |
                      Where-Object { $_.Name -and $_.Name.ToLower() -like 'd:\*pagefile.sys' } |
                      Select-Object -First 1
    } catch { }

    if ($null -ne $pf) {
        if ($pf.InitialSize -ge $MinPagefileMB -and $pf.MaximumSize -ge $MinPagefileMB) {
            Pass "D:\pagefile.sys initial=$($pf.InitialSize) MB, max=$($pf.MaximumSize) MB."
        } else {
            Warn "D:\pagefile.sys is smaller than recommended ($($pf.InitialSize)/$($pf.MaximumSize) MB)."
        }
    } elseif ($null -ne $runtimeOnD) {
        # Configured as system-managed: visible in PageFileUsage but not PageFileSetting.
        $allocMB = [int]$runtimeOnD.AllocatedBaseSize
        if ($allocMB -ge $MinPagefileMB) {
            Pass "D:\pagefile.sys is system-managed, currently $allocMB MB allocated."
        } else {
            Warn "D:\pagefile.sys is system-managed, only $allocMB MB allocated (< $MinPagefileMB MB)."
        }
    } else {
        # Final diagnostic so the user can see what WMI actually has.
        if ($allPf.Count -gt 0) {
            $names = ($allPf | ForEach-Object { $_.Name }) -join ', '
            Warn "No pagefile on D:. WMI reports configured pagefiles at: $names"
        } else {
            Warn "No pagefile configured on D:. Run host-tune.ps1 to create a 16 GB pagefile (then reboot)."
        }
    }
} catch {
    Warn "Could not read pagefile settings: $($_.Exception.Message)"
}

# Check 7: VT-x ---------------------------------------------------------------
# Reliable detection requires cross-checking three signals because Win32_Processor
# reports VirtualizationFirmwareEnabled=False whenever Hyper-V or VBS/Memory Integrity
# is already consuming the host hypervisor.
Write-Header "Check 7/8: VT-x / AMD-V enabled in firmware"
try {
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    $cpuSays = $cpu.VirtualizationFirmwareEnabled

    $sysinfoLines = systeminfo 2>$null
    $hvDetected   = $sysinfoLines | Select-String -SimpleMatch 'A hypervisor has been detected'
    $vtFirmware   = $sysinfoLines | Select-String -SimpleMatch 'Virtualization Enabled In Firmware'

    if ($cpuSays -eq $true) {
        Pass "VT-x / AMD-V enabled (Win32_Processor)."
    } elseif ($hvDetected) {
        # Windows is itself running on the hypervisor -- that proves VT-x is on.
        Pass "VT-x / AMD-V enabled (hypervisor already running on host)."
    } elseif ($vtFirmware -and $vtFirmware -match ':\s*Yes') {
        Pass "VT-x / AMD-V enabled (systeminfo)."
    } elseif ($vtFirmware -and $vtFirmware -match ':\s*No') {
        Fail "VT-x / AMD-V DISABLED in firmware. Reboot, enter BIOS/UEFI, enable virtualization."
    } else {
        # Fall through: VirtualBox is installed and was detected in Check 1.
        # If VT-x were truly disabled, VirtualBox could not start any 64-bit VM.
        # Promote to WARN, not FAIL, and tell the user the real test is `vagrant up`.
        Warn "Win32_Processor reports VT-x disabled but a hypervisor signal was not detectable either."
        Warn "    This is common when Memory Integrity / VBS is on. Definitive test: 'vagrant up' will fail loudly if VT-x is truly off."
    }
} catch {
    Warn "VT-x check failed: $($_.Exception.Message). Verify in BIOS if 'vagrant up' fails later."
}

# Check 8: Power plan + Hyper-V state ----------------------------------------
Write-Header "Check 8/8: Power plan and Hyper-V state"
try {
    $active = (powercfg /getactivescheme) -replace '.*\((.*)\).*', '$1'
    if ($active -match 'High performance') {
        Pass "Active power plan: High Performance."
    } else {
        Warn "Active power plan: '$active'. Run host-tune.ps1 to switch to High Performance."
    }
} catch {
    Warn "Could not read power plan: $($_.Exception.Message)"
}
try {
    $hv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
    if ($hv -and $hv.State -eq 'Enabled') {
        Warn "Hyper-V is enabled. VirtualBox will work but is slower. If 'vagrant up' fails with VT-x errors:"
        Warn "    (admin) bcdedit /set hypervisorlaunchtype off  ; reboot"
    } else {
        Pass "Hyper-V is disabled (best for VirtualBox performance)."
    }
} catch {
    # Get-WindowsOptionalFeature is admin-only on some SKUs; ignore quietly.
    Pass "Hyper-V state could not be queried (likely fine)."
}

# ---------- summary ----------------------------------------------------------
Write-Host ""
Write-Host "=========================================================" -ForegroundColor White
if ($Script:Failures -eq 0 -and $Script:Warnings -eq 0) {
    Write-Host " RESULT: ALL GREEN. You are ready for Stage 1." -ForegroundColor Green
    Write-Host "=========================================================" -ForegroundColor White
    exit 0
}
if ($Script:Failures -eq 0) {
    Write-Host " RESULT: $($Script:Warnings) warning(s), 0 failures. Proceed with caution." -ForegroundColor Yellow
    Write-Host "=========================================================" -ForegroundColor White
    exit 0
}
Write-Host " RESULT: $($Script:Failures) failure(s), $($Script:Warnings) warning(s). Fix before Stage 1." -ForegroundColor Red
Write-Host "=========================================================" -ForegroundColor White
exit 1
