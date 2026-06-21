# Internal helper: parses each .ps1 in this directory and reports errors
# without executing anything. Safe to run anytime.
$files = @('host-tune.ps1','preflight.ps1','ssd-health.ps1')
$exitCode = 0
foreach ($f in $files) {
    $path = (Join-Path $PSScriptRoot $f)
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Host ("MISS {0}" -f $f) -ForegroundColor Yellow
        $exitCode = 1
        continue
    }
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
        Write-Host ("FAIL {0}" -f $f) -ForegroundColor Red
        $errors | ForEach-Object {
            Write-Host ("  line {0}: {1}" -f $_.Extent.StartLineNumber, $_.Message) -ForegroundColor Red
        }
        $exitCode = 1
    } else {
        Write-Host ("OK   {0}" -f $f) -ForegroundColor Green
    }
}
exit $exitCode
