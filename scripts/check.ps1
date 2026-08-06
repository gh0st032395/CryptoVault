# The single verification command for CryptoVault, on Windows.
#
# Mirrors scripts/check.sh step for step. Run it before every commit.
#
# Usage:
#   .\scripts\check.ps1          full check
#   .\scripts\check.ps1 -Fast    skip the slow supply-chain audit

[CmdletBinding()]
param(
    [switch]$Fast
)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

function Step($message) { Write-Host "`n> $message" -ForegroundColor Cyan }
function Skip($message, $reason) { Write-Host "`n> $message (skipped: $reason)" -ForegroundColor Yellow }

# cargo writes progress to stderr, which PowerShell would otherwise treat as a
# failure. Check the real exit code instead.
function Invoke-Checked([string]$command, [string[]]$commandArgs) {
    & $command @commandArgs
    if ($LASTEXITCODE -ne 0) {
        throw "$command $($commandArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

Step 'Formatting'
Invoke-Checked cargo @('fmt', '--all', '--', '--check')

Step 'Lints (warnings are errors)'
Invoke-Checked cargo @('clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings')

Step 'Tests'
Invoke-Checked cargo @('test', '--workspace', '--all-features')

Step 'Documentation builds without warnings'
$env:RUSTDOCFLAGS = '-D warnings'
Invoke-Checked cargo @('doc', '--workspace', '--no-deps', '--all-features')
Remove-Item Env:\RUSTDOCFLAGS

if ($Fast) {
    Skip 'Supply chain' '-Fast'
}
elseif (Get-Command cargo-deny -ErrorAction SilentlyContinue) {
    Step 'Supply chain (licences, advisories, sources)'
    Invoke-Checked cargo @('deny', 'check')
}
else {
    Skip 'Supply chain' 'cargo-deny not installed - cargo install cargo-deny'
}

Write-Host "`n[OK] All checks passed" -ForegroundColor Green
