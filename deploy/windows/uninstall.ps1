[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExecutablePath,

    [Parameter(Mandatory = $true)]
    [string]$ConfigPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$executable = (Resolve-Path -LiteralPath $ExecutablePath).Path
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "watchdog executable is missing: $ExecutablePath"
}

$config = (Resolve-Path -LiteralPath $ConfigPath).Path
if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
    throw "watchdog configuration is missing: $ConfigPath"
}

# The command authenticates and persists the owner-local Stopped intent before
# it asks SCM to remove the service. There is deliberately no data-deletion
# switch here: state, credentials, and release bytes remain for explicit,
# separately audited lifecycle work.
& $executable service uninstall --config $config
if ($LASTEXITCODE -ne 0) {
    throw "watchdog service removal failed with exit code $LASTEXITCODE"
}

Write-Output 'ascension-watchdog service definition removed; state and releases were preserved.'
