[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExecutablePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExecutableSha256,

    [Parameter(Mandatory = $true)]
    [string]$ConfigPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$executableItem = Get-Item -LiteralPath $ExecutablePath -Force
if ($executableItem.PSIsContainer) {
    throw "watchdog executable is a directory: $ExecutablePath"
}
if (($executableItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "watchdog executable must not be a reparse point: $ExecutablePath"
}
$executable = (Resolve-Path -LiteralPath $ExecutablePath).Path
if (-not [StringComparer]::OrdinalIgnoreCase.Equals((Split-Path -Leaf $executable), 'watchdog.exe')) {
    throw "watchdog executable must be the fixed watchdog.exe leaf: $ExecutablePath"
}
$canonicalExecutableItem = Get-Item -LiteralPath $executable -Force
if ($canonicalExecutableItem.PSIsContainer -or
    ($canonicalExecutableItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "watchdog executable must be a regular non-reparse file: $ExecutablePath"
}
$actualExecutableSha256 = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not [StringComparer]::OrdinalIgnoreCase.Equals($actualExecutableSha256, $ExecutableSha256)) {
    throw "watchdog executable digest mismatch: expected $ExecutableSha256"
}

$configItem = Get-Item -LiteralPath $ConfigPath -Force
if ($configItem.PSIsContainer) {
    throw "watchdog configuration is a directory: $ConfigPath"
}
if (($configItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "watchdog configuration must not be a reparse point: $ConfigPath"
}
$config = (Resolve-Path -LiteralPath $ConfigPath).Path
# The native command performs the bounded protected config read. This wrapper
# only rejects directories/reparse leaves before invoking it.

# The command authenticates and persists the owner-local Stopped intent before
# it asks SCM to remove the service. There is deliberately no data-deletion
# switch here: state, credentials, and release bytes remain for explicit,
# separately audited lifecycle work.
& $executable service uninstall --config $config
if ($LASTEXITCODE -ne 0) {
    throw "watchdog service removal failed with exit code $LASTEXITCODE"
}

Write-Output 'ascension-watchdog service definition removed; state and releases were preserved.'
