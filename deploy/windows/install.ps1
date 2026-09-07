[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ReleasePath,

    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    [string]$ServiceAccount = 'NT SERVICE\ascension-watchdog'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$release = (Resolve-Path -LiteralPath $ReleasePath).Path
$config = (Resolve-Path -LiteralPath $ConfigPath).Path
$executable = Join-Path $release 'watchdog.exe'
$manifest = Join-Path $release 'release-manifest.json'

if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "validated release is missing watchdog.exe: $release"
}
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
    throw "validated release is missing release-manifest.json: $release"
}
if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
    throw "configuration file is missing: $config"
}

# The Rust command validates the closed configuration and registers the
# automatic-start service through the existing SCM API. It never receives a
# password or any other secret on its command line, and it does not start the
# service or initialize its database.
& $executable service install --config $config --executable $executable --account $ServiceAccount
if ($LASTEXITCODE -ne 0) {
    throw "watchdog service installation failed with exit code $LASTEXITCODE"
}

Write-Output "ascension-watchdog installation prepared; service was not started."
Write-Output "state and releases were preserved."
