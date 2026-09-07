[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ReleasePath,

    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    # This must be an independently protected verifier from the release stage,
    # not the candidate watchdog.exe being installed. Its digest is checked
    # before execution; deployment still owns the verifier path ACL and the
    # no-TOCTOU provisioning boundary.
    [Parameter(Mandatory = $true)]
    [string]$VerifierPath,

    # This digest is deployment input, not a value read from the candidate
    # manifest. It identifies the verifier bytes before they are executed.
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$VerifierSha256,

    [string]$ServiceAccount = 'NT SERVICE\ascension-watchdog'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$release = (Resolve-Path -LiteralPath $ReleasePath).Path
$config = (Resolve-Path -LiteralPath $ConfigPath).Path
$verifier = (Resolve-Path -LiteralPath $VerifierPath).Path
$executable = Join-Path $release 'watchdog.exe'
$manifest = Join-Path $release 'release-manifest.json'

if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "release is missing watchdog.exe: $release"
}
if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
    throw "release is missing release-manifest.json: $release"
}
if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
    throw "configuration file is missing: $config"
}
if (-not (Test-Path -LiteralPath $verifier -PathType Leaf)) {
    throw "trusted release verifier is missing: $VerifierPath"
}
$verifierItem = Get-Item -LiteralPath $verifier -Force
if (($verifierItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'trusted release verifier must not be a reparse point'
}
$actualVerifierSha256 = (Get-FileHash -LiteralPath $verifier -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not [StringComparer]::OrdinalIgnoreCase.Equals($actualVerifierSha256, $VerifierSha256)) {
    throw "trusted release verifier digest mismatch: expected $VerifierSha256"
}
if ([StringComparer]::OrdinalIgnoreCase.Equals($verifier, (Resolve-Path -LiteralPath $executable).Path)) {
    throw 'trusted release verifier must be separate from the candidate watchdog.exe'
}

$inspection = & $verifier release inspect --manifest $manifest --root $release 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "trusted release verification failed before SCM mutation: $($inspection -join ' ')"
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
