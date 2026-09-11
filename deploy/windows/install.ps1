[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ReleasePath,

    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

    # This must be an independently protected verifier from the release stage,
    # not the candidate watchdog.exe being installed. Its digest is checked
    # before execution; deployment owns the verifier path checks and ACL
    # provisioning, while the native release reader remains the final gate.
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

$defaultServiceAccount = 'NT SERVICE\ascension-watchdog'
if (-not [StringComparer]::OrdinalIgnoreCase.Equals($ServiceAccount, $defaultServiceAccount)) {
    throw "Windows packaging only provisions the fixed virtual service account: $defaultServiceAccount"
}

function Assert-PathIsNotReparse {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must not be a reparse point: $Path"
    }
}

Assert-PathIsNotReparse -Path $ReleasePath -Label 'release path'
Assert-PathIsNotReparse -Path $ConfigPath -Label 'configuration path'
Assert-PathIsNotReparse -Path $VerifierPath -Label 'trusted verifier path'

$release = (Resolve-Path -LiteralPath $ReleasePath).Path
$config = (Resolve-Path -LiteralPath $ConfigPath).Path
$verifier = (Resolve-Path -LiteralPath $VerifierPath).Path
$executable = Join-Path $release 'watchdog.exe'
$manifest = Join-Path $release 'release-manifest.json'

function Assert-DirectoryHasNoReparsePoints {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer) {
        throw "$Label is not a directory: $Path"
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must not be a reparse point: $Path"
    }

    foreach ($entry in @(Get-ChildItem -LiteralPath $Path -Force -Recurse)) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains a reparse point: $($entry.FullName)"
        }
    }
}

function Assert-RegularFileHasNoReparsePoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) {
        throw "$Label is a directory: $Path"
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must not be a reparse point: $Path"
    }
}

function Invoke-Icacls {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    $output = & icacls.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$Operation failed with exit code ${LASTEXITCODE}: $($output -join ' ')"
    }
}

Assert-DirectoryHasNoReparsePoints -Path $release -Label 'release directory'

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
Assert-RegularFileHasNoReparsePoint -Path $executable -Label 'release watchdog executable'
Assert-RegularFileHasNoReparsePoint -Path $manifest -Label 'release manifest'
Assert-RegularFileHasNoReparsePoint -Path $config -Label 'watchdog configuration'
Assert-RegularFileHasNoReparsePoint -Path $verifier -Label 'trusted release verifier'
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

# The service must be able to traverse and read the selected release/config,
# while the service identity must not be granted write access to either. Reset
# inheritance so an inherited user or broad group ACE cannot silently replace
# the approved bytes after inspection. The fixed SIDs avoid localized group
# names; icacls receives an argument array, never a shell command string.
$serviceRead = ('{0}:(OI)(CI)(RX)' -f $ServiceAccount)
Invoke-Icacls -Arguments @(
    $release,
    '/reset',
    '/T',
    '/C'
) -Operation 'release ACL reset'
Invoke-Icacls -Arguments @(
    $release,
    '/inheritance:r',
    '/grant:r',
    '*S-1-5-18:(OI)(CI)(F)',
    '*S-1-5-32-544:(OI)(CI)(F)',
    $serviceRead,
    '/T',
    '/C'
) -Operation 'release ACL provisioning'
Invoke-Icacls -Arguments @(
    $config,
    '/reset',
    '/C'
) -Operation 'configuration ACL reset'
Invoke-Icacls -Arguments @(
    $config,
    '/inheritance:r',
    '/grant:r',
    '*S-1-5-18:(F)',
    '*S-1-5-32-544:(F)',
    ('{0}:(R)' -f $ServiceAccount),
    '/C'
) -Operation 'configuration ACL provisioning'
Invoke-Icacls -Arguments @(
    $config,
    '/setowner',
    '*S-1-5-18'
) -Operation 'configuration owner provisioning'

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
