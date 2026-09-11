[CmdletBinding()]
param(
    [string]$RepositoryPath = (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repository = (Resolve-Path -LiteralPath $RepositoryPath).Path
$installScript = Join-Path $repository 'deploy/windows/install.ps1'
$uninstallScript = Join-Path $repository 'deploy/windows/uninstall.ps1'

foreach ($script in @($installScript, $uninstallScript)) {
    if (-not (Test-Path -LiteralPath $script -PathType Leaf)) {
        throw "packaging script is missing: $script"
    }
    $tokens = $null
    $parseErrors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $script,
        [ref]$tokens,
        [ref]$parseErrors
    ) | Out-Null
    if ($parseErrors.Count -ne 0) {
        throw "PowerShell parser rejected ${script}: $($parseErrors -join '; ')"
    }
}

$installText = Get-Content -LiteralPath $installScript -Raw
$uninstallText = Get-Content -LiteralPath $uninstallScript -Raw

foreach ($fragment in @(
        'Assert-PathIsNotReparse',
        'Assert-DirectoryHasNoReparsePoints',
        'Assert-RegularFileHasNoReparsePoint',
        'VerifierSha256',
        'Get-FileHash',
        'release inspect',
        '/reset',
        '/inheritance:r',
        '*S-1-5-18',
        '*S-1-5-32-544',
        'release ACL provisioning',
        'configuration ACL provisioning',
        '& $executable service install',
        'service was not started',
        'state and releases were preserved'
    )) {
    if (-not $installText.Contains($fragment)) {
        throw "Windows installer lost required boundary: $fragment"
    }
}
foreach ($fragment in @(
        '& $executable service uninstall',
        'data-deletion',
        'state and releases were preserved'
    )) {
    if (-not $uninstallText.Contains($fragment)) {
        throw "Windows uninstaller lost required boundary: $fragment"
    }
}
if ($uninstallText -match '(?im)^\s*Remove-Item\b') {
    throw 'Windows uninstaller must not remove state or release files'
}
$inspectionOffset = $installText.IndexOf('$inspection', [System.StringComparison]::Ordinal)
$serviceInstallOffset = $installText.IndexOf('& $executable service install', [System.StringComparison]::Ordinal)
if ($inspectionOffset -lt 0 -or $serviceInstallOffset -le $inspectionOffset) {
    throw 'Windows installer must complete protected release inspection before SCM mutation'
}

# Exercise the installer gates without invoking SCM. The first attempt must
# stop at the verifier digest boundary. The second uses a deterministic failing
# verifier and must stop before the candidate executable/service command. No
# service, release selector, or owner database is touched by this fixture.
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('ascension-watchdog-package-' + [Guid]::NewGuid().ToString('N'))
$release = Join-Path $scratch 'release'
$config = Join-Path $scratch 'watchdog.json'
$verifier = Join-Path $scratch 'trusted-verifier.cmd'
$marker = Join-Path $scratch 'verifier-invoked.marker'
New-Item -ItemType Directory -Path $release -Force | Out-Null
try {
    Set-Content -LiteralPath (Join-Path $release 'watchdog.exe') -Value 'fixture-not-an-executable' -NoNewline
    Set-Content -LiteralPath (Join-Path $release 'release-manifest.json') -Value '{}' -NoNewline
    Set-Content -LiteralPath $config -Value '{}' -NoNewline
    $verifierBody = @'
@echo off
echo invoked>"%ASCENSION_PACKAGE_TEST_MARKER%"
exit /b 7
'@
    Set-Content -LiteralPath $verifier -Value $verifierBody -Encoding ascii -NoNewline
    $digest = (Get-FileHash -LiteralPath $verifier -Algorithm SHA256).Hash
    $env:ASCENSION_PACKAGE_TEST_MARKER = $marker

    $digestRejected = $false
    try {
        & $installScript -ReleasePath $release -ConfigPath $config -VerifierPath $verifier -VerifierSha256 ('0' * 64)
    } catch {
        $digestRejected = $true
    }
    if (-not $digestRejected) {
        throw 'installer accepted a mismatched trusted verifier digest'
    }
    if (Test-Path -LiteralPath $marker) {
        throw 'installer invoked the trusted verifier before digest validation'
    }

    $inspectionRejected = $false
    try {
        & $installScript -ReleasePath $release -ConfigPath $config -VerifierPath $verifier -VerifierSha256 $digest
    } catch {
        $inspectionRejected = $true
    }
    if (-not $inspectionRejected) {
        throw 'installer accepted a failing protected release inspection'
    }
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        throw 'installer did not invoke the verifier for the protected inspection gate'
    }
} finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item Env:ASCENSION_PACKAGE_TEST_MARKER -ErrorAction SilentlyContinue
}

# A missing config must be rejected before an uninstall command is invoked.
$uninstallRejected = $false
try {
    & $uninstallScript -ExecutablePath $installScript -ConfigPath (Join-Path $repository 'missing-watchdog.json')
} catch {
    $uninstallRejected = $true
}
if (-not $uninstallRejected) {
    throw 'uninstaller accepted a missing owner-local configuration'
}

Write-Output 'Windows packaging parser and preflight gates passed; no SCM mutation was attempted.'
