[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExecutablePath,

    [switch]$DeleteData,

    [string]$DataPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$executable = (Resolve-Path -LiteralPath $ExecutablePath).Path
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "watchdog executable is missing: $ExecutablePath"
}

if ($DeleteData -and [string]::IsNullOrWhiteSpace($DataPath)) {
    throw '-DeleteData requires an exact -DataPath; data is preserved by default.'
}

& $executable service uninstall
if ($LASTEXITCODE -ne 0) {
    throw "watchdog service removal failed with exit code $LASTEXITCODE"
}

if ($DeleteData) {
    $data = (Resolve-Path -LiteralPath $DataPath -ErrorAction Stop).Path
    $root = [IO.Path]::GetPathRoot($data)
    if ($data -eq $root) {
        throw 'refusing to remove a filesystem root as service data'
    }
    Remove-Item -LiteralPath $data -Recurse -Force
    Write-Output "explicit service data removal completed: $data"
} else {
    Write-Output 'ascension-watchdog service definition removed; state and releases were preserved.'
}
